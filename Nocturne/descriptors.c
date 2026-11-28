/* Nocturne の上の Python のファイル記述子（Nocturne/descriptors.h）。

   記述子は開いたファイルを名指し、開いたファイルはハンドル、文書の中の位置、読みが取らなかったチャネルの
   メッセージの残りを持つ。os.dup は同じ開いたファイルの二つ目の記述子を作り、最後の記述子が閉じるとハンドルを
   閉じる。記述子 0、1、2（stdin、stdout、stderr）はアプリの入力、出力、記録の流れで、起動元が名指したハンドル
   （n_input、n_output、n_log）。そこにある出力の文書は、中核のライブラリーの流れと同じく後ろへ足すので、シェルの
   "> 名前" を分け合うアプリは互いの後ろに書く。

   端末へつながる記述子は、中核のライブラリーの n_line_read が編集した行を読む。主のスレッドのチャネルの読みは
   _PyOS_NocturneWait で待つので、Ctrl+C が EINTR で終わらせ、Python が SIGINT の handler を走らせる。

   socket の記述子（Nocturne/socketmodule.c）は、Python が求めるとおり socket() からあり、TCP か UDP のハンドルは
   つなぐか、聞くか、bind した時に来る：それまで開いたファイルは種類だけを持ち、ハンドルを持たない。os.read と
   os.write は、チャネルと同じく socket の流れにも届く。

   錠の順：表の錠、次に開いたファイルの錠。逆の順で取る間、どちらも持たない。 */
#include "Python.h"
#include "pycore_signal.h"        // _PyOS_NocturneWait()
#include "descriptors.h"

#include <errno.h>
#include <signal.h>               // raise()
#include <stdlib.h>
#include <string.h>

struct open_file {
    int32_t handle;               /* 契約のハンドルの番号。-1 はまだハンドルの無い socket */
    int kind;                     /* N_KIND_* */
    bool readable;
    bool writable;
    bool append;                  /* 書きはどれも文書の終わりへ */
    bool blocking;
    bool terminal;                /* 端末の入力の流れ：読みは行 */
    uint32_t refs;                /* 名指す記述子と、使っている呼び出し */
    PyMutex lock;                 /* position、pending */
    uint64_t position;            /* 文書 */
    char *pending;                /* チャネル：受けてまだ読んでいないバイト */
    size_t pending_at, pending_end;
};

static struct {
    PyMutex lock;
    struct open_file **files;
    int count;
    bool standard;                /* 0、1、2 を見た */
} table;

/* 端末の読みが取る一番長い行。 */
#define TERMINAL_LINE (64 * 1024)

static int
fail(n_result r)
{
    errno = (int)(r < 0 ? -r : r);
    return -1;
}

const char *
_Py_result_text(n_result r, char *buf, size_t size)
{
    n_result n = n_result_text(r, buf, size - 1);
    buf[n < 0 ? 0 : (size_t)n < size - 1 ? (size_t)n : size - 1] = '\0';
    return buf;
}

int
_Py_complete_path(const char *name, char out[_PY_PATH_MAX])
{
    /* NUL の場所を残す。全部の長さが容量を越えれば、パスは長すぎる */
    n_result r = n_path_complete(name, strlen(name), out, _PY_PATH_MAX - 1);
    if (r < 0) {
        return fail(r);
    }
    if (r > _PY_PATH_MAX - 1) {
        errno = ENAMETOOLONG;
        return -1;
    }
    out[r] = '\0';
    return (int)r;
}

n_result
_Py_entry_info(const char *path, struct n_entry *entry)
{
    memset(entry, 0, sizeof *entry);
    entry->bytes = sizeof *entry;
    return n_entry_info(path, strlen(path), entry);
}

n_result
_Py_folder_list(const char *folder, struct n_entry **entries)
{
    size_t length = strlen(folder);
    *entries = NULL;
    /* 数を聞いてから読む。その間に項が増えれば読み直す */
    n_result count = n_folder_list(folder, length, NULL, 0, sizeof(struct n_entry), 0);
    for (;;) {
        if (count < 0) {
            return count;
        }
        size_t capacity = (size_t)count + 1;
        struct n_entry *list = PyMem_RawCalloc(capacity, sizeof *list);
        if (list == NULL) {
            return -N_ERR_NO_MEMORY;
        }
        for (size_t i = 0; i < capacity; i++) {
            list[i].bytes = sizeof list[i];
        }
        n_result total = n_folder_list(folder, length, list, capacity, sizeof *list, 0);
        if (total >= 0 && (size_t)total <= capacity) {
            *entries = list;
            return total;
        }
        PyMem_RawFree(list);
        count = total;
    }
}

/* Nocturne に mode は無い：項は読めて書けると言い、開く時に系がその所有者の利用者を確かめる。C: が持つ時刻は
   変えた時刻の一つ。 */
void
_Py_entry_stat(const struct n_entry *entry, struct _Py_stat_struct *status)
{
    memset(status, 0, sizeof *status);
    status->st_ino = entry->id;
    status->st_mode = entry->kind == N_KIND_FOLDER ? S_IFDIR | 0777 : S_IFREG | 0666;
    status->st_nlink = 1;
    status->st_uid = entry->owner;
    status->st_size = (int64_t)entry->size;
    status->st_mtime = entry->modified;
    status->st_mtime_nsec = (int)entry->modified_ns;
    status->st_atime = status->st_ctime = status->st_mtime;
    status->st_atime_nsec = status->st_ctime_nsec = status->st_mtime_nsec;
}

int
_Py_path_stat(const char *name, struct _Py_stat_struct *status)
{
    char path[_PY_PATH_MAX];
    if (_Py_complete_path(name, path) < 0) {
        return -1;
    }
    struct n_entry entry;
    n_result r = _Py_entry_info(path, &entry);
    if (r < 0) {
        return fail(r);
    }
    _Py_entry_stat(&entry, status);
    return 0;
}

/* ---- 表 ---- */

static struct open_file *
open_file_make(int32_t handle, int kind)
{
    struct open_file *f = PyMem_RawCalloc(1, sizeof *f);
    if (f == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    f->handle = handle;
    f->kind = kind;
    f->blocking = true;
    f->refs = 1;
    return f;
}

static void
open_file_put(struct open_file *f)
{
    if (__atomic_sub_fetch(&f->refs, 1, __ATOMIC_ACQ_REL) != 0) {
        return;
    }
    if (f->handle >= 0) {
        n_handle_close((n_handle){f->handle});
    }
    PyMem_RawFree(f->pending);
    PyMem_RawFree(f);
}

/* 表は少なくとも count の項を持つ。表の錠を持って呼ぶ。 */
static int
table_reserve(int count)
{
    if (count <= table.count) {
        return 0;
    }
    int grown = table.count ? table.count : 16;
    while (grown < count) {
        grown *= 2;
    }
    struct open_file **files = PyMem_RawRealloc(table.files, sizeof *files * (size_t)grown);
    if (files == NULL) {
        errno = ENOMEM;
        return -1;
    }
    memset(files + table.count, 0, sizeof *files * (size_t)(grown - table.count));
    table.files = files;
    table.count = grown;
    return 0;
}

/* 記述子 0、1、2：アプリの入力、出力、記録の流れで、表を初めて使う時に作る。起動元が渡さなかった流れは記述子を
   持たない。表の錠を持って呼ぶ。 */
static void
table_standard(void)
{
    if (table.standard) {
        return;
    }
    table.standard = true;
    if (table_reserve(3) < 0) {
        return;
    }
    n_result (*const streams[3])(n_handle *) = {n_input, n_output, n_log};
    for (int fd = 0; fd < 3; fd++) {
        n_handle h;
        if (streams[fd](&h) < 0) {
            continue;
        }
        n_result kind = n_handle_kind(h);
        if (kind < 0) {
            continue;
        }
        struct open_file *f = open_file_make(h.handle, (int)kind);
        if (f == NULL) {
            continue;
        }
        f->readable = f->writable = true;
        f->append = kind == N_KIND_DOCUMENT && fd != 0;
        f->terminal = fd == 0 && n_terminal(h);
        table.files[fd] = f;
    }
}

/* fd が名指す開いたファイル。open_file_put まで持つ。 */
static struct open_file *
fd_get(int fd)
{
    struct open_file *f = NULL;
    PyMutex_Lock(&table.lock);
    table_standard();
    if (fd >= 0 && fd < table.count) {
        f = table.files[fd];
    }
    if (f != NULL) {
        __atomic_add_fetch(&f->refs, 1, __ATOMIC_RELAXED);
    }
    PyMutex_Unlock(&table.lock);
    if (f == NULL) {
        errno = EBADF;
    }
    return f;
}

/* 一番小さい空いた記述子が f を名指す。f は表に参照を与える。 */
static int
fd_install(struct open_file *f)
{
    PyMutex_Lock(&table.lock);
    table_standard();
    int fd = 0;
    while (fd < table.count && table.files[fd] != NULL) {
        fd++;
    }
    if (table_reserve(fd + 1) < 0) {
        PyMutex_Unlock(&table.lock);
        return -1;
    }
    table.files[fd] = f;
    PyMutex_Unlock(&table.lock);
    return fd;
}

int
_Py_fd_adopt(int32_t handle, int readable, int writable)
{
    n_result kind = n_handle_kind((n_handle){handle});
    if (kind < 0) {
        return fail(kind);
    }
    struct open_file *f = open_file_make(handle, (int)kind);
    if (f == NULL) {
        return -1;
    }
    f->readable = readable;
    f->writable = writable;
    int fd = fd_install(f);
    if (fd < 0) {
        f->handle = -1;
        open_file_put(f);
    }
    return fd;
}

/* Python の旗（os.O_*）で文書を開く。 */
static n_result
open_document(const char *path, int flags, n_document *document)
{
    size_t length = strlen(path);
    enum n_document_access access =
        (flags & O_ACCMODE) == O_RDONLY ? N_DOCUMENT_ACCESS_READ : N_DOCUMENT_ACCESS_EDIT;
    if ((flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL)) {
        return n_document_open(path, length, N_DOCUMENT_ACCESS_CREATE, document);
    }
    n_result r = n_document_open(path, length, access, document);
    if (r == -N_ERR_NOT_FOUND && (flags & O_CREAT)) {
        r = n_document_open(path, length, N_DOCUMENT_ACCESS_CREATE, document);
        if (r == -N_ERR_EXISTS) {
            r = n_document_open(path, length, access, document);  /* その間に作られた */
        }
    }
    if (r >= 0 && (flags & O_TRUNC)) {
        r = n_document_set_size(*document, 0);
        if (r < 0) {
            n_handle_close((n_handle){document->handle});
        }
    }
    return r;
}

int
_Py_fd_open(const char *name, int flags)
{
    char path[_PY_PATH_MAX];
    if (_Py_complete_path(name, path) < 0) {
        return -1;
    }
    n_document document;
    n_result r = open_document(path, flags, &document);
    if (r < 0) {
        return fail(r);
    }
    struct open_file *f = open_file_make(document.handle, N_KIND_DOCUMENT);
    if (f == NULL) {
        n_handle_close((n_handle){document.handle});
        return -1;
    }
    f->readable = (flags & O_ACCMODE) != O_WRONLY;
    f->writable = (flags & O_ACCMODE) != O_RDONLY;
    f->append = (flags & O_APPEND) != 0;
    int fd = fd_install(f);
    if (fd < 0) {
        open_file_put(f);
    }
    return fd;
}

int32_t
_Py_fd_handle(int fd)
{
    struct open_file *f = fd_get(fd);
    if (f == NULL) {
        return -1;
    }
    int32_t h = __atomic_load_n(&f->handle, __ATOMIC_ACQUIRE);
    open_file_put(f);
    if (h < 0) {
        errno = ENOTCONN;
    }
    return h;
}

int
_Py_fd_kind(int fd)
{
    struct open_file *f = fd_get(fd);
    if (f == NULL) {
        return -1;
    }
    int kind = f->kind;
    open_file_put(f);
    return kind;
}

int
_Py_fd_socket(int kind)
{
    struct open_file *f = open_file_make(-1, kind);
    if (f == NULL) {
        return -1;
    }
    f->readable = f->writable = true;
    int fd = fd_install(f);
    if (fd < 0) {
        open_file_put(f);
    }
    return fd;
}

int
_Py_fd_attach(int fd, int32_t handle)
{
    struct open_file *f = fd_get(fd);
    if (f == NULL) {
        return -1;
    }
    int32_t none = -1;
    bool attached = __atomic_compare_exchange_n(&f->handle, &none, handle, false,
                                                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    open_file_put(f);
    if (!attached) {
        errno = EISCONN;
        return -1;
    }
    return 0;
}

int
_Py_fd_detach(int fd, int32_t handle)
{
    struct open_file *f = fd_get(fd);
    if (f == NULL) {
        return -1;
    }
    int32_t expected = handle;
    bool detached = __atomic_compare_exchange_n(&f->handle, &expected, -1, false,
                                                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    open_file_put(f);
    if (!detached) {
        errno = EISCONN;
        return -1;
    }
    return 0;
}

int
_Py_fd_poll(int fd, int32_t *handle)
{
    struct open_file *f = fd_get(fd);
    if (f == NULL) {
        return -1;
    }
    int ready = 0;
    *handle = -1;
    int32_t h = __atomic_load_n(&f->handle, __ATOMIC_ACQUIRE);
    if (f->kind == N_KIND_DOCUMENT) {
        ready = N_EVENT_RECEIVABLE | N_EVENT_SENDABLE;
    }
    else if (h < 0) {
        /* 一度もつながらなかった socket：その呼び出しはすぐ答える */
        ready = N_EVENT_RECEIVABLE | N_EVENT_SENDABLE | N_EVENT_CLOSED;
    }
    else {
        PyMutex_Lock(&f->lock);
        if (f->pending != NULL) {
            ready = N_EVENT_RECEIVABLE;
        }
        PyMutex_Unlock(&f->lock);
        *handle = h;
    }
    open_file_put(f);
    return ready;
}

int
_Py_fd_close(int fd)
{
    struct open_file *f = NULL;
    PyMutex_Lock(&table.lock);
    table_standard();
    if (fd >= 0 && fd < table.count) {
        f = table.files[fd];
        table.files[fd] = NULL;
    }
    PyMutex_Unlock(&table.lock);
    if (f == NULL) {
        errno = EBADF;
        return -1;
    }
    open_file_put(f);
    return 0;
}

void
_Py_fd_close_range(int first, int last)
{
    for (int fd = first < 0 ? 0 : first; fd <= last; fd++) {
        PyMutex_Lock(&table.lock);
        int count = table.count;
        PyMutex_Unlock(&table.lock);
        if (fd >= count) {
            break;
        }
        (void)_Py_fd_close(fd);
    }
}

int
_Py_fd_dup(int fd)
{
    struct open_file *f = fd_get(fd);
    if (f == NULL) {
        return -1;
    }
    int copy = fd_install(f);
    if (copy < 0) {
        open_file_put(f);
    }
    return copy;
}

int
_Py_fd_dup2(int fd, int fd2)
{
    struct open_file *f = fd_get(fd);
    if (f == NULL) {
        return -1;
    }
    if (fd2 < 0) {
        open_file_put(f);
        errno = EBADF;
        return -1;
    }
    if (fd2 == fd) {
        open_file_put(f);
        return fd2;
    }
    PyMutex_Lock(&table.lock);
    if (table_reserve(fd2 + 1) < 0) {
        PyMutex_Unlock(&table.lock);
        open_file_put(f);
        return -1;
    }
    struct open_file *old = table.files[fd2];
    table.files[fd2] = f;
    PyMutex_Unlock(&table.lock);
    if (old != NULL) {
        open_file_put(old);
    }
    return fd2;
}

/* ---- 読み ---- */

/* 前に受けてまだ読んでいないバイト。f の錠を持って呼ぶ。 */
static size_t
take_pending(struct open_file *f, char *buf, size_t count)
{
    size_t n = Py_MIN(count, f->pending_end - f->pending_at);
    memcpy(buf, f->pending + f->pending_at, n);
    f->pending_at += n;
    if (f->pending_at == f->pending_end) {
        PyMem_RawFree(f->pending);
        f->pending = NULL;
        f->pending_at = f->pending_end = 0;
    }
    return n;
}

/* 主のスレッドの止まる読みのために、h に何かが来るか Ctrl+C まで待つ：0 か、errno EINTR の -1。 */
static int
wait_receivable(int32_t h)
{
    if (_PyOS_NocturneWait(h, N_EVENT_RECEIVABLE | N_EVENT_CLOSED, NULL, 0, N_CLOCK_NEVER) < 0) {
        errno = EINTR;
        return -1;
    }
    return 0;
}

/* TCP の流れのバイトか、UDP の datagram 一つ（buf に入る分）を、チャネルの読みと同じく待って読む。f の錠を持たずに
   呼ぶ：socket へ送るスレッドは、受けるスレッドを待たない。 */
static Py_ssize_t
read_socket(struct open_file *f, char *buf, size_t count)
{
    int32_t h = __atomic_load_n(&f->handle, __ATOMIC_ACQUIRE);
    if (h < 0) {
        errno = ENOTCONN;
        return -1;
    }
    for (;;) {
        bool interruptible = f->blocking && _PyOS_NocturneInterruptible();
        uint64_t deadline = f->blocking && !interruptible ? N_CLOCK_NEVER : 0;
        n_result r;
        if (f->kind == N_KIND_TCP) {
            r = n_tcp_receive_until((n_tcp){h}, (uint8_t *)buf, count, deadline, NULL, 0);
        }
        else {
            struct n_udp_received received = {.bytes = sizeof received};
            r = n_udp_receive_until((n_udp){h}, (uint8_t *)buf, count, &received, deadline, NULL, 0);
        }
        if ((r == -N_ERR_NOT_READY || r == -N_ERR_TIMEOUT) && deadline == 0) {
            if (!interruptible) {
                errno = EAGAIN;
                return -1;
            }
            if (wait_receivable(h) < 0) {
                return -1;
            }
            continue;
        }
        /* 長い datagram は buf に入った分だけ（n_udp_receive_until は datagram の長さを返す） */
        return r < 0 ? fail(r) : (Py_ssize_t)Py_MIN((size_t)r, count);
    }
}

/* 受けたメッセージの添え物を閉じる（記述子の読みは添え物を受けない）。 */
static void
drop_attached(n_handle attached)
{
    if (attached.handle >= 0) {
        n_handle_close(attached);
    }
}

/* チャネルの次のメッセージの buf に入る部分。残りは pending に持つ。f の錠を持って呼ぶ。 */
static Py_ssize_t
read_channel(struct open_file *f, char *buf, size_t count)
{
    bool console = f->kind == N_KIND_CONSOLE;
    for (;;) {
        bool interruptible = f->blocking && _PyOS_NocturneInterruptible();
        n_handle attached = {-1};
        n_result r = console
            ? n_console_receive((n_console){f->handle}, (uint8_t *)buf, count)
            : n_channel_receive((n_channel){f->handle}, (uint8_t *)buf, count, &attached, 0);
        if (r >= 0) {
            drop_attached(attached);
        }
        if (r == 0 && !console) {
            continue;  /* 空のメッセージはバイトを持たない */
        }
        if (r == -N_ERR_CLOSED) {
            return 0;
        }
        if (r == -N_ERR_NOT_READY) {
            if (!f->blocking) {
                return fail(r);
            }
            if (interruptible) {
                if (wait_receivable(f->handle) < 0) {
                    return -1;
                }
                continue;
            }
            /* 閉じた後も残ったメッセージは受けられる：待ちが closed なら受けて確かめる */
            if (console) {
                _PyOS_NocturneWait(f->handle, N_EVENT_RECEIVABLE | N_EVENT_CLOSED, NULL, 0, N_CLOCK_NEVER);
            }
            else {
                r = n_channel_wait((n_channel){f->handle}, N_CLOCK_NEVER);
                if (r < 0 && r != -N_ERR_CLOSED) {
                    return fail(r);
                }
            }
            continue;
        }
        if (r < 0) {
            return fail(r);
        }
        if (!console && (size_t)r > count) {
            /* 場所より大きいメッセージは受けずに大きさが返る：持つ場所へ受け、残りを pending に回す */
            char *message = PyMem_RawMalloc((size_t)r);
            if (message == NULL) {
                errno = ENOMEM;
                return -1;
            }
            r = n_channel_receive((n_channel){f->handle}, (uint8_t *)message, (size_t)r, &attached, 0);
            if (r < 0) {
                PyMem_RawFree(message);
                return fail(r);
            }
            drop_attached(attached);
            f->pending = message;
            f->pending_at = 0;
            f->pending_end = (size_t)r;
            return (Py_ssize_t)take_pending(f, buf, count);
        }
        return (Py_ssize_t)r;
    }
}

static PyMutex terminal_lock;

Py_ssize_t
_Py_terminal_line(const char *prompt, char *buf, size_t size)
{
    assert(size >= 2);
    PyMutex_Lock(&terminal_lock);
    _PyOS_NocturneInterruptsPause();
    n_result n = n_line_read(prompt, strlen(prompt), buf, size - 2, 0, NULL, NULL);
    _PyOS_NocturneInterruptsResume();
    PyMutex_Unlock(&terminal_lock);
    if (n == -N_ERR_CANCELLED) {
        raise(SIGINT);
        errno = EINTR;
        return -1;
    }
    if (n < 0) {
        return 0;
    }
    if ((size_t)n > size - 2) {
        n = (n_result)(size - 2);  /* 長すぎる行は場所に入った分 */
    }
    buf[n] = '\n';
    buf[n + 1] = '\0';
    return (Py_ssize_t)n + 1;
}

/* 端末で打った行の buf に入る部分。残りは pending に持つ。f の錠を持って呼ぶ。 */
static Py_ssize_t
read_terminal(struct open_file *f, char *buf, size_t count)
{
    char *line = PyMem_RawMalloc(TERMINAL_LINE);
    if (line == NULL) {
        errno = ENOMEM;
        return -1;
    }
    Py_ssize_t n = _Py_terminal_line("", line, TERMINAL_LINE);
    if (n <= 0) {
        PyMem_RawFree(line);
        return n;
    }
    f->pending = line;
    f->pending_at = 0;
    f->pending_end = (size_t)n;
    return (Py_ssize_t)take_pending(f, buf, count);
}

Py_ssize_t
_Py_fd_read(int fd, void *buf, size_t count)
{
    struct open_file *f = fd_get(fd);
    if (f == NULL) {
        return -1;
    }
    Py_ssize_t r;
    if (!f->readable) {
        errno = EBADF;
        r = -1;
    }
    else if (count == 0) {
        r = 0;
    }
    else if (f->kind == N_KIND_TCP || f->kind == N_KIND_UDP) {
        r = read_socket(f, buf, count);
    }
    else {
        PyMutex_Lock(&f->lock);
        if (f->pending != NULL) {
            r = (Py_ssize_t)take_pending(f, buf, count);
        }
        else if (f->kind == N_KIND_DOCUMENT) {
            n_result got = n_document_read_at((n_document){f->handle}, f->position, (uint8_t *)buf, count);
            if (got > 0) {
                f->position += (uint64_t)got;
            }
            r = got < 0 ? fail(got) : (Py_ssize_t)got;
        }
        else if (f->terminal) {
            r = read_terminal(f, buf, count);
        }
        else {
            r = read_channel(f, buf, count);
        }
        PyMutex_Unlock(&f->lock);
    }
    open_file_put(f);
    return r;
}

/* ---- 書き ---- */

/* buf の全部を文書の位置へ、足す形の文書は終わりへ書く。f の錠を持って呼ぶ。 */
static Py_ssize_t
write_document(struct open_file *f, const char *buf, size_t count)
{
    n_document document = {f->handle};
    bool claimed = false;
    if (f->append) {
        /* 錠が、足すほかの者を同じ終わりに書かせない */
        claimed = n_document_claim(document, 0, N_DOCUMENT_WHOLE, N_DOCUMENT_CLAIM_KIND_EXCLUSIVE, 1) == 0;
        uint64_t size = 0;
        n_result r = n_document_size(document, &size);
        if (r < 0) {
            if (claimed) {
                n_document_release(document, 0, N_DOCUMENT_WHOLE);
            }
            return fail(r);
        }
        f->position = size;
    }
    size_t done = 0;
    n_result r = 0;
    while (done < count) {
        r = n_document_write_at(document, f->position, (const uint8_t *)buf + done, count - done);
        if (r <= 0) {
            break;
        }
        done += (size_t)r;
        f->position += (uint64_t)r;
    }
    if (claimed) {
        n_document_release(document, 0, N_DOCUMENT_WHOLE);
    }
    if (done == 0 && r < 0) {
        return fail(r);
    }
    return (Py_ssize_t)done;
}

/* buf の頭を TCP の流れへ、止まる書きと同じく空きを待って書く（主のスレッドでは Ctrl+C が待ちを終える）。UDP の
   socket の記述子は送り先の住所を持たない。 */
static Py_ssize_t
write_socket(struct open_file *f, const char *buf, size_t count)
{
    int32_t h = __atomic_load_n(&f->handle, __ATOMIC_ACQUIRE);
    if (h < 0) {
        errno = ENOTCONN;
        return -1;
    }
    if (f->kind == N_KIND_UDP) {
        errno = EDESTADDRREQ;
        return -1;
    }
    for (;;) {
        bool interruptible = f->blocking && _PyOS_NocturneInterruptible();
        n_result r = f->blocking && !interruptible
            ? n_tcp_send_until((n_tcp){h}, (const uint8_t *)buf, count, 0, N_CLOCK_NEVER, NULL, 0)
            : n_tcp_send((n_tcp){h}, (const uint8_t *)buf, count, 0);
        if (r == -N_ERR_NOT_READY && interruptible) {
            if (_PyOS_NocturneWait(h, N_EVENT_SENDABLE | N_EVENT_CLOSED, NULL, 0,
                                   N_CLOCK_NEVER) < 0) {
                errno = EINTR;
                return -1;
            }
            continue;
        }
        return r < 0 ? fail(r) : (Py_ssize_t)r;
    }
}

Py_ssize_t
_Py_fd_write(int fd, const void *buf, size_t count)
{
    struct open_file *f = fd_get(fd);
    if (f == NULL) {
        return -1;
    }
    Py_ssize_t r;
    if (!f->writable) {
        errno = EBADF;
        r = -1;
    }
    else if (f->kind == N_KIND_DOCUMENT) {
        PyMutex_Lock(&f->lock);
        r = write_document(f, buf, count);
        PyMutex_Unlock(&f->lock);
    }
    else if (f->kind == N_KIND_TCP || f->kind == N_KIND_UDP) {
        r = write_socket(f, buf, count);
    }
    else {
        /* 一つの送りが一つのメッセージ。読む側が遠く遅れている間、送りは待つ（docs/nocturne-native-abi.md §4） */
        n_result sent = n_channel_send((n_channel){f->handle}, buf, count, (n_handle){-1});
        r = sent < 0 ? fail(sent) : (Py_ssize_t)count;
    }
    open_file_put(f);
    return r;
}

/* ---- 文書 ---- */

long long
_Py_fd_seek(int fd, long long offset, int whence)
{
    struct open_file *f = fd_get(fd);
    if (f == NULL) {
        return -1;
    }
    long long r = -1;
    if (f->kind != N_KIND_DOCUMENT) {
        errno = ESPIPE;
        goto done;
    }
    PyMutex_Lock(&f->lock);
    long long base;
    if (whence == SEEK_SET) {
        base = 0;
    }
    else if (whence == SEEK_CUR) {
        base = (long long)f->position;
    }
    else if (whence == SEEK_END) {
        uint64_t size = 0;
        n_result got = n_document_size((n_document){f->handle}, &size);
        base = got < 0 ? -1 : (long long)size;
        if (got < 0) {
            fail(got);
        }
    }
    else {
        errno = EINVAL;
        base = -1;
    }
    if (base >= 0) {
        if (offset < 0 ? base < -offset : offset > LLONG_MAX - base) {
            errno = EINVAL;
        }
        else {
            f->position = (uint64_t)(base + offset);
            r = (long long)f->position;
        }
    }
    PyMutex_Unlock(&f->lock);
done:
    open_file_put(f);
    return r;
}

int
_Py_fd_truncate(int fd, long long size)
{
    struct open_file *f = fd_get(fd);
    if (f == NULL) {
        return -1;
    }
    int r;
    if (size < 0) {
        errno = EINVAL;
        r = -1;
    }
    else if (!f->writable) {
        errno = EBADF;
        r = -1;
    }
    else {
        n_result set = n_document_set_size((n_document){f->handle}, (uint64_t)size);
        r = set < 0 ? fail(set) : 0;
    }
    open_file_put(f);
    return r;
}

/* 文書の中身を媒体に載せる。 */
int
_Py_fd_sync(int fd)
{
    struct open_file *f = fd_get(fd);
    if (f == NULL) {
        return -1;
    }
    int r = 0;
    if (f->kind == N_KIND_DOCUMENT) {
        n_result committed = n_document_commit((n_document){f->handle}, N_DOCUMENT_COMMIT_KIND_WAIT);
        r = committed < 0 ? fail(committed) : 0;
    }
    else {
        errno = EINVAL;
        r = -1;
    }
    open_file_put(f);
    return r;
}

int
_Py_fd_stat(int fd, struct _Py_stat_struct *status)
{
    struct open_file *f = fd_get(fd);
    if (f == NULL) {
        return -1;
    }
    int r = 0;
    if (f->kind == N_KIND_DOCUMENT) {
        struct n_entry entry = {.bytes = sizeof entry};
        n_result info = n_document_info((n_document){f->handle}, &entry);
        if (info < 0) {
            r = fail(info);
        }
        else {
            _Py_entry_stat(&entry, status);
        }
    }
    else {
        memset(status, 0, sizeof *status);
        status->st_mode = f->terminal || f->kind == N_KIND_CONSOLE ? S_IFCHR | 0666
                          : f->kind == N_KIND_TCP || f->kind == N_KIND_UDP ? S_IFSOCK | 0666
                          : S_IFIFO | 0666;
        status->st_nlink = 1;
    }
    open_file_put(f);
    return r;
}

int
_Py_fd_isatty(int fd)
{
    struct open_file *f = fd_get(fd);
    if (f == NULL) {
        return -1;
    }
    int r = f->terminal || f->kind == N_KIND_CONSOLE || (f->handle >= 0 && n_terminal((n_handle){f->handle}));
    open_file_put(f);
    return r;
}

int
_Py_fd_get_blocking(int fd)
{
    struct open_file *f = fd_get(fd);
    if (f == NULL) {
        return -1;
    }
    int r = f->blocking;
    open_file_put(f);
    return r;
}

int
_Py_fd_set_blocking(int fd, int blocking)
{
    struct open_file *f = fd_get(fd);
    if (f == NULL) {
        return -1;
    }
    PyMutex_Lock(&f->lock);
    f->blocking = blocking != 0;
    PyMutex_Unlock(&f->lock);
    open_file_put(f);
    return 0;
}
