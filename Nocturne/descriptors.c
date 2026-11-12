/* Python's file descriptors on Nocturne (Nocturne/descriptors.h).

   A descriptor names an open file, which holds the handle, the position in a
   document and the rest of a channel message a read did not take. os.dup gives
   a second descriptor for the same open file, which closes its handle when the
   last of them closes. Descriptors 0, 1 and 2 (stdin, stdout, stderr) are the
   app's input, output and log streams, the handles its launcher named
   (n_input, n_output, n_log); an output document there is appended to, as
   libc's streams do, so apps sharing a shell's "> name" write after each other.

   A descriptor that reaches the terminal reads lines that libc's n_line_read
   edits, as the line discipline of a terminal does elsewhere. A read of a
   channel on the main thread waits through _PyOS_NocturneWait, so that Ctrl+C
   ends it with EINTR and Python runs its SIGINT handler.

   A socket's descriptor (Nocturne/socketmodule.c) exists from socket() on,
   as Python expects, while its TCP or UDP handle comes once it connects,
   listens or binds: until then the open file has its kind and no handle.
   os.read and os.write reach a socket's stream as they reach a channel.

   Lock order: the table's lock, then an open file's. Neither is held while
   another is taken the other way round. */
#include "Python.h"
#include "pycore_signal.h"        // _PyOS_NocturneWait()
#include "descriptors.h"

#include <errno.h>
#include <signal.h>               // raise()
#include <stdlib.h>
#include <string.h>

struct open_file {
    n_handle handle;              /* -1: a socket with no handle yet */
    int kind;                     /* N_KIND_* */
    bool readable;
    bool writable;
    bool append;                  /* every write goes to the document's end */
    bool blocking;
    bool terminal;                /* the input stream at a terminal: reads are lines */
    uint32_t refs;                /* descriptors naming it, and calls using it */
    PyMutex lock;                 /* position, pending */
    uint64_t position;            /* documents */
    char *pending;                /* channels: bytes received and not yet read */
    size_t pending_at, pending_end;
};

static struct {
    PyMutex lock;
    struct open_file **files;
    int count;
    bool standard;                /* 0, 1 and 2 were looked at */
} table;

/* The longest line a read of the terminal takes. */
#define TERMINAL_LINE (64 * 1024)

static int
fail(n_result r)
{
    errno = (int)(r < 0 ? -r : r);
    return -1;
}

int
_Py_complete_path(const char *name, char out[_PY_PATH_MAX])
{
    n_result r = n_path_complete(name, out, _PY_PATH_MAX);
    if (r == -N_ERR_TOO_LARGE) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return r < 0 ? fail(r) : 0;
}

/* Nocturne has no modes: an entry reads as readable and writable, and the
   system checks the user it belongs to when it is opened. C: keeps one time,
   the modified time. */
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
    n_result r = n_entry_info(path, &entry);
    if (r < 0) {
        return fail(r);
    }
    _Py_entry_stat(&entry, status);
    return 0;
}

/* ---- the table ---- */

static struct open_file *
open_file_make(n_handle handle, int kind)
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
        n_handle_close(f->handle);
    }
    PyMem_RawFree(f->pending);
    PyMem_RawFree(f);
}

/* The table holds at least count slots. Called with its lock. */
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

/* Descriptors 0, 1 and 2: the app's input, output and log streams, made the
   first time the table is used. A stream the launcher did not give has no
   descriptor. Called with its lock. */
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
    const n_handle streams[3] = {n_input(), n_output(), n_log()};
    for (int fd = 0; fd < 3; fd++) {
        n_handle h = streams[fd];
        n_result kind = h >= 0 ? n_handle_kind(h) : h;
        if (kind < 0) {
            continue;
        }
        struct open_file *f = open_file_make(h, (int)kind);
        if (f == NULL) {
            continue;
        }
        f->readable = f->writable = true;
        f->append = kind == N_KIND_DOCUMENT && fd != 0;
        f->terminal = fd == 0 && n_terminal(h);
        table.files[fd] = f;
    }
}

/* The open file fd names, held until open_file_put. */
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

/* The lowest free descriptor names f, which gives the table its reference. */
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
_Py_fd_adopt(n_handle handle, int readable, int writable)
{
    n_result kind = n_handle_kind(handle);
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

/* A document by Python's flags (os.O_*). */
static n_handle
open_document(const char *path, int flags)
{
    int access = (flags & O_ACCMODE) == O_RDONLY ? N_DOCUMENT_READ : N_DOCUMENT_EDIT;
    if ((flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL)) {
        return n_document_open(path, N_DOCUMENT_CREATE);
    }
    n_handle h = n_document_open(path, access);
    if (h == -N_ERR_NOT_FOUND && (flags & O_CREAT)) {
        h = n_document_open(path, N_DOCUMENT_CREATE);
        if (h == -N_ERR_EXISTS) {
            h = n_document_open(path, access);  /* made meanwhile */
        }
    }
    if (h >= 0 && (flags & O_TRUNC)) {
        n_result r = n_document_set_size(h, 0);
        if (r < 0) {
            n_handle_close(h);
            return (n_handle)r;
        }
    }
    return h;
}

int
_Py_fd_open(const char *name, int flags)
{
    char path[_PY_PATH_MAX];
    if (_Py_complete_path(name, path) < 0) {
        return -1;
    }
    n_handle h = open_document(path, flags);
    if (h < 0) {
        return fail(h);
    }
    struct open_file *f = open_file_make(h, N_KIND_DOCUMENT);
    if (f == NULL) {
        n_handle_close(h);
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

n_handle
_Py_fd_handle(int fd)
{
    struct open_file *f = fd_get(fd);
    if (f == NULL) {
        return -1;
    }
    n_handle h = __atomic_load_n(&f->handle, __ATOMIC_ACQUIRE);
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
_Py_fd_attach(int fd, n_handle handle)
{
    struct open_file *f = fd_get(fd);
    if (f == NULL) {
        return -1;
    }
    n_handle none = -1;
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
_Py_fd_detach(int fd, n_handle handle)
{
    struct open_file *f = fd_get(fd);
    if (f == NULL) {
        return -1;
    }
    n_handle expected = handle;
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
_Py_fd_poll(int fd, n_handle *handle)
{
    struct open_file *f = fd_get(fd);
    if (f == NULL) {
        return -1;
    }
    int ready = 0;
    *handle = -1;
    n_handle h = __atomic_load_n(&f->handle, __ATOMIC_ACQUIRE);
    if (f->kind == N_KIND_DOCUMENT) {
        ready = N_EVENT_RECEIVABLE | N_EVENT_SENDABLE;
    }
    else if (h < 0) {
        /* a socket that never connected: its calls answer at once */
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

/* ---- reading ---- */

/* Bytes received earlier and not yet read. Called with f's lock. */
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

/* Waits until h has something for a blocking read on the main thread, or
   until Ctrl+C: 0, or -1 with errno EINTR. */
static int
wait_receivable(n_handle h)
{
    if (_PyOS_NocturneWait(h, N_EVENT_RECEIVABLE | N_EVENT_CLOSED, NULL, 0, N_CLOCK_NEVER) < 0) {
        errno = EINTR;
        return -1;
    }
    return 0;
}

/* Bytes of a TCP stream, or one UDP datagram (what fits buf), as a read of
   a channel waits. Not called with f's lock: a thread that sends to the
   socket does not wait for one that receives from it. */
static Py_ssize_t
read_socket(struct open_file *f, char *buf, size_t count)
{
    n_handle h = __atomic_load_n(&f->handle, __ATOMIC_ACQUIRE);
    if (h < 0) {
        errno = ENOTCONN;
        return -1;
    }
    for (;;) {
        bool interruptible = f->blocking && _PyOS_NocturneInterruptible();
        uint64_t deadline = f->blocking && !interruptible ? N_CLOCK_NEVER : 0;
        n_result r = f->kind == N_KIND_TCP
            ? tcp_recv(h, buf, count, deadline)
            : udp_receive(h, buf, count, NULL, deadline, -1);
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
        /* 長い datagram は buf に入った分だけ（udp_receive は datagram の長さを返す） */
        return r < 0 ? fail(r) : (Py_ssize_t)Py_MIN((size_t)r, count);
    }
}

/* The next message of a channel, the part of it that fits buf and the rest
   kept as pending. Called with f's lock. */
static Py_ssize_t
read_channel(struct open_file *f, char *buf, size_t count)
{
    for (;;) {
        bool interruptible = f->blocking && _PyOS_NocturneInterruptible();
        int flags = f->blocking && !interruptible ? N_CHANNEL_WAIT : 0;
        n_result r = f->kind == N_KIND_CONSOLE
            ? n_console_receive(f->handle, buf, count, flags)
            : n_channel_receive(f->handle, buf, count, flags, NULL);
        if (r == 0 && f->kind != N_KIND_CONSOLE) {
            continue;  /* an empty message carries no bytes */
        }
        if (r == -N_ERR_CLOSED) {
            return 0;
        }
        if (r == -N_ERR_NOT_READY && interruptible) {
            if (wait_receivable(f->handle) < 0) {
                return -1;
            }
            continue;
        }
        if (r == -N_ERR_TOO_LARGE && f->kind != N_KIND_CONSOLE) {
            n_result size = n_channel_receive(f->handle, NULL, 0, N_CHANNEL_PEEK, NULL);
            if (size < 0) {
                return fail(size);
            }
            char *message = PyMem_RawMalloc((size_t)size);
            if (message == NULL) {
                errno = ENOMEM;
                return -1;
            }
            r = n_channel_receive(f->handle, message, (size_t)size, 0, NULL);
            if (r < 0) {
                PyMem_RawFree(message);
                return fail(r);
            }
            f->pending = message;
            f->pending_at = 0;
            f->pending_end = (size_t)r;
            return (Py_ssize_t)take_pending(f, buf, count);
        }
        if (r < 0) {
            return fail(r);
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
    int n = n_line_read(prompt, buf, size - 1, 0, NULL);
    _PyOS_NocturneInterruptsResume();
    PyMutex_Unlock(&terminal_lock);
    if (n == N_LINE_INTERRUPTED) {
        raise(SIGINT);
        errno = EINTR;
        return -1;
    }
    if (n < 0) {
        return 0;
    }
    buf[n] = '\n';
    buf[n + 1] = '\0';
    return n + 1;
}

/* A line typed at the terminal, the part that fits buf and the rest kept as
   pending. Called with f's lock. */
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
            n_result got = n_document_read_at(f->handle, f->position, buf, count);
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

/* ---- writing ---- */

/* All of buf at the document's position, or at its end for an appending one.
   Called with f's lock. */
static Py_ssize_t
write_document(struct open_file *f, const char *buf, size_t count)
{
    bool claimed = false;
    if (f->append) {
        /* the claim keeps other appenders from writing at the same end */
        claimed = n_document_claim(f->handle, N_CLAIM_EXCLUSIVE, true) == 0;
        n_result size = n_document_size(f->handle);
        if (size < 0) {
            if (claimed) {
                n_document_release(f->handle);
            }
            return fail(size);
        }
        f->position = (uint64_t)size;
    }
    size_t done = 0;
    n_result r = 0;
    while (done < count) {
        r = n_document_write_at(f->handle, f->position, buf + done, count - done);
        if (r <= 0) {
            break;
        }
        done += (size_t)r;
        f->position += (uint64_t)r;
    }
    if (claimed) {
        n_document_release(f->handle);
    }
    if (done == 0 && r < 0) {
        return fail(r);
    }
    return (Py_ssize_t)done;
}

/* A prefix of buf onto a TCP stream, waiting for room as a blocking write
   does (Ctrl+C ends the wait on the main thread). A UDP socket's descriptor
   has no address to send to. */
static Py_ssize_t
write_socket(struct open_file *f, const char *buf, size_t count)
{
    n_handle h = __atomic_load_n(&f->handle, __ATOMIC_ACQUIRE);
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
            ? tcp_send_until(h, buf, count, N_CLOCK_NEVER)
            : tcp_send_some(h, buf, count);
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
        /* one send is one message; the send waits while the reader is far
           behind (docs/nocturne-native-abi.md §4) */
        n_result sent = n_channel_send(f->handle, buf, count, -1);
        r = sent < 0 ? fail(sent) : (Py_ssize_t)sent;
    }
    open_file_put(f);
    return r;
}

/* ---- documents ---- */

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
        n_result size = n_document_size(f->handle);
        base = size;
        if (size < 0) {
            fail(size);
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
        n_result set = n_document_set_size(f->handle, (uint64_t)size);
        r = set < 0 ? fail(set) : 0;
    }
    open_file_put(f);
    return r;
}

/* The document's content on the medium. */
int
_Py_fd_sync(int fd)
{
    struct open_file *f = fd_get(fd);
    if (f == NULL) {
        return -1;
    }
    int r = 0;
    if (f->kind == N_KIND_DOCUMENT) {
        n_result committed = n_document_commit(f->handle, N_COMMIT_WAIT);
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
        struct n_entry entry;
        n_result info = n_document_info(f->handle, &entry);
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
    int r = f->terminal || f->kind == N_KIND_CONSOLE || n_terminal(f->handle);
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
