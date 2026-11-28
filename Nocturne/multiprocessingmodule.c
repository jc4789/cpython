/* _multiprocessing：Nocturne の上の multiprocessing のネイティブの半分（ports/cpython/README.md）。

   multiprocessing は各プロセスを一つのアプリとして起動し（n_app_launch、Lib/multiprocessing/popen_spawn_nocturne.py）、
   受け継ぐハンドルを起動の表で渡す（docs/nocturne-native-abi.md §5）。プロセスが分け合うものは系のオブジェクトで作る：

   - SemLock：共有のページ（§7）の上のセマフォの語。acquire は原子の交換で語を下げ、番地の待ちで眠る（共有のページでは
     アプリをまたいで効く）。release は語を上げ、眠る者を一つ目覚めさせる。子が受け継ぐのはページのハンドル。
   - Shared：書ける buffer としての共有のページ。multiprocessing.heap のアリーナ（Value、Array、sharedctypes）。
   - channel_send と channel_receive：Connection のメッセージはチャネルのメッセージ（§4）なので、区切りは系のもの。
     pickle したオブジェクトが持つハンドルは、本体の前の空のメッセージに一つずつ添えて渡る：本体は添え物を持たず、
     添え物を持つ空のメッセージは本体でない。
   - wait：系のイベントキュー（§6）の上の multiprocessing.connection.wait。チャネルか TCP の接続は N_EVENT_RECEIVABLE
     か N_EVENT_CLOSED を知らせれば、アプリ（Process の sentinel）は N_EVENT_APP_ENDED を知らせれば用意ができている。

   主のスレッドでは Ctrl+C が待ちを終え、Python が SIGINT の handler を走らせ、handler が例外を起こさなければ同じ
   締め切りまで待ち続ける（PEP 475）。ハンドルは契約のハンドルの番号（int32_t）で持ち、契約の関数へは種類の構造体で
   渡す。 */
#include "Python.h"
#include "pycore_signal.h"        // _PyOS_NocturneWait()
#include "pycore_time.h"          // _PyTime_FromSecondsObject()
#include "descriptors.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

/* Lib/multiprocessing/synchronize.py の列挙と同じ。 */
enum { RECURSIVE_MUTEX, SEMAPHORE };

typedef struct {
    PyTypeObject *semlock_type;
    PyTypeObject *shared_type;
} module_state;

static inline module_state *
get_state(PyObject *module)
{
    return (module_state *)PyModule_GetState(module);
}

static PyObject *
raise_result(n_result r)
{
    errno = (int)-r;
    return PyErr_SetFromErrno(PyExc_OSError);
}

/* 秒の timeout（None は無し）からの単調時計の締め切り。0 か、例外つきの -1。負の timeout は、Python 自身の
   セマフォと待ちと同じく 0。 */
static int
deadline_of(PyObject *timeout, uint64_t *deadline)
{
    *deadline = N_CLOCK_NEVER;
    if (timeout == Py_None) {
        return 0;
    }
    PyTime_t t;
    if (_PyTime_FromSecondsObject(&t, timeout, _PyTime_ROUND_TIMEOUT) < 0) {
        return -1;
    }
    *deadline = t <= 0 ? 0 : n_clock_after((uint64_t)t);
    return 0;
}

/* ---- SemLock ---- */

/* セマフォのあるページ。value がセマフォで、waiters はそれで眠ろうとしているどのアプリのスレッドも数える：release は
   誰かが眠る時だけ目覚めさせる。どちらも逐次一貫で読み書きする：待つ者は waiters を上げてから value を読み、release は
   value を上げてから waiters を読むので、どちらかがもう片方を見る。 */
struct semaphore_page {
    uint32_t value;
    uint32_t waiters;
};

typedef struct {
    PyObject_HEAD
    int32_t handle;                   /* ページの共有のオブジェクト */
    struct semaphore_page *page;
    unsigned long last_tid;
    int count;                        /* このプロセスの acquire から release を引いた数 */
    int maxvalue;
    int kind;
} SemLockObject;

#define ISMINE(o) ((o)->count > 0 && PyThread_get_thread_ident() == (o)->last_tid)

static bool
semaphore_take(struct semaphore_page *page)
{
    uint32_t v = __atomic_load_n(&page->value, __ATOMIC_SEQ_CST);
    while (v > 0) {
        if (__atomic_compare_exchange_n(&page->value, &v, v - 1, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
            return true;
        }
    }
    return false;
}

/* 語が上がっている間に取らずに去る待つ者は、受けたかもしれない目覚めを次の眠る者へ渡す：答えの無い release を
   残さない。 */
static void
semaphore_pass_on(struct semaphore_page *page)
{
    if (__atomic_load_n(&page->value, __ATOMIC_SEQ_CST) > 0 &&
        __atomic_load_n(&page->waiters, __ATOMIC_SEQ_CST) > 0) {
        n_wake_address((size_t)&page->value, 1);
    }
}

/* 締め切りまでセマフォを取る：1 は取った、0 は締め切り、-1 は例外つき（SIGINT の handler が例外を置いた）。一周ごとに、
   語を取るか、締め切りで終わるか、release が語を変えるまで眠る。 */
static int
semaphore_wait(struct semaphore_page *page, uint64_t deadline)
{
    for (;;) {
        __atomic_add_fetch(&page->waiters, 1, __ATOMIC_SEQ_CST);
        if (semaphore_take(page)) {
            __atomic_sub_fetch(&page->waiters, 1, __ATOMIC_SEQ_CST);
            return 1;
        }
        int woke;
        Py_BEGIN_ALLOW_THREADS
        woke = _PyOS_NocturneWait(-1, 0, &page->value, 0, deadline);
        Py_END_ALLOW_THREADS
        __atomic_sub_fetch(&page->waiters, 1, __ATOMIC_SEQ_CST);
        if (woke < 0) {
            semaphore_pass_on(page);
            if (PyErr_CheckSignals() < 0) {
                return -1;
            }
            continue;
        }
        if (woke == 0 && n_clock_monotonic() >= deadline) {
            if (semaphore_take(page)) {
                return 1;
            }
            semaphore_pass_on(page);
            return 0;
        }
    }
}

static PyObject *
semlock_acquire(PyObject *op, PyObject *args, PyObject *kwargs)
{
    SemLockObject *self = (SemLockObject *)op;
    static char *keywords[] = {"block", "timeout", NULL};
    int blocking = 1;
    PyObject *timeout = Py_None;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|pO:acquire", keywords, &blocking, &timeout)) {
        return NULL;
    }
    if (self->kind == RECURSIVE_MUTEX && ISMINE(self)) {
        ++self->count;
        Py_RETURN_TRUE;
    }
    uint64_t deadline;
    if (deadline_of(timeout, &deadline) < 0) {
        return NULL;
    }
    int taken = semaphore_take(self->page);
    if (!taken && blocking) {
        taken = semaphore_wait(self->page, deadline);
        if (taken < 0) {
            return NULL;
        }
    }
    if (!taken) {
        Py_RETURN_FALSE;
    }
    ++self->count;
    self->last_tid = PyThread_get_thread_ident();
    Py_RETURN_TRUE;
}

static PyObject *
semlock_release(PyObject *op, PyObject *Py_UNUSED(ignored))
{
    SemLockObject *self = (SemLockObject *)op;
    if (self->kind == RECURSIVE_MUTEX) {
        if (!ISMINE(self)) {
            PyErr_SetString(PyExc_AssertionError, "attempt to release recursive lock not owned by thread");
            return NULL;
        }
        if (self->count > 1) {
            --self->count;
            Py_RETURN_NONE;
        }
    }
    struct semaphore_page *page = self->page;
    uint32_t v = __atomic_load_n(&page->value, __ATOMIC_SEQ_CST);
    do {
        if (v >= (uint32_t)self->maxvalue) {
            PyErr_SetString(PyExc_ValueError, "semaphore or lock released too many times");
            return NULL;
        }
    } while (!__atomic_compare_exchange_n(&page->value, &v, v + 1, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST));
    if (__atomic_load_n(&page->waiters, __ATOMIC_SEQ_CST) > 0) {
        n_wake_address((size_t)&page->value, 1);
    }
    --self->count;
    Py_RETURN_NONE;
}

static PyObject *
semlock_enter(PyObject *op, PyObject *Py_UNUSED(ignored))
{
    PyObject *args = PyTuple_New(0);
    if (args == NULL) {
        return NULL;
    }
    PyObject *r = semlock_acquire(op, args, NULL);
    Py_DECREF(args);
    return r;
}

static PyObject *
semlock_exit(PyObject *op, PyObject *Py_UNUSED(args))
{
    return semlock_release(op, NULL);
}

static PyObject *
semlock_count(PyObject *op, PyObject *Py_UNUSED(ignored))
{
    return PyLong_FromLong(((SemLockObject *)op)->count);
}

static PyObject *
semlock_is_mine(PyObject *op, PyObject *Py_UNUSED(ignored))
{
    return PyBool_FromLong(ISMINE((SemLockObject *)op));
}

static PyObject *
semlock_get_value(PyObject *op, PyObject *Py_UNUSED(ignored))
{
    return PyLong_FromUnsignedLong(__atomic_load_n(&((SemLockObject *)op)->page->value, __ATOMIC_SEQ_CST));
}

static PyObject *
semlock_is_zero(PyObject *op, PyObject *Py_UNUSED(ignored))
{
    return PyBool_FromLong(__atomic_load_n(&((SemLockObject *)op)->page->value, __ATOMIC_SEQ_CST) == 0);
}

/* A spawned process's objects start with none of the launcher's acquires
   counted; no app on Nocturne is a copy of another, so there is nothing to
   rezero. synchronize.py does not call it on Nocturne; it stays for code
   that calls the SemLock interface. */
static PyObject *
semlock_after_fork(PyObject *op, PyObject *Py_UNUSED(ignored))
{
    ((SemLockObject *)op)->count = 0;
    Py_RETURN_NONE;
}

/* handle のページの上の SemLock。ハンドルはそれが持つ。 */
static PyObject *
semlock_over(PyTypeObject *type, int32_t handle, int kind, int maxvalue)
{
    n_result mapping = n_shared_map((n_shared){handle}, N_PAGE_BYTES, N_MEMORY_ACCESS_READ_WRITE);
    if (mapping < 0) {
        return raise_result(mapping);
    }
    SemLockObject *self = (SemLockObject *)type->tp_alloc(type, 0);
    if (self == NULL) {
        n_memory_release((size_t)mapping, N_PAGE_BYTES);
        return NULL;
    }
    self->handle = handle;
    self->page = (struct semaphore_page *)(size_t)mapping;
    self->kind = kind;
    self->maxvalue = maxvalue;
    return (PyObject *)self;
}

static int
semlock_check(int kind, int maxvalue)
{
    if (kind != RECURSIVE_MUTEX && kind != SEMAPHORE) {
        PyErr_SetString(PyExc_ValueError, "unrecognized kind");
        return -1;
    }
    if (maxvalue < 1) {
        PyErr_SetString(PyExc_ValueError, "maxvalue must be at least 1");
        return -1;
    }
    return 0;
}

/* SemLock(kind, value, maxvalue)：自分のページの上の新しいセマフォ。 */
static PyObject *
semlock_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"kind", "value", "maxvalue", NULL};
    int kind, value, maxvalue;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "iii:SemLock", keywords, &kind, &value, &maxvalue)) {
        return NULL;
    }
    if (semlock_check(kind, maxvalue) < 0) {
        return NULL;
    }
    if (value < 0 || value > maxvalue) {
        PyErr_SetString(PyExc_ValueError, "invalid value");
        return NULL;
    }
    n_shared shared;
    n_result created = n_shared_create(N_PAGE_BYTES, &shared);
    if (created < 0) {
        return raise_result(created);
    }
    PyObject *self = semlock_over(type, shared.handle, kind, maxvalue);
    if (self == NULL) {
        n_handle_close((n_handle){shared.handle});
        return NULL;
    }
    __atomic_store_n(&((SemLockObject *)self)->page->value, (uint32_t)value, __ATOMIC_SEQ_CST);
    return self;
}

/* _rebuild(handle, kind, maxvalue, name)：起動したプロセスが受け継いだ SemLock。handle は起動の表の中の番号、name は
   None。 */
static PyObject *
semlock_rebuild(PyObject *cls, PyObject *args)
{
    int handle, kind, maxvalue;
    PyObject *name;
    if (!PyArg_ParseTuple(args, "iiiO:_rebuild", &handle, &kind, &maxvalue, &name)) {
        return NULL;
    }
    if (name != Py_None) {
        PyErr_SetString(PyExc_ValueError, "a SemLock has no name on Nocturne");
        return NULL;
    }
    if (semlock_check(kind, maxvalue) < 0) {
        return NULL;
    }
    return semlock_over((PyTypeObject *)cls, handle, kind, maxvalue);
}

static void
semlock_dealloc(PyObject *op)
{
    SemLockObject *self = (SemLockObject *)op;
    PyTypeObject *tp = Py_TYPE(self);
    PyObject_GC_UnTrack(self);
    if (self->page != NULL) {
        n_memory_release((size_t)self->page, N_PAGE_BYTES);
    }
    if (self->handle >= 0) {
        n_handle_close((n_handle){self->handle});
    }
    tp->tp_free(self);
    Py_DECREF(tp);
}

static int
semlock_traverse(PyObject *op, visitproc visit, void *arg)
{
    Py_VISIT(Py_TYPE(op));
    return 0;
}

static PyObject *
semlock_handle(PyObject *op, void *Py_UNUSED(closure))
{
    return PyLong_FromLong(((SemLockObject *)op)->handle);
}

static PyObject *
semlock_name(PyObject *op, void *Py_UNUSED(closure))
{
    Py_RETURN_NONE;
}

static PyMethodDef semlock_methods[] = {
    {"acquire", _PyCFunction_CAST(semlock_acquire), METH_VARARGS | METH_KEYWORDS,
     "acquire($self, /, block=True, timeout=None)\n--\n\nAcquire the semaphore/lock."},
    {"release", semlock_release, METH_NOARGS, "release($self, /)\n--\n\nRelease the semaphore/lock."},
    {"__enter__", semlock_enter, METH_NOARGS, "__enter__($self, /)\n--\n\nEnter the semaphore/lock."},
    {"__exit__", semlock_exit, METH_VARARGS, "__exit__($self, type=None, value=None, traceback=None, /)\n--\n\n"
                                             "Exit the semaphore/lock."},
    {"_count", semlock_count, METH_NOARGS,
     "_count($self, /)\n--\n\nNum of `acquire()`s minus num of `release()`s for this process."},
    {"_is_mine", semlock_is_mine, METH_NOARGS, "_is_mine($self, /)\n--\n\nWhether the lock is owned by this thread."},
    {"_get_value", semlock_get_value, METH_NOARGS, "_get_value($self, /)\n--\n\nGet the value of the semaphore."},
    {"_is_zero", semlock_is_zero, METH_NOARGS, "_is_zero($self, /)\n--\n\nReturn whether semaphore has value zero."},
    {"_rebuild", semlock_rebuild, METH_VARARGS | METH_CLASS,
     "_rebuild(handle, kind, maxvalue, name, /)\n--\n\nThe SemLock a spawned process inherited."},
    {"_after_fork", semlock_after_fork, METH_NOARGS, "_after_fork($self, /)\n--\n\nRezero the net acquisition count."},
    {NULL}
};

static PyMemberDef semlock_members[] = {
    {"kind", Py_T_INT, offsetof(SemLockObject, kind), Py_READONLY, ""},
    {"maxvalue", Py_T_INT, offsetof(SemLockObject, maxvalue), Py_READONLY, ""},
    {NULL}
};

static PyGetSetDef semlock_getset[] = {
    {"handle", semlock_handle, NULL, "the handle of the semaphore's shared page", NULL},
    {"name", semlock_name, NULL, "None: a semaphore on Nocturne has no name", NULL},
    {NULL}
};

static PyType_Slot semlock_slots[] = {
    {Py_tp_dealloc, semlock_dealloc},
    {Py_tp_traverse, semlock_traverse},
    {Py_tp_methods, semlock_methods},
    {Py_tp_members, semlock_members},
    {Py_tp_getset, semlock_getset},
    {Py_tp_new, semlock_new},
    {Py_tp_doc, (void *)PyDoc_STR("Semaphore/Mutex type")},
    {0, NULL}
};

static PyType_Spec semlock_spec = {
    .name = "_multiprocessing.SemLock",
    .basicsize = sizeof(SemLockObject),
    .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC | Py_TPFLAGS_IMMUTABLETYPE,
    .slots = semlock_slots,
};

/* ---- Shared ---- */

typedef struct {
    PyObject_HEAD
    int32_t handle;
    void *mapping;
    Py_ssize_t size;                  /* buffer が見せるバイト */
    size_t mapped;                    /* 頁の倍数の大きさ */
} SharedObject;

/* Shared(size, handle=-1)：size バイトの共有のページ。新しく作るか、（handle）起動したプロセスが受け継いだもので、
   そのハンドルはこれが持つ。 */
static PyObject *
shared_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"size", "handle", NULL};
    Py_ssize_t size;
    int handle = -1;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "n|i:Shared", keywords, &size, &handle)) {
        return NULL;
    }
    if (size <= 0) {
        PyErr_SetString(PyExc_ValueError, "size must be positive");
        return NULL;
    }
    size_t mapped = ((size_t)size + N_PAGE_BYTES - 1) & ~(size_t)(N_PAGE_BYTES - 1);
    bool created = handle < 0;
    if (created) {
        n_shared shared;
        n_result r = n_shared_create(mapped, &shared);
        if (r < 0) {
            return raise_result(r);
        }
        handle = shared.handle;
    }
    n_result mapping = n_shared_map((n_shared){handle}, mapped, N_MEMORY_ACCESS_READ_WRITE);
    if (mapping < 0) {
        if (created) {
            n_handle_close((n_handle){handle});
        }
        return raise_result(mapping);
    }
    SharedObject *self = (SharedObject *)type->tp_alloc(type, 0);
    if (self == NULL) {
        n_memory_release((size_t)mapping, mapped);
        if (created) {
            n_handle_close((n_handle){handle});
        }
        return NULL;
    }
    self->handle = handle;
    self->mapping = (void *)(size_t)mapping;
    self->size = size;
    self->mapped = mapped;
    return (PyObject *)self;
}

static void
shared_dealloc(PyObject *op)
{
    SharedObject *self = (SharedObject *)op;
    PyTypeObject *tp = Py_TYPE(self);
    PyObject_GC_UnTrack(self);
    if (self->mapping != NULL) {
        n_memory_release((size_t)self->mapping, self->mapped);
    }
    if (self->handle >= 0) {
        n_handle_close((n_handle){self->handle});
    }
    tp->tp_free(self);
    Py_DECREF(tp);
}

static int
shared_traverse(PyObject *op, visitproc visit, void *arg)
{
    Py_VISIT(Py_TYPE(op));
    return 0;
}

/* memoryview はオブジェクトを持つので、それがある間ページはマップされたまま。 */
static int
shared_getbuffer(PyObject *op, Py_buffer *view, int flags)
{
    SharedObject *self = (SharedObject *)op;
    return PyBuffer_FillInfo(view, op, self->mapping, self->size, 0, flags);
}

static PyObject *
shared_handle(PyObject *op, void *Py_UNUSED(closure))
{
    return PyLong_FromLong(((SharedObject *)op)->handle);
}

static PyObject *
shared_size(PyObject *op, void *Py_UNUSED(closure))
{
    return PyLong_FromSsize_t(((SharedObject *)op)->size);
}

static PyGetSetDef shared_getset[] = {
    {"handle", shared_handle, NULL, "the handle of the shared object", NULL},
    {"size", shared_size, NULL, "the bytes the buffer shows", NULL},
    {NULL}
};

static PyType_Slot shared_slots[] = {
    {Py_tp_dealloc, shared_dealloc},
    {Py_tp_traverse, shared_traverse},
    {Py_tp_getset, shared_getset},
    {Py_tp_new, shared_new},
    {Py_bf_getbuffer, shared_getbuffer},
    {Py_tp_doc, (void *)PyDoc_STR("Shared(size, handle=-1)\n--\n\nPages of shared memory as a writable buffer.")},
    {0, NULL}
};

static PyType_Spec shared_spec = {
    .name = "_multiprocessing.Shared",
    .basicsize = sizeof(SharedObject),
    .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC | Py_TPFLAGS_IMMUTABLETYPE,
    .slots = shared_slots,
};

/* ---- チャネル ---- */

/* channel_pair()：新しいチャネルの両端。 */
static PyObject *
mp_channel_pair(PyObject *module, PyObject *Py_UNUSED(ignored))
{
    n_channel one, other;
    n_result r = n_channel_pair(&other, &one);
    if (r < 0) {
        return raise_result(r);
    }
    return Py_BuildValue("(ii)", one.handle, other.handle);
}

/* channel_send(handle, data, handles=())：handles の一つごとに空のメッセージを送ってから、data を一つのメッセージで
   送る。handles はここで開いたまま。受け手が取っていない 1 MiB を持つ間、送りは待つ（§4）。 */
static PyObject *
mp_channel_send(PyObject *module, PyObject *args)
{
    int channel;
    Py_buffer data;
    PyObject *handles = NULL;
    if (!PyArg_ParseTuple(args, "iy*|O:channel_send", &channel, &data, &handles)) {
        return NULL;
    }
    PyObject *fast = NULL;
    Py_ssize_t count = 0;
    if (handles != NULL) {
        fast = PySequence_Fast(handles, "handles must be a sequence");
        if (fast == NULL) {
            PyBuffer_Release(&data);
            return NULL;
        }
        count = PySequence_Fast_GET_SIZE(fast);
    }
    n_result r = 0;
    for (Py_ssize_t i = 0; r >= 0 && i < count; i++) {
        int carried = PyLong_AsInt(PySequence_Fast_GET_ITEM(fast, i));
        if (carried == -1 && PyErr_Occurred()) {
            goto fail;
        }
        Py_BEGIN_ALLOW_THREADS
        r = n_channel_send((n_channel){channel}, NULL, 0, (n_handle){carried});
        Py_END_ALLOW_THREADS
    }
    if (r >= 0) {
        Py_BEGIN_ALLOW_THREADS
        r = n_channel_send((n_channel){channel}, data.buf, (size_t)data.len, (n_handle){-1});
        Py_END_ALLOW_THREADS
    }
    Py_XDECREF(fast);
    PyBuffer_Release(&data);
    if (r < 0) {
        return raise_result(r);
    }
    Py_RETURN_NONE;
fail:
    Py_XDECREF(fast);
    PyBuffer_Release(&data);
    return NULL;
}

/* チャネルにメッセージが来るか、相手の端が無くなるまで待つ：0 か、例外つきの -1。 */
static int
channel_wait(int32_t channel)
{
    for (;;) {
        int woke;
        Py_BEGIN_ALLOW_THREADS
        woke = _PyOS_NocturneWait(channel, N_EVENT_RECEIVABLE | N_EVENT_CLOSED, NULL, 0, N_CLOCK_NEVER);
        Py_END_ALLOW_THREADS
        if (woke >= 0) {
            return 0;
        }
        if (PyErr_CheckSignals() < 0) {
            return -1;
        }
    }
}

/* channel_receive(handle, maxsize=None)：(data, handles)。次のメッセージと、その前に添えて渡ったハンドルで、来るまで
   待つ。メッセージが maxsize より長ければ data は None で、メッセージは捨てる。相手の端が無くなり、何も残っていなければ
   EOFError。 */
static PyObject *
mp_channel_receive(PyObject *module, PyObject *args)
{
    int channel;
    PyObject *maxsize_object = Py_None;
    if (!PyArg_ParseTuple(args, "i|O:channel_receive", &channel, &maxsize_object)) {
        return NULL;
    }
    Py_ssize_t maxsize = PY_SSIZE_T_MAX;
    if (maxsize_object != Py_None) {
        maxsize = PyLong_AsSsize_t(maxsize_object);
        if (maxsize == -1 && PyErr_Occurred()) {
            return NULL;
        }
    }
    PyObject *carried = PyList_New(0);
    if (carried == NULL) {
        return NULL;
    }
    for (;;) {
        n_result size;
        Py_BEGIN_ALLOW_THREADS
        size = n_channel_receive((n_channel){channel}, NULL, 0, NULL, N_CHANNEL_RECEIVE_OPTIONS_PEEK);
        Py_END_ALLOW_THREADS
        if (size == -N_ERR_NOT_READY) {
            if (channel_wait(channel) < 0) {
                goto fail;
            }
            continue;
        }
        if (size == -N_ERR_CLOSED) {
            PyErr_SetNone(PyExc_EOFError);
            goto fail;
        }
        if (size < 0) {
            raise_result(size);
            goto fail;
        }
        if (size > maxsize) {
            n_result dropped;
            Py_BEGIN_ALLOW_THREADS
            dropped = n_channel_receive((n_channel){channel}, NULL, 0, NULL, N_CHANNEL_RECEIVE_OPTIONS_DISCARD);
            Py_END_ALLOW_THREADS
            if (dropped < 0) {
                raise_result(dropped);
                goto fail;
            }
            return Py_BuildValue("(ON)", Py_None, carried);
        }
        PyObject *data = PyBytes_FromStringAndSize(NULL, size);
        if (data == NULL) {
            goto fail;
        }
        n_handle attached = {-1};
        n_result got;
        Py_BEGIN_ALLOW_THREADS
        got = n_channel_receive((n_channel){channel}, (uint8_t *)PyBytes_AS_STRING(data), (size_t)size, &attached, 0);
        Py_END_ALLOW_THREADS
        if (got == -N_ERR_NOT_READY || got > size) {
            /* 測ったメッセージはほかのスレッドが取った（大きいメッセージは受けずに大きさが返る） */
            Py_DECREF(data);
            continue;
        }
        if (got < 0) {
            Py_DECREF(data);
            if (got == -N_ERR_CLOSED) {
                PyErr_SetNone(PyExc_EOFError);
            }
            else {
                raise_result(got);
            }
            goto fail;
        }
        if (attached.handle >= 0) {
            Py_DECREF(data);
            PyObject *h = PyLong_FromLong(attached.handle);
            if (h == NULL || PyList_Append(carried, h) < 0) {
                Py_XDECREF(h);
                n_handle_close(attached);
                goto fail;
            }
            Py_DECREF(h);
            continue;
        }
        return Py_BuildValue("(NN)", data, carried);
    }
fail:
    for (Py_ssize_t i = 0; i < PyList_GET_SIZE(carried); i++) {
        n_handle_close((n_handle){(int32_t)PyLong_AsLong(PyList_GET_ITEM(carried, i))});
    }
    Py_DECREF(carried);
    return NULL;
}

/* ---- wait ---- */

struct waited {
    PyObject *object;                 /* 呼び手の並びから借りる */
    int32_t handle;                   /* -1 は待つものが無い */
    uint32_t interest;
    uint32_t ready;                   /* N_EVENT_* */
};

/* 呼び手の並びのハンドル：0 か、例外つきの -1。ハンドルはそのまま。記述子（Nocturne/descriptors.h）は持つバイトに
   すぐ答え、残りをそのハンドルで待つ。 */
static int
read_waited(bool descriptors, struct waited *out, Py_ssize_t n, PyObject *fast)
{
    for (Py_ssize_t i = 0; i < n; i++) {
        PyObject *object = PySequence_Fast_GET_ITEM(fast, i);
        int value = PyLong_AsInt(object);
        if (value == -1 && PyErr_Occurred()) {
            return -1;
        }
        struct waited w = {.object = object, .handle = value, .interest = N_EVENT_RECEIVABLE | N_EVENT_CLOSED};
        if (descriptors) {
            int ready = _Py_fd_poll(value, &w.handle);
            if (ready < 0) {
                PyErr_SetFromErrno(PyExc_OSError);
                return -1;
            }
            w.ready = (uint32_t)ready & (N_EVENT_RECEIVABLE | N_EVENT_CLOSED);
        }
        else {
            n_result kind = n_handle_kind((n_handle){value});
            if (kind < 0) {
                raise_result(kind);
                return -1;
            }
            if (kind == N_KIND_APP) {
                w.interest = N_EVENT_APP_ENDED;
            }
        }
        out[i] = w;
    }
    return 0;
}

static PyObject *
ready_objects(const struct waited *list, Py_ssize_t from, Py_ssize_t to)
{
    PyObject *result = PyList_New(0);
    for (Py_ssize_t i = from; result != NULL && i < to; i++) {
        if (list[i].ready && PyList_Append(result, list[i].object) < 0) {
            Py_CLEAR(result);
        }
    }
    return result;
}

/* wait(handles, descriptors, timeout=None)：(用意のできたハンドル, 用意のできた記述子)。どれかの用意ができるか、
   timeout 秒が過ぎるまで待つ。 */
static PyObject *
mp_wait(PyObject *module, PyObject *args)
{
    PyObject *handles_object, *descriptors_object, *timeout = Py_None;
    if (!PyArg_ParseTuple(args, "OO|O:wait", &handles_object, &descriptors_object, &timeout)) {
        return NULL;
    }
    uint64_t deadline;
    if (deadline_of(timeout, &deadline) < 0) {
        return NULL;
    }
    PyObject *result = NULL;
    PyObject *hfast = PySequence_Fast(handles_object, "handles must be a sequence");
    PyObject *dfast = hfast == NULL ? NULL : PySequence_Fast(descriptors_object, "descriptors must be a sequence");
    struct waited *list = NULL;
    struct n_notification *events = NULL;
    n_events queue = {-1};
    if (dfast == NULL) {
        goto done;
    }
    Py_ssize_t nh = PySequence_Fast_GET_SIZE(hfast), nd = PySequence_Fast_GET_SIZE(dfast);
    Py_ssize_t n = nh + nd;
    list = PyMem_New(struct waited, n > 0 ? n : 1);
    events = PyMem_New(struct n_notification, n + 1);
    if (list == NULL || events == NULL) {
        PyErr_NoMemory();
        goto done;
    }
    if (read_waited(false, list, nh, hfast) < 0 || read_waited(true, list + nh, nd, dfast) < 0) {
        goto done;
    }
    n_result created = n_events_create(&queue);
    if (created < 0) {
        queue.handle = -1;
        raise_result(created);
        goto done;
    }
    bool ready_now = false;
    for (Py_ssize_t i = 0; i < n; i++) {
        ready_now |= list[i].ready != 0;
        if (list[i].handle < 0) {
            continue;
        }
        n_result watched = n_events_watch(queue, (n_handle){list[i].handle}, list[i].interest, (uint64_t)i);
        if (watched < 0) {
            raise_result(watched);
            goto done;
        }
    }
    /* 今用意のできたものがあれば、残りを待たない */
    uint64_t until = ready_now ? 0 : deadline;
    for (;;) {
        n_result got;
        Py_BEGIN_ALLOW_THREADS
        got = _PyOS_NocturneWaitEvents(queue, events, (size_t)(n + 1), until);
        Py_END_ALLOW_THREADS
        if (got == -N_ERR_CANCELLED) {
            if (PyErr_CheckSignals() < 0) {
                goto done;
            }
            continue;
        }
        if (got < 0) {
            raise_result(got);
            goto done;
        }
        for (n_result i = 0; i < got; i++) {
            if (events[i].token < (uint64_t)n) {
                list[events[i].token].ready |= events[i].events & list[events[i].token].interest;
            }
        }
        break;
    }
    PyObject *ready_handles = ready_objects(list, 0, nh);
    PyObject *ready_descriptors = ready_handles == NULL ? NULL : ready_objects(list, nh, n);
    if (ready_descriptors != NULL) {
        result = Py_BuildValue("(NN)", ready_handles, ready_descriptors);
    }
    else {
        Py_XDECREF(ready_handles);
    }
done:
    if (queue.handle >= 0) {
        n_handle_close((n_handle){queue.handle});
    }
    PyMem_Free(list);
    PyMem_Free(events);
    Py_XDECREF(hfast);
    Py_XDECREF(dfast);
    return result;
}

static PyMethodDef mp_functions[] = {
    {"channel_pair", mp_channel_pair, METH_NOARGS, "channel_pair()\n--\n\nA new channel's two ends."},
    {"channel_send", mp_channel_send, METH_VARARGS,
     "channel_send(handle, data, handles=(), /)\n--\n\n"
     "Send data as one message, carrying the handles before it."},
    {"channel_receive", mp_channel_receive, METH_VARARGS,
     "channel_receive(handle, maxsize=None, /)\n--\n\n"
     "The next message and the handles carried before it: (data, handles).\n"
     "data is None for a message longer than maxsize, which is dropped."},
    {"wait", mp_wait, METH_VARARGS,
     "wait(handles, descriptors, timeout=None, /)\n--\n\n"
     "Wait until handles or descriptors are ready: (ready handles, ready descriptors)."},
    {NULL, NULL}
};

static int
mp_exec(PyObject *module)
{
    module_state *state = get_state(module);
    state->semlock_type = (PyTypeObject *)PyType_FromModuleAndSpec(module, &semlock_spec, NULL);
    if (state->semlock_type == NULL) {
        return -1;
    }
    PyObject *max = PyLong_FromLong(INT_MAX);
    if (max == NULL) {
        return -1;
    }
    int r = PyDict_SetItemString(state->semlock_type->tp_dict, "SEM_VALUE_MAX", max);
    Py_DECREF(max);
    if (r < 0 || PyModule_AddType(module, state->semlock_type) < 0) {
        return -1;
    }
    state->shared_type = (PyTypeObject *)PyType_FromModuleAndSpec(module, &shared_spec, NULL);
    if (state->shared_type == NULL || PyModule_AddType(module, state->shared_type) < 0) {
        return -1;
    }
    PyObject *flags = PyDict_New();
    if (flags == NULL || PyModule_Add(module, "flags", flags) < 0) {
        return -1;
    }
    /* 共有の記憶とそのマップの単位（multiprocessing.heap） */
    return PyModule_AddIntConstant(module, "PAGESIZE", (long)N_PAGE_BYTES);
}

static int
mp_traverse(PyObject *module, visitproc visit, void *arg)
{
    module_state *state = get_state(module);
    Py_VISIT(state->semlock_type);
    Py_VISIT(state->shared_type);
    return 0;
}

static int
mp_clear(PyObject *module)
{
    module_state *state = get_state(module);
    Py_CLEAR(state->semlock_type);
    Py_CLEAR(state->shared_type);
    return 0;
}

static void
mp_free(void *module)
{
    (void)mp_clear((PyObject *)module);
}

static PyModuleDef_Slot mp_slots[] = {
    {Py_mod_exec, mp_exec},
    {Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
    {Py_mod_gil, Py_MOD_GIL_NOT_USED},
    {0, NULL}
};

static struct PyModuleDef mp_module = {
    PyModuleDef_HEAD_INIT,
    .m_name = "_multiprocessing",
    .m_doc = "multiprocessing's native half on Nocturne.",
    .m_size = sizeof(module_state),
    .m_methods = mp_functions,
    .m_slots = mp_slots,
    .m_traverse = mp_traverse,
    .m_clear = mp_clear,
    .m_free = mp_free,
};

PyMODINIT_FUNC
PyInit__multiprocessing(void)
{
    return PyModuleDef_Init(&mp_module);
}
