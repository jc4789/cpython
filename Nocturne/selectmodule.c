/* select：Nocturne の上の Python の select のモジュール（ports/cpython/README.md）。

   select.select は、渡された記述子（Nocturne/descriptors.h）のハンドルを系のイベントキューの一つで待つ：記述子は、
   そのハンドルが N_EVENT_RECEIVABLE か N_EVENT_CLOSED を知らせるか、受けたバイトが読まれるのを待っていれば読めて、
   ハンドルが N_EVENT_SENDABLE か N_EVENT_CLOSED を知らせれば書ける。文書の記述子はいつも両方で、一度もつながらなかった
   socket はすぐ答える。例外の状態は無い：系は急ぎのデータを持たない。

   キューは状態で知らせる（nocturne.core の events）ので、一度の待ちが用意のできたハンドルを全部知らせる。主のスレッド
   では Ctrl+C が待ちを終え、Python が SIGINT の handler を走らせ、handler が例外を起こさなければ同じ締め切りまで待ち
   続ける（PEP 475）。モジュールは select だけを持つ：selectors は SelectSelector を選ぶ。 */
#include "Python.h"
#include "pycore_signal.h"        // _PyOS_NocturneWaitEvents()
#include "pycore_time.h"          // _PyTime_FromSecondsObject()
#include "descriptors.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

struct entry {
    PyObject *object;             /* 呼び手の並びから借りる */
    int ready;                    /* N_EVENT_* */
    int32_t handle;               /* -1 は待つものが無い */
};

/* 呼び手の並びが名指すもの：0 か、例外つきの -1。 */
static int
read_entries(PyObject *sequence, struct entry **out, Py_ssize_t *count, PyObject **fast)
{
    *fast = PySequence_Fast(sequence, "arguments 1-3 must be sequences");
    if (*fast == NULL) {
        return -1;
    }
    Py_ssize_t n = PySequence_Fast_GET_SIZE(*fast);
    struct entry *entries = PyMem_New(struct entry, n > 0 ? n : 1);
    if (entries == NULL) {
        PyErr_NoMemory();
        return -1;
    }
    for (Py_ssize_t i = 0; i < n; i++) {
        PyObject *object = PySequence_Fast_GET_ITEM(*fast, i);
        int fd = PyObject_AsFileDescriptor(object);
        if (fd < 0) {
            PyMem_Free(entries);
            return -1;
        }
        int32_t handle;
        int ready = _Py_fd_poll(fd, &handle);
        if (ready < 0) {
            PyMem_Free(entries);
            PyErr_SetFromErrno(PyExc_OSError);
            return -1;
        }
        entries[i] = (struct entry){.object = object, .ready = ready, .handle = handle};
    }
    *out = entries;
    *count = n;
    return 0;
}

struct watched {
    int32_t handle;
    uint32_t interest;
    uint32_t events;              /* 待ちが知らせたもの */
};

static int
by_handle(const void *a, const void *b)
{
    int32_t x = ((const struct watched *)a)->handle, y = ((const struct watched *)b)->handle;
    return x < y ? -1 : x > y;
}

static struct watched *
find_watched(struct watched *list, Py_ssize_t count, int32_t handle)
{
    struct watched key = {.handle = handle};
    return bsearch(&key, list, (size_t)count, sizeof *list, by_handle);
}

/* entries のうち mask の用意ができたものを、新しいリストで返す。 */
static PyObject *
ready_list(const struct entry *entries, Py_ssize_t count, struct watched *list,
           Py_ssize_t watched, uint32_t mask)
{
    PyObject *result = PyList_New(0);
    for (Py_ssize_t i = 0; result != NULL && i < count; i++) {
        uint32_t ready = (uint32_t)entries[i].ready;
        if (entries[i].handle >= 0) {
            struct watched *w = find_watched(list, watched, entries[i].handle);
            if (w != NULL) {
                ready |= w->events;
            }
        }
        if ((ready & mask) && PyList_Append(result, entries[i].object) < 0) {
            Py_CLEAR(result);
        }
    }
    return result;
}

static PyObject *
select_select(PyObject *module, PyObject *args)
{
    PyObject *rlist, *wlist, *xlist, *timeout_object = Py_None;
    if (!PyArg_UnpackTuple(args, "select", 3, 4, &rlist, &wlist, &xlist, &timeout_object)) {
        return NULL;
    }
    uint64_t deadline = N_CLOCK_NEVER;
    if (timeout_object != Py_None) {
        PyTime_t timeout;
        if (_PyTime_FromSecondsObject(&timeout, timeout_object, _PyTime_ROUND_TIMEOUT) < 0) {
            if (PyErr_ExceptionMatches(PyExc_TypeError)) {
                PyErr_SetString(PyExc_TypeError, "timeout must be a float or None");
            }
            return NULL;
        }
        if (timeout < 0) {
            PyErr_SetString(PyExc_ValueError, "timeout must be non-negative");
            return NULL;
        }
        deadline = timeout == 0 ? 0 : n_clock_after((uint64_t)timeout);
    }

    PyObject *result = NULL;
    PyObject *rfast = NULL, *wfast = NULL, *xfast = NULL;
    struct entry *r = NULL, *w = NULL, *x = NULL;
    Py_ssize_t nr = 0, nw = 0, nx = 0;
    struct watched *list = NULL;
    struct n_notification *events = NULL;
    n_events queue = {-1};
    if (read_entries(rlist, &r, &nr, &rfast) < 0 || read_entries(wlist, &w, &nw, &wfast) < 0 ||
        read_entries(xlist, &x, &nx, &xfast) < 0) {
        goto done;
    }

    /* ハンドルごとに一度、その記述子のどれかが待つものと一緒に */
    list = PyMem_New(struct watched, nr + nw + 1);
    events = PyMem_New(struct n_notification, nr + nw + 1);
    if (list == NULL || events == NULL) {
        PyErr_NoMemory();
        goto done;
    }
    Py_ssize_t count = 0;
    bool ready_now = false;
    for (Py_ssize_t i = 0; i < nr; i++) {
        ready_now |= (r[i].ready & (N_EVENT_RECEIVABLE | N_EVENT_CLOSED)) != 0;
        if (r[i].handle >= 0) {
            list[count++] = (struct watched){.handle = r[i].handle, .interest = N_EVENT_RECEIVABLE | N_EVENT_CLOSED};
        }
    }
    for (Py_ssize_t i = 0; i < nw; i++) {
        ready_now |= (w[i].ready & (N_EVENT_SENDABLE | N_EVENT_CLOSED)) != 0;
        if (w[i].handle >= 0) {
            list[count++] = (struct watched){.handle = w[i].handle, .interest = N_EVENT_SENDABLE | N_EVENT_CLOSED};
        }
    }
    qsort(list, (size_t)count, sizeof *list, by_handle);
    Py_ssize_t distinct = 0;
    for (Py_ssize_t i = 0; i < count; i++) {
        if (distinct > 0 && list[distinct - 1].handle == list[i].handle) {
            list[distinct - 1].interest |= list[i].interest;
        }
        else {
            list[distinct++] = list[i];
        }
    }

    n_result created = n_events_create(&queue);
    if (created < 0) {
        queue.handle = -1;
        errno = (int)-created;
        PyErr_SetFromErrno(PyExc_OSError);
        goto done;
    }
    for (Py_ssize_t i = 0; i < distinct; i++) {
        n_result watched = n_events_watch(queue, (n_handle){list[i].handle}, list[i].interest, (uint64_t)i);
        if (watched < 0) {
            errno = (int)-watched;
            PyErr_SetFromErrno(PyExc_OSError);
            goto done;
        }
    }
    /* 今用意のできたものがあれば、残りを待たない */
    uint64_t until = ready_now ? 0 : deadline;
    for (;;) {
        n_result got;
        Py_BEGIN_ALLOW_THREADS
        got = _PyOS_NocturneWaitEvents(queue, events, (size_t)(distinct + 1), until);
        Py_END_ALLOW_THREADS
        if (got == -N_ERR_CANCELLED) {
            if (PyErr_CheckSignals() < 0) {
                goto done;
            }
            continue;
        }
        if (got < 0) {
            errno = (int)-got;
            PyErr_SetFromErrno(PyExc_OSError);
            goto done;
        }
        for (n_result i = 0; i < got; i++) {
            if (events[i].token < (uint64_t)distinct) {
                list[events[i].token].events |= events[i].events;
            }
        }
        break;
    }
    PyObject *readable = ready_list(r, nr, list, distinct, N_EVENT_RECEIVABLE | N_EVENT_CLOSED);
    PyObject *writable = readable == NULL ? NULL
                         : ready_list(w, nw, list, distinct, N_EVENT_SENDABLE | N_EVENT_CLOSED);
    if (writable != NULL) {
        result = Py_BuildValue("(NN[])", readable, writable);
    }
    else {
        Py_XDECREF(readable);
    }
done:
    if (queue.handle >= 0) {
        n_handle_close((n_handle){queue.handle});
    }
    PyMem_Free(list);
    PyMem_Free(events);
    PyMem_Free(r);
    PyMem_Free(w);
    PyMem_Free(x);
    Py_XDECREF(rfast);
    Py_XDECREF(wfast);
    Py_XDECREF(xfast);
    return result;
}

static PyMethodDef select_functions[] = {
    {"select", select_select, METH_VARARGS,
     "select(rlist, wlist, xlist, timeout=None, /)\n--\n\n"
     "Wait until one or more file descriptors are ready for some kind of I/O.\n\n"
     "The first three arguments are iterables of file descriptors to be waited for:\n"
     "rlist -- wait until ready for reading\n"
     "wlist -- wait until ready for writing\n"
     "xlist -- wait for an \"exceptional condition\"\n"
     "If only one kind of condition is required, pass [] for the other lists.\n\n"
     "A file descriptor is either a socket or file object, or a small integer\n"
     "gotten from a fileno() method call on one of those.\n\n"
     "The optional 4th argument specifies a timeout in seconds; it may be\n"
     "a floating-point number to specify fractions of seconds.  If it is absent\n"
     "or None, the call will never time out.\n\n"
     "The return value is a tuple of three lists corresponding to the first three\n"
     "arguments; each contains the subset of the corresponding file descriptors\n"
     "that are ready.  The system has no exceptional conditions: the third list\n"
     "is always empty."},
    {NULL, NULL}
};

static int
select_exec(PyObject *module)
{
    return PyModule_AddObjectRef(module, "error", PyExc_OSError);
}

static PyModuleDef_Slot select_slots[] = {
    {Py_mod_exec, select_exec},
    {Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
    {Py_mod_gil, Py_MOD_GIL_NOT_USED},
    {0, NULL}
};

static struct PyModuleDef selectmodule = {
    PyModuleDef_HEAD_INIT,
    .m_name = "select",
    .m_doc = "This module supports asynchronous I/O on multiple file descriptors.",
    .m_size = 0,
    .m_methods = select_functions,
    .m_slots = select_slots,
};

PyMODINIT_FUNC
PyInit_select(void)
{
    return PyModuleDef_Init(&selectmodule);
}
