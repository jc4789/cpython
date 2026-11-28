/* select: Python's select module on Nocturne (ports/cpython/README.md).

   select.select waits in one of the system's event queues for the handles of
   the descriptors it is given (Nocturne/descriptors.h): a descriptor is
   readable when its handle reports KABI_EVENT_RECEIVABLE or KABI_EVENT_CLOSED, or
   when bytes it received are waiting to be read, and writable when its handle
   reports KABI_EVENT_SENDABLE or KABI_EVENT_CLOSED. A document's descriptor is
   always both, and a socket that never connected answers at once. Nothing is
   ever exceptional: the system has no urgent data.

   The queue is level-triggered (nocturne.h), so a wait reports every handle
   that is ready. On the main thread Ctrl+C ends the wait, Python runs its
   SIGINT handler, and the wait goes on to the same deadline unless the
   handler raised (PEP 475). The module has select alone: selectors chooses
   its SelectSelector. */
#include "Python.h"
#include "pycore_signal.h"        // _PyOS_NocturneWaitEvents()
#include "pycore_time.h"          // _PyTime_FromSecondsObject()
#include "descriptors.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

struct entry {
    PyObject *object;             /* borrowed from the caller's sequence */
    int ready;                    /* KABI_EVENT_* */
    n_handle handle;              /* -1: nothing to wait for */
};

/* What a sequence of the caller names: 0, or -1 with an exception. */
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
        n_handle handle;
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
    n_handle handle;
    uint32_t interest;
    uint32_t events;              /* what the wait reported */
};

static int
by_handle(const void *a, const void *b)
{
    n_handle x = ((const struct watched *)a)->handle, y = ((const struct watched *)b)->handle;
    return x < y ? -1 : x > y;
}

static struct watched *
find_watched(struct watched *list, Py_ssize_t count, n_handle handle)
{
    struct watched key = {.handle = handle};
    return bsearch(&key, list, (size_t)count, sizeof *list, by_handle);
}

/* The objects of entries that are ready for mask, in a new list. */
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
    uint64_t deadline = KABI_CLOCK_NEVER;
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
    struct kabi_event *events = NULL;
    n_handle queue = -1;
    if (read_entries(rlist, &r, &nr, &rfast) < 0 || read_entries(wlist, &w, &nw, &wfast) < 0 ||
        read_entries(xlist, &x, &nx, &xfast) < 0) {
        goto done;
    }

    /* each handle once, with what any of its descriptors waits for */
    list = PyMem_New(struct watched, nr + nw + 1);
    events = PyMem_New(struct kabi_event, nr + nw + 1);
    if (list == NULL || events == NULL) {
        PyErr_NoMemory();
        goto done;
    }
    Py_ssize_t count = 0;
    bool ready_now = false;
    for (Py_ssize_t i = 0; i < nr; i++) {
        ready_now |= (r[i].ready & (KABI_EVENT_RECEIVABLE | KABI_EVENT_CLOSED)) != 0;
        if (r[i].handle >= 0) {
            list[count++] = (struct watched){.handle = r[i].handle, .interest = KABI_EVENT_RECEIVABLE | KABI_EVENT_CLOSED};
        }
    }
    for (Py_ssize_t i = 0; i < nw; i++) {
        ready_now |= (w[i].ready & (KABI_EVENT_SENDABLE | KABI_EVENT_CLOSED)) != 0;
        if (w[i].handle >= 0) {
            list[count++] = (struct watched){.handle = w[i].handle, .interest = KABI_EVENT_SENDABLE | KABI_EVENT_CLOSED};
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

    queue = n_events_create();
    if (queue < 0) {
        errno = (int)-queue;
        PyErr_SetFromErrno(PyExc_OSError);
        goto done;
    }
    for (Py_ssize_t i = 0; i < distinct; i++) {
        n_result watched = n_events_watch(queue, list[i].handle, list[i].interest, (uint64_t)i);
        if (watched < 0) {
            errno = (int)-watched;
            PyErr_SetFromErrno(PyExc_OSError);
            goto done;
        }
    }
    /* what is ready now needs no wait for the rest */
    uint64_t until = ready_now ? 0 : deadline;
    for (;;) {
        long got;
        Py_BEGIN_ALLOW_THREADS
        got = _PyOS_NocturneWaitEvents(queue, events, (unsigned long)(distinct + 1), until);
        Py_END_ALLOW_THREADS
        if (got < 0) {
            if (PyErr_CheckSignals() < 0) {
                goto done;
            }
            continue;
        }
        for (long i = 0; i < got; i++) {
            if (events[i].token < (uint64_t)distinct) {
                list[events[i].token].events |= events[i].events;
            }
        }
        break;
    }
    PyObject *readable = ready_list(r, nr, list, distinct, KABI_EVENT_RECEIVABLE | KABI_EVENT_CLOSED);
    PyObject *writable = readable == NULL ? NULL
                         : ready_list(w, nw, list, distinct, KABI_EVENT_SENDABLE | KABI_EVENT_CLOSED);
    if (writable != NULL) {
        result = Py_BuildValue("(NN[])", readable, writable);
    }
    else {
        Py_XDECREF(readable);
    }
done:
    if (queue >= 0) {
        n_handle_close(queue);
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
