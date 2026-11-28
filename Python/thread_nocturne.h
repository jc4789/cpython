/* Nocturne のスレッド（docs/nocturne-native-abi.md §5）：nocturne.h の thread_create_sized・thread_join・
   thread_detach と、ISO C の tss（threads.h）。錠は PyMutex（Python/lock.c）、眠りは Python/parking_lot.c の
   _PySemaphore で、どちらも番地の待ち（wait_on_address）に乗る。 */

#include "pycore_interp.h"        // _PyInterpreterState.threads.stacksize
#include "pycore_time.h"          // _PyTime_AsMicroseconds()

#include "nocturne.h"
#include <threads.h>

/* 新しいスレッドの stack の既定：主スレッドの stack と同じ大きさ（PyThread__init_thread がカーネルに聞く）。
   頁は初めて触れたときに入るので、大きくても使った分だけ。 */
static size_t nocturne_default_stack;

static void
PyThread__init_thread(void)
{
    uintptr_t low = 0, high = 0;
    if (thread_stack_bounds(&low, &high) == 0 && high > low) {
        nocturne_default_stack = (size_t)(high - low);
    }
}

int
PyThread_start_joinable_thread(void (*func)(void *), void *arg,
                               PyThread_ident_t *ident, PyThread_handle_t *handle)
{
    if (!initialized) {
        PyThread_init_thread();
    }
    PyThreadState *tstate = _PyThreadState_GET();
    size_t stacksize = tstate ? tstate->interp->threads.stacksize : 0;
    n_result tid = thread_create_sized(func, arg, stacksize ? stacksize : nocturne_default_stack);
    if (tid < 0) {
        return -1;
    }
    *ident = (PyThread_ident_t)tid;
    *handle = (PyThread_handle_t)tid;
    return 0;
}

unsigned long
PyThread_start_new_thread(void (*func)(void *), void *arg)
{
    PyThread_handle_t handle;
    PyThread_ident_t ident;
    if (PyThread_start_joinable_thread(func, arg, &ident, &handle)) {
        return PYTHREAD_INVALID_THREAD_ID;
    }
    if (PyThread_detach_thread(handle)) {
        return PYTHREAD_INVALID_THREAD_ID;
    }
    return (unsigned long)ident;
}

int
PyThread_join_thread(PyThread_handle_t handle)
{
    return thread_join((int)handle) < 0;
}

int
PyThread_detach_thread(PyThread_handle_t handle)
{
    return thread_detach((int)handle) < 0;
}

/* スレッドの識別子はカーネルのもので、システムの中で一つ。 */
PyThread_ident_t
PyThread_get_thread_ident_ex(void)
{
    if (!initialized) {
        PyThread_init_thread();
    }
    return (PyThread_ident_t)thread_id();
}

unsigned long
PyThread_get_thread_ident(void)
{
    return (unsigned long)PyThread_get_thread_ident_ex();
}

unsigned long
PyThread_get_thread_native_id(void)
{
    if (!initialized) {
        PyThread_init_thread();
    }
    return (unsigned long)thread_id();
}

void _Py_NO_RETURN
PyThread_exit_thread(void)
{
    if (!initialized) {
        exit(0);
    }
    thread_exit();
}

void _Py_NO_RETURN
PyThread_hang_thread(void)
{
    for (;;) {
        n_sleep_until(KABI_CLOCK_NEVER);
    }
}

/* stack の大きさ：0 は既定。下限はカーネルの既定（256 KiB）より小さくしない。 */
#define THREAD_MIN_STACKSIZE (256 * 1024)

static int
_pythread_nocturne_set_stacksize(size_t size)
{
    if (size != 0 && size < THREAD_MIN_STACKSIZE) {
        return -1;
    }
    _PyInterpreterState_GET()->threads.stacksize = size;
    return 0;
}

#define THREAD_SET_STACKSIZE(x) _pythread_nocturne_set_stacksize(x)


/* 古い TLS の口（PEP 539 で非推奨）：ISO C の tss の番号をそのまま鍵にする。 */

int
PyThread_create_key(void)
{
    tss_t key;
    if (tss_create(&key, NULL) != thrd_success) {
        return -1;
    }
    return (int)key;
}

void
PyThread_delete_key(int key)
{
    tss_delete((tss_t)key);
}

int
PyThread_set_key_value(int key, void *value)
{
    return tss_set((tss_t)key, value) == thrd_success ? 0 : -1;
}

void *
PyThread_get_key_value(int key)
{
    return tss_get((tss_t)key);
}

void
PyThread_delete_key_value(int key)
{
    tss_set((tss_t)key, NULL);
}

void
PyThread_ReInitTLS(void)
{
}


/* TSS の口（PEP 539）。 */

int
PyThread_tss_create(Py_tss_t *key)
{
    assert(key != NULL);
    if (key->_is_initialized) {
        return 0;
    }
    if (tss_create(&key->_key, NULL) != thrd_success) {
        return -1;
    }
    key->_is_initialized = 1;
    return 0;
}

void
PyThread_tss_delete(Py_tss_t *key)
{
    assert(key != NULL);
    if (!key->_is_initialized) {
        return;
    }
    tss_delete(key->_key);
    key->_is_initialized = 0;
}

int
PyThread_tss_set(Py_tss_t *key, void *value)
{
    assert(key != NULL);
    return tss_set(key->_key, value) == thrd_success ? 0 : -1;
}

void *
PyThread_tss_get(Py_tss_t *key)
{
    assert(key != NULL);
    return tss_get(key->_key);
}
