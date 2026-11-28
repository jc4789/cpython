// Define Py_NSIG constant for signal handling.

#ifndef Py_INTERNAL_SIGNAL_H
#define Py_INTERNAL_SIGNAL_H
#ifdef __cplusplus
extern "C" {
#endif

#ifndef Py_BUILD_CORE
#  error "this header requires Py_BUILD_CORE define"
#endif

#include <signal.h>               // NSIG


// Restore signals that the interpreter has called SIG_IGN on to SIG_DFL.
// Export for '_posixsubprocess' shared extension.
PyAPI_FUNC(void) _Py_RestoreSignals(void);

#ifdef _SIG_MAXSIG
   // gh-91145: On FreeBSD, <signal.h> defines NSIG as 32: it doesn't include
   // realtime signals: [SIGRTMIN,SIGRTMAX]. Use _SIG_MAXSIG instead. For
   // example on x86-64 FreeBSD 13, SIGRTMAX is 126 and _SIG_MAXSIG is 128.
#  define Py_NSIG _SIG_MAXSIG
#elif defined(NSIG)
#  define Py_NSIG NSIG
#elif defined(_NSIG)
#  define Py_NSIG _NSIG            // BSD/SysV
#elif defined(_SIGMAX)
#  define Py_NSIG (_SIGMAX + 1)    // QNX
#elif defined(SIGMAX)
#  define Py_NSIG (SIGMAX + 1)     // djgpp
#elif defined(__nocturne__)
#  define Py_NSIG (SIGTERM + 1)    // ISO C's signals, 1 to SIGTERM
#else
#  define Py_NSIG 64               // Use a reasonable default value
#endif

#define INVALID_FD (-1)

struct _signals_runtime_state {
    struct {
        // tripped and func should be accessed using atomic ops.
        int tripped;
        PyObject* func;
    } handlers[Py_NSIG];

    volatile struct {
#ifdef MS_WINDOWS
        /* This would be "SOCKET fd" if <winsock2.h> were always included.
           It isn't so we must cast to SOCKET where appropriate. */
        volatile int fd;
#elif defined(__VXWORKS__)
        int fd;
#else
        sig_atomic_t fd;
#endif

        int warn_on_full_buffer;
#ifdef MS_WINDOWS
        int use_send;
#endif
    } wakeup;

    /* Speed up sigcheck() when none tripped.
       is_tripped should be accessed using atomic ops. */
    int is_tripped;

    /* These objects necessarily belong to the main interpreter. */
    PyObject *default_handler;
    PyObject *ignore_handler;

#ifdef MS_WINDOWS
    /* This would be "HANDLE sigint_event" if <windows.h> were always included.
       It isn't so we must cast to HANDLE everywhere "sigint_event" is used. */
    void *sigint_event;
#endif

    /* True if the main interpreter thread exited due to an unhandled
     * KeyboardInterrupt exception, suggesting the user pressed ^C. */
    int unhandled_keyboard_interrupt;
};

#ifdef MS_WINDOWS
# define _signals_WAKEUP_INIT \
    {.fd = INVALID_FD, .warn_on_full_buffer = 1, .use_send = 0}
#else
# define _signals_WAKEUP_INIT \
    {.fd = INVALID_FD, .warn_on_full_buffer = 1}
#endif

#define _signals_RUNTIME_INIT \
    { \
        .wakeup = _signals_WAKEUP_INIT, \
    }


// Export for '_multiprocessing' shared extension
PyAPI_FUNC(int) _PyOS_IsMainThread(void);

#ifdef MS_WINDOWS
// <windows.h> is not included by Python.h so use void* instead of HANDLE.
// Export for '_multiprocessing' shared extension
PyAPI_FUNC(void*) _PyOS_SigintEvent(void);
#endif

#ifdef __nocturne__
// Nocturne's Ctrl+C (Modules/signalmodule.c): the terminal sends a message
// for each one on the n_interrupts channel, and a thread of the interpreter
// delivers it as SIGINT. A wait of the main thread stops for it, as a wait
// on Windows's _PyOS_SigintEvent() does.

// Whether the calling thread's waits stop for SIGINT: the main thread, while
// a terminal sends Ctrl+C.
extern int _PyOS_NocturneInterruptible(void);

// On an interruptible thread: wait until handle h (-1: none) reports one of
// interest (KABI_EVENT_*), the word at address (NULL: none) holds another value
// than expected, the monotonic clock reaches deadline (KABI_CLOCK_NEVER: never),
// or SIGINT is delivered. 1: the handle or the word, 0: the deadline,
// -1: SIGINT. Another thread waits for the handle or the word in the same
// way, without SIGINT.
extern int _PyOS_NocturneWait(int h, unsigned int interest,
                              volatile unsigned int *address,
                              unsigned int expected,
                              unsigned long long deadline);

// On an interruptible thread: n_events_wait on the caller's queue, or until
// SIGINT is delivered: the count of the queue's own events, or -1 for SIGINT.
// The wait uses the token _PY_NOCTURNE_SIGINT_TOKEN of the queue. Another
// thread just waits.
#define _PY_NOCTURNE_SIGINT_TOKEN (~0ULL)
struct kabi_event;
extern long _PyOS_NocturneWaitEvents(int queue, struct kabi_event *events,
                                     unsigned long max,
                                     unsigned long long deadline);

// 網の呼出し（net_resolve など）の cancel に渡す channel の端を *cancel に書く。
// 待ちが SIGINT で止まるスレッドでは、SIGINT がその相手を閉じ、待ちは
// KABI_ERR_CANCELLED で終わる。ほかのスレッドは -1（取り消し無し）。0 か、errno
// つきの -1（SIGINT がもう来ていれば EINTR）。
extern int _PyOS_NocturneNetCancel(int *cancel);

// While the libc's n_line_read reads a terminal line it takes Ctrl+C itself:
// the interpreter's thread keeps off the channel between Pause and Resume.
// Pause returns once that thread has delivered what it took before.
extern void _PyOS_NocturneInterruptsPause(void);
extern void _PyOS_NocturneInterruptsResume(void);
#endif

#ifdef __cplusplus
}
#endif
#endif  // !Py_INTERNAL_SIGNAL_H
