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
#  define Py_NSIG (SIGTERM + 1)    // ISO C の信号、1 から SIGTERM まで
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
#include <nocturne/core/events.h>

// Nocturne の Ctrl+C（Modules/signalmodule.c）：端末は Ctrl+C ごとに n_interrupts のチャネルへメッセージを送り、
// インタープリターのスレッドの一つがそれを SIGINT として届ける。主のスレッドの待ちは、Windows の
// _PyOS_SigintEvent() の待ちと同じく、それで止まる。

// 呼んだスレッドの待ちが SIGINT で止まるか：端末が Ctrl+C を送る間の主のスレッド。
extern int _PyOS_NocturneInterruptible(void);

// 止まれるスレッドで、ハンドル h（-1 は無し）が interest（N_EVENT_*）のどれかを知らせるか、番地 address（NULL は無し）
// の語が expected でなくなるか、単調時計が deadline（N_CLOCK_NEVER は来ない）に着くか、SIGINT が届くまで待つ。
// 1：ハンドルか語、0：締め切り、-1：SIGINT。ほかのスレッドは SIGINT なしに同じくハンドルか語を待つ。
extern int _PyOS_NocturneWait(int32_t h, uint32_t interest,
                              volatile uint32_t *address,
                              uint32_t expected,
                              uint64_t deadline);

// 止まれるスレッドで、呼び手のキューを n_events_wait で、SIGINT が届くまで待つ：キュー自身の通知の数（締め切りは 0）、
// SIGINT は -N_ERR_CANCELLED、ほかの失敗はその結果コード。待ちはキューの token _PY_NOCTURNE_SIGINT_TOKEN を使う。ほかの
// スレッドはただ待つ。
#define _PY_NOCTURNE_SIGINT_TOKEN (~0ULL)
extern n_result _PyOS_NocturneWaitEvents(n_events queue,
                                         struct n_notification *notifications,
                                         size_t capacity, uint64_t deadline);

// 網の呼び出し（n_net_resolve など）の cancel に渡すチャネルの端を *cancel に書く。待ちが SIGINT で止まるスレッドでは、
// SIGINT がその相手を閉じ、待ちは -N_ERR_CANCELLED で終わる。ほかのスレッドは handle -1（取り消し無し）。0 か、
// errno つきの -1（SIGINT がもう来ていれば EINTR）。
extern int _PyOS_NocturneNetCancel(n_handle *cancel);

// 中核のライブラリーの n_line_read は端末の行を読む間 Ctrl+C を自分で受ける：Pause と Resume の間、インタープリターの
// スレッドはチャネルから離れる。Pause は、そのスレッドが前に受けたものを届けてから戻る。
extern void _PyOS_NocturneInterruptsPause(void);
extern void _PyOS_NocturneInterruptsResume(void);
#endif

#ifdef __cplusplus
}
#endif
#endif  // !Py_INTERNAL_SIGNAL_H
