/* Python's file descriptors on Nocturne (Nocturne/descriptors.c).

   Nocturne has no file descriptors: an app holds typed handles, and a document
   has no shared cursor (docs/nocturne-native-abi.md §3). Python's os and io
   speak of small numbers with a position, so the interpreter keeps them, as the
   C runtime does on Windows. Every function returns -1 and sets errno (an
   N_ERR_* code) on failure, and raises nothing. */
#ifndef Py_NOCTURNE_DESCRIPTORS_H
#define Py_NOCTURNE_DESCRIPTORS_H

#ifndef Py_BUILD_CORE
#  error "this header requires Py_BUILD_CORE define"
#endif

#include "nocturne.h"
#include "pycore_fileutils.h"     // struct _Py_stat_struct

/* How os.open and io.FileIO open a document: Python's flags (os.O_*). */
#define O_RDONLY  0x0000
#define O_WRONLY  0x0001
#define O_RDWR    0x0002
#define O_ACCMODE 0x0003
#define O_APPEND  0x0008
#define O_CREAT   0x0100
#define O_TRUNC   0x0200
#define O_EXCL    0x0400

/* The longest complete path the os module passes to the system. */
#define _PY_PATH_MAX 4096

/* name made complete inside the app's current folder (n_path_complete). */
extern int _Py_complete_path(const char *name, char out[_PY_PATH_MAX]);
/* What Python's stat says of an entry of C: (n_entry_info, n_folder_list). */
extern void _Py_entry_stat(const struct n_entry *entry, struct _Py_stat_struct *status);
extern int _Py_path_stat(const char *name, struct _Py_stat_struct *status);

extern int _Py_fd_open(const char *name, int flags);
/* A descriptor for a handle the app holds (a channel's end, a document); it
   closes the handle when its last descriptor closes. */
extern int _Py_fd_adopt(n_handle handle, int readable, int writable);
/* The descriptor's handle, or -1 with errno (ENOTCONN: a socket that has
   none yet). */
extern n_handle _Py_fd_handle(int fd);
/* The descriptor's N_KIND_*, or -1. */
extern int _Py_fd_kind(int fd);
/* A socket's descriptor, of kind N_KIND_TCP or N_KIND_UDP, before its handle;
   _Py_fd_attach gives it the handle once (EISCONN after). */
extern int _Py_fd_socket(int kind);
extern int _Py_fd_attach(int fd, n_handle handle);
/* socket の descriptor から handle を外し、handle の無い descriptor に戻す（bind() した TCP の socket が listener を
   閉じて繋ぐ時）。handle が今の handle でなければ EISCONN。handle は呼ぶ側が閉じる。 */
extern int _Py_fd_detach(int fd, n_handle handle);
/* What select looks at: the N_EVENT_* a call on the descriptor answers at
   once (a document's reads and writes, bytes received and not yet read), and
   the handle to wait for the rest (-1: nothing to wait for). -1 for a bad
   descriptor. */
extern int _Py_fd_poll(int fd, n_handle *handle);
extern int _Py_fd_close(int fd);
extern void _Py_fd_close_range(int first, int last);
extern Py_ssize_t _Py_fd_read(int fd, void *buf, size_t count);
extern Py_ssize_t _Py_fd_write(int fd, const void *buf, size_t count);
extern long long _Py_fd_seek(int fd, long long offset, int whence);
extern int _Py_fd_truncate(int fd, long long size);
extern int _Py_fd_sync(int fd);
extern int _Py_fd_stat(int fd, struct _Py_stat_struct *status);
/* Whether the descriptor reaches a terminal: 1, 0, or -1 for a bad one. */
extern int _Py_fd_isatty(int fd);
extern int _Py_fd_dup(int fd);
extern int _Py_fd_dup2(int fd, int fd2);
extern int _Py_fd_get_blocking(int fd);
extern int _Py_fd_set_blocking(int fd, int blocking);

/* A line the user types at the terminal of the input stream, edited by libc's
   n_line_read, with its '\n': its length, 0 at the end of input, or -1 with
   errno EINTR after Ctrl+C, which it delivers as SIGINT. size is at least 2. */
extern Py_ssize_t _Py_terminal_line(const char *prompt, char *buf, size_t size);

#endif /* !Py_NOCTURNE_DESCRIPTORS_H */
