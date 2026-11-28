/* Nocturne の上の Python のファイル記述子（Nocturne/descriptors.c）。

   Nocturne にファイル記述子は無い：アプリは種類ごとのハンドルを持ち、文書は共有のカーソルを持たない
   （docs/nocturne-native-abi.md §3）。Python の os と io は位置を持つ小さな数で話すので、Windows の C の実行時
   ライブラリーと同じく、インタープリターがそれを持つ。どの関数も、失敗では -1 を返して errno（契約の結果コード
   N_ERR_* の数）を置き、例外は起こさない。ハンドルは契約のハンドルの番号（int32_t）で持ち、契約の関数へは種類の
   構造体（(n_document){h} ほか）で渡す。 */
#ifndef Py_NOCTURNE_DESCRIPTORS_H
#define Py_NOCTURNE_DESCRIPTORS_H

#ifndef Py_BUILD_CORE
#  error "this header requires Py_BUILD_CORE define"
#endif

#include <nocturne/core.h>
#include "pycore_fileutils.h"     // struct _Py_stat_struct

/* os.open と io.FileIO が文書を開く形：Python の旗（os.O_*）。 */
#define O_RDONLY  0x0000
#define O_WRONLY  0x0001
#define O_RDWR    0x0002
#define O_ACCMODE 0x0003
#define O_APPEND  0x0008
#define O_CREAT   0x0100
#define O_TRUNC   0x0200
#define O_EXCL    0x0400

/* os のモジュールが系へ渡す完全なパスの一番長いもの。 */
#define _PY_PATH_MAX 4096

/* name をアプリの今のフォルダーの中で完全にしたパス（n_path_complete）を out に NUL で終えて書き、その長さを
   返す。 */
extern int _Py_complete_path(const char *name, char out[_PY_PATH_MAX]);
/* C: の項について Python の stat が言うこと（n_entry_info、n_folder_list）。 */
extern void _Py_entry_stat(const struct n_entry *entry, struct _Py_stat_struct *status);
extern int _Py_path_stat(const char *name, struct _Py_stat_struct *status);
/* NUL で終わる完全なパス path の項の記録を entry に書く。 */
extern n_result _Py_entry_info(const char *path, struct n_entry *entry);
/* 完全なパス folder のフォルダーの項の全部を、PyMem_RawMalloc の領域に読んで *entries に置き、その数を返す（呼び手が
   PyMem_RawFree で返す）。失敗は結果コードで、*entries は NULL。 */
extern n_result _Py_folder_list(const char *folder, struct n_entry **entries);
/* 結果コードの文を buf に NUL で終えて書き、buf を返す。 */
extern const char *_Py_result_text(n_result r, char *buf, size_t size);

extern int _Py_fd_open(const char *name, int flags);
/* アプリが持つハンドル（チャネルの端、文書）の記述子。最後の記述子が閉じるとハンドルを閉じる。 */
extern int _Py_fd_adopt(int32_t handle, int readable, int writable);
/* 記述子のハンドル。無ければ -1 と errno（ENOTCONN：まだハンドルの無い socket）。 */
extern int32_t _Py_fd_handle(int fd);
/* 記述子の N_KIND_*。無ければ -1。 */
extern int _Py_fd_kind(int fd);
/* 種類 N_KIND_TCP か N_KIND_UDP の、ハンドルより前の socket の記述子。_Py_fd_attach がハンドルを一度だけ与える
   （後は EISCONN）。 */
extern int _Py_fd_socket(int kind);
extern int _Py_fd_attach(int fd, int32_t handle);
/* socket の記述子からハンドルを外し、ハンドルの無い記述子に戻す（bind() した TCP の socket が listener を閉じて
   つなぐ時）。handle が今のハンドルでなければ EISCONN。handle は呼ぶ側が閉じる。 */
extern int _Py_fd_detach(int fd, int32_t handle);
/* select が見るもの：記述子への呼び出しがすぐ答える N_EVENT_*（文書の読み書き、受けてまだ読んでいないバイト）と、
   残りを待つハンドル（-1 は待つものが無い）。悪い記述子は -1。 */
extern int _Py_fd_poll(int fd, int32_t *handle);
extern int _Py_fd_close(int fd);
extern void _Py_fd_close_range(int first, int last);
extern Py_ssize_t _Py_fd_read(int fd, void *buf, size_t count);
extern Py_ssize_t _Py_fd_write(int fd, const void *buf, size_t count);
extern long long _Py_fd_seek(int fd, long long offset, int whence);
extern int _Py_fd_truncate(int fd, long long size);
extern int _Py_fd_sync(int fd);
extern int _Py_fd_stat(int fd, struct _Py_stat_struct *status);
/* 記述子が端末へつながるか：1、0、悪い記述子は -1。 */
extern int _Py_fd_isatty(int fd);
extern int _Py_fd_dup(int fd);
extern int _Py_fd_dup2(int fd, int fd2);
extern int _Py_fd_get_blocking(int fd);
extern int _Py_fd_set_blocking(int fd, int blocking);

/* 入力の流れの端末で利用者が打つ行（中核のライブラリーの n_line_read が編集する）を、'\n' と NUL を付けて buf に
   書く：その長さ、入力の終わりは 0、Ctrl+C の後は errno EINTR の -1（SIGINT として届ける）。size は 2 以上。 */
extern Py_ssize_t _Py_terminal_line(const char *prompt, char *buf, size_t size);

#endif /* !Py_NOCTURNE_DESCRIPTORS_H */
