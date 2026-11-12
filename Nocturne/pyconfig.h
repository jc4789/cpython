/* Nocturne の pyconfig.h（ports/cpython/README.md）。

   Nocturne は UNIX でも POSIX でも Windows でもない。C ライブラリーは ISO C と Nocturne のネイティブの口
   （nocturne.h）だけを持ち、unistd.h も sys の見出しも無い。だから HAVE_ の項は ISO C のものだけで、POSIX の
   関数の項は一つも立てない。機械の違いはソースの __nocturne__ の節が持つ（clang が定義する）。
   拡張モジュールは全部プログラムに組み込む（Nocturne/config.c）：名で引く輸入が無いので、動的に読む
   拡張は無い。 */
#ifndef Py_PYCONFIG_H
#define Py_PYCONFIG_H

#ifndef __nocturne__
#  error "Nocturne/pyconfig.h は Nocturne の clang（x86_64-unknown-nocturne）で組む"
#endif

/* sys.platform */
#define PLATFORM "nocturne"
/* sys._framework：macOS の framework の組みではない */
#define _PYTHONFRAMEWORK ""

/* x86-64：型の大きさと並び */
#define SIZEOF_SHORT 2
#define SIZEOF_INT 4
#define SIZEOF_LONG 8
#define SIZEOF_LONG_LONG 8
#define SIZEOF_LONG_DOUBLE 16
#define SIZEOF_FLOAT 4
#define SIZEOF_DOUBLE 8
#define SIZEOF_VOID_P 8
#define SIZEOF_SIZE_T 8
#define SIZEOF_UINTPTR_T 8
#define SIZEOF_TIME_T 8
#define SIZEOF_WCHAR_T 4
#define SIZEOF__BOOL 1
#define SIZEOF_FPOS_T 8
#define ALIGNOF_LONG 8
#define ALIGNOF_SIZE_T 8
#define ALIGNOF_MAX_ALIGN_T 16
#define HAVE_LONG_DOUBLE 1
#define DOUBLE_IS_LITTLE_ENDIAN_IEEE754 1
#define HAVE_GCC_ASM_FOR_X64 1
#define HAVE_BUILTIN_ATOMIC 1
#define HAVE_STD_ATOMIC 1
#define _Py_STACK_GROWS_DOWN 1
#define HAVE_COMPUTED_GOTOS 1
#define USE_COMPUTED_GOTOS 1
#define _Py_HACL_CAN_COMPILE_VEC128 1
#define _Py_HACL_CAN_COMPILE_VEC256 1

/* ISO C の見出しと関数 */
#define STDC_HEADERS 1
#define HAVE_WCHAR_H 1
#define HAVE_CLOCK 1
#define HAVE_STRFTIME 1
#define HAVE_WCSFTIME 1
#define HAVE_WCSCOLL 1
#define HAVE_WCSXFRM 1
#define HAVE_MBRTOWC 1
#define HAVE_TIMEGM 1        /* C23 の timegm（time.h） */

/* 組みの選び */
#define PY_SUPPORT_TIER 0
#define WITH_DOC_STRINGS 1
#define WITH_PYMALLOC 1
#define PYLONG_BITS_IN_DIGIT 30
#define PY_BUILTIN_HASHLIB_HASHES "md5,sha1,sha2,sha3,blake2"

/* n_thread_name はスレッドの名を UTF-8 の 31 バイトに切る（nocturne.h） */
#define _PYTHREAD_NAME_MAXLEN 31

#endif /* Py_PYCONFIG_H */
