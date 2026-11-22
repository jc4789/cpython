/* The modules built into Nocturne's python (ports/cpython/README.md).

   Nocturne has no imports by name, so there are no extension modules to load:
   every C module of the port is here, and ports/cpython/build.py compiles
   their sources. nocturne is the os module's own (Nocturne/nocturnemodule.c),
   as nt is on Windows and posix elsewhere; zlib is over the system's DEFLATE
   codec (Nocturne/zlibmodule.c), _socket over its TCP and UDP
   (Nocturne/socketmodule.c), select over its event queues
   (Nocturne/selectmodule.c), _multiprocessing over its apps, channels,
   shared pages and address waits (Nocturne/multiprocessingmodule.c), _bz2
   over the libbzip2 of Nocturne's tree (third_party/bzip2, with
   Nocturne/bz2error.c). */
#include "Python.h"

extern PyObject* PyInit__abc(void);
extern PyObject* PyInit__asyncio(void);
extern PyObject* PyInit__ast(void);
extern PyObject* PyInit__bisect(void);
extern PyObject* PyInit__blake2(void);
extern PyObject* PyInit__bz2(void);
extern PyObject* PyInit__codecs(void);
extern PyObject* PyInit__codecs_cn(void);
extern PyObject* PyInit__codecs_hk(void);
extern PyObject* PyInit__codecs_iso2022(void);
extern PyObject* PyInit__codecs_jp(void);
extern PyObject* PyInit__codecs_kr(void);
extern PyObject* PyInit__codecs_tw(void);
extern PyObject* PyInit__collections(void);
extern PyObject* PyInit__contextvars(void);
extern PyObject* PyInit__csv(void);
extern PyObject* PyInit__datetime(void);
extern PyObject* PyInit__elementtree(void);
extern PyObject* PyInit__functools(void);
extern PyObject* PyInit__heapq(void);
extern PyObject* PyInit__hmac(void);
extern PyObject* PyInit__imp(void);
extern PyObject* PyInit__interpchannels(void);
extern PyObject* PyInit__interpqueues(void);
extern PyObject* PyInit__interpreters(void);
extern PyObject* PyInit__io(void);
extern PyObject* PyInit__json(void);
extern PyObject* PyInit__locale(void);
extern PyObject* PyInit__lsprof(void);
extern PyObject* PyInit__math_integer(void);
extern PyObject* PyInit__md5(void);
extern PyObject* PyInit__multiprocessing(void);
extern PyObject* PyInit__multibytecodec(void);
extern PyObject* PyInit__opcode(void);
extern PyObject* PyInit__operator(void);
extern PyObject* PyInit__pickle(void);
extern PyObject* PyInit__queue(void);
extern PyObject* PyInit__random(void);
extern PyObject* PyInit__sha1(void);
extern PyObject* PyInit__sha2(void);
extern PyObject* PyInit__sha3(void);
extern PyObject* PyInit__signal(void);
extern PyObject* PyInit__sre(void);
extern PyObject* PyInit__stat(void);
extern PyObject* PyInit__statistics(void);
extern PyObject* PyInit__string(void);
extern PyObject* PyInit__struct(void);
extern PyObject* PyInit__suggestions(void);
extern PyObject* PyInit__symtable(void);
extern PyObject* PyInit__sysconfig(void);
extern PyObject* PyInit__thread(void);
extern PyObject* PyInit__tokenize(void);
extern PyObject* PyInit__tracemalloc(void);
extern PyObject* PyInit__types(void);
extern PyObject* PyInit__typing(void);
extern PyObject* PyInit__weakref(void);
extern PyObject* PyInit__zoneinfo(void);
extern PyObject* PyInit_array(void);
extern PyObject* PyInit_atexit(void);
extern PyObject* PyInit_binascii(void);
extern PyObject* PyInit_cmath(void);
extern PyObject* PyInit_errno(void);
extern PyObject* PyInit_faulthandler(void);
extern PyObject* PyInit_gc(void);
extern PyObject* PyInit_itertools(void);
extern PyObject* PyInit_math(void);
extern PyObject* PyInit_nocturne(void);
extern PyObject* PyInit_pyexpat(void);
extern PyObject* PyInit__socket(void);
extern PyObject* PyInit__ssl(void);
extern PyObject* PyInit_select(void);
extern PyObject* PyInit_time(void);
extern PyObject* PyInit_unicodedata(void);
extern PyObject* PyInit_zlib(void);
extern PyObject* PyMarshal_Init(void);
extern PyObject* _PyWarnings_Init(void);

struct _inittab _PyImport_Inittab[] = {
    {"nocturne", PyInit_nocturne},

    {"_abc", PyInit__abc},
    {"_asyncio", PyInit__asyncio},
    {"_ast", PyInit__ast},
    {"_bisect", PyInit__bisect},
    {"_blake2", PyInit__blake2},
    {"_bz2", PyInit__bz2},
    {"_codecs", PyInit__codecs},
    {"_collections", PyInit__collections},
    {"_contextvars", PyInit__contextvars},
    {"_csv", PyInit__csv},
    {"_datetime", PyInit__datetime},
    {"_elementtree", PyInit__elementtree},
    {"_functools", PyInit__functools},
    {"_heapq", PyInit__heapq},
    {"_hmac", PyInit__hmac},
    {"_interpchannels", PyInit__interpchannels},
    {"_interpqueues", PyInit__interpqueues},
    {"_interpreters", PyInit__interpreters},
    {"_io", PyInit__io},
    {"_json", PyInit__json},
    {"_locale", PyInit__locale},
    {"_lsprof", PyInit__lsprof},
    {"_math_integer", PyInit__math_integer},
    {"_md5", PyInit__md5},
    {"_opcode", PyInit__opcode},
    {"_operator", PyInit__operator},
    {"_multiprocessing", PyInit__multiprocessing},
    {"_pickle", PyInit__pickle},
    {"_queue", PyInit__queue},
    {"_random", PyInit__random},
    {"_sha1", PyInit__sha1},
    {"_sha2", PyInit__sha2},
    {"_sha3", PyInit__sha3},
    {"_signal", PyInit__signal},
    {"_socket", PyInit__socket},
    {"_sre", PyInit__sre},
    {"_ssl", PyInit__ssl},
    {"_stat", PyInit__stat},
    {"_statistics", PyInit__statistics},
    {"_string", PyInit__string},
    {"_struct", PyInit__struct},
    {"_suggestions", PyInit__suggestions},
    {"_symtable", PyInit__symtable},
    {"_sysconfig", PyInit__sysconfig},
    {"_thread", PyInit__thread},
    {"_tokenize", PyInit__tokenize},
    {"_tracemalloc", PyInit__tracemalloc},
    {"_types", PyInit__types},
    {"_typing", PyInit__typing},
    {"_weakref", PyInit__weakref},
    {"_zoneinfo", PyInit__zoneinfo},
    {"array", PyInit_array},
    {"atexit", PyInit_atexit},
    {"binascii", PyInit_binascii},
    {"cmath", PyInit_cmath},
    {"errno", PyInit_errno},
    {"faulthandler", PyInit_faulthandler},
    {"gc", PyInit_gc},
    {"itertools", PyInit_itertools},
    {"math", PyInit_math},
    {"pyexpat", PyInit_pyexpat},
    {"select", PyInit_select},
    {"time", PyInit_time},
    {"unicodedata", PyInit_unicodedata},
    {"zlib", PyInit_zlib},

    /* CJK codecs */
    {"_multibytecodec", PyInit__multibytecodec},
    {"_codecs_cn", PyInit__codecs_cn},
    {"_codecs_hk", PyInit__codecs_hk},
    {"_codecs_iso2022", PyInit__codecs_iso2022},
    {"_codecs_jp", PyInit__codecs_jp},
    {"_codecs_kr", PyInit__codecs_kr},
    {"_codecs_tw", PyInit__codecs_tw},

    /* This module "lives in" with marshal.c */
    {"marshal", PyMarshal_Init},

    /* This lives it with import.c */
    {"_imp", PyInit__imp},

    /* These entries are here for sys.builtin_module_names */
    {"builtins", NULL},
    {"sys", NULL},
    {"_warnings", _PyWarnings_Init},

    /* Sentinel */
    {0, 0}
};
