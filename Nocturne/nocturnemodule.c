/* _nocturne: the os module's own module on Nocturne, as nt is on Windows and
   posix elsewhere (ports/cpython/README.md). 名前 nocturne は Nocturne の契約の
   バインディングのパッケージ（Lib\nocturne）。

   Lib/os.py takes its functions from here, Lib/nocturnepath.py is os.path and
   Lib/subprocess.py launches apps with _launch. The functions speak of
   Python's descriptors (Nocturne/descriptors.c) and of the paths of C:
   (docs/nocturne-native-abi.md §3). A failure is an OSError whose errno is the
   N_ERR_* code, which libc's errno.h names.

   Nocturne has no modes, links, fork or exec, so what Python's os has for them
   is not here. A name never has a link to follow, so follow_symlinks changes
   nothing, and dir_fd is not supported (os.supports_dir_fd is empty). */
#include "Python.h"
#include "pycore_call.h"          // _PyObject_CallNoArgs()
#include "pycore_fileutils.h"     // _Py_read(), _Py_write(), _Py_fstat_noraise()
#include "pycore_object.h"        // _PyObject_LookupSpecial()
#include "pycore_pylifecycle.h"   // _PyOS_URandom()
#include "pycore_pymem.h"         // _PyMem_RawStrdup()
#include "pycore_signal.h"        // _PyOS_NocturneWait()
#include "pycore_time.h"          // _PyTime_ObjectToTimespec()
#include "descriptors.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

/* os.access's modes. Nocturne decides who may read or write a document when
   it is opened, so access says whether the entry is there. */
#define F_OK 0
#define X_OK 1
#define W_OK 2
#define R_OK 4

/* How many entries a scandir iterator asks the system for at a time. */
#define SCANDIR_BATCH 64

typedef struct {
    PyTypeObject *StatResultType;
    PyTypeObject *TerminalSizeType;
    PyTypeObject *AppEndType;
    PyTypeObject *DirEntryType;
    PyTypeObject *ScandirIteratorType;
} nocturne_state;

static struct PyModuleDef nocturnemodule;

static inline nocturne_state *
get_state(PyObject *module)
{
    void *state = PyModule_GetState(module);
    assert(state != NULL);
    return (nocturne_state *)state;
}

/* The state of the module whose type made op. */
static nocturne_state *
type_state(PyObject *op)
{
    PyObject *module = PyType_GetModuleByDef(Py_TYPE(op), &nocturnemodule);
    return module == NULL ? NULL : get_state(module);
}

/* ---- failures ---- */

static PyObject *
raise_result(n_result r, PyObject *filename)
{
    errno = (int)-r;
    return PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError, filename);
}

static PyObject *
raise_result2(n_result r, PyObject *filename, PyObject *filename2)
{
    errno = (int)-r;
    return PyErr_SetFromErrnoWithFilenameObjects(PyExc_OSError, filename, filename2);
}

static int
dir_fd_unavailable(PyObject *dir_fd)
{
    if (dir_fd != NULL && dir_fd != Py_None) {
        PyErr_SetString(PyExc_NotImplementedError, "dir_fd unavailable on this platform");
        return -1;
    }
    return 0;
}

/* ---- path arguments ---- */

/* An argument that names an entry of C: (str, bytes or os.PathLike), or a
   descriptor where the function takes one. */
typedef struct {
    bool nullable;                /* None is the current folder */
    bool allow_fd;
    PyObject *object;             /* what was passed */
    PyObject *bytes;              /* its UTF-8 bytes (surrogateescape) */
    const char *narrow;           /* what the system is given */
    int fd;                       /* -1 unless a descriptor was passed */
    bool is_bytes;                /* names come back as bytes */
} path_arg;

#define PATH_ARG(nullable_, allow_fd_) \
    {.nullable = (nullable_), .allow_fd = (allow_fd_), .narrow = ".", .fd = -1}

static void
path_clear(path_arg *path)
{
    Py_CLEAR(path->object);
    Py_CLEAR(path->bytes);
}

/* PEP 519: the str or bytes a path-like object stands for (Include/osmodule.h). */
PyObject *
PyOS_FSPath(PyObject *path)
{
    if (PyUnicode_Check(path) || PyBytes_Check(path)) {
        return Py_NewRef(path);
    }
    PyObject *func = _PyObject_LookupSpecial(path, &_Py_ID(__fspath__));
    if (func == NULL || func == Py_None) {
        Py_XDECREF(func);
        if (PyErr_Occurred()) {
            return NULL;
        }
        return PyErr_Format(PyExc_TypeError, "expected str, bytes or os.PathLike object, not %.200s",
                            _PyType_Name(Py_TYPE(path)));
    }
    PyObject *repr = _PyObject_CallNoArgs(func);
    Py_DECREF(func);
    if (repr == NULL) {
        return NULL;
    }
    if (!(PyUnicode_Check(repr) || PyBytes_Check(repr))) {
        PyErr_Format(PyExc_TypeError, "expected %.200s.__fspath__() to return str or bytes, not %.200s",
                     _PyType_Name(Py_TYPE(path)), _PyType_Name(Py_TYPE(repr)));
        Py_DECREF(repr);
        return NULL;
    }
    return repr;
}

static PyObject *
nocturne_fspath(PyObject *module, PyObject *path)
{
    return PyOS_FSPath(path);
}

/* A PyArg converter ("O&") for path_arg. The caller clears it. */
static int
path_converter(PyObject *o, void *p)
{
    path_arg *path = p;
    if (o == NULL) {
        path_clear(path);
        return 1;
    }
    path->object = Py_NewRef(o);
    if (o == Py_None) {
        if (!path->nullable) {
            PyErr_SetString(PyExc_TypeError, "path should be string, bytes or os.PathLike, not NoneType");
            path_clear(path);
            return 0;
        }
        return Py_CLEANUP_SUPPORTED;
    }
    if (path->allow_fd && PyIndex_Check(o)) {
        int fd = PyLong_AsInt(o);
        if (fd == -1 && PyErr_Occurred()) {
            path_clear(path);
            return 0;
        }
        path->fd = fd;
        return Py_CLEANUP_SUPPORTED;
    }
    PyObject *fs = PyOS_FSPath(o);
    if (fs == NULL) {
        path_clear(path);
        return 0;
    }
    path->is_bytes = PyBytes_Check(fs);
    int ok = PyUnicode_FSConverter(fs, &path->bytes);
    Py_DECREF(fs);
    if (!ok) {
        path_clear(path);
        return 0;
    }
    path->narrow = PyBytes_AS_STRING(path->bytes);
    return Py_CLEANUP_SUPPORTED;
}

/* The complete path the argument names inside the current folder. */
static int
path_complete(const path_arg *path, char out[_PY_PATH_MAX])
{
    if (_Py_complete_path(path->narrow, out) < 0) {
        PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError, path->object);
        return -1;
    }
    return 0;
}

/* A name of C: in the argument's type: bytes for bytes, str otherwise. */
static PyObject *
path_name(const path_arg *path, const char *name, size_t length)
{
    if (path->is_bytes) {
        return PyBytes_FromStringAndSize(name, (Py_ssize_t)length);
    }
    return PyUnicode_DecodeFSDefaultAndSize(name, (Py_ssize_t)length);
}

/* ---- stat_result and terminal_size ---- */

static PyStructSequence_Field stat_result_fields[] = {
    {"st_mode", "S_IFDIR for a folder, S_IFREG for a document, readable and writable"},
    {"st_ino", "the entry's identifier on C:, which stays with it when it moves"},
    {"st_dev", "0: C: is the one drive"},
    {"st_nlink", "1: an entry has one name"},
    {"st_uid", "the user the entry belongs to (0: the system)"},
    {"st_gid", "0: Nocturne has no groups"},
    {"st_size", "total size, in bytes"},
    /* The NULLs are PyStructSequence_UnnamedField (nocturne_exec). */
    {NULL, "integer time of last modification"},
    {NULL, "integer time of last modification"},
    {NULL, "integer time of last modification"},
    {"st_atime", "time of last modification: C: keeps no time of access"},
    {"st_mtime", "time of last modification"},
    {"st_ctime", "time of last modification: C: keeps no time of change"},
    {"st_atime_ns", "time of last modification in nanoseconds"},
    {"st_mtime_ns", "time of last modification in nanoseconds"},
    {"st_ctime_ns", "time of last modification in nanoseconds"},
    {NULL}
};

static PyStructSequence_Desc stat_result_desc = {
    "os.stat_result",
    "stat_result: Result from stat, fstat, or lstat.\n\n"
    "As a tuple: (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime);\n"
    "the attributes also give the times as floats and in nanoseconds.",
    stat_result_fields,
    10
};

static PyStructSequence_Field terminal_size_fields[] = {
    {"columns", "width of the terminal window in characters"},
    {"lines", "height of the terminal window in characters"},
    {NULL}
};

static PyStructSequence_Desc terminal_size_desc = {
    "os.terminal_size",
    "A tuple of (columns, lines) for holding terminal window size",
    terminal_size_fields,
    2
};

/* Sets the integer, float and nanosecond fields of one time. */
static int
stat_set_time(PyObject *v, int index, int64_t seconds, int nanoseconds)
{
    __int128 total = (__int128)seconds * 1000000000 + nanoseconds;
    PyObject *integer = PyLong_FromLongLong(seconds);
    PyObject *real = PyFloat_FromDouble((double)seconds + nanoseconds * 1e-9);
    PyObject *ns = PyLong_FromNativeBytes(&total, sizeof total, -1);
    PyStructSequence_SET_ITEM(v, index, integer);
    PyStructSequence_SET_ITEM(v, index + 3, real);
    PyStructSequence_SET_ITEM(v, index + 6, ns);
    return integer && real && ns ? 0 : -1;
}

static PyObject *
stat_result_make(nocturne_state *state, const struct _Py_stat_struct *st)
{
    PyObject *v = PyStructSequence_New(state->StatResultType);
    if (v == NULL) {
        return NULL;
    }
    PyObject *items[] = {
        PyLong_FromUnsignedLong(st->st_mode),
        PyLong_FromUnsignedLongLong(st->st_ino),
        PyLong_FromUnsignedLongLong(st->st_dev),
        PyLong_FromLong(st->st_nlink),
        PyLong_FromUnsignedLong(st->st_uid),
        PyLong_FromUnsignedLong(st->st_gid),
        PyLong_FromLongLong(st->st_size),
    };
    bool failed = false;
    for (int i = 0; i < (int)Py_ARRAY_LENGTH(items); i++) {
        PyStructSequence_SET_ITEM(v, i, items[i]);
        failed |= items[i] == NULL;
    }
    failed |= stat_set_time(v, 7, st->st_atime, st->st_atime_nsec) < 0;
    failed |= stat_set_time(v, 8, st->st_mtime, st->st_mtime_nsec) < 0;
    failed |= stat_set_time(v, 9, st->st_ctime, st->st_ctime_nsec) < 0;
    if (failed) {
        Py_DECREF(v);
        return NULL;
    }
    return v;
}

static PyObject *
stat_result_of_entry(nocturne_state *state, const struct n_entry *entry)
{
    struct _Py_stat_struct st;
    _Py_entry_stat(entry, &st);
    return stat_result_make(state, &st);
}

/* ---- the environment ---- */

/* このアプリの Python の環境：os.environ の元と、起動するアプリが受ける環境。初めは起動の環境（中核のライブラリーの
   n_environment。変わらない）で、putenv と unsetenv が変えると、それからは配列と文字列がこのモジュールのもの
   になる。起動の環境は変わらないので、C の getenv は起動の環境を読み続ける。 */
static struct {
    PyMutex lock;
    char **strings;               /* "NAME=value", ended by NULL */
    size_t count;
} environment;

/* 起動の時の環境の index 番目の "名前=値" を、NUL で終えた PyMem_RawMalloc の領域で返す。NULL は記憶が足りない。 */
static char *
environment_launched(size_t index)
{
    size_t capacity = 256;
    for (;;) {
        char *text = PyMem_RawMalloc(capacity + 1);
        if (text == NULL) {
            return NULL;
        }
        n_result length = n_environment(index, text, capacity);
        if (length < 0) {
            text[0] = '\0';
            return text;
        }
        if ((size_t)length <= capacity) {
            text[length] = '\0';
            return text;
        }
        PyMem_RawFree(text);
        capacity = (size_t)length;
    }
}

/* モジュール自身の環境のコピー。錠を持って呼ぶ。 */
static int
environment_own(void)
{
    if (environment.strings != NULL) {
        return 0;
    }
    size_t count = n_environment_count();
    char **strings = PyMem_RawCalloc(count + 1, sizeof *strings);
    if (strings == NULL) {
        return -1;
    }
    for (size_t i = 0; i < count; i++) {
        strings[i] = environment_launched(i);
        if (strings[i] == NULL) {
            for (size_t k = 0; k < i; k++) {
                PyMem_RawFree(strings[k]);
            }
            PyMem_RawFree(strings);
            return -1;
        }
    }
    environment.strings = strings;
    environment.count = count;
    return 0;
}

/* The index of name's string, or count. Called with the lock. */
static size_t
environment_find(const char *name, size_t length)
{
    size_t i = 0;
    while (i < environment.count
           && !(strncmp(environment.strings[i], name, length) == 0 && environment.strings[i][length] == '=')) {
        i++;
    }
    return i;
}

/* A copy of the environment as bytes objects, for a launch. */
static PyObject *
environment_snapshot(void)
{
    PyObject *list = PyList_New(0);
    if (list == NULL) {
        return NULL;
    }
    PyMutex_Lock(&environment.lock);
    if (environment_own() < 0) {
        PyMutex_Unlock(&environment.lock);
        Py_DECREF(list);
        return PyErr_NoMemory();
    }
    char *const *strings = environment.strings;
    for (size_t i = 0; strings[i] != NULL; i++) {
        PyObject *b = PyBytes_FromString(strings[i]);
        if (b == NULL || PyList_Append(list, b) < 0) {
            Py_XDECREF(b);
            Py_CLEAR(list);
            break;
        }
        Py_DECREF(b);
    }
    PyMutex_Unlock(&environment.lock);
    return list;
}

static int
environment_check_name(const char *name)
{
    if (name[0] == '\0' || strchr(name, '=') != NULL) {
        PyErr_SetString(PyExc_ValueError, "illegal environment variable name");
        return -1;
    }
    return 0;
}

static PyObject *
nocturne_putenv(PyObject *module, PyObject *args)
{
    PyObject *name = NULL, *value = NULL;
    if (!PyArg_ParseTuple(args, "O&O&:putenv", PyUnicode_FSConverter, &name, PyUnicode_FSConverter, &value)) {
        Py_XDECREF(name);
        return NULL;
    }
    PyObject *result = NULL;
    const char *n = PyBytes_AS_STRING(name), *v = PyBytes_AS_STRING(value);
    if (environment_check_name(n) < 0) {
        goto done;
    }
    size_t nlen = strlen(n), vlen = strlen(v);
    char *string = PyMem_RawMalloc(nlen + vlen + 2);
    if (string == NULL) {
        PyErr_NoMemory();
        goto done;
    }
    memcpy(string, n, nlen);
    string[nlen] = '=';
    memcpy(string + nlen + 1, v, vlen + 1);
    PyMutex_Lock(&environment.lock);
    if (environment_own() < 0) {
        PyMutex_Unlock(&environment.lock);
        PyMem_RawFree(string);
        PyErr_NoMemory();
        goto done;
    }
    size_t i = environment_find(n, nlen);
    if (i < environment.count) {
        char *old = environment.strings[i];
        environment.strings[i] = string;
        PyMem_RawFree(old);
    }
    else {
        char **grown = PyMem_RawMalloc((environment.count + 2) * sizeof *grown);
        if (grown == NULL) {
            PyMutex_Unlock(&environment.lock);
            PyMem_RawFree(string);
            PyErr_NoMemory();
            goto done;
        }
        memcpy(grown, environment.strings, environment.count * sizeof *grown);
        grown[environment.count] = string;
        grown[environment.count + 1] = NULL;
        char **old = environment.strings;
        environment.strings = grown;
        environment.count++;
        PyMem_RawFree(old);
    }
    PyMutex_Unlock(&environment.lock);
    result = Py_None;
done:
    Py_DECREF(name);
    Py_DECREF(value);
    return Py_XNewRef(result);
}

static PyObject *
nocturne_unsetenv(PyObject *module, PyObject *arg)
{
    PyObject *name;
    if (!PyUnicode_FSConverter(arg, &name)) {
        return NULL;
    }
    const char *n = PyBytes_AS_STRING(name);
    if (environment_check_name(n) < 0) {
        Py_DECREF(name);
        return NULL;
    }
    size_t nlen = strlen(n);
    PyMutex_Lock(&environment.lock);
    if (environment_own() < 0) {
        PyMutex_Unlock(&environment.lock);
        Py_DECREF(name);
        return PyErr_NoMemory();
    }
    size_t i = environment_find(n, nlen);
    if (i < environment.count) {
        PyMem_RawFree(environment.strings[i]);
        memmove(environment.strings + i, environment.strings + i + 1,
                (environment.count - i) * sizeof *environment.strings);
        environment.count--;
    }
    PyMutex_Unlock(&environment.lock);
    Py_DECREF(name);
    Py_RETURN_NONE;
}

/* os.environ's data: bytes names to bytes values. */
static PyObject *
environ_dict(void)
{
    PyObject *dict = PyDict_New();
    PyObject *strings = environment_snapshot();
    if (dict == NULL || strings == NULL) {
        Py_XDECREF(dict);
        Py_XDECREF(strings);
        return NULL;
    }
    for (Py_ssize_t i = 0; i < PyList_GET_SIZE(strings); i++) {
        const char *s = PyBytes_AS_STRING(PyList_GET_ITEM(strings, i));
        const char *eq = strchr(s, '=');
        if (eq == NULL || eq == s) {
            continue;
        }
        PyObject *k = PyBytes_FromStringAndSize(s, eq - s);
        PyObject *v = PyBytes_FromString(eq + 1);
        int r = k && v ? PyDict_SetDefaultRef(dict, k, v, NULL) : -1;
        Py_XDECREF(k);
        Py_XDECREF(v);
        if (r < 0) {
            Py_DECREF(strings);
            Py_DECREF(dict);
            return NULL;
        }
    }
    Py_DECREF(strings);
    return dict;
}

/* ---- entries of C: ---- */

static PyObject *
nocturne_stat_impl(PyObject *module, path_arg *path, const char *function)
{
    struct _Py_stat_struct st;
    int r;
    Py_BEGIN_ALLOW_THREADS
    r = path->fd >= 0 ? _Py_fstat_noraise(path->fd, &st) : _Py_path_stat(path->narrow, &st);
    Py_END_ALLOW_THREADS
    if (r < 0) {
        return PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError, path->object);
    }
    return stat_result_make(get_state(module), &st);
}

static PyObject *
nocturne_stat(PyObject *module, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"path", "dir_fd", "follow_symlinks", NULL};
    path_arg path = PATH_ARG(false, true);
    PyObject *dir_fd = NULL;
    int follow = 1;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&|$Op:stat", keywords, path_converter, &path, &dir_fd,
                                     &follow)) {
        return NULL;
    }
    PyObject *result = dir_fd_unavailable(dir_fd) < 0 ? NULL : nocturne_stat_impl(module, &path, "stat");
    path_clear(&path);
    return result;
}

static PyObject *
nocturne_lstat(PyObject *module, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"path", "dir_fd", NULL};
    path_arg path = PATH_ARG(false, false);
    PyObject *dir_fd = NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&|$O:lstat", keywords, path_converter, &path, &dir_fd)) {
        return NULL;
    }
    PyObject *result = dir_fd_unavailable(dir_fd) < 0 ? NULL : nocturne_stat_impl(module, &path, "lstat");
    path_clear(&path);
    return result;
}

static PyObject *
nocturne_fstat(PyObject *module, PyObject *arg)
{
    int fd = PyLong_AsInt(arg);
    if (fd == -1 && PyErr_Occurred()) {
        return NULL;
    }
    struct _Py_stat_struct st;
    if (_Py_fstat(fd, &st) < 0) {
        return NULL;
    }
    return stat_result_make(get_state(module), &st);
}

static PyObject *
nocturne_listdir(PyObject *module, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"path", NULL};
    path_arg path = PATH_ARG(true, false);
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|O&:listdir", keywords, path_converter, &path)) {
        return NULL;
    }
    PyObject *result = NULL;
    char folder[_PY_PATH_MAX];
    struct n_entry *entries = NULL;
    n_result count = 0;
    if (path_complete(&path, folder) < 0) {
        goto done;
    }
    Py_BEGIN_ALLOW_THREADS
    count = _Py_folder_list(folder, &entries);
    Py_END_ALLOW_THREADS
    if (count < 0) {
        raise_result(count, path.object);
        goto done;
    }
    result = PyList_New(count);
    for (n_result i = 0; result != NULL && i < count; i++) {
        PyObject *name = path_name(&path, entries[i].name, strlen(entries[i].name));
        if (name == NULL) {
            Py_CLEAR(result);
            break;
        }
        PyList_SET_ITEM(result, i, name);
    }
    PyMem_RawFree(entries);
done:
    path_clear(&path);
    return result;
}

static PyObject *
nocturne_mkdir(PyObject *module, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"path", "mode", "dir_fd", NULL};
    path_arg path = PATH_ARG(false, false);
    int mode = 0777;
    PyObject *dir_fd = NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&|i$O:mkdir", keywords, path_converter, &path, &mode,
                                     &dir_fd)) {
        return NULL;
    }
    PyObject *result = NULL;
    char full[_PY_PATH_MAX];
    if (dir_fd_unavailable(dir_fd) == 0 && path_complete(&path, full) == 0) {
        n_result r;
        Py_BEGIN_ALLOW_THREADS
        r = n_folder_create(full, strlen(full));
        Py_END_ALLOW_THREADS
        result = r < 0 ? raise_result(r, path.object) : Py_NewRef(Py_None);
    }
    path_clear(&path);
    return result;
}

/* Removes the entry path names if it is of kind (N_KIND_FOLDER or
   N_KIND_DOCUMENT); one of the other kind fails with mismatch. */
static PyObject *
remove_entry(PyObject *args, PyObject *kwargs, const char *format, uint32_t kind, int mismatch)
{
    static char *keywords[] = {"path", "dir_fd", NULL};
    path_arg path = PATH_ARG(false, false);
    PyObject *dir_fd = NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, format, keywords, path_converter, &path, &dir_fd)) {
        return NULL;
    }
    PyObject *result = NULL;
    char full[_PY_PATH_MAX];
    if (dir_fd_unavailable(dir_fd) == 0 && path_complete(&path, full) == 0) {
        struct n_entry entry;
        n_result r;
        Py_BEGIN_ALLOW_THREADS
        r = _Py_entry_info(full, &entry);
        if (r >= 0) {
            r = entry.kind == kind ? n_entry_remove(full, strlen(full)) : -mismatch;
        }
        Py_END_ALLOW_THREADS
        result = r < 0 ? raise_result(r, path.object) : Py_NewRef(Py_None);
    }
    path_clear(&path);
    return result;
}

static PyObject *
nocturne_rmdir(PyObject *module, PyObject *args, PyObject *kwargs)
{
    return remove_entry(args, kwargs, "O&|$O:rmdir", N_KIND_FOLDER, N_ERR_NOT_FOLDER);
}

static PyObject *
nocturne_remove(PyObject *module, PyObject *args, PyObject *kwargs)
{
    return remove_entry(args, kwargs, "O&|$O:remove", N_KIND_DOCUMENT, N_ERR_IS_FOLDER);
}

static PyObject *
nocturne_unlink(PyObject *module, PyObject *args, PyObject *kwargs)
{
    return remove_entry(args, kwargs, "O&|$O:unlink", N_KIND_DOCUMENT, N_ERR_IS_FOLDER);
}

/* rename never replaces an entry (FileExistsError), as on Windows; replace
   lets a document take the name of another document. */
static PyObject *
move_entry(PyObject *args, PyObject *kwargs, const char *format, bool replace)
{
    static char *keywords[] = {"src", "dst", "src_dir_fd", "dst_dir_fd", NULL};
    path_arg src = PATH_ARG(false, false), dst = PATH_ARG(false, false);
    PyObject *src_dir_fd = NULL, *dst_dir_fd = NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, format, keywords, path_converter, &src, path_converter, &dst,
                                     &src_dir_fd, &dst_dir_fd)) {
        return NULL;
    }
    PyObject *result = NULL;
    char from[_PY_PATH_MAX], to[_PY_PATH_MAX];
    if (dir_fd_unavailable(src_dir_fd) == 0 && dir_fd_unavailable(dst_dir_fd) == 0
        && path_complete(&src, from) == 0 && path_complete(&dst, to) == 0) {
        n_result r;
        Py_BEGIN_ALLOW_THREADS
        r = replace ? n_entry_replace(from, strlen(from), to, strlen(to))
                    : n_entry_move(from, strlen(from), to, strlen(to));
        Py_END_ALLOW_THREADS
        result = r < 0 ? raise_result2(r, src.object, dst.object) : Py_NewRef(Py_None);
    }
    path_clear(&src);
    path_clear(&dst);
    return result;
}

static PyObject *
nocturne_rename(PyObject *module, PyObject *args, PyObject *kwargs)
{
    return move_entry(args, kwargs, "O&O&|$OO:rename", false);
}

static PyObject *
nocturne_replace(PyObject *module, PyObject *args, PyObject *kwargs)
{
    return move_entry(args, kwargs, "O&O&|$OO:replace", true);
}

/* 文を書く関数（out text）の結果を NUL で終えて buf に書く。入らなければ ENAMETOOLONG。0 か、errno つきの -1。 */
static int
folder_text(n_result (*get)(char *, size_t), char buf[_PY_PATH_MAX])
{
    n_result length = get(buf, _PY_PATH_MAX - 1);
    if (length < 0 || length > _PY_PATH_MAX - 1) {
        errno = length < 0 ? (int)-length : ENAMETOOLONG;
        return -1;
    }
    buf[length] = '\0';
    return 0;
}

static PyObject *
nocturne_getcwd(PyObject *module, PyObject *Py_UNUSED(ignored))
{
    char folder[_PY_PATH_MAX];
    if (folder_text(n_folder, folder) < 0) {
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    return PyUnicode_DecodeFSDefault(folder);
}

static PyObject *
nocturne_getcwdb(PyObject *module, PyObject *Py_UNUSED(ignored))
{
    char folder[_PY_PATH_MAX];
    if (folder_text(n_folder, folder) < 0) {
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    return PyBytes_FromString(folder);
}

static PyObject *
nocturne_chdir(PyObject *module, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"path", NULL};
    path_arg path = PATH_ARG(false, false);
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&:chdir", keywords, path_converter, &path)) {
        return NULL;
    }
    PyObject *result = NULL;
    char full[_PY_PATH_MAX];
    if (path_complete(&path, full) == 0) {
        n_result r;
        Py_BEGIN_ALLOW_THREADS
        r = n_folder_set(full, strlen(full));
        Py_END_ALLOW_THREADS
        result = r < 0 ? raise_result(r, path.object) : Py_NewRef(Py_None);
    }
    path_clear(&path);
    return result;
}

static PyObject *
nocturne_access(PyObject *module, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"path", "mode", "dir_fd", "effective_ids", "follow_symlinks", NULL};
    path_arg path = PATH_ARG(false, false);
    int mode, effective_ids = 0, follow = 1;
    PyObject *dir_fd = NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&i|$Opp:access", keywords, path_converter, &path, &mode,
                                     &dir_fd, &effective_ids, &follow)) {
        return NULL;
    }
    PyObject *result = NULL;
    if (dir_fd_unavailable(dir_fd) == 0) {
        if (effective_ids) {
            PyErr_SetString(PyExc_NotImplementedError, "effective_ids unavailable on this platform");
        }
        else {
            struct _Py_stat_struct st;
            int r;
            Py_BEGIN_ALLOW_THREADS
            r = _Py_path_stat(path.narrow, &st);
            Py_END_ALLOW_THREADS
            result = PyBool_FromLong(r == 0);
        }
    }
    path_clear(&path);
    return result;
}

/* The wall time in ns that utime's times or ns gives as the modified time. */
static int
utime_modified(PyObject *times, PyObject *ns, int64_t *wall)
{
    if (times != NULL && times != Py_None && ns != NULL) {
        PyErr_SetString(PyExc_ValueError, "utime: you may specify either 'times' or 'ns' but not both");
        return -1;
    }
    if (ns != NULL) {
        if (!PyTuple_Check(ns) || PyTuple_GET_SIZE(ns) != 2) {
            PyErr_SetString(PyExc_TypeError, "utime: 'ns' must be a tuple of two ints");
            return -1;
        }
        long long value = PyLong_AsLongLong(PyTuple_GET_ITEM(ns, 1));
        if (value == -1 && PyErr_Occurred()) {
            return -1;
        }
        *wall = value;
        return 0;
    }
    if (times != NULL && times != Py_None) {
        if (!PyTuple_Check(times) || PyTuple_GET_SIZE(times) != 2) {
            PyErr_SetString(PyExc_TypeError, "utime: 'times' must be either a tuple of two numbers or None");
            return -1;
        }
        time_t seconds;
        long nanoseconds;
        if (_PyTime_ObjectToTimespec(PyTuple_GET_ITEM(times, 1), &seconds, &nanoseconds, _PyTime_ROUND_FLOOR) < 0) {
            return -1;
        }
        *wall = (int64_t)seconds * 1000000000 + nanoseconds;
        return 0;
    }
    *wall = n_clock_wall();
    return 0;
}

/* C: keeps one time: the modified time is the last of the times given. */
static PyObject *
nocturne_utime(PyObject *module, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"path", "times", "ns", "dir_fd", "follow_symlinks", NULL};
    path_arg path = PATH_ARG(false, false);
    PyObject *times = NULL, *ns = NULL, *dir_fd = NULL;
    int follow = 1;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&|O$OOp:utime", keywords, path_converter, &path, &times, &ns,
                                     &dir_fd, &follow)) {
        return NULL;
    }
    PyObject *result = NULL;
    char full[_PY_PATH_MAX];
    int64_t wall;
    if (dir_fd_unavailable(dir_fd) == 0 && utime_modified(times, ns, &wall) == 0 && path_complete(&path, full) == 0) {
        n_result r;
        Py_BEGIN_ALLOW_THREADS
        r = n_entry_set_modified(full, strlen(full), wall);
        Py_END_ALLOW_THREADS
        result = r < 0 ? raise_result(r, path.object) : Py_NewRef(Py_None);
    }
    path_clear(&path);
    return result;
}

static PyObject *
nocturne_truncate(PyObject *module, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"path", "length", NULL};
    path_arg path = PATH_ARG(false, true);
    long long length;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&L:truncate", keywords, path_converter, &path, &length)) {
        return NULL;
    }
    PyObject *result = NULL;
    char full[_PY_PATH_MAX];
    if (length < 0) {
        errno = EINVAL;
        PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError, path.object);
    }
    else if (path.fd >= 0) {
        int r;
        Py_BEGIN_ALLOW_THREADS
        r = _Py_fd_truncate(path.fd, length);
        Py_END_ALLOW_THREADS
        result = r < 0 ? PyErr_SetFromErrno(PyExc_OSError) : Py_NewRef(Py_None);
    }
    else if (path_complete(&path, full) == 0) {
        n_result r;
        Py_BEGIN_ALLOW_THREADS
        n_document document;
        r = n_document_open(full, strlen(full), N_DOCUMENT_ACCESS_EDIT, &document);
        if (r >= 0) {
            r = n_document_set_size(document, (uint64_t)length);
            n_result closed = n_handle_close((n_handle){document.handle});
            if (r >= 0) {
                r = closed;
            }
        }
        Py_END_ALLOW_THREADS
        result = r < 0 ? raise_result(r, path.object) : Py_NewRef(Py_None);
    }
    path_clear(&path);
    return result;
}

/* ---- descriptors ---- */

static int
fd_argument(PyObject *arg, int *fd)
{
    *fd = PyLong_AsInt(arg);
    return *fd == -1 && PyErr_Occurred() ? -1 : 0;
}

static PyObject *
nocturne_open(PyObject *module, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"path", "flags", "mode", "dir_fd", NULL};
    path_arg path = PATH_ARG(false, false);
    int flags, mode = 0777;
    PyObject *dir_fd = NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&i|i$O:open", keywords, path_converter, &path, &flags, &mode,
                                     &dir_fd)) {
        return NULL;
    }
    PyObject *result = NULL;
    if (dir_fd_unavailable(dir_fd) == 0
        && PySys_Audit("open", "OOi", path.object, Py_None, flags) == 0) {
        int fd;
        Py_BEGIN_ALLOW_THREADS
        fd = _Py_fd_open(path.narrow, flags);
        Py_END_ALLOW_THREADS
        result = fd < 0 ? PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError, path.object) : PyLong_FromLong(fd);
    }
    path_clear(&path);
    return result;
}

static PyObject *
nocturne_close(PyObject *module, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"fd", NULL};
    int fd;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "i:close", keywords, &fd)) {
        return NULL;
    }
    int r;
    Py_BEGIN_ALLOW_THREADS
    r = _Py_fd_close(fd);
    Py_END_ALLOW_THREADS
    return r < 0 ? PyErr_SetFromErrno(PyExc_OSError) : Py_NewRef(Py_None);
}

static PyObject *
nocturne_closerange(PyObject *module, PyObject *args)
{
    int low, high;
    if (!PyArg_ParseTuple(args, "ii:closerange", &low, &high)) {
        return NULL;
    }
    if (high > low) {
        Py_BEGIN_ALLOW_THREADS
        _Py_fd_close_range(low < 0 ? 0 : low, high - 1);
        Py_END_ALLOW_THREADS
    }
    Py_RETURN_NONE;
}

static PyObject *
nocturne_read(PyObject *module, PyObject *args)
{
    int fd;
    Py_ssize_t length;
    if (!PyArg_ParseTuple(args, "in:read", &fd, &length)) {
        return NULL;
    }
    if (length < 0) {
        errno = EINVAL;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    PyBytesWriter *writer = PyBytesWriter_Create(length);
    if (writer == NULL) {
        return NULL;
    }
    Py_ssize_t n = _Py_read(fd, PyBytesWriter_GetData(writer), (size_t)length);
    if (n < 0) {
        PyBytesWriter_Discard(writer);
        return NULL;
    }
    return PyBytesWriter_FinishWithSize(writer, n);
}

static PyObject *
nocturne_readinto(PyObject *module, PyObject *args)
{
    int fd;
    Py_buffer buffer;
    if (!PyArg_ParseTuple(args, "iw*:readinto", &fd, &buffer)) {
        return NULL;
    }
    Py_ssize_t n = _Py_read(fd, buffer.buf, (size_t)buffer.len);
    PyBuffer_Release(&buffer);
    return n < 0 ? NULL : PyLong_FromSsize_t(n);
}

static PyObject *
nocturne_write(PyObject *module, PyObject *args)
{
    int fd;
    Py_buffer data;
    if (!PyArg_ParseTuple(args, "iy*:write", &fd, &data)) {
        return NULL;
    }
    Py_ssize_t n = _Py_write(fd, data.buf, (size_t)data.len);
    PyBuffer_Release(&data);
    return n < 0 ? NULL : PyLong_FromSsize_t(n);
}

static PyObject *
nocturne_lseek(PyObject *module, PyObject *args)
{
    int fd, how;
    long long position;
    if (!PyArg_ParseTuple(args, "iLi:lseek", &fd, &position, &how)) {
        return NULL;
    }
    long long r;
    Py_BEGIN_ALLOW_THREADS
    r = _Py_fd_seek(fd, position, how);
    Py_END_ALLOW_THREADS
    return r < 0 ? PyErr_SetFromErrno(PyExc_OSError) : PyLong_FromLongLong(r);
}

static PyObject *
nocturne_ftruncate(PyObject *module, PyObject *args)
{
    int fd;
    long long length;
    if (!PyArg_ParseTuple(args, "iL:ftruncate", &fd, &length)) {
        return NULL;
    }
    int r;
    Py_BEGIN_ALLOW_THREADS
    r = _Py_fd_truncate(fd, length);
    Py_END_ALLOW_THREADS
    return r < 0 ? PyErr_SetFromErrno(PyExc_OSError) : Py_NewRef(Py_None);
}

static PyObject *
nocturne_fsync(PyObject *module, PyObject *arg)
{
    int fd = PyObject_AsFileDescriptor(arg);
    if (fd < 0) {
        return NULL;
    }
    int r;
    Py_BEGIN_ALLOW_THREADS
    r = _Py_fd_sync(fd);
    Py_END_ALLOW_THREADS
    return r < 0 ? PyErr_SetFromErrno(PyExc_OSError) : Py_NewRef(Py_None);
}

static PyObject *
nocturne_isatty(PyObject *module, PyObject *arg)
{
    int fd;
    if (fd_argument(arg, &fd) < 0) {
        return NULL;
    }
    return PyBool_FromLong(_Py_isatty(fd) == 1);
}

static PyObject *
nocturne_dup(PyObject *module, PyObject *arg)
{
    int fd;
    if (fd_argument(arg, &fd) < 0) {
        return NULL;
    }
    int copy = _Py_dup(fd);
    return copy < 0 ? NULL : PyLong_FromLong(copy);
}

static PyObject *
nocturne_dup2(PyObject *module, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"fd", "fd2", "inheritable", NULL};
    int fd, fd2, inheritable = 1;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "ii|p:dup2", keywords, &fd, &fd2, &inheritable)) {
        return NULL;
    }
    int r;
    Py_BEGIN_ALLOW_THREADS
    r = _Py_fd_dup2(fd, fd2);
    Py_END_ALLOW_THREADS
    return r < 0 ? PyErr_SetFromErrno(PyExc_OSError) : PyLong_FromLong(r);
}

/* A channel's two ends: one to read, one to write. */
static PyObject *
nocturne_pipe(PyObject *module, PyObject *Py_UNUSED(ignored))
{
    n_channel read_end, write_end;
    n_result r = n_channel_pair(&write_end, &read_end);
    if (r < 0) {
        return raise_result(r, NULL);
    }
    int read_fd = _Py_fd_adopt(read_end.handle, 1, 0);
    if (read_fd < 0) {
        n_handle_close((n_handle){read_end.handle});
        n_handle_close((n_handle){write_end.handle});
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    int write_fd = _Py_fd_adopt(write_end.handle, 0, 1);
    if (write_fd < 0) {
        n_handle_close((n_handle){write_end.handle});
        _Py_fd_close(read_fd);
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    return Py_BuildValue("(ii)", read_fd, write_fd);
}

static PyObject *
nocturne_get_blocking(PyObject *module, PyObject *arg)
{
    int fd;
    if (fd_argument(arg, &fd) < 0) {
        return NULL;
    }
    int blocking = _Py_get_blocking(fd);
    return blocking < 0 ? NULL : PyBool_FromLong(blocking);
}

static PyObject *
nocturne_set_blocking(PyObject *module, PyObject *args)
{
    int fd, blocking;
    if (!PyArg_ParseTuple(args, "ip:set_blocking", &fd, &blocking)) {
        return NULL;
    }
    return _Py_set_blocking(fd, blocking) < 0 ? NULL : Py_NewRef(Py_None);
}

static PyObject *
nocturne_device_encoding(PyObject *module, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"fd", NULL};
    int fd;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "i:device_encoding", keywords, &fd)) {
        return NULL;
    }
    return _Py_device_encoding(fd);
}

static PyObject *
nocturne_get_terminal_size(PyObject *module, PyObject *args)
{
    int fd = 1;
    if (!PyArg_ParseTuple(args, "|i:get_terminal_size", &fd)) {
        return NULL;
    }
    int32_t h = _Py_fd_handle(fd);
    if (h < 0) {
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    struct n_terminal_grid size;
    n_result r;
    Py_BEGIN_ALLOW_THREADS
    r = n_terminal_size((n_handle){h}, &size);
    Py_END_ALLOW_THREADS
    if (r < 0) {
        return raise_result(r, NULL);
    }
    PyObject *v = PyStructSequence_New(get_state(module)->TerminalSizeType);
    if (v == NULL) {
        return NULL;
    }
    PyObject *columns = PyLong_FromUnsignedLong(size.columns);
    PyObject *lines = PyLong_FromUnsignedLong(size.rows);
    PyStructSequence_SET_ITEM(v, 0, columns);
    PyStructSequence_SET_ITEM(v, 1, lines);
    if (columns == NULL || lines == NULL) {
        Py_DECREF(v);
        return NULL;
    }
    return v;
}

/* ---- scandir ---- */

typedef struct {
    PyObject_HEAD
    PyObject *name;
    PyObject *path;
    PyObject *stat;               /* made by the first stat() */
    struct n_entry entry;
} DirEntry;

static void
DirEntry_dealloc(PyObject *op)
{
    DirEntry *self = (DirEntry *)op;
    PyTypeObject *type = Py_TYPE(op);
    Py_XDECREF(self->name);
    Py_XDECREF(self->path);
    Py_XDECREF(self->stat);
    type->tp_free(op);
    Py_DECREF(type);
}

static PyObject *
DirEntry_repr(PyObject *op)
{
    return PyUnicode_FromFormat("<DirEntry %R>", ((DirEntry *)op)->name);
}

static PyObject *
DirEntry_fspath(PyObject *op, PyObject *Py_UNUSED(ignored))
{
    return Py_NewRef(((DirEntry *)op)->path);
}

/* follow_symlinks is taken and changes nothing: Nocturne has no links. */
static int
DirEntry_follow(PyObject *args, PyObject *kwargs, const char *format)
{
    static char *keywords[] = {"follow_symlinks", NULL};
    int follow = 1;
    return PyArg_ParseTupleAndKeywords(args, kwargs, format, keywords, &follow) ? 0 : -1;
}

static PyObject *
DirEntry_is_dir(PyObject *op, PyObject *args, PyObject *kwargs)
{
    if (DirEntry_follow(args, kwargs, "|$p:is_dir") < 0) {
        return NULL;
    }
    return PyBool_FromLong(((DirEntry *)op)->entry.kind == N_KIND_FOLDER);
}

static PyObject *
DirEntry_is_file(PyObject *op, PyObject *args, PyObject *kwargs)
{
    if (DirEntry_follow(args, kwargs, "|$p:is_file") < 0) {
        return NULL;
    }
    return PyBool_FromLong(((DirEntry *)op)->entry.kind == N_KIND_DOCUMENT);
}

static PyObject *
DirEntry_is_symlink(PyObject *op, PyObject *Py_UNUSED(ignored))
{
    Py_RETURN_FALSE;
}

static PyObject *
DirEntry_is_junction(PyObject *op, PyObject *Py_UNUSED(ignored))
{
    Py_RETURN_FALSE;
}

/* What the folder's listing said of the entry. */
static PyObject *
DirEntry_stat(PyObject *op, PyObject *args, PyObject *kwargs)
{
    DirEntry *self = (DirEntry *)op;
    if (DirEntry_follow(args, kwargs, "|$p:stat") < 0) {
        return NULL;
    }
    if (self->stat == NULL) {
        nocturne_state *state = type_state(op);
        if (state == NULL) {
            return NULL;
        }
        self->stat = stat_result_of_entry(state, &self->entry);
    }
    return Py_XNewRef(self->stat);
}

static PyObject *
DirEntry_inode(PyObject *op, PyObject *Py_UNUSED(ignored))
{
    return PyLong_FromUnsignedLongLong(((DirEntry *)op)->entry.id);
}

static PyMemberDef DirEntry_members[] = {
    {"name", Py_T_OBJECT_EX, offsetof(DirEntry, name), Py_READONLY, "the entry's name"},
    {"path", Py_T_OBJECT_EX, offsetof(DirEntry, path), Py_READONLY, "the entry's path"},
    {NULL}
};

static PyMethodDef DirEntry_methods[] = {
    {"is_dir", _PyCFunction_CAST(DirEntry_is_dir), METH_VARARGS | METH_KEYWORDS, "Return True if the entry is a folder."},
    {"is_file", _PyCFunction_CAST(DirEntry_is_file), METH_VARARGS | METH_KEYWORDS,
     "Return True if the entry is a document."},
    {"is_symlink", DirEntry_is_symlink, METH_NOARGS, "Return False: Nocturne has no links."},
    {"is_junction", DirEntry_is_junction, METH_NOARGS, "Return False: Nocturne has no junctions."},
    {"stat", _PyCFunction_CAST(DirEntry_stat), METH_VARARGS | METH_KEYWORDS, "Return stat_result for the entry."},
    {"inode", DirEntry_inode, METH_NOARGS, "Return the entry's identifier on C:."},
    {"__fspath__", DirEntry_fspath, METH_NOARGS, "Return the file system path representation of the object."},
    {"__class_getitem__", Py_GenericAlias, METH_O | METH_CLASS, "See PEP 585"},
    {NULL}
};

static PyType_Slot DirEntry_slots[] = {
    {Py_tp_dealloc, DirEntry_dealloc},
    {Py_tp_repr, DirEntry_repr},
    {Py_tp_methods, DirEntry_methods},
    {Py_tp_members, DirEntry_members},
    {0, 0}
};

static PyType_Spec DirEntry_spec = {
    .name = "_nocturne.DirEntry",
    .basicsize = sizeof(DirEntry),
    .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_DISALLOW_INSTANTIATION | Py_TPFLAGS_IMMUTABLETYPE,
    .slots = DirEntry_slots,
};

typedef struct {
    PyObject_HEAD
    path_arg path;                /* what scandir was given */
    char *folder;                 /* its complete path */
    struct n_entry *batch;
    Py_ssize_t batch_at, batch_count;
    uint64_t next;                /* the index of the next entry to list */
    bool last;                    /* the batch is the folder's last */
} ScandirIterator;

static void
ScandirIterator_close_impl(ScandirIterator *it)
{
    PyMem_Free(it->batch);
    PyMem_Free(it->folder);
    it->batch = NULL;
    it->folder = NULL;
    it->batch_at = it->batch_count = 0;
    it->last = true;
}

static void
ScandirIterator_dealloc(PyObject *op)
{
    ScandirIterator *it = (ScandirIterator *)op;
    PyTypeObject *type = Py_TYPE(op);
    ScandirIterator_close_impl(it);
    path_clear(&it->path);
    type->tp_free(op);
    Py_DECREF(type);
}

/* Lists the folder's next batch. */
static int
ScandirIterator_list(ScandirIterator *it)
{
    n_result r;
    Py_BEGIN_ALLOW_THREADS
    for (int i = 0; i < SCANDIR_BATCH; i++) {
        it->batch[i].bytes = sizeof it->batch[i];
    }
    r = n_folder_list(it->folder, strlen(it->folder), it->batch, SCANDIR_BATCH, sizeof *it->batch, it->next);
    Py_END_ALLOW_THREADS
    if (r < 0) {
        ScandirIterator_close_impl(it);
        raise_result(r, it->path.object);
        return -1;
    }
    /* r は next から後の項の全部の数で、書いたのは束に入る分 */
    n_result written = r < SCANDIR_BATCH ? r : SCANDIR_BATCH;
    it->next += (uint64_t)written;
    it->batch_at = 0;
    it->batch_count = (Py_ssize_t)written;
    it->last = r <= SCANDIR_BATCH;
    return 0;
}

/* The DirEntry's path: the name joined to what scandir was given. */
static PyObject *
ScandirIterator_entry_path(ScandirIterator *it, const char *name)
{
    const char *folder = it->path.narrow;
    size_t flen = strlen(folder), nlen = strlen(name);
    bool separator = flen > 0 && folder[flen - 1] != '\\' && folder[flen - 1] != '/'
                     && !(flen == 2 && folder[1] == ':');
    char *joined = PyMem_Malloc(flen + nlen + 2);
    if (joined == NULL) {
        return PyErr_NoMemory();
    }
    memcpy(joined, folder, flen);
    size_t at = flen;
    if (separator) {
        joined[at++] = '\\';
    }
    memcpy(joined + at, name, nlen);
    PyObject *path = path_name(&it->path, joined, at + nlen);
    PyMem_Free(joined);
    return path;
}

static PyObject *
ScandirIterator_iternext(PyObject *op)
{
    ScandirIterator *it = (ScandirIterator *)op;
    for (;;) {
        if (it->batch_at < it->batch_count) {
            const struct n_entry *e = &it->batch[it->batch_at++];
            nocturne_state *state = type_state(op);
            if (state == NULL) {
                return NULL;
            }
            DirEntry *entry = PyObject_New(DirEntry, state->DirEntryType);
            if (entry == NULL) {
                return NULL;
            }
            entry->stat = NULL;
            entry->entry = *e;
            entry->name = path_name(&it->path, e->name, strlen(e->name));
            entry->path = entry->name ? ScandirIterator_entry_path(it, e->name) : NULL;
            if (entry->path == NULL) {
                Py_DECREF(entry);
                return NULL;
            }
            return (PyObject *)entry;
        }
        if (it->last) {
            ScandirIterator_close_impl(it);
            return NULL;
        }
        if (ScandirIterator_list(it) < 0) {
            return NULL;
        }
    }
}

static PyObject *
ScandirIterator_close(PyObject *op, PyObject *Py_UNUSED(ignored))
{
    ScandirIterator_close_impl((ScandirIterator *)op);
    Py_RETURN_NONE;
}

static PyObject *
ScandirIterator_enter(PyObject *op, PyObject *Py_UNUSED(ignored))
{
    return Py_NewRef(op);
}

static PyObject *
ScandirIterator_exit(PyObject *op, PyObject *Py_UNUSED(args))
{
    ScandirIterator_close_impl((ScandirIterator *)op);
    Py_RETURN_NONE;
}

static PyMethodDef ScandirIterator_methods[] = {
    {"__enter__", ScandirIterator_enter, METH_NOARGS},
    {"__exit__", ScandirIterator_exit, METH_VARARGS},
    {"close", ScandirIterator_close, METH_NOARGS},
    {NULL}
};

static PyType_Slot ScandirIterator_slots[] = {
    {Py_tp_dealloc, ScandirIterator_dealloc},
    {Py_tp_iter, PyObject_SelfIter},
    {Py_tp_iternext, ScandirIterator_iternext},
    {Py_tp_methods, ScandirIterator_methods},
    {0, 0}
};

static PyType_Spec ScandirIterator_spec = {
    .name = "_nocturne.ScandirIterator",
    .basicsize = sizeof(ScandirIterator),
    .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_DISALLOW_INSTANTIATION | Py_TPFLAGS_IMMUTABLETYPE,
    .slots = ScandirIterator_slots,
};

static PyObject *
nocturne_scandir(PyObject *module, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"path", NULL};
    nocturne_state *state = get_state(module);
    ScandirIterator *it = PyObject_New(ScandirIterator, state->ScandirIteratorType);
    if (it == NULL) {
        return NULL;
    }
    it->path = (path_arg)PATH_ARG(true, false);
    it->folder = NULL;
    it->batch = NULL;
    it->batch_at = it->batch_count = 0;
    it->next = 0;
    it->last = true;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|O&:scandir", keywords, path_converter, &it->path)) {
        Py_DECREF(it);
        return NULL;
    }
    it->folder = PyMem_Malloc(_PY_PATH_MAX);
    it->batch = PyMem_Malloc(SCANDIR_BATCH * sizeof *it->batch);
    if (it->folder == NULL || it->batch == NULL) {
        Py_DECREF(it);
        return PyErr_NoMemory();
    }
    if (path_complete(&it->path, it->folder) < 0 || ScandirIterator_list(it) < 0) {
        Py_DECREF(it);
        return NULL;
    }
    return (PyObject *)it;
}

/* ---- apps ---- */

/* The bytes of each item of a sequence of str, bytes or os.PathLike, in a new
   list, and a NULL-ended array of pointers into them. */
static const char **
string_array(PyObject *seq, const char *what, PyObject **keep, uint32_t *count)
{
    PyObject *fast = PySequence_Fast(seq, what);
    if (fast == NULL) {
        return NULL;
    }
    Py_ssize_t n = PySequence_Fast_GET_SIZE(fast);
    PyObject *list = PyList_New(n);
    const char **array = PyMem_Calloc((size_t)n + 1, sizeof *array);
    if (list == NULL || array == NULL) {
        goto fail;
    }
    for (Py_ssize_t i = 0; i < n; i++) {
        PyObject *b;
        if (!PyUnicode_FSConverter(PySequence_Fast_GET_ITEM(fast, i), &b)) {
            goto fail;
        }
        PyList_SET_ITEM(list, i, b);
        array[i] = PyBytes_AS_STRING(b);
    }
    Py_DECREF(fast);
    *keep = list;
    *count = (uint32_t)n;
    return array;
fail:
    if (array == NULL && !PyErr_Occurred()) {
        PyErr_NoMemory();
    }
    Py_DECREF(fast);
    Py_XDECREF(list);
    PyMem_Free(array);
    return NULL;
}

/* 文の並びを、各文の後ろに 0 の byte を置いて一つの文に詰める（PyMem_RawMalloc）。NULL は記憶が足りない。 */
static char *
pack_strings(const char *const *strings, uint32_t count, size_t *bytes)
{
    size_t total = 0;
    for (uint32_t i = 0; i < count; i++) {
        total += strlen(strings[i]) + 1;
    }
    char *packed = PyMem_RawMalloc(total > 0 ? total : 1);
    if (packed == NULL) {
        return NULL;
    }
    size_t at = 0;
    for (uint32_t i = 0; i < count; i++) {
        size_t length = strlen(strings[i]) + 1;
        memcpy(packed + at, strings[i], length);
        at += length;
    }
    *bytes = total;
    return packed;
}

/* 完全なパスのプログラムを起動する。standard はアプリの入力、出力、記録の流れの記述子（-1 は無し）。given のハンドルを
   その順に渡すので、アプリのハンドル i は given[i]（§5）。流れのうちこのアプリの端末へつながるものが、子を端末へつなぐ。
   アプリのハンドルの番号か、負の n_result を返す。 */
static n_result
launch_app(const char *program, const char **arguments, uint32_t argument_count, const char **environment_strings,
           uint32_t environment_count, const int standard[3], const char *folder, const int32_t *given,
           uint32_t given_count)
{
    n_handle streams[3];
    for (int i = 0; i < 3; i++) {
        streams[i].handle = -1;
        if (standard[i] >= 0) {
            streams[i].handle = _Py_fd_handle(standard[i]);
            if (streams[i].handle < 0) {
                return -N_ERR_NO_HANDLE;
            }
        }
    }
    size_t arguments_bytes = 0, environment_bytes = 0;
    char *packed_arguments = pack_strings(arguments, argument_count, &arguments_bytes);
    char *packed_environment = pack_strings(environment_strings, environment_count, &environment_bytes);
    n_handle *handles = PyMem_RawMalloc((given_count > 0 ? given_count : 1) * sizeof *handles);
    n_result r = -N_ERR_NO_MEMORY;
    if (packed_arguments != NULL && packed_environment != NULL && handles != NULL) {
        for (uint32_t i = 0; i < given_count; i++) {
            handles[i].handle = given[i];
        }
        struct n_launch launch = {
            .bytes = sizeof launch,
            .arguments = packed_arguments,
            .arguments_bytes = arguments_bytes,
            .environment = packed_environment,
            .environment_bytes = environment_bytes,
            .handles = handles,
            .handles_count = given_count,
            .folder = folder,
            .folder_bytes = strlen(folder),
            .input = streams[0],
            .output = streams[1],
            .log = streams[2],
            .interrupts = {-1},
            .identity_grant = {-1},
            .table = {-1},
        };
        launch.terminal = n_launch_terminal(streams[0], streams[1], streams[2]);
        n_app app;
        r = n_app_launch(program, strlen(program), &launch, &app);
        if (r >= 0) {
            r = app.handle;
        }
    }
    PyMem_RawFree(handles);
    PyMem_RawFree(packed_environment);
    PyMem_RawFree(packed_arguments);
    return r;
}

enum wait_outcome {
    WAIT_ENDED,                   /* *end holds how the app ended */
    WAIT_DEADLINE,
    WAIT_INTERRUPTED,             /* SIGINT came first */
    WAIT_FAILED,                  /* *error holds the n_result */
};

/* Waits for the app's end until deadline. Called without the GIL. */
static enum wait_outcome
wait_app(int32_t app, uint64_t deadline, struct n_app_end *end, n_result *error)
{
    for (;;) {
        n_result r;
        int woke = 1;
        end->bytes = sizeof *end;
        if (_PyOS_NocturneInterruptible()) {
            woke = _PyOS_NocturneWait(app, N_EVENT_APP_ENDED, NULL, 0, deadline);
            r = n_app_result((n_app){app}, 0, end);
        }
        else {
            r = n_app_result((n_app){app}, deadline, end);
        }
        if (r >= 0) {
            return WAIT_ENDED;
        }
        if (r != -N_ERR_NOT_READY && r != -N_ERR_TIMEOUT) {
            *error = r;
            return WAIT_FAILED;
        }
        if (woke < 0) {
            return WAIT_INTERRUPTED;
        }
        if (n_clock_monotonic() >= deadline) {
            return WAIT_DEADLINE;
        }
    }
}

/* The handles of a sequence of ints, in a new array: NULL with an exception
   on failure. */
static int32_t *
handle_array(PyObject *seq, uint32_t *count)
{
    PyObject *fast = PySequence_Fast(seq, "handles must be a sequence");
    if (fast == NULL) {
        return NULL;
    }
    Py_ssize_t n = PySequence_Fast_GET_SIZE(fast);
    int32_t *array = PyMem_Malloc(((size_t)n + 1) * sizeof *array);
    if (array == NULL) {
        Py_DECREF(fast);
        PyErr_NoMemory();
        return NULL;
    }
    for (Py_ssize_t i = 0; i < n; i++) {
        int h = PyLong_AsInt(PySequence_Fast_GET_ITEM(fast, i));
        if (h == -1 && PyErr_Occurred()) {
            Py_DECREF(fast);
            PyMem_Free(array);
            return NULL;
        }
        array[i] = h;
    }
    Py_DECREF(fast);
    *count = (uint32_t)n;
    return array;
}

/* _launch(program, arguments, environment, standard, folder, handles=()): the
   app's handle and its identifier (getpid's in the app). environment None is
   this app's (putenv's); standard the descriptors for its input, output and
   log (-1: none); folder None the current one; handles the handles it gets,
   handle i of the app being handles[i] (negative: none). */
static PyObject *
nocturne__launch(PyObject *module, PyObject *args)
{
    path_arg program = PATH_ARG(false, false), folder = PATH_ARG(true, false);
    PyObject *arguments, *environment_object, *handles_object = NULL;
    int standard[3];
    if (!PyArg_ParseTuple(args, "O&OO(iii)O&|O:_launch", path_converter, &program, &arguments, &environment_object,
                          &standard[0], &standard[1], &standard[2], path_converter, &folder, &handles_object)) {
        return NULL;
    }
    PyObject *result = NULL, *keep_arguments = NULL, *keep_environment = NULL;
    const char **argv = NULL, **envp = NULL;
    int32_t *given = NULL;
    uint32_t argc = 0, envc = 0, given_count = 0;
    if (handles_object != NULL) {
        given = handle_array(handles_object, &given_count);
        if (given == NULL) {
            goto done;
        }
    }
    char path[_PY_PATH_MAX], cwd[_PY_PATH_MAX];
    if (path_complete(&program, path) < 0 || path_complete(&folder, cwd) < 0) {
        goto done;
    }
    argv = string_array(arguments, "arguments must be a sequence", &keep_arguments, &argc);
    if (argv == NULL) {
        goto done;
    }
    if (environment_object == Py_None) {
        environment_object = environment_snapshot();
        if (environment_object == NULL) {
            goto done;
        }
        envp = string_array(environment_object, "environment must be a sequence", &keep_environment, &envc);
        Py_DECREF(environment_object);
    }
    else {
        envp = string_array(environment_object, "environment must be a sequence", &keep_environment, &envc);
    }
    if (envp == NULL) {
        goto done;
    }
    n_result app;
    Py_BEGIN_ALLOW_THREADS
    app = launch_app(path, argv, argc, envp, envc, standard, cwd, given, given_count);
    Py_END_ALLOW_THREADS
    if (app < 0) {
        raise_result(app, program.object);
    }
    else {
        uint64_t id = 0;
        n_app_id((n_app){(int32_t)app}, &id);
        result = Py_BuildValue("(iL)", (int)app, (long long)id);
        if (result == NULL) {
            n_handle_close((n_handle){(int32_t)app});
        }
    }
done:
    PyMem_Free(given);
    PyMem_Free(argv);
    PyMem_Free(envp);
    Py_XDECREF(keep_arguments);
    Py_XDECREF(keep_environment);
    path_clear(&program);
    path_clear(&folder);
    return result;
}

/* Python's returncode (subprocess, os.system): 0 for success, the code the
   program ended itself with, or a negated signal number for a program that
   did not. A Nocturne app that did not end itself gets the ISO C signal of
   the condition that ended it (N3220 7.14 paragraph 3): an abort is SIGABRT,
   an erroneous arithmetic operation SIGFPE, an invalid instruction or a call
   from outside the entry image SIGILL, any other fault and a stack run out
   SIGSEGV (an invalid access to storage), a stop SIGTERM (a termination
   request). os.app_end says exactly how it ended. */
static int
returncode_of(const struct n_app_end *end)
{
    switch (end->kind) {
    case N_APP_END_KIND_EXITED:
        return end->exited.code;
    case N_APP_END_KIND_ABORTED:
        return -SIGABRT;
    case N_APP_END_KIND_FAULT:
        /* AMD64 APM Vol. 2, Table 8-1 */
        switch (end->fault.vector) {
        case 0: case 4: case 16: case 19:   /* #DE, #OF, #MF, #XF */
            return -SIGFPE;
        case 1: case 3: case 6: case 7:     /* #DB, #BP, #UD, #NM */
            return -SIGILL;
        default:
            return -SIGSEGV;
        }
    case N_APP_END_KIND_FOREIGN_CALL:
        return -SIGILL;
    case N_APP_END_KIND_RESOURCE:
        return -SIGSEGV;
    default:
        return -SIGTERM;
    }
}

/* ---- app_end ---- */

static PyStructSequence_Field app_end_fields[] = {
    {"kind", "how the app ended: 'exited', 'aborted', 'fault', 'resource', 'foreign_call' or 'stopped'"},
    {"returncode", "subprocess's returncode: the code when it exited, else the negated ISO C signal of its end"},
    {"code", "the code the program ended itself with (exited)"},
    {"thread", "the thread that ended it (aborted, fault, resource, foreign_call)"},
    {"instruction", "the instruction's address (fault, resource, foreign_call), or the abort's caller (aborted)"},
    {"cpu", "the CPU the thread ran on (fault, resource, foreign_call)"},
    {"address", "the address the thread touched (fault: a page fault, resource)"},
    {"vector", "the CPU exception's number (fault)"},
    {"error", "the CPU exception's error code (fault)"},
    {"resource", "the resource the thread ran out of: 'stack' (resource)"},
    {"call", "the number of the call from outside the entry image (foreign_call)"},
    {"reason", "why it was stopped: 'asked', 'session' or 'power' (stopped)"},
    {"stopped_by", "the identifier of the app that stopped it, 0 for the system (stopped)"},
    {"stopped_by_program", "the program of the app that stopped it (stopped)"},
    {"text", "how it ended, in words"},
    {NULL}
};
#define APP_END_FIELDS 15

static PyStructSequence_Desc app_end_desc = {
    "os.app_end",
    "app_end: how an app ended (struct n_app_end of common/abi.h).\n\n"
    "As a tuple: (kind, returncode). The other attributes are None where the\n"
    "kind gives them no value.",
    app_end_fields,
    2
};

static PyObject *
app_end_make(nocturne_state *state, const struct n_app_end *end)
{
    static const char *const kinds[] = {
        [N_APP_END_KIND_EXITED] = "exited", [N_APP_END_KIND_ABORTED] = "aborted", [N_APP_END_KIND_FAULT] = "fault",
        [N_APP_END_KIND_RESOURCE] = "resource", [N_APP_END_KIND_FOREIGN_CALL] = "foreign_call", [N_APP_END_KIND_STOPPED] = "stopped",
    };
    static const char *const reasons[] = {
        [N_APP_STOP_REASON_ASKED] = "asked", [N_APP_STOP_REASON_SESSION] = "session", [N_APP_STOP_REASON_POWER] = "power",
    };
    PyObject *items[APP_END_FIELDS] = {NULL};
    int failed = 0;
#define PUT(i, value) (failed |= (items[i] = (value)) == NULL)
    const struct n_app_place *at = NULL;
    char text[256];
    n_result written = n_app_end_text(end, text, sizeof text);
    size_t length = written < 0 ? 0 : (size_t)written < sizeof text ? (size_t)written : sizeof text;
    PUT(0, PyUnicode_FromString(end->kind < Py_ARRAY_LENGTH(kinds) && kinds[end->kind] ? kinds[end->kind] : "unknown"));
    PUT(1, PyLong_FromLong(returncode_of(end)));
    switch (end->kind) {
    case N_APP_END_KIND_EXITED:
        PUT(2, PyLong_FromLong(end->exited.code));
        break;
    case N_APP_END_KIND_ABORTED:
        PUT(3, PyLong_FromLongLong(end->aborted.thread));
        PUT(4, PyLong_FromUnsignedLongLong(end->aborted.from));
        break;
    case N_APP_END_KIND_FAULT:
        at = &end->fault.at;
        PUT(6, PyLong_FromUnsignedLongLong(end->fault.address));
        PUT(7, PyLong_FromUnsignedLong(end->fault.vector));
        PUT(8, PyLong_FromUnsignedLongLong(end->fault.error));
        break;
    case N_APP_END_KIND_RESOURCE:
        at = &end->resource.at;
        PUT(6, PyLong_FromUnsignedLongLong(end->resource.address));
        if (end->resource.resource == N_APP_RESOURCE_STACK) {
            PUT(9, PyUnicode_FromString("stack"));
        }
        break;
    case N_APP_END_KIND_FOREIGN_CALL:
        at = &end->foreign_call.at;
        PUT(10, PyLong_FromUnsignedLongLong(end->foreign_call.call));
        break;
    case N_APP_END_KIND_STOPPED: {
        const struct n_app_stopped *s = &end->stopped;
        PUT(11, PyUnicode_FromString(s->reason < Py_ARRAY_LENGTH(reasons) && reasons[s->reason] ? reasons[s->reason]
                                                                                              : "unknown"));
        PUT(12, PyLong_FromLongLong(s->by_app));
        PUT(13, PyUnicode_DecodeUTF8(s->by_program, (Py_ssize_t)strnlen(s->by_program, sizeof s->by_program),
                                     "replace"));
        break;
    }
    }
    if (at != NULL) {
        PUT(3, PyLong_FromLongLong(at->thread));
        PUT(4, PyLong_FromUnsignedLongLong(at->address));
        PUT(5, PyLong_FromUnsignedLong(at->cpu));
    }
    PUT(14, PyUnicode_DecodeUTF8(text, (Py_ssize_t)length, "replace"));
#undef PUT
    PyObject *v = failed ? NULL : PyStructSequence_New(state->AppEndType);
    for (int i = 0; i < APP_END_FIELDS; i++) {
        if (v == NULL) {
            Py_XDECREF(items[i]);
        }
        else {
            PyStructSequence_SET_ITEM(v, i, items[i] != NULL ? items[i] : Py_NewRef(Py_None));
        }
    }
    return v;
}

/* _wait(app, timeout=None): how the app ended (os.app_end), or None when
   timeout seconds passed first. Ctrl+C ends the wait with KeyboardInterrupt. */
static PyObject *
nocturne__wait(PyObject *module, PyObject *args)
{
    int app;
    PyObject *timeout = Py_None;
    if (!PyArg_ParseTuple(args, "i|O:_wait", &app, &timeout)) {
        return NULL;
    }
    uint64_t deadline = N_CLOCK_NEVER;
    if (timeout != Py_None) {
        PyTime_t ns;
        if (_PyTime_FromSecondsObject(&ns, timeout, _PyTime_ROUND_TIMEOUT) < 0) {
            return NULL;
        }
        deadline = ns <= 0 ? n_clock_monotonic() : n_clock_after((uint64_t)ns);
    }
    for (;;) {
        struct n_app_end end = {.bytes = sizeof end};
        n_result error = 0;
        enum wait_outcome outcome;
        Py_BEGIN_ALLOW_THREADS
        outcome = wait_app(app, deadline, &end, &error);
        Py_END_ALLOW_THREADS
        switch (outcome) {
        case WAIT_ENDED:
            return app_end_make(get_state(module), &end);
        case WAIT_DEADLINE:
            Py_RETURN_NONE;
        case WAIT_FAILED:
            return raise_result(error, NULL);
        case WAIT_INTERRUPTED:
            if (PyErr_CheckSignals() < 0) {
                return NULL;
            }
            break;
        }
    }
}

/* _stop(app): stops the app and every app it launched. */
static PyObject *
nocturne__stop(PyObject *module, PyObject *arg)
{
    int app;
    if (fd_argument(arg, &app) < 0) {
        return NULL;
    }
    n_result r = n_app_stop((n_app){app}, N_APP_STOP_OPTIONS_TREE);
    return r < 0 ? raise_result(r, NULL) : Py_NewRef(Py_None);
}

static PyObject *
nocturne__handle_close(PyObject *module, PyObject *arg)
{
    int h;
    if (fd_argument(arg, &h) < 0) {
        return NULL;
    }
    n_result r = n_handle_close((n_handle){h});
    return r < 0 ? raise_result(r, NULL) : Py_NewRef(Py_None);
}

/* _app_open(id): a handle of the running app of identifier id, one this app
   may touch (§13): it reports N_EVENT_APP_ENDED when the app ends. */
static PyObject *
nocturne__app_open(PyObject *module, PyObject *arg)
{
    long long id = PyLong_AsLongLong(arg);
    if (id == -1 && PyErr_Occurred()) {
        return NULL;
    }
    n_app app;
    n_result r = n_app_open((uint64_t)id, &app);
    return r < 0 ? raise_result(r, NULL) : PyLong_FromLong(app.handle);
}

/* _fd_adopt(handle, readable, writable): a descriptor for a handle this app
   holds (a channel's end, a TCP connection, a document), which closes the
   handle when its last descriptor closes. */
static PyObject *
nocturne__fd_adopt(PyObject *module, PyObject *args)
{
    int h, readable, writable;
    if (!PyArg_ParseTuple(args, "ipp:_fd_adopt", &h, &readable, &writable)) {
        return NULL;
    }
    int fd = _Py_fd_adopt(h, readable, writable);
    return fd < 0 ? PyErr_SetFromErrno(PyExc_OSError) : PyLong_FromLong(fd);
}

/* _fd_handle(fd): the handle a descriptor speaks for; it stays the
   descriptor's. */
static PyObject *
nocturne__fd_handle(PyObject *module, PyObject *arg)
{
    int fd;
    if (fd_argument(arg, &fd) < 0) {
        return NULL;
    }
    int32_t h = _Py_fd_handle(fd);
    return h < 0 ? PyErr_SetFromErrno(PyExc_OSError) : PyLong_FromLong(h);
}

/* _find_program(name): the complete path of the program a shell runs for
   name (a bare name is looked for in the system's and the apps' folders), or
   None. */
static PyObject *
nocturne__find_program(PyObject *module, PyObject *arg)
{
    path_arg name = PATH_ARG(false, false);
    if (!path_converter(arg, &name)) {
        return NULL;
    }
    char path[_PY_PATH_MAX];
    n_result found;
    Py_BEGIN_ALLOW_THREADS
    found = n_find_program(name.narrow, strlen(name.narrow), path, sizeof path);
    Py_END_ALLOW_THREADS
    bool fits = found >= 0 && (size_t)found <= sizeof path;
    PyObject *result = fits ? path_name(&name, path, (size_t)found) : Py_NewRef(Py_None);
    path_clear(&name);
    return result;
}

/* system(command): runs command with the shell (sh -c), which reads and
   writes this app's standard handles, and returns its result. Ctrl+C stops
   it and what it launched, then raises KeyboardInterrupt. */
static PyObject *
nocturne_system(PyObject *module, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"command", NULL};
    PyObject *command;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&:system", keywords, PyUnicode_FSConverter, &command)) {
        return NULL;
    }
    PyObject *result = NULL, *strings = NULL, *keep = NULL;
    const char **envp = NULL;
    uint32_t envc = 0;
    char sh[_PY_PATH_MAX], folder[_PY_PATH_MAX];
    if (PySys_Audit("os.system", "(O)", command) < 0) {
        goto done;
    }
    n_result found = n_find_program("sh", 2, sh, sizeof sh - 1);
    if (found < 0 || (size_t)found > sizeof sh - 1) {
        errno = ENOENT;
        PyErr_SetFromErrnoWithFilename(PyExc_OSError, "sh");
        goto done;
    }
    sh[found] = '\0';
    if (folder_text(n_folder, folder) < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto done;
    }
    strings = environment_snapshot();
    if (strings == NULL) {
        goto done;
    }
    envp = string_array(strings, "environment", &keep, &envc);
    if (envp == NULL) {
        goto done;
    }
    const char *argv[] = {"sh", "-c", PyBytes_AS_STRING(command), NULL};
    const int standard[3] = {0, 1, 2};
    struct n_app_end end = {.bytes = sizeof end, .kind = N_APP_END_KIND_EXITED};
    n_result error = 0;
    enum wait_outcome outcome = WAIT_FAILED;
    Py_BEGIN_ALLOW_THREADS
    n_result app = launch_app(sh, argv, 3, envp, envc, standard, folder, NULL, 0);
    if (app < 0) {
        error = app;
    }
    else {
        outcome = wait_app((int32_t)app, N_CLOCK_NEVER, &end, &error);
        if (outcome == WAIT_INTERRUPTED) {
            n_app_stop((n_app){(int32_t)app}, N_APP_STOP_OPTIONS_TREE);
            n_app_result((n_app){(int32_t)app}, N_CLOCK_NEVER, &end);
        }
        n_handle_close((n_handle){(int32_t)app});
    }
    Py_END_ALLOW_THREADS
    switch (outcome) {
    case WAIT_ENDED:
    case WAIT_DEADLINE:
        result = PyLong_FromLong(returncode_of(&end));
        break;
    case WAIT_INTERRUPTED:
        if (PyErr_CheckSignals() == 0) {
            result = PyLong_FromLong(returncode_of(&end));
        }
        break;
    case WAIT_FAILED:
        raise_result(error, NULL);
        break;
    }
done:
    PyMem_Free(envp);
    Py_XDECREF(keep);
    Py_XDECREF(strings);
    Py_DECREF(command);
    return result;
}

static PyObject *
nocturne_getpid(PyObject *module, PyObject *Py_UNUSED(ignored))
{
    return PyLong_FromLongLong(n_app_self());
}

static PyObject *
nocturne_getppid(PyObject *module, PyObject *Py_UNUSED(ignored))
{
    uint64_t parent;
    n_result r = n_app_parent(&parent);
    return r < 0 ? raise_result(r, NULL) : PyLong_FromUnsignedLongLong(parent);
}

/* The name of the user this app runs for. */
static PyObject *
nocturne_getlogin(PyObject *module, PyObject *Py_UNUSED(ignored))
{
    struct n_identity self;
    n_result r = n_identity_self(&self);
    if (r < 0) {
        return raise_result(r, NULL);
    }
    /* 数を聞いてから読む。その間に増えれば読み直す */
    struct n_account *accounts = NULL;
    Py_BEGIN_ALLOW_THREADS
    r = n_accounts_list(NULL, 0);
    while (r >= 0) {
        size_t capacity = (size_t)r + 1;
        accounts = PyMem_RawCalloc(capacity, sizeof *accounts);
        if (accounts == NULL) {
            r = -N_ERR_NO_MEMORY;
            break;
        }
        r = n_accounts_list(accounts, capacity);
        if (r >= 0 && (size_t)r <= capacity) {
            break;
        }
        PyMem_RawFree(accounts);
        accounts = NULL;
    }
    Py_END_ALLOW_THREADS
    if (r < 0) {
        return raise_result(r, NULL);
    }
    PyObject *name = NULL;
    for (n_result i = 0; i < r && name == NULL; i++) {
        if (accounts[i].user == self.user) {
            name = PyUnicode_DecodeFSDefault(accounts[i].name);
            if (name == NULL) {
                break;
            }
        }
    }
    PyMem_RawFree(accounts);
    if (name == NULL && !PyErr_Occurred()) {
        raise_result(-N_ERR_NOT_FOUND, NULL);
    }
    return name;
}

/* The folders of the user this app runs for. */
static PyObject *
nocturne__user_folder(PyObject *module, PyObject *Py_UNUSED(ignored))
{
    char folder[_PY_PATH_MAX];
    if (folder_text(n_user_folder, folder) < 0) {
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    return PyUnicode_DecodeFSDefault(folder);
}

static PyObject *
nocturne__temp_folder(PyObject *module, PyObject *Py_UNUSED(ignored))
{
    char folder[_PY_PATH_MAX];
    if (folder_text(n_temp_folder, folder) < 0) {
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    return PyUnicode_DecodeFSDefault(folder);
}

static PyObject *
nocturne_cpu_count(PyObject *module, PyObject *Py_UNUSED(ignored))
{
    struct n_processors info = {.bytes = sizeof info};
    if (n_cpu_info(&info) < 0 || info.scheduler == 0) {
        Py_RETURN_NONE;
    }
    return PyLong_FromUnsignedLong(info.scheduler);
}

static PyObject *
nocturne_urandom(PyObject *module, PyObject *arg)
{
    Py_ssize_t size = PyLong_AsSsize_t(arg);
    if (size == -1 && PyErr_Occurred()) {
        return NULL;
    }
    if (size < 0) {
        return PyErr_Format(PyExc_ValueError, "negative argument not allowed");
    }
    PyBytesWriter *writer = PyBytesWriter_Create(size);
    if (writer == NULL) {
        return NULL;
    }
    if (_PyOS_URandom(PyBytesWriter_GetData(writer), size) < 0) {
        PyBytesWriter_Discard(writer);
        return NULL;
    }
    return PyBytesWriter_Finish(writer);
}

static PyObject *
nocturne_strerror(PyObject *module, PyObject *arg)
{
    int code = PyLong_AsInt(arg);
    if (code == -1 && PyErr_Occurred()) {
        return NULL;
    }
    return _Py_strerror(code);
}

static PyObject *
nocturne__exit(PyObject *module, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"status", NULL};
    int status;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "i:_exit", keywords, &status)) {
        return NULL;
    }
    _Exit(status);
}

/* ---- the module ---- */

#define KEYWORDS(f) _PyCFunction_CAST(f), METH_VARARGS | METH_KEYWORDS

static PyMethodDef nocturne_methods[] = {
    {"fspath", nocturne_fspath, METH_O, "fspath(path)\n--\n\n"
                                        "Return the str or bytes representation of a path-like object."},
    {"stat", KEYWORDS(nocturne_stat), "stat(path, *, dir_fd=None, follow_symlinks=True)\n--\n\n"
                                      "Perform a stat system call on the given path or descriptor."},
    {"lstat", KEYWORDS(nocturne_lstat), "lstat(path, *, dir_fd=None)\n--\n\nThe same as stat: Nocturne has no links."},
    {"fstat", nocturne_fstat, METH_O, "fstat(fd, /)\n--\n\nPerform a stat system call on the given descriptor."},
    {"listdir", KEYWORDS(nocturne_listdir), "listdir(path=None)\n--\n\nReturn a list of the names in the folder."},
    {"scandir", KEYWORDS(nocturne_scandir), "scandir(path=None)\n--\n\n"
                                            "Return an iterator of DirEntry objects for the folder."},
    {"mkdir", KEYWORDS(nocturne_mkdir), "mkdir(path, mode=0o777, *, dir_fd=None)\n--\n\nCreate a folder."},
    {"rmdir", KEYWORDS(nocturne_rmdir), "rmdir(path, *, dir_fd=None)\n--\n\nRemove an empty folder."},
    {"remove", KEYWORDS(nocturne_remove), "remove(path, *, dir_fd=None)\n--\n\nRemove a document."},
    {"unlink", KEYWORDS(nocturne_unlink), "unlink(path, *, dir_fd=None)\n--\n\nRemove a document."},
    {"rename", KEYWORDS(nocturne_rename), "rename(src, dst, *, src_dir_fd=None, dst_dir_fd=None)\n--\n\n"
                                          "Rename an entry. An entry named dst is never replaced."},
    {"replace", KEYWORDS(nocturne_replace), "replace(src, dst, *, src_dir_fd=None, dst_dir_fd=None)\n--\n\n"
                                            "Rename an entry; a document src takes the place of a document dst."},
    {"getcwd", nocturne_getcwd, METH_NOARGS, "getcwd()\n--\n\nReturn the current folder."},
    {"getcwdb", nocturne_getcwdb, METH_NOARGS, "getcwdb()\n--\n\nReturn the current folder as bytes."},
    {"chdir", KEYWORDS(nocturne_chdir), "chdir(path)\n--\n\nChange the current folder."},
    {"access", KEYWORDS(nocturne_access),
     "access(path, mode, *, dir_fd=None, effective_ids=False, follow_symlinks=True)\n--\n\n"
     "Return whether the entry is there. Nocturne decides who may read or write a document when it is opened."},
    {"utime", KEYWORDS(nocturne_utime), "utime(path, times=None, *, ns=<unrepresentable>, dir_fd=None, "
                                        "follow_symlinks=True)\n--\n\n"
                                        "Set the modified time of an entry (C: keeps no other)."},
    {"truncate", KEYWORDS(nocturne_truncate), "truncate(path, length)\n--\n\nTruncate a document to length bytes."},
    {"open", KEYWORDS(nocturne_open), "open(path, flags, mode=0o777, *, dir_fd=None)\n--\n\n"
                                      "Open a document and return a descriptor."},
    {"close", KEYWORDS(nocturne_close), "close(fd)\n--\n\nClose a descriptor."},
    {"closerange", nocturne_closerange, METH_VARARGS, "closerange(fd_low, fd_high, /)\n--\n\n"
                                                      "Close the descriptors from fd_low to fd_high, not included."},
    {"read", nocturne_read, METH_VARARGS, "read(fd, length, /)\n--\n\nRead at most length bytes from a descriptor."},
    {"readinto", nocturne_readinto, METH_VARARGS, "readinto(fd, buffer, /)\n--\n\nRead into a buffer object."},
    {"write", nocturne_write, METH_VARARGS, "write(fd, data, /)\n--\n\nWrite bytes to a descriptor."},
    {"lseek", nocturne_lseek, METH_VARARGS, "lseek(fd, position, whence, /)\n--\n\n"
                                            "Set the position of a descriptor of a document."},
    {"ftruncate", nocturne_ftruncate, METH_VARARGS, "ftruncate(fd, length, /)\n--\n\n"
                                                    "Truncate the document of a descriptor."},
    {"fsync", nocturne_fsync, METH_O, "fsync(fd)\n--\n\nSave a descriptor's document to the medium."},
    {"isatty", nocturne_isatty, METH_O, "isatty(fd, /)\n--\n\nReturn True if the descriptor reaches a terminal."},
    {"dup", nocturne_dup, METH_O, "dup(fd, /)\n--\n\nReturn a second descriptor for the same open file."},
    {"dup2", KEYWORDS(nocturne_dup2), "dup2(fd, fd2, inheritable=True)\n--\n\n"
                                      "Make fd2 name the open file of fd."},
    {"pipe", nocturne_pipe, METH_NOARGS, "pipe()\n--\n\n"
                                         "Return the descriptors of a new channel's ends: (read, write)."},
    {"get_blocking", nocturne_get_blocking, METH_O, "get_blocking(fd, /)\n--\n\n"
                                                    "Get the blocking mode of the descriptor."},
    {"set_blocking", nocturne_set_blocking, METH_VARARGS, "set_blocking(fd, blocking, /)\n--\n\n"
                                                          "Set the blocking mode of the descriptor."},
    {"device_encoding", KEYWORDS(nocturne_device_encoding), "device_encoding(fd)\n--\n\n"
                                                            "Return 'utf-8' for a terminal, None otherwise."},
    {"get_terminal_size", nocturne_get_terminal_size, METH_VARARGS,
     "get_terminal_size(fd=<unrepresentable>, /)\n--\n\nReturn the size of the terminal the descriptor reaches."},
    {"putenv", nocturne_putenv, METH_VARARGS, "putenv(name, value, /)\n--\n\nChange or add an environment variable."},
    {"unsetenv", nocturne_unsetenv, METH_O, "unsetenv(name, /)\n--\n\nDelete an environment variable."},
    {"system", KEYWORDS(nocturne_system), "system(command)\n--\n\nRun the command in the shell and return the shell's returncode."},
    {"getpid", nocturne_getpid, METH_NOARGS, "getpid()\n--\n\nReturn this app's identifier."},
    {"getppid", nocturne_getppid, METH_NOARGS, "getppid()\n--\n\nReturn the identifier of the app that launched this one."},
    {"getlogin", nocturne_getlogin, METH_NOARGS, "getlogin()\n--\n\nReturn the name of the user this app runs for."},
    {"cpu_count", nocturne_cpu_count, METH_NOARGS, "cpu_count()\n--\n\nReturn the number of running CPUs."},
    {"urandom", nocturne_urandom, METH_O, "urandom(size, /)\n--\n\nReturn bytes from the system's entropy."},
    {"strerror", nocturne_strerror, METH_O, "strerror(code, /)\n--\n\nTranslate an error code to a message string."},
    {"_exit", KEYWORDS(nocturne__exit), "_exit(status)\n--\n\nEnd the app at once with the status."},
    {"_launch", nocturne__launch, METH_VARARGS,
     "_launch(program, arguments, environment, standard, folder, handles=(), /)\n--\n\n"
     "Launch an app and return its handle and identifier (Lib/subprocess.py)."},
    {"_wait", nocturne__wait, METH_VARARGS, "_wait(app, timeout=None, /)\n--\n\n"
                                            "Wait for an app's end: how it ended (app_end), or None after timeout seconds."},
    {"_stop", nocturne__stop, METH_O, "_stop(app, /)\n--\n\nStop an app and every app it launched."},
    {"_handle_close", nocturne__handle_close, METH_O, "_handle_close(handle, /)\n--\n\nClose a handle."},
    {"_app_open", nocturne__app_open, METH_O,
     "_app_open(id, /)\n--\n\nA handle of the running app of identifier id."},
    {"_fd_adopt", nocturne__fd_adopt, METH_VARARGS,
     "_fd_adopt(handle, readable, writable, /)\n--\n\nA descriptor that owns a handle this app holds."},
    {"_fd_handle", nocturne__fd_handle, METH_O, "_fd_handle(fd, /)\n--\n\nThe handle a descriptor speaks for."},
    {"_find_program", nocturne__find_program, METH_O,
     "_find_program(name, /)\n--\n\nReturn the path of the program a shell runs for name, or None."},
    {"_user_folder", nocturne__user_folder, METH_NOARGS, "_user_folder()\n--\n\nReturn the user's folder."},
    {"_temp_folder", nocturne__temp_folder, METH_NOARGS, "_temp_folder()\n--\n\nReturn the user's temporary folder."},
    {NULL, NULL}
};

static int
add_int(PyObject *module, const char *name, long value)
{
    return PyModule_AddIntConstant(module, name, value);
}

static int
nocturne_exec(PyObject *module)
{
    nocturne_state *state = get_state(module);
    for (int i = 7; i <= 9; i++) {
        stat_result_fields[i].name = PyStructSequence_UnnamedField;
    }
    state->StatResultType = PyStructSequence_NewType(&stat_result_desc);
    state->TerminalSizeType = PyStructSequence_NewType(&terminal_size_desc);
    state->AppEndType = PyStructSequence_NewType(&app_end_desc);
    state->DirEntryType = (PyTypeObject *)PyType_FromModuleAndSpec(module, &DirEntry_spec, NULL);
    state->ScandirIteratorType = (PyTypeObject *)PyType_FromModuleAndSpec(module, &ScandirIterator_spec, NULL);
    if (state->StatResultType == NULL || state->TerminalSizeType == NULL || state->AppEndType == NULL
        || state->DirEntryType == NULL || state->ScandirIteratorType == NULL) {
        return -1;
    }
    if (PyModule_AddType(module, state->StatResultType) < 0
        || PyModule_AddType(module, state->TerminalSizeType) < 0
        || PyModule_AddType(module, state->AppEndType) < 0
        || PyModule_AddType(module, state->DirEntryType) < 0) {
        return -1;
    }
    if (add_int(module, "O_RDONLY", O_RDONLY) < 0 || add_int(module, "O_WRONLY", O_WRONLY) < 0
        || add_int(module, "O_RDWR", O_RDWR) < 0 || add_int(module, "O_APPEND", O_APPEND) < 0
        || add_int(module, "O_CREAT", O_CREAT) < 0 || add_int(module, "O_TRUNC", O_TRUNC) < 0
        || add_int(module, "O_EXCL", O_EXCL) < 0 || add_int(module, "F_OK", F_OK) < 0
        || add_int(module, "R_OK", R_OK) < 0 || add_int(module, "W_OK", W_OK) < 0
        || add_int(module, "X_OK", X_OK) < 0) {
        return -1;
    }
    if (PyModule_AddObjectRef(module, "error", PyExc_OSError) < 0) {
        return -1;
    }
    if (PyModule_Add(module, "environ", environ_dict()) < 0) {
        return -1;
    }
    /* Lib/os.py's supports_fd: truncate takes a descriptor too. */
    if (PyModule_Add(module, "_have_functions", Py_BuildValue("[s]", "HAVE_FTRUNCATE")) < 0) {
        return -1;
    }
    return 0;
}

static int
nocturne_traverse(PyObject *module, visitproc visit, void *arg)
{
    nocturne_state *state = get_state(module);
    Py_VISIT(state->StatResultType);
    Py_VISIT(state->TerminalSizeType);
    Py_VISIT(state->AppEndType);
    Py_VISIT(state->DirEntryType);
    Py_VISIT(state->ScandirIteratorType);
    return 0;
}

static int
nocturne_clear(PyObject *module)
{
    nocturne_state *state = get_state(module);
    Py_CLEAR(state->StatResultType);
    Py_CLEAR(state->TerminalSizeType);
    Py_CLEAR(state->AppEndType);
    Py_CLEAR(state->DirEntryType);
    Py_CLEAR(state->ScandirIteratorType);
    return 0;
}

static void
nocturne_free(void *module)
{
    nocturne_clear((PyObject *)module);
}

static PyModuleDef_Slot nocturne_slots[] = {
    {Py_mod_exec, nocturne_exec},
    {Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
    {Py_mod_gil, Py_MOD_GIL_NOT_USED},
    {0, NULL}
};

static struct PyModuleDef nocturnemodule = {
    PyModuleDef_HEAD_INIT,
    .m_name = "_nocturne",
    .m_doc = "What Lib/os.py takes from Nocturne: C:, descriptors, apps and the environment.",
    .m_size = sizeof(nocturne_state),
    .m_methods = nocturne_methods,
    .m_slots = nocturne_slots,
    .m_traverse = nocturne_traverse,
    .m_clear = nocturne_clear,
    .m_free = nocturne_free,
};

PyMODINIT_FUNC
PyInit__nocturne(void)
{
    return PyModuleDef_Init(&nocturnemodule);
}
