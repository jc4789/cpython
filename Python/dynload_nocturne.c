/* Nocturne の拡張モジュール（ports/cpython/README.md、Nocturne の docs/records/nos-20261127/sekkei.md の 2.8 と 2.10）。

   拡張モジュールは .NLIB のライブラリーで、中核のライブラリーの実装の読み込み（n_image_load）で読む。読み込む側が
   名指す契約は、拡張モジュールが提供するプロバイダー _Py_NOCTURNE_EXTENSION_PROVIDER の major と minor
   （Nocturne/pyconfig.h）で、モジュールの関数（PyModExport_<名>、PyInit_<名>）はそのプロバイダーのエクスポートから
   引く。拡張モジュールが使う C の API は、python.NOS が提供するプロバイダー _Py_NOCTURNE_API_PROVIDER の
   major PY_MINOR_VERSION で、カーネルが読み込みの時に結ぶ。だから別の 3.x の版で組んだ拡張モジュールは、結べない
   まま読み込みが失敗する。拡張モジュールの要求はプロセスの表で結ぶ。読み込んだイメージはプロセスの終わりまで
   外れない。 */

#include "Python.h"
#include "pycore_importdl.h"

#include <nos.h>
#include <nocturne.h>
#include <nocturne_language.h>

/* python.NOS が提供する C の API（見え方が default の定義の全部。エクスポートの一覧は ports/cpython/build.py が作る）。 */
NOS_PROVIDE(_Py_NOCTURNE_API_PROVIDER, PY_MINOR_VERSION, 0, 0);

const char *_PyImport_DynLoadFiletab[] = {
    "." _Py_NOCTURNE_SOABI ".NLIB",
    ".NLIB",
    NULL,
};

/* 書式から作る文（PyUnicode_FromFormat の書式は ASCII だけなので、UTF-8 の文は C の書式で作る）。パスのバイトが
   UTF-8 でなければ surrogateescape で持つ。 */
static PyObject *
message(const char *format, ...)
{
    char text[1024];
    va_list arguments;
    va_start(arguments, format);
    PyOS_vsnprintf(text, sizeof(text), format, arguments);
    va_end(arguments);
    return PyUnicode_DecodeUTF8(text, (Py_ssize_t)strlen(text), "surrogateescape");
}

/* 読み込みの失敗の文：結び付けの失敗なら中核のライブラリーの文（n_locale_link_failure）、ほかは結果の文。 */
static PyObject *
link_failure_text(const char *pathname, n_result r)
{
    struct n_link_failure f;
    if (n_image_failure(&f) < 0) {
        return message("%s を読み込めない：%s", pathname, n_result_text(r));
    }
    char why[640];
    n_locale_link_failure(why, sizeof(why), &f);
    return message("%s を読み込めない：%s", pathname, why);
}

static int
set_import_error(PyObject *text, const char *shortname, const char *pathname)
{
    if (text == NULL) {
        return -1;
    }
    PyObject *name = PyUnicode_FromString(shortname);
    PyObject *path = name != NULL ? PyUnicode_DecodeFSDefault(pathname) : NULL;
    if (path != NULL) {
        PyErr_SetImportError(text, name, path);
    }
    Py_XDECREF(path);
    Py_XDECREF(name);
    Py_DECREF(text);
    return -1;
}

dl_funcptr
_PyImport_FindSharedFuncptr(const char *prefix, const char *shortname, const char *pathname, FILE *fp)
{
    (void)fp;
    n_handle document = n_document_open(pathname, N_DOCUMENT_READ);
    if (document < 0) {
        set_import_error(message("%s を開けない：%s", pathname, n_result_text(document)), shortname,
                         pathname);
        return NULL;
    }
    const struct n_image *image;
    n_result r;
    Py_BEGIN_ALLOW_THREADS
    /* 同じ文書をもう一度読み込めば（PyModExport の次に PyInit を引く時）、同じイメージが返る */
    r = n_image_load(document, -1, _Py_NOCTURNE_EXTENSION_PROVIDER, _Py_NOCTURNE_EXTENSION_MAJOR,
                     _Py_NOCTURNE_EXTENSION_MINOR, &image);
    Py_END_ALLOW_THREADS
    n_handle_close(document);
    if (r < 0) {
        if (r == -N_ERR_WRONG_GENERATION) {
            set_import_error(message("%s は拡張モジュールの契約 %s %d.%d を提供しない", pathname,
                                                  _Py_NOCTURNE_EXTENSION_PROVIDER, _Py_NOCTURNE_EXTENSION_MAJOR,
                                                  _Py_NOCTURNE_EXTENSION_MINOR),
                             shortname, pathname);
        }
        else {
            set_import_error(link_failure_text(pathname, r), shortname, pathname);
        }
        return NULL;
    }
    char funcname[258];
    PyOS_snprintf(funcname, sizeof(funcname), "%.20s_%.200s", prefix, shortname);
    return (dl_funcptr)n_image_symbol(image, _Py_NOCTURNE_EXTENSION_PROVIDER, funcname);
}
