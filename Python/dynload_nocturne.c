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

/* python.NOS が提供する C の API（見え方が default の定義の全部。エクスポートの一覧は ports/cpython/build.py が作る）。 */
NOS_PROVIDE(_Py_NOCTURNE_API_PROVIDER, PY_MINOR_VERSION, 0, 0);

const char *_PyImport_DynLoadFiletab[] = {
    "." _Py_NOCTURNE_SOABI ".NLIB",
    ".NLIB",
    NULL,
};

/* 結び付けの失敗（struct n_link_failure）の文。 */
static PyObject *
link_failure_text(const char *pathname, n_result r)
{
    struct n_link_failure f;
    if (n_image_failure(&f) < 0) {
        return PyUnicode_FromFormat("%s を読み込めない：%s", pathname, n_result_text(r));
    }
    const char *why;
    switch (f.reason) {
    case N_LINK_PROVIDER:
        why = "要るプロバイダーが無い";
        break;
    case N_LINK_VERSION:
        why = "提供者の版が要求に合わない";
        break;
    case N_LINK_SYMBOL:
        why = "要るシンボルが無い";
        break;
    case N_LINK_CYCLE:
        why = "プロバイダーの依存に輪がある";
        break;
    case N_LINK_SINGLE:
        why = "プロセスに一つのプロバイダーの結び付けが合わない";
        break;
    case N_LINK_REPLACEMENT:
        why = "置き換えの項が置き換えられるエクスポートを指さない";
        break;
    case N_LINK_ABI:
        why = "nocturne.abi を要求できないイメージが要求した";
        break;
    case N_LINK_KIND:
        why = "ライブラリーのイメージでないか、壊れている";
        break;
    case N_LINK_CONFLICT:
        why = "プログラムが提供するプロバイダーを、ほかのイメージも提供する";
        break;
    case N_LINK_RUNTIME:
        why = "プロセスのランタイムを二つ目として読み込もうとした";
        break;
    default:
        why = n_result_text(r);
        break;
    }
    return PyUnicode_FromFormat("%s を読み込めない：%s（%s の要求 %s %u.%u%s%s）", pathname, why, f.image,
                                f.provider, (unsigned)f.major, (unsigned)f.minor, f.symbol[0] ? " の " : "",
                                f.symbol);
}

static int
set_import_error(PyObject *message, const char *shortname, const char *pathname)
{
    if (message == NULL) {
        return -1;
    }
    PyObject *name = PyUnicode_FromString(shortname);
    PyObject *path = name != NULL ? PyUnicode_DecodeFSDefault(pathname) : NULL;
    if (path != NULL) {
        PyErr_SetImportError(message, name, path);
    }
    Py_XDECREF(path);
    Py_XDECREF(name);
    Py_DECREF(message);
    return -1;
}

dl_funcptr
_PyImport_FindSharedFuncptr(const char *prefix, const char *shortname, const char *pathname, FILE *fp)
{
    (void)fp;
    n_handle document = n_document_open(pathname, N_DOCUMENT_READ);
    if (document < 0) {
        set_import_error(PyUnicode_FromFormat("%s を開けない：%s", pathname, n_result_text(document)), shortname,
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
            set_import_error(PyUnicode_FromFormat("%s は拡張モジュールの契約 %s %d.%d を提供しない", pathname,
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
