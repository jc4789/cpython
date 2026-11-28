/* Nocturne の拡張モジュールの宣言（ports/cpython/README.md の「拡張モジュール」）。

   拡張モジュールのイメージは、どれか一つの翻訳単位でこの見出しを取り込む：イメージは、読み込む側
   （Python/dynload_nocturne.c）が名指す契約 _Py_NOCTURNE_EXTENSION_PROVIDER を提供する。モジュールの関数
   （PyModExport_<名> か PyInit_<名>）は、nos-link のエクスポートの一覧（--exports）に
   「python.extension PyInit_<名>」の行で書く。C の API は python.NOS をリンクの入力にして結ぶ。 */
#ifndef Py_NOCTURNE_PYEXTENSION_H
#define Py_NOCTURNE_PYEXTENSION_H

#include "pyconfig.h"
#include <nos.h>

NOS_PROVIDE(_Py_NOCTURNE_EXTENSION_PROVIDER, _Py_NOCTURNE_EXTENSION_MAJOR, _Py_NOCTURNE_EXTENSION_MINOR, 0);

#endif /* Py_NOCTURNE_PYEXTENSION_H */
