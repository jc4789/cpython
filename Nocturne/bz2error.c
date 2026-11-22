/* What a program that builds libbzip2 without stdio gives it (the bzip2
   manual, 3.8): bz_internal_error, which the library calls when one of its
   own checks fails (errcode is the AssertH number, 1001 to 1007). The library
   cannot go on, so neither can python: it stops with the number. */
#include "Python.h"
#include "pycore_pyerrors.h"
#include "bzlib_private.h"

void bz_internal_error(int errcode)
{
    _Py_FatalErrorFormat(__func__, "libbzip2 internal error %d (bzip2 %s)", errcode, BZ2_bzlibVersion());
}
