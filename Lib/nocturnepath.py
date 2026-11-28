# Module 'nocturnepath' -- common operations on Nocturne pathnames
"""Common pathname manipulations, Nocturne version.

Instead of importing this module directly, import os and refer to this
module as os.path.

A complete path names an entry of C: from its root: 'C:\\Users\\a' or
'\\Users\\a', with '/' working as '\\'. 'C:' and 'C:a' are in the current
folder, as 'a' is: C: is the one drive. Names compare without regard to case,
and there are no links (docs/nocturne-native-abi.md §3).
"""

# strings representing various path-related bits and pieces
# These are primarily for export; internally, they are hardcoded.
# Should be set before imports for resolving cyclic dependency.
curdir = '.'
pardir = '..'
extsep = '.'
sep = '\\'
pathsep = ';'
altsep = '/'
# システムのプログラムのフォルダー。shutil.which は、シェルと同じくアプリのフォルダーも探す。
defpath = 'C:\\Nocturne\\System'

import os
import sys
import genericpath
from genericpath import *

__all__ = ["normcase","isabs","join","splitdrive","splitroot","split","splitext",
           "basename","dirname","commonprefix","getsize","getmtime",
           "getatime","getctime", "islink","exists","lexists","isdir","isfile",
           "ismount","expanduser","expandvars","normpath",
           "abspath","curdir","pardir","sep","pathsep","defpath","altsep",
           "extsep","realpath","supports_unicode_filenames","relpath",
           "samefile", "sameopenfile", "samestat", "commonpath", "isjunction",
           "isdevdrive", "ALL_BUT_LAST", "ALLOW_MISSING"]

def _get_bothseps(path):
    if isinstance(path, bytes):
        return b'\\/'
    else:
        return '\\/'


def normcase(s, /):
    """Normalize case of pathname.

    Makes all characters lowercase and all slashes into backslashes, as C:
    compares names.
    """
    s = os.fspath(s)
    if isinstance(s, bytes):
        return os.fsencode(os.fsdecode(s).replace('/', '\\').lower())
    return s.replace('/', '\\').lower()


def isabs(s, /):
    """Test whether a path is complete: whether it has a root."""
    return bool(splitroot(s)[1])


def splitroot(p, /):
    """Split a pathname into drive, root and tail.

    The drive is a letter and a colon, the root one separator, and the tail
    anything after them. Either part may be empty."""
    p = os.fspath(p)
    if isinstance(p, bytes):
        seps = b'\\/'
        colon = b':'
        empty = b''
        letter = p[:1].isalpha() and p[:1].isascii()
    else:
        seps = '\\/'
        colon = ':'
        empty = ''
        letter = p[:1].isascii() and p[:1].isalpha()
    drive = p[:2] if letter and p[1:2] == colon else empty
    rest = p[len(drive):]
    if rest[:1] and rest[:1] in seps:
        return drive, rest[:1], rest[1:]
    return drive, empty, rest


def splitdrive(p, /):
    """Split a pathname into drive and path specifiers.
    Returns a 2-tuple (drive, path); either part may be empty.

    It is always true that:
        result[0] + result[1] == p
    """
    drive, root, tail = splitroot(p)
    return drive, root + tail


# Join two (or more) paths. A part with a root starts again; a drive without a
# root ('C:a') is in the folder the parts before it name, as C: is the one
# drive.
def join(path, /, *paths):
    path = os.fspath(path)
    if isinstance(path, bytes):
        sep = b'\\'
        seps = b'\\/'
    else:
        sep = '\\'
        seps = '\\/'
    try:
        result_drive, result_root, result_path = splitroot(path)
        for p in paths:
            p_drive, p_root, p_path = splitroot(p)
            if p_root:
                result_drive = p_drive or result_drive
                result_root = p_root
                result_path = p_path
                continue
            if not result_drive:
                result_drive = p_drive
            if result_path and result_path[-1:] not in seps:
                result_path = result_path + sep
            result_path = result_path + p_path
        return result_drive + result_root + result_path
    except (TypeError, AttributeError, BytesWarning):
        genericpath._check_arg_types('join', path, *paths)
        raise


# Split a path in head (everything up to the last separator) and tail (the
# rest). The resulting head won't end in a separator unless it is the root.

def split(p, /):
    """Split a pathname.

    Return tuple (head, tail) where tail is everything after the final
    slash.  Either part may be empty."""
    p = os.fspath(p)
    seps = _get_bothseps(p)
    d, r, p = splitroot(p)
    # set i to index beyond p's last slash
    i = len(p)
    while i and p[i-1] not in seps:
        i -= 1
    head, tail = p[:i], p[i:]  # now tail has no slashes
    return d + r + head.rstrip(seps), tail


def splitext(p, /):
    p = os.fspath(p)
    if isinstance(p, bytes):
        return genericpath._splitext(p, b'\\', b'/', b'.')
    else:
        return genericpath._splitext(p, '\\', '/', '.')
splitext.__doc__ = genericpath._splitext.__doc__


def basename(p, /):
    """Returns the final component of a pathname"""
    return split(p)[1]


def dirname(p, /):
    """Returns the directory component of a pathname"""
    return split(p)[0]


def ismount(path):
    """Test whether a path is a mount point: the root of C:."""
    drive, root, rest = splitroot(abspath(path))
    return bool(root) and not rest


def expanduser(path):
    """Expand ~ to the folder of the user this app runs for.

    ~user, and a path without ~, are returned unchanged."""
    path = os.fspath(path)
    if isinstance(path, bytes):
        seps = b'\\/'
        tilde = b'~'
    else:
        seps = '\\/'
        tilde = '~'
    if not path.startswith(tilde) or (path[1:2] and path[1:2] not in seps):
        return path
    from _nocturne import _user_folder
    userhome = _user_folder()
    if isinstance(path, bytes):
        userhome = os.fsencode(userhome)
    return userhome.rstrip(seps) + path[1:]


# Expand paths containing shell variable substitutions: $var and ${var}.
_varpattern = r'\$(\w+|\{[^}]*\}?)'
_varsub = None
_varsubb = None

def expandvars(path):
    """Expand shell variables of form $var and ${var}.  Unknown variables
    are left unchanged."""
    path = os.fspath(path)
    global _varsub, _varsubb
    if isinstance(path, bytes):
        if b'$' not in path:
            return path
        if not _varsubb:
            import re
            _varsubb = re.compile(_varpattern.encode(), re.ASCII).sub
        sub = _varsubb
        start = b'{'
        end = b'}'
        environ = os.environb
    else:
        if '$' not in path:
            return path
        if not _varsub:
            import re
            _varsub = re.compile(_varpattern, re.ASCII).sub
        sub = _varsub
        start = '{'
        end = '}'
        environ = os.environ

    def repl(m):
        name = m[1]
        if name.startswith(start):
            if not name.endswith(end):
                return m[0]
            name = name[1:-1]
        try:
            return environ[name]
        except KeyError:
            return m[0]

    return sub(repl, path)


# Normalize a path, e.g. A//B, A/./B and A/foo/../B all become A\B.
def normpath(path):
    """Normalize path, eliminating double slashes, etc."""
    path = os.fspath(path)
    if isinstance(path, bytes):
        sep = b'\\'
        altsep = b'/'
        curdir = b'.'
        pardir = b'..'
    else:
        sep = '\\'
        altsep = '/'
        curdir = '.'
        pardir = '..'
    path = path.replace(altsep, sep)
    drive, root, path = splitroot(path)
    prefix = drive + root
    comps = path.split(sep)
    i = 0
    while i < len(comps):
        if not comps[i] or comps[i] == curdir:
            del comps[i]
        elif comps[i] == pardir:
            if i > 0 and comps[i-1] != pardir:
                del comps[i-1:i+1]
                i -= 1
            elif i == 0 and root:
                del comps[i]
            else:
                i += 1
        else:
            i += 1
    # If the path is now empty, substitute '.'
    if not prefix and not comps:
        comps.append(curdir)
    return prefix + sep.join(comps)


def abspath(path):
    """Return the complete version of a path, with the drive."""
    path = os.fspath(path)
    cwd = os.getcwdb() if isinstance(path, bytes) else os.getcwd()
    if not isabs(path):
        path = join(cwd, splitroot(path)[2])
    elif not splitroot(path)[0]:
        path = splitroot(cwd)[0] + path
    return normpath(path)


def realpath(path, /, *, strict=False):
    """Return the complete version of a path: Nocturne has no links.

    strict raises OSError when the entry is not there; ALL_BUT_LAST lets the
    last name be missing, and ALLOW_MISSING any of them."""
    path = abspath(path)
    if strict is ALLOW_MISSING or not strict:
        return path
    if strict is ALL_BUT_LAST and not lexists(path):
        head = dirname(path)
        if not isdir(head):
            os.stat(head)
            import errno
            raise NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), head)
        return path
    os.stat(path)
    return path


supports_unicode_filenames = True

def relpath(path, start=None):
    """Return a relative version of a path"""
    path = os.fspath(path)
    if not path:
        raise ValueError("no path specified")

    if isinstance(path, bytes):
        sep = b'\\'
        curdir = b'.'
        pardir = b'..'
    else:
        sep = '\\'
        curdir = '.'
        pardir = '..'

    if start is None:
        start = curdir
    else:
        start = os.fspath(start)

    try:
        start_abs = abspath(start)
        path_abs = abspath(path)
        start_drive, _, start_rest = splitroot(start_abs)
        path_drive, _, path_rest = splitroot(path_abs)
        if normcase(start_drive) != normcase(path_drive):
            raise ValueError("path is on mount %r, start on mount %r" % (
                path_drive, start_drive))

        start_list = start_rest.split(sep) if start_rest else []
        path_list = path_rest.split(sep) if path_rest else []
        # Work out how much of the filepath is shared by start and path.
        i = 0
        for e1, e2 in zip(start_list, path_list):
            if normcase(e1) != normcase(e2):
                break
            i += 1

        rel_list = [pardir] * (len(start_list)-i) + path_list[i:]
        if not rel_list:
            return curdir
        return sep.join(rel_list)
    except (TypeError, ValueError, AttributeError, BytesWarning, DeprecationWarning):
        genericpath._check_arg_types('relpath', path, start)
        raise


# Return the longest common sub-path of the iterable of paths given as input.
# The function is case-insensitive and 'separator-insensitive', as C: is: the
# returned path has the '\' separator and the case of the first path given,
# and no trailing separator.

def commonpath(paths):
    """Given an iterable of path names, returns the longest common sub-path."""
    paths = tuple(map(os.fspath, paths))
    if not paths:
        raise ValueError('commonpath() arg is an empty iterable')

    if isinstance(paths[0], bytes):
        sep = b'\\'
        altsep = b'/'
        curdir = b'.'
    else:
        sep = '\\'
        altsep = '/'
        curdir = '.'

    try:
        drivesplits = [splitroot(p.replace(altsep, sep).lower()) for p in paths]
        split_paths = [p.split(sep) for d, r, p in drivesplits]

        # Check that all drives match. The check is made only now otherwise
        # type errors for mixing strings and bytes would not be caught.
        if len({d for d, r, p in drivesplits}) != 1:
            raise ValueError("Paths don't have the same drive")

        drive, root, path = splitroot(paths[0].replace(altsep, sep))
        if len({r for d, r, p in drivesplits}) != 1:
            if drive:
                raise ValueError("Can't mix absolute and relative paths")
            else:
                raise ValueError("Can't mix rooted and not-rooted paths")

        common = path.split(sep)
        common = [c for c in common if c and c != curdir]

        split_paths = [[c for c in s if c and c != curdir] for s in split_paths]
        s1 = min(split_paths)
        s2 = max(split_paths)
        for i, c in enumerate(s1):
            if c != s2[i]:
                common = common[:i]
                break
        else:
            common = common[:len(s1)]

        return drive + root + sep.join(common)
    except (TypeError, AttributeError):
        genericpath._check_arg_types('commonpath', *paths)
        raise
