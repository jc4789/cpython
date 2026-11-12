/* zlib: Python's zlib module on Nocturne, over the system's DEFLATE codec
   (libc's deflate.h), not over the zlib library (ports/cpython/README.md).

   The formats are RFC 1950 (zlib), 1951 (raw DEFLATE) and 1952 (gzip), which
   wbits chooses as zlib's windowBits does. The codec's own limits show here:
   a decoder takes any window up to 32 KiB whatever wbits says, memLevel only
   tunes zlib's memory and is checked but not used, and Z_PARTIAL_FLUSH,
   Z_BLOCK and Z_TREES flush as Z_SYNC_FLUSH does (all the input goes out, at a
   byte). The module has no ZLIB_VERSION: it is not built on zlib. */
#include "Python.h"
#include "deflate.h"
#include "store/crc32.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* zlib's names and values (zlib.h), which Python code passes. */
#define MAX_WBITS 15
#define DEFLATED 8
#define DEF_MEM_LEVEL 8
#define DEF_BUF_SIZE 16384
#define Z_NO_COMPRESSION 0
#define Z_BEST_SPEED 1
#define Z_BEST_COMPRESSION 9
#define Z_DEFAULT_COMPRESSION (-1)
#define Z_FILTERED 1
#define Z_HUFFMAN_ONLY 2
#define Z_RLE 3
#define Z_FIXED 4
#define Z_DEFAULT_STRATEGY 0
#define Z_NO_FLUSH 0
#define Z_PARTIAL_FLUSH 1
#define Z_SYNC_FLUSH 2
#define Z_FULL_FLUSH 3
#define Z_FINISH 4
#define Z_BLOCK 5
#define Z_TREES 6

typedef struct {
    PyTypeObject *CompressType;
    PyTypeObject *DecompressType;
    PyTypeObject *ZlibDecompressorType;
    PyObject *ZlibError;
} zlib_state;

static inline zlib_state *
get_state(PyObject *module)
{
    return (zlib_state *)PyModule_GetState(module);
}

static struct PyModuleDef zlibmodule;

static zlib_state *
type_state(PyTypeObject *type)
{
    PyObject *module = PyType_GetModuleByDef(type, &zlibmodule);
    return module == NULL ? NULL : get_state(module);
}

/* ---- wbits ---- */

/* What a wbits value asks for: a wrapper, or either wrapper by the data's first
   byte (32 + windowBits when decompressing). */
typedef struct {
    enum deflate_wrap wrap;
    bool either;
    unsigned window_bits;   /* 0: the zlib header says */
} wbits_choice;

/* deflateInit2's windowBits: 8 to 15 zlib (8 is 9), -9 to -15 raw, 16 + 9 to 15 gzip. */
static bool
compress_wbits(int wbits, wbits_choice *out)
{
    out->either = false;
    if (wbits >= 8 && wbits <= 15) {
        *out = (wbits_choice){DEFLATE_ZLIB, false, wbits == 8 ? 9 : (unsigned)wbits};
    }
    else if (wbits <= -9 && wbits >= -15) {
        *out = (wbits_choice){DEFLATE_RAW, false, (unsigned)-wbits};
    }
    else if (wbits >= 25 && wbits <= 31) {
        *out = (wbits_choice){DEFLATE_GZIP, false, (unsigned)wbits - 16};
    }
    else {
        return false;
    }
    return true;
}

/* inflateInit2's windowBits: 0 or 8 to 15 zlib, -8 to -15 raw, 16 + those gzip,
   32 + those either. */
static bool
decompress_wbits(int wbits, wbits_choice *out)
{
    out->either = false;
    if (wbits < 0) {
        if (wbits < -15 || wbits > -8) {
            return false;
        }
        *out = (wbits_choice){DEFLATE_RAW, false, (unsigned)-wbits};
        return true;
    }
    int bits = wbits & 15;
    if ((bits && bits < 8) || wbits > 47) {
        return false;
    }
    if (wbits >= 32) {
        *out = (wbits_choice){DEFLATE_ZLIB, true, (unsigned)bits};
    }
    else if (wbits >= 16) {
        *out = (wbits_choice){DEFLATE_GZIP, false, (unsigned)bits};
    }
    else {
        *out = (wbits_choice){DEFLATE_ZLIB, false, (unsigned)bits};
    }
    return true;
}

/* ---- decompressed bytes ---- */

/* Where inflate's put writes: a growing buffer of at most limit bytes. It runs
   without the GIL, so it uses the raw allocator. */
typedef struct {
    char *bytes;
    size_t len, cap, limit;
    bool no_memory;
} sink;

static size_t
sink_put(void *context, const uint8_t *bytes, size_t n)
{
    sink *s = context;
    size_t room = s->limit - s->len, take = n < room ? n : room;
    if (s->cap - s->len < take) {
        size_t cap = s->cap ? s->cap : DEF_BUF_SIZE;
        while (cap - s->len < take) {
            cap *= 2;
        }
        char *grown = PyMem_RawRealloc(s->bytes, cap);
        if (grown == NULL) {
            s->no_memory = true;
            return 0;
        }
        s->bytes = grown;
        s->cap = cap;
    }
    memcpy(s->bytes + s->len, bytes, take);
    s->len += take;
    return take;
}

static void
sink_start(sink *s, size_t limit)
{
    s->len = 0;
    s->limit = limit;
    s->no_memory = false;
}

/* The bytes the sink took, as a bytes object; the buffer stays for the next call. */
static PyObject *
sink_bytes(sink *s)
{
    if (s->no_memory) {
        return PyErr_NoMemory();
    }
    return PyBytes_FromStringAndSize(s->bytes, (Py_ssize_t)s->len);
}

static void
sink_free(sink *s)
{
    PyMem_RawFree(s->bytes);
    s->bytes = NULL;
    s->len = s->cap = 0;
}

/* ---- a decompressor ---- */

/* An inflate stream behind a Python object. With `either` the wrapper is not
   known until the first byte: 0x1F begins gzip (RFC 1952 2.3.1), anything else
   zlib, and the stream begins then. */
typedef struct {
    struct inflate_stream *stream;
    wbits_choice choice;
    Py_buffer zdict;        /* .obj NULL without one */
    sink out;
} decoder;

static bool
decoder_begin_stream(decoder *d, enum deflate_wrap wrap)
{
    d->stream = inflate_begin(wrap, 0, sink_put, &d->out);
    if (d->stream == NULL) {
        return false;
    }
    if (d->zdict.obj != NULL && wrap != DEFLATE_GZIP &&
        !inflate_dictionary(d->stream, d->zdict.buf, (size_t)d->zdict.len)) {
        inflate_end(d->stream);
        d->stream = NULL;
        return false;
    }
    return true;
}

/* zdict: a bytes-like object, or NULL. Returns -1 with an exception set. */
static int
decoder_init(decoder *d, const wbits_choice *choice, PyObject *zdict)
{
    memset(d, 0, sizeof *d);
    d->choice = *choice;
    if (zdict != NULL) {
        if (PyObject_GetBuffer(zdict, &d->zdict, PyBUF_SIMPLE) < 0) {
            PyErr_SetString(PyExc_TypeError, "zdict argument must support the buffer protocol");
            return -1;
        }
    }
    if (!d->choice.either && !decoder_begin_stream(d, d->choice.wrap)) {
        PyErr_NoMemory();
        return -1;
    }
    return 0;
}

static void
decoder_clear(decoder *d)
{
    inflate_end(d->stream);
    d->stream = NULL;
    if (d->zdict.obj != NULL) {
        PyBuffer_Release(&d->zdict);
    }
    sink_free(&d->out);
}

/* A second decoder that goes on from where d is. -1 with an exception set. */
static int
decoder_copy(decoder *to, const decoder *from)
{
    memset(to, 0, sizeof *to);
    to->choice = from->choice;
    if (from->zdict.obj != NULL && PyObject_GetBuffer(from->zdict.obj, &to->zdict, PyBUF_SIMPLE) < 0) {
        return -1;
    }
    if (from->stream != NULL && (to->stream = inflate_copy(from->stream, sink_put, &to->out)) == NULL) {
        decoder_clear(to);
        PyErr_NoMemory();
        return -1;
    }
    return 0;
}

/* Decompresses data[0..n) into d->out (at most limit bytes); *used is how many
   input bytes the stream took. The GIL is released. */
static enum inflate_result
decoder_feed(decoder *d, const char *data, size_t n, bool last, size_t limit, size_t *used)
{
    sink_start(&d->out, limit);
    *used = 0;
    if (d->stream == NULL) {
        if (!n) {
            return last ? INFLATE_INVALID : INFLATE_MORE;
        }
        if (!decoder_begin_stream(d, (uint8_t)data[0] == 0x1F ? DEFLATE_GZIP : DEFLATE_ZLIB)) {
            d->out.no_memory = true;
            return INFLATE_STOPPED;
        }
    }
    enum inflate_result r;
    Py_BEGIN_ALLOW_THREADS
    r = inflate_feed(d->stream, data, n, last, used);
    Py_END_ALLOW_THREADS
    return r;
}

static PyObject *
data_error(zlib_state *state, const char *while_)
{
    PyErr_Format(state->ZlibError, "Error -3 %s: invalid data for this format", while_);
    return NULL;
}

/* ---- checksums ---- */

static PyObject *
zlib_adler32(PyObject *module, PyObject *args)
{
    Py_buffer data;
    unsigned int value = 1;
    if (!PyArg_ParseTuple(args, "y*|I:adler32", &data, &value)) {
        return NULL;
    }
    uint32_t result;
    Py_BEGIN_ALLOW_THREADS
    result = deflate_adler32(value, data.buf, (size_t)data.len);
    Py_END_ALLOW_THREADS
    PyBuffer_Release(&data);
    return PyLong_FromUnsignedLong(result);
}

static PyObject *
zlib_crc32(PyObject *module, PyObject *args)
{
    Py_buffer data;
    unsigned int value = 0;
    if (!PyArg_ParseTuple(args, "y*|I:crc32", &data, &value)) {
        return NULL;
    }
    uint32_t result;
    Py_BEGIN_ALLOW_THREADS
    result = crc32_ieee(value, data.buf, (size_t)data.len);
    Py_END_ALLOW_THREADS
    PyBuffer_Release(&data);
    return PyLong_FromUnsignedLong(result);
}

/* len2 of the combine functions: a non-negative int. */
static int
combine_length(PyObject *len2, uint64_t *out)
{
    if (!PyLong_Check(len2)) {
        PyErr_Format(PyExc_TypeError, "len2 must be int, not %.200s", Py_TYPE(len2)->tp_name);
        return -1;
    }
    unsigned long long n = PyLong_AsUnsignedLongLong(len2);
    if (n == (unsigned long long)-1 && PyErr_Occurred()) {
        if (PyErr_ExceptionMatches(PyExc_OverflowError) && PyLong_IsNegative(len2) == 1) {
            PyErr_Clear();
            PyErr_SetString(PyExc_ValueError, "len2 must be non-negative");
        }
        return -1;
    }
    *out = n;
    return 0;
}

/* RFC 1950 9: the sums of A followed by B, from A's, B's and B's length. */
static uint32_t
adler32_combine(uint32_t adler1, uint32_t adler2, uint64_t len2)
{
    const uint32_t base = 65521;
    uint32_t rem = (uint32_t)(len2 % base);
    uint32_t sum1 = adler1 & 0xFFFF;
    uint32_t sum2 = (uint32_t)((uint64_t)rem * sum1 % base);
    sum1 += (adler2 & 0xFFFF) + base - 1;
    sum2 += (adler1 >> 16) + (adler2 >> 16) + base - rem;
    sum1 %= base;
    sum2 %= base;
    return sum2 << 16 | sum1;
}

/* CRC-32 over GF(2): a times b modulo the polynomial, bits reflected (RFC 1952 8). */
static uint32_t
crc_multiply(uint32_t a, uint32_t b)
{
    uint32_t product = 0;
    for (uint32_t m = 1u << 31; m; m >>= 1) {
        if (a & m) {
            product ^= b;
        }
        b = b & 1 ? (b >> 1) ^ 0xEDB88320u : b >> 1;
    }
    return product;
}

/* x^(8 * n) modulo the polynomial: CRC-32 of A followed by n bytes of B is A's
   shifted by it, plus B's. */
static uint32_t
crc_shift(uint64_t n)
{
    uint32_t power = 1u << 30;      /* x^1 */
    uint32_t result = 1u << 31;     /* x^0 */
    for (uint64_t bits = n * 8; bits; bits >>= 1) {
        if (bits & 1) {
            result = crc_multiply(power, result);
        }
        power = crc_multiply(power, power);
    }
    return result;
}

static PyObject *
zlib_adler32_combine(PyObject *module, PyObject *args)
{
    unsigned int adler1, adler2;
    PyObject *len2;
    uint64_t n;
    if (!PyArg_ParseTuple(args, "IIO:adler32_combine", &adler1, &adler2, &len2) || combine_length(len2, &n) < 0) {
        return NULL;
    }
    return PyLong_FromUnsignedLong(adler32_combine(adler1, adler2, n));
}

static PyObject *
zlib_crc32_combine(PyObject *module, PyObject *args)
{
    unsigned int crc1, crc2;
    PyObject *len2;
    uint64_t n;
    if (!PyArg_ParseTuple(args, "IIO:crc32_combine", &crc1, &crc2, &len2) || combine_length(len2, &n) < 0) {
        return NULL;
    }
    if (n > UINT64_MAX / 8) {
        PyErr_SetString(PyExc_OverflowError, "len2 is too large");
        return NULL;
    }
    return PyLong_FromUnsignedLong(crc_multiply(crc_shift(n), crc1) ^ crc2);
}

/* ---- compression ---- */

/* The settings of compressobj's arguments; false with an exception set. */
static bool
compress_settings(int level, int method, int wbits, int mem_level, int strategy, struct deflate_settings *out)
{
    wbits_choice choice;
    if (level == Z_DEFAULT_COMPRESSION) {
        level = 6;
    }
    if (level < 0 || level > 9 || method != DEFLATED || !compress_wbits(wbits, &choice) || mem_level < 1 ||
        mem_level > 9 || strategy < Z_DEFAULT_STRATEGY || strategy > Z_FIXED) {
        PyErr_SetString(PyExc_ValueError, "Invalid initialization option");
        return false;
    }
    static const enum deflate_strategy strategies[] = {
        [Z_DEFAULT_STRATEGY] = DEFLATE_DEFAULT, [Z_FILTERED] = DEFLATE_FILTERED,
        [Z_HUFFMAN_ONLY] = DEFLATE_HUFFMAN_ONLY, [Z_RLE] = DEFLATE_RLE, [Z_FIXED] = DEFLATE_FIXED,
    };
    *out = (struct deflate_settings){.level = level, .window_bits = choice.window_bits, .wrap = choice.wrap,
                                     .strategy = strategies[strategy]};
    return true;
}

/* Feeds data to the stream and returns what came out. The GIL is released. */
static PyObject *
deflate_bytes(struct deflate_stream *stream, const void *data, size_t n, enum deflate_flush flush)
{
    struct deflate_out out = {.grow = true};
    int r;
    Py_BEGIN_ALLOW_THREADS
    r = deflate_feed(stream, data, n, flush, &out);
    Py_END_ALLOW_THREADS
    PyObject *result = r < 0 ? PyErr_NoMemory() : PyBytes_FromStringAndSize((const char *)out.p, (Py_ssize_t)out.len);
    free(out.p);
    return result;
}

static PyObject *
zlib_compress(PyObject *module, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"", "level", "wbits", NULL};
    Py_buffer data;
    int level = Z_DEFAULT_COMPRESSION, wbits = MAX_WBITS;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y*|ii:compress", keywords, &data, &level, &wbits)) {
        return NULL;
    }
    zlib_state *state = get_state(module);
    PyObject *result = NULL;
    wbits_choice choice;
    struct deflate_settings settings;
    if (level != Z_DEFAULT_COMPRESSION && (level < 0 || level > 9)) {
        PyErr_SetString(state->ZlibError, "Bad compression level");
    }
    else if (!compress_wbits(wbits, &choice)) {
        PyErr_SetString(state->ZlibError, "Error -2 while compressing data: inconsistent stream state");
    }
    else if (compress_settings(level, DEFLATED, wbits, DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY, &settings)) {
        struct deflate_stream *stream = deflate_begin(&settings);
        if (stream == NULL) {
            PyErr_NoMemory();
        }
        else {
            result = deflate_bytes(stream, data.buf, (size_t)data.len, DEFLATE_FINISH);
            deflate_end(stream);
        }
    }
    PyBuffer_Release(&data);
    return result;
}

typedef struct {
    PyObject_HEAD
    PyMutex mutex;
    struct deflate_stream *stream;  /* NULL after flush(Z_FINISH) */
} compobject;

static PyObject *
zlib_compressobj(PyObject *module, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"level", "method", "wbits", "memLevel", "strategy", "zdict", NULL};
    int level = Z_DEFAULT_COMPRESSION, method = DEFLATED, wbits = MAX_WBITS, mem_level = DEF_MEM_LEVEL;
    int strategy = Z_DEFAULT_STRATEGY;
    PyObject *zdict = NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|iiiiiO:compressobj", keywords, &level, &method, &wbits,
                                     &mem_level, &strategy, &zdict)) {
        return NULL;
    }
    zlib_state *state = get_state(module);
    struct deflate_settings settings;
    if (!compress_settings(level, method, wbits, mem_level, strategy, &settings)) {
        return NULL;
    }
    Py_buffer dictionary = {.obj = NULL};
    if (zdict != NULL && zdict != Py_None) {
        if (PyObject_GetBuffer(zdict, &dictionary, PyBUF_SIMPLE) < 0) {
            return NULL;
        }
        if (settings.wrap == DEFLATE_GZIP) {
            PyBuffer_Release(&dictionary);
            PyErr_SetString(PyExc_ValueError, "Invalid dictionary");
            return NULL;
        }
        settings.dictionary = dictionary.buf;
        settings.dictionary_size = (size_t)dictionary.len;
    }
    compobject *self = PyObject_GC_New(compobject, state->CompressType);
    if (self != NULL) {
        self->mutex = (PyMutex){0};
        self->stream = deflate_begin(&settings);
        if (self->stream == NULL) {
            Py_CLEAR(self);
            PyErr_NoMemory();
        }
        else {
            PyObject_GC_Track(self);
        }
    }
    if (dictionary.obj != NULL) {
        PyBuffer_Release(&dictionary);
    }
    return (PyObject *)self;
}

static void
Compress_dealloc(PyObject *op)
{
    compobject *self = (compobject *)op;
    PyTypeObject *type = Py_TYPE(op);
    PyObject_GC_UnTrack(op);
    deflate_end(self->stream);
    PyObject_GC_Del(op);
    Py_DECREF(type);
}

static int
traverse_type(PyObject *op, visitproc visit, void *arg)
{
    Py_VISIT(Py_TYPE(op));
    return 0;
}

static PyObject *
finished_error(zlib_state *state, const char *while_)
{
    PyErr_Format(state->ZlibError, "Error -2 %s: inconsistent stream state", while_);
    return NULL;
}

static PyObject *
Compress_compress(PyObject *op, PyObject *arg)
{
    compobject *self = (compobject *)op;
    zlib_state *state = type_state(Py_TYPE(op));
    Py_buffer data;
    if (PyObject_GetBuffer(arg, &data, PyBUF_SIMPLE) < 0) {
        return NULL;
    }
    PyMutex_Lock(&self->mutex);
    PyObject *result = self->stream == NULL ? finished_error(state, "while compressing data")
                                            : deflate_bytes(self->stream, data.buf, (size_t)data.len,
                                                            DEFLATE_NO_FLUSH);
    PyMutex_Unlock(&self->mutex);
    PyBuffer_Release(&data);
    return result;
}

static PyObject *
Compress_flush(PyObject *op, PyObject *args)
{
    compobject *self = (compobject *)op;
    zlib_state *state = type_state(Py_TYPE(op));
    int mode = Z_FINISH;
    if (!PyArg_ParseTuple(args, "|i:flush", &mode)) {
        return NULL;
    }
    if (mode == Z_NO_FLUSH) {
        return PyBytes_FromStringAndSize(NULL, 0);
    }
    enum deflate_flush flush;
    switch (mode) {
    case Z_FINISH:
        flush = DEFLATE_FINISH;
        break;
    case Z_FULL_FLUSH:
        flush = DEFLATE_FULL;
        break;
    case Z_SYNC_FLUSH:
    case Z_PARTIAL_FLUSH:
    case Z_BLOCK:
    case Z_TREES:
        flush = DEFLATE_SYNC;
        break;
    default:
        return finished_error(state, "while flushing");
    }
    PyMutex_Lock(&self->mutex);
    PyObject *result = NULL;
    if (self->stream == NULL) {
        finished_error(state, "while flushing");
    }
    else {
        result = deflate_bytes(self->stream, NULL, 0, flush);
        if (flush == DEFLATE_FINISH) {
            deflate_end(self->stream);
            self->stream = NULL;
        }
    }
    PyMutex_Unlock(&self->mutex);
    return result;
}

static PyObject *
Compress_copy(PyObject *op, PyObject *Py_UNUSED(ignored))
{
    compobject *self = (compobject *)op;
    PyMutex_Lock(&self->mutex);
    compobject *copy = NULL;
    if (self->stream == NULL) {
        PyErr_SetString(PyExc_ValueError, "Inconsistent stream state");
    }
    else if ((copy = PyObject_GC_New(compobject, Py_TYPE(op))) != NULL) {
        copy->mutex = (PyMutex){0};
        copy->stream = deflate_copy(self->stream);
        if (copy->stream == NULL) {
            Py_CLEAR(copy);
            PyErr_NoMemory();
        }
        else {
            PyObject_GC_Track(copy);
        }
    }
    PyMutex_Unlock(&self->mutex);
    return (PyObject *)copy;
}

static PyObject *
Compress_deepcopy(PyObject *op, PyObject *memo)
{
    return Compress_copy(op, NULL);
}

static PyMethodDef Compress_methods[] = {
    {"compress", Compress_compress, METH_O,
     "compress($self, data, /)\n--\n\nReturn a bytes object containing compressed data.\n\n"
     "After calling this function, some of the input data may still be stored in internal buffers "
     "for later processing. Call the flush() method to clear these buffers."},
    {"flush", Compress_flush, METH_VARARGS,
     "flush($self, mode=zlib.Z_FINISH, /)\n--\n\nReturn a bytes object containing any remaining compressed data.\n\n"
     "Z_FINISH ends the stream; Z_SYNC_FLUSH and Z_FULL_FLUSH send out everything given so far."},
    {"copy", Compress_copy, METH_NOARGS, "copy($self, /)\n--\n\nReturn a copy of the compression object."},
    {"__copy__", Compress_copy, METH_NOARGS, NULL},
    {"__deepcopy__", Compress_deepcopy, METH_O, NULL},
    {NULL, NULL}
};

static PyType_Slot Compress_slots[] = {
    {Py_tp_dealloc, Compress_dealloc},
    {Py_tp_traverse, traverse_type},
    {Py_tp_methods, Compress_methods},
    {0, 0}
};

static PyType_Spec Compress_spec = {
    .name = "zlib.Compress",
    .basicsize = sizeof(compobject),
    .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_DISALLOW_INSTANTIATION | Py_TPFLAGS_HAVE_GC | Py_TPFLAGS_IMMUTABLETYPE,
    .slots = Compress_slots,
};

/* ---- decompression ---- */

static PyObject *
zlib_decompress(PyObject *module, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"", "wbits", "bufsize", NULL};
    Py_buffer data;
    int wbits = MAX_WBITS;
    Py_ssize_t bufsize = DEF_BUF_SIZE;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y*|in:decompress", keywords, &data, &wbits, &bufsize)) {
        return NULL;
    }
    zlib_state *state = get_state(module);
    PyObject *result = NULL;
    wbits_choice choice;
    decoder d;
    if (bufsize < 0) {
        PyErr_SetString(PyExc_ValueError, "bufsize must be non-negative");
    }
    else if (!decompress_wbits(wbits, &choice)) {
        PyErr_SetString(state->ZlibError, "Error -2 while preparing to decompress data: inconsistent stream state");
    }
    else if (decoder_init(&d, &choice, NULL) == 0) {
        size_t used;
        switch (decoder_feed(&d, data.buf, (size_t)data.len, true, SIZE_MAX, &used)) {
        case INFLATE_END:
            result = sink_bytes(&d.out);
            break;
        case INFLATE_MORE:
        case INFLATE_INVALID:
            /* a cut stream took all of its input; bad data stops where it goes wrong */
            if (used == (size_t)data.len) {
                PyErr_SetString(state->ZlibError,
                                "Error -5 while decompressing data: incomplete or truncated stream");
            }
            else {
                data_error(state, "while decompressing data");
            }
            break;
        case INFLATE_STOPPED:
            PyErr_NoMemory();
            break;
        }
        decoder_clear(&d);
    }
    PyBuffer_Release(&data);
    return result;
}

typedef struct {
    PyObject_HEAD
    PyMutex mutex;
    decoder d;
    PyObject *unused_data;
    PyObject *unconsumed_tail;
    char eof;
} decompobject;

static PyObject *
zlib_decompressobj(PyObject *module, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"wbits", "zdict", NULL};
    int wbits = MAX_WBITS;
    PyObject *zdict = NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|iO:decompressobj", keywords, &wbits, &zdict)) {
        return NULL;
    }
    zlib_state *state = get_state(module);
    wbits_choice choice;
    if (!decompress_wbits(wbits, &choice)) {
        PyErr_SetString(PyExc_ValueError, "Invalid initialization option");
        return NULL;
    }
    if (zdict != NULL && !PyObject_CheckBuffer(zdict)) {
        PyErr_SetString(PyExc_TypeError, "zdict argument must support the buffer protocol");
        return NULL;
    }
    decompobject *self = PyObject_GC_New(decompobject, state->DecompressType);
    if (self == NULL) {
        return NULL;
    }
    self->mutex = (PyMutex){0};
    self->eof = 0;
    self->unused_data = PyBytes_FromStringAndSize(NULL, 0);
    self->unconsumed_tail = Py_NewRef(self->unused_data);
    memset(&self->d, 0, sizeof self->d);
    PyObject_GC_Track(self);
    if (self->unused_data == NULL || decoder_init(&self->d, &choice, zdict) < 0) {
        Py_DECREF(self);
        return NULL;
    }
    return (PyObject *)self;
}

static void
Decompress_dealloc(PyObject *op)
{
    decompobject *self = (decompobject *)op;
    PyTypeObject *type = Py_TYPE(op);
    PyObject_GC_UnTrack(op);
    decoder_clear(&self->d);
    Py_XDECREF(self->unused_data);
    Py_XDECREF(self->unconsumed_tail);
    PyObject_GC_Del(op);
    Py_DECREF(type);
}

/* The bytes after the stream's end join unused_data. */
static int
add_unused(PyObject **unused, const char *bytes, size_t n)
{
    if (!n) {
        return 0;
    }
    Py_ssize_t had = PyBytes_GET_SIZE(*unused);
    PyObject *joined = PyBytes_FromStringAndSize(NULL, had + (Py_ssize_t)n);
    if (joined == NULL) {
        return -1;
    }
    memcpy(PyBytes_AS_STRING(joined), PyBytes_AS_STRING(*unused), (size_t)had);
    memcpy(PyBytes_AS_STRING(joined) + had, bytes, n);
    Py_SETREF(*unused, joined);
    return 0;
}

/* Decompress.decompress and flush: feeds data with an output limit; what the
   stream did not take becomes unconsumed_tail. Called with the mutex held. */
static PyObject *
Decompress_feed(decompobject *self, zlib_state *state, const char *data, size_t n, size_t limit)
{
    if (self->eof) {
        if (add_unused(&self->unused_data, data, n) < 0) {
            return NULL;
        }
        return PyBytes_FromStringAndSize(NULL, 0);
    }
    size_t used;
    enum inflate_result r = decoder_feed(&self->d, data, n, false, limit, &used);
    if (r == INFLATE_INVALID) {
        return data_error(state, "while decompressing data");
    }
    PyObject *result = sink_bytes(&self->d.out);
    if (result == NULL) {
        return NULL;
    }
    PyObject *tail = PyBytes_FromStringAndSize(r == INFLATE_STOPPED ? data + used : NULL,
                                               r == INFLATE_STOPPED ? (Py_ssize_t)(n - used) : 0);
    if (tail == NULL) {
        Py_DECREF(result);
        return NULL;
    }
    Py_SETREF(self->unconsumed_tail, tail);
    if (r == INFLATE_END) {
        self->eof = 1;
        if (add_unused(&self->unused_data, data + used, n - used) < 0) {
            Py_DECREF(result);
            return NULL;
        }
    }
    return result;
}

static PyObject *
Decompress_decompress(PyObject *op, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"", "max_length", NULL};
    decompobject *self = (decompobject *)op;
    Py_buffer data;
    Py_ssize_t max_length = 0;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y*|n:decompress", keywords, &data, &max_length)) {
        return NULL;
    }
    if (max_length < 0) {
        PyBuffer_Release(&data);
        PyErr_SetString(PyExc_ValueError, "max_length must be non-negative");
        return NULL;
    }
    zlib_state *state = type_state(Py_TYPE(op));
    PyMutex_Lock(&self->mutex);
    PyObject *result = Decompress_feed(self, state, data.buf, (size_t)data.len,
                                       max_length ? (size_t)max_length : SIZE_MAX);
    PyMutex_Unlock(&self->mutex);
    PyBuffer_Release(&data);
    return result;
}

static PyObject *
Decompress_flush(PyObject *op, PyObject *args)
{
    decompobject *self = (decompobject *)op;
    Py_ssize_t length = DEF_BUF_SIZE;
    if (!PyArg_ParseTuple(args, "|n:flush", &length)) {
        return NULL;
    }
    if (length <= 0) {
        PyErr_SetString(PyExc_ValueError, "length must be greater than zero");
        return NULL;
    }
    zlib_state *state = type_state(Py_TYPE(op));
    PyMutex_Lock(&self->mutex);
    /* everything the unconsumed tail makes, whatever its size; length only sizes the first buffer */
    PyObject *tail = Py_NewRef(self->unconsumed_tail);
    PyObject *result = Decompress_feed(self, state, PyBytes_AS_STRING(tail), (size_t)PyBytes_GET_SIZE(tail),
                                       SIZE_MAX);
    Py_DECREF(tail);
    PyMutex_Unlock(&self->mutex);
    return result;
}

static PyObject *
Decompress_copy(PyObject *op, PyObject *Py_UNUSED(ignored))
{
    decompobject *self = (decompobject *)op;
    PyMutex_Lock(&self->mutex);
    decompobject *copy = PyObject_GC_New(decompobject, Py_TYPE(op));
    if (copy != NULL) {
        copy->mutex = (PyMutex){0};
        copy->eof = self->eof;
        copy->unused_data = Py_NewRef(self->unused_data);
        copy->unconsumed_tail = Py_NewRef(self->unconsumed_tail);
        memset(&copy->d, 0, sizeof copy->d);
        PyObject_GC_Track(copy);
        if (decoder_copy(&copy->d, &self->d) < 0) {
            Py_CLEAR(copy);
        }
    }
    PyMutex_Unlock(&self->mutex);
    return (PyObject *)copy;
}

static PyObject *
Decompress_deepcopy(PyObject *op, PyObject *memo)
{
    return Decompress_copy(op, NULL);
}

static PyMethodDef Decompress_methods[] = {
    {"decompress", _PyCFunction_CAST(Decompress_decompress), METH_VARARGS | METH_KEYWORDS,
     "decompress($self, data, /, max_length=0)\n--\n\n"
     "Return a bytes object containing the decompressed version of the data.\n\n"
     "With max_length, at most that many bytes come back; the input not taken is in unconsumed_tail."},
    {"flush", Decompress_flush, METH_VARARGS,
     "flush($self, length=zlib.DEF_BUF_SIZE, /)\n--\n\nReturn what the unconsumed input decompresses to."},
    {"copy", Decompress_copy, METH_NOARGS, "copy($self, /)\n--\n\nReturn a copy of the decompression object."},
    {"__copy__", Decompress_copy, METH_NOARGS, NULL},
    {"__deepcopy__", Decompress_deepcopy, METH_O, NULL},
    {NULL, NULL}
};

static PyMemberDef Decompress_members[] = {
    {"unused_data", Py_T_OBJECT_EX, offsetof(decompobject, unused_data), Py_READONLY,
     "The bytes after the end of the compressed data."},
    {"unconsumed_tail", Py_T_OBJECT_EX, offsetof(decompobject, unconsumed_tail), Py_READONLY,
     "The input a limited decompress() did not take."},
    {"eof", Py_T_BOOL, offsetof(decompobject, eof), Py_READONLY, "True once the end of the stream is reached."},
    {NULL}
};

static PyType_Slot Decompress_slots[] = {
    {Py_tp_dealloc, Decompress_dealloc},
    {Py_tp_traverse, traverse_type},
    {Py_tp_methods, Decompress_methods},
    {Py_tp_members, Decompress_members},
    {0, 0}
};

static PyType_Spec Decompress_spec = {
    .name = "zlib.Decompress",
    .basicsize = sizeof(decompobject),
    .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_DISALLOW_INSTANTIATION | Py_TPFLAGS_HAVE_GC | Py_TPFLAGS_IMMUTABLETYPE,
    .slots = Decompress_slots,
};

/* ---- _ZlibDecompressor: the interface of bz2's and lzma's decompressors ---- */

typedef struct {
    PyObject_HEAD
    PyMutex mutex;
    decoder d;
    PyObject *unused_data;
    char *input;            /* input the stream has not taken yet (PyMem_Raw) */
    size_t input_len;
    char eof;
    char needs_input;
} zlibdecompressor;

static PyObject *
ZlibDecompressor_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"wbits", "zdict", NULL};
    int wbits = MAX_WBITS;
    PyObject *zdict = NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|iO:_ZlibDecompressor", keywords, &wbits, &zdict)) {
        return NULL;
    }
    wbits_choice choice;
    if (!decompress_wbits(wbits, &choice)) {
        PyErr_SetString(PyExc_ValueError, "Invalid initialization option");
        return NULL;
    }
    zlibdecompressor *self = PyObject_GC_New(zlibdecompressor, type);
    if (self == NULL) {
        return NULL;
    }
    self->mutex = (PyMutex){0};
    self->eof = 0;
    self->needs_input = 1;
    self->input = NULL;
    self->input_len = 0;
    memset(&self->d, 0, sizeof self->d);
    self->unused_data = PyBytes_FromStringAndSize(NULL, 0);
    PyObject_GC_Track(self);
    if (self->unused_data == NULL || decoder_init(&self->d, &choice, zdict) < 0) {
        Py_DECREF(self);
        return NULL;
    }
    return (PyObject *)self;
}

static void
ZlibDecompressor_dealloc(PyObject *op)
{
    zlibdecompressor *self = (zlibdecompressor *)op;
    PyTypeObject *type = Py_TYPE(op);
    PyObject_GC_UnTrack(op);
    decoder_clear(&self->d);
    PyMem_RawFree(self->input);
    Py_XDECREF(self->unused_data);
    PyObject_GC_Del(op);
    Py_DECREF(type);
}

static PyObject *
ZlibDecompressor_decompress(PyObject *op, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"data", "max_length", NULL};
    zlibdecompressor *self = (zlibdecompressor *)op;
    Py_buffer data;
    Py_ssize_t max_length = -1;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y*|n:decompress", keywords, &data, &max_length)) {
        return NULL;
    }
    zlib_state *state = type_state(Py_TYPE(op));
    PyObject *result = NULL;
    PyMutex_Lock(&self->mutex);
    if (self->eof) {
        PyErr_SetString(PyExc_EOFError, "End of stream already reached");
        goto done;
    }
    /* the input held from before, then data */
    const char *in = data.buf;
    size_t n = (size_t)data.len;
    if (self->input_len) {
        char *joined = PyMem_RawRealloc(self->input, self->input_len + n ? self->input_len + n : 1);
        if (joined == NULL) {
            PyErr_NoMemory();
            goto done;
        }
        memcpy(joined + self->input_len, data.buf, n);
        self->input = joined;
        in = joined;
        n += self->input_len;
    }
    size_t used;
    enum inflate_result r = decoder_feed(&self->d, in, n, false, max_length < 0 ? SIZE_MAX : (size_t)max_length,
                                         &used);
    if (r == INFLATE_INVALID) {
        data_error(state, "while decompressing data");
        goto done;
    }
    if ((result = sink_bytes(&self->d.out)) == NULL) {
        goto done;
    }
    if (r == INFLATE_END) {
        self->eof = 1;
        self->needs_input = 0;
        PyObject *unused = PyBytes_FromStringAndSize(in + used, (Py_ssize_t)(n - used));
        if (unused == NULL) {
            Py_CLEAR(result);
            goto done;
        }
        Py_SETREF(self->unused_data, unused);
        self->input_len = 0;
    }
    else {
        /* STOPPED: more output waits, even with nothing held */
        self->needs_input = r == INFLATE_MORE;
        size_t rest = r == INFLATE_STOPPED ? n - used : 0;
        if (rest && in != self->input) {
            char *held = PyMem_RawRealloc(self->input, rest);
            if (held == NULL) {
                Py_CLEAR(result);
                PyErr_NoMemory();
                goto done;
            }
            memcpy(held, in + used, rest);
            self->input = held;
        }
        else if (rest) {
            memmove(self->input, self->input + used, rest);
        }
        self->input_len = rest;
    }
done:
    PyMutex_Unlock(&self->mutex);
    PyBuffer_Release(&data);
    return result;
}

static PyMethodDef ZlibDecompressor_methods[] = {
    {"decompress", _PyCFunction_CAST(ZlibDecompressor_decompress), METH_VARARGS | METH_KEYWORDS,
     "decompress($self, /, data, max_length=-1)\n--\n\n"
     "Decompress *data*, returning uncompressed data as bytes.\n\n"
     "If *max_length* is nonnegative, returns at most *max_length* bytes of decompressed data. If this limit "
     "is reached and further output can be produced, *self.needs_input* will be set to ``False``. In this "
     "case, the next call to *decompress()* may provide *data* as b'' to obtain more of the output.\n\n"
     "Attempting to decompress data after the end of stream is reached raises an EOFError. Any data found "
     "after the end of the stream is ignored and saved in the unused_data attribute."},
    {NULL, NULL}
};

static PyMemberDef ZlibDecompressor_members[] = {
    {"eof", Py_T_BOOL, offsetof(zlibdecompressor, eof), Py_READONLY, "True if the end-of-stream marker has been reached."},
    {"unused_data", Py_T_OBJECT_EX, offsetof(zlibdecompressor, unused_data), Py_READONLY,
     "Data found after the end of the compressed stream."},
    {"needs_input", Py_T_BOOL, offsetof(zlibdecompressor, needs_input), Py_READONLY,
     "True if more input is needed before more decompressed data can be produced."},
    {NULL}
};

static PyType_Slot ZlibDecompressor_slots[] = {
    {Py_tp_new, ZlibDecompressor_new},
    {Py_tp_dealloc, ZlibDecompressor_dealloc},
    {Py_tp_traverse, traverse_type},
    {Py_tp_methods, ZlibDecompressor_methods},
    {Py_tp_members, ZlibDecompressor_members},
    {Py_tp_doc, (void *)"_ZlibDecompressor(wbits=15, zdict=b'')\n--\n\n"
                        "Create a decompressor object for decompressing data incrementally."},
    {0, 0}
};

static PyType_Spec ZlibDecompressor_spec = {
    .name = "zlib._ZlibDecompressor",
    .basicsize = sizeof(zlibdecompressor),
    .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC | Py_TPFLAGS_IMMUTABLETYPE,
    .slots = ZlibDecompressor_slots,
};

/* ---- the module ---- */

#define KEYWORDS(f) _PyCFunction_CAST(f), METH_VARARGS | METH_KEYWORDS

static PyMethodDef zlib_methods[] = {
    {"adler32", zlib_adler32, METH_VARARGS,
     "adler32($module, data, value=1, /)\n--\n\nCompute an Adler-32 checksum of data."},
    {"crc32", zlib_crc32, METH_VARARGS, "crc32($module, data, value=0, /)\n--\n\nCompute a CRC-32 checksum of data."},
    {"adler32_combine", zlib_adler32_combine, METH_VARARGS,
     "adler32_combine($module, adler1, adler2, len2, /)\n--\n\nCombine two Adler-32 checksums into one."},
    {"crc32_combine", zlib_crc32_combine, METH_VARARGS,
     "crc32_combine($module, crc1, crc2, len2, /)\n--\n\nCombine two CRC-32 checksums into one."},
    {"compress", KEYWORDS(zlib_compress),
     "compress($module, data, /, level=Z_DEFAULT_COMPRESSION, wbits=MAX_WBITS)\n--\n\n"
     "Returns a bytes object containing compressed data."},
    {"compressobj", KEYWORDS(zlib_compressobj),
     "compressobj($module, /, level=Z_DEFAULT_COMPRESSION, method=DEFLATED, wbits=MAX_WBITS, "
     "memLevel=DEF_MEM_LEVEL, strategy=Z_DEFAULT_STRATEGY, zdict=None)\n--\n\n"
     "Return a compressor object."},
    {"decompress", KEYWORDS(zlib_decompress),
     "decompress($module, data, /, wbits=MAX_WBITS, bufsize=DEF_BUF_SIZE)\n--\n\n"
     "Returns a bytes object containing the uncompressed data."},
    {"decompressobj", KEYWORDS(zlib_decompressobj),
     "decompressobj($module, /, wbits=MAX_WBITS, zdict=b'')\n--\n\nReturn a decompressor object."},
    {NULL, NULL}
};

static int
zlib_exec(PyObject *module)
{
    zlib_state *state = get_state(module);
    state->CompressType = (PyTypeObject *)PyType_FromModuleAndSpec(module, &Compress_spec, NULL);
    state->DecompressType = (PyTypeObject *)PyType_FromModuleAndSpec(module, &Decompress_spec, NULL);
    state->ZlibDecompressorType = (PyTypeObject *)PyType_FromModuleAndSpec(module, &ZlibDecompressor_spec, NULL);
    state->ZlibError = PyErr_NewException("zlib.error", NULL, NULL);
    if (state->CompressType == NULL || state->DecompressType == NULL || state->ZlibDecompressorType == NULL ||
        state->ZlibError == NULL) {
        return -1;
    }
    if (PyModule_AddObjectRef(module, "error", state->ZlibError) < 0 ||
        PyModule_AddObjectRef(module, "_ZlibDecompressor", (PyObject *)state->ZlibDecompressorType) < 0) {
        return -1;
    }
    static const struct {
        const char *name;
        int value;
    } constants[] = {
        {"MAX_WBITS", MAX_WBITS}, {"DEFLATED", DEFLATED}, {"DEF_MEM_LEVEL", DEF_MEM_LEVEL},
        {"DEF_BUF_SIZE", DEF_BUF_SIZE}, {"Z_NO_COMPRESSION", Z_NO_COMPRESSION}, {"Z_BEST_SPEED", Z_BEST_SPEED},
        {"Z_BEST_COMPRESSION", Z_BEST_COMPRESSION}, {"Z_DEFAULT_COMPRESSION", Z_DEFAULT_COMPRESSION},
        {"Z_FILTERED", Z_FILTERED}, {"Z_HUFFMAN_ONLY", Z_HUFFMAN_ONLY}, {"Z_RLE", Z_RLE}, {"Z_FIXED", Z_FIXED},
        {"Z_DEFAULT_STRATEGY", Z_DEFAULT_STRATEGY}, {"Z_NO_FLUSH", Z_NO_FLUSH}, {"Z_PARTIAL_FLUSH", Z_PARTIAL_FLUSH},
        {"Z_SYNC_FLUSH", Z_SYNC_FLUSH}, {"Z_FULL_FLUSH", Z_FULL_FLUSH}, {"Z_FINISH", Z_FINISH},
        {"Z_BLOCK", Z_BLOCK}, {"Z_TREES", Z_TREES},
    };
    for (size_t i = 0; i < sizeof constants / sizeof constants[0]; i++) {
        if (PyModule_AddIntConstant(module, constants[i].name, constants[i].value) < 0) {
            return -1;
        }
    }
    return 0;
}

static int
zlib_traverse(PyObject *module, visitproc visit, void *arg)
{
    zlib_state *state = get_state(module);
    Py_VISIT(state->CompressType);
    Py_VISIT(state->DecompressType);
    Py_VISIT(state->ZlibDecompressorType);
    Py_VISIT(state->ZlibError);
    return 0;
}

static int
zlib_clear(PyObject *module)
{
    zlib_state *state = get_state(module);
    Py_CLEAR(state->CompressType);
    Py_CLEAR(state->DecompressType);
    Py_CLEAR(state->ZlibDecompressorType);
    Py_CLEAR(state->ZlibError);
    return 0;
}

static void
zlib_free(void *module)
{
    zlib_clear((PyObject *)module);
}

static PyModuleDef_Slot zlib_slots[] = {
    {Py_mod_exec, zlib_exec},
    {Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
    {Py_mod_gil, Py_MOD_GIL_NOT_USED},
    {0, NULL}
};

static struct PyModuleDef zlibmodule = {
    PyModuleDef_HEAD_INIT,
    .m_name = "zlib",
    .m_doc = "The functions in this module allow compression and decompression using the DEFLATE formats: "
             "zlib (RFC 1950), raw DEFLATE (RFC 1951) and gzip (RFC 1952), with the system's own codec.\n\n"
             "adler32(string[, start]) -- Compute an Adler-32 checksum.\n"
             "compress(data[, level]) -- Compress data, with compression level 0-9 or -1.\n"
             "compressobj([level[, ...]]) -- Return a compressor object.\n"
             "crc32(string[, start]) -- Compute a CRC-32 checksum.\n"
             "decompress(string,[wbits],[bufsize]) -- Decompresses a compressed string.\n"
             "decompressobj([wbits[, zdict]]) -- Return a decompressor object.\n",
    .m_size = sizeof(zlib_state),
    .m_methods = zlib_methods,
    .m_slots = zlib_slots,
    .m_traverse = zlib_traverse,
    .m_clear = zlib_clear,
    .m_free = zlib_free,
};

PyMODINIT_FUNC
PyInit_zlib(void)
{
    return PyModuleDef_Init(&zlibmodule);
}
