/* _ssl：Nocturne の Python の TLS。lib/http の TLS（net_stream.h）の上に書き、OpenSSL は使わない
   （ports/cpython/README.md）。

   client は net_stream の client（TLS 1.3 と 1.2。鍵交換は X25519MLKEM768 を先に申し出る）、server は net_stream の
   server（TLS 1.3 だけ。TLS_AES_256_GCM_SHA384、X25519MLKEM768、P-256・P-384・P-521 の ECDSA の身元）。

   握手と読み書きは net_stream の待たない口（ns_handshake の 0、ns_try_read、ns_try_write、ns_try_close）で進め、
   待つのはこの module：socket の timeout まで、GIL を放して socket の handle を待つ（_PyOS_NocturneWait。主の
   スレッドの待ちは Ctrl+C で終わり、SIGINT の処理が例外を上げなければ続く：PEP 475）。だから待たない socket は
   SSLWantReadError と SSLWantWriteError を上げ、MemoryBIO の流れは運び手の無い byte の受け渡しになる。
   一つの流れの net_stream の呼出しは、流れの錠（mtx）で一つずつにする。錠は GIL を放してから取る。

   信頼の根は、set_default_verify_paths がシステムの証明書の folder（KABI_FOLDER_CERTIFICATES）、load_verify_locations
   が呼ぶ側の証明書。

   無いもの：client の証明書（load_cert_chain は server の身元だけ。server は CertificateRequest を送らない）、
   session の再開（SSLSession）、cipher の選び（set_ciphers）、CRL、鍵の記録（keylog_filename）、message の
   callback、post-handshake の認証、NPN、PSK、channel binding、鎖の取り出し、OpenSSL の版の数。
   OPENSSL_VERSION は TLS の library の名（OpenSSL でない library はそこに自分の名を書く）。 */
#include "Python.h"
#include "pycore_modsupport.h"    // _PyArg_NoKeywords()
#include "pycore_signal.h"        // _PyOS_NocturneWait()
#include "pycore_time.h"          // _PyTime_FromSecondsObject()
#include "descriptors.h"          // _Py_fd_handle()
#include "net_stream.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <threads.h>

/* ssl.py が名で読む数。値は Python の ssl の約束（PROTOCOL_*、SSL_ERROR_*、CERT_*）と TLS の版の番号。 */
#define PROTOCOL_TLS 2
#define PROTOCOL_TLS_CLIENT 0x10
#define PROTOCOL_TLS_SERVER 0x11
#define CERT_NONE 0
#define CERT_OPTIONAL 1
#define CERT_REQUIRED 2
#define PROTO_MINIMUM_SUPPORTED (-2)
#define PROTO_MAXIMUM_SUPPORTED (-1)
#define PROTO_SSLv3 0x0300
#define PROTO_TLSv1 0x0301
#define PROTO_TLSv1_1 0x0302
#define PROTO_TLSv1_2 0x0303
#define PROTO_TLSv1_3 0x0304
#define SSL_ERROR_SSL 1
#define SSL_ERROR_WANT_READ 2
#define SSL_ERROR_WANT_WRITE 3
#define SSL_ERROR_SYSCALL 5
#define SSL_ERROR_ZERO_RETURN 6
#define SSL_ERROR_EOF 8

/* options の旗。OP_NO_TLSv1_2、OP_NO_TLSv1_3、OP_IGNORE_UNEXPECTED_EOF のほかは、この TLS がいつもそうする形で、
   外せない（options はいつもそれを含む）。 */
#define OP_ALL 0L
#define OP_NO_SSLv2 0L
#define OP_SINGLE_DH_USE 0L
#define OP_SINGLE_ECDH_USE 0L
#define OP_IGNORE_UNEXPECTED_EOF (1L << 7)
#define OP_NO_TICKET (1L << 14)
#define OP_NO_COMPRESSION (1L << 17)
#define OP_ENABLE_MIDDLEBOX_COMPAT (1L << 20)
#define OP_CIPHER_SERVER_PREFERENCE (1L << 22)
#define OP_NO_SSLv3 (1L << 25)
#define OP_NO_TLSv1 (1L << 26)
#define OP_NO_TLSv1_2 (1L << 27)
#define OP_NO_TLSv1_1 (1L << 28)
#define OP_NO_TLSv1_3 (1L << 29)
#define OP_NO_RENEGOTIATION (1L << 30)
#define OPTIONS_ALWAYS (OP_NO_TICKET | OP_NO_COMPRESSION | OP_ENABLE_MIDDLEBOX_COMPAT | OP_CIPHER_SERVER_PREFERENCE | \
                        OP_NO_SSLv3 | OP_NO_TLSv1 | OP_NO_TLSv1_1 | OP_NO_RENEGOTIATION)
#define OPTIONS_KNOWN (OPTIONS_ALWAYS | OP_IGNORE_UNEXPECTED_EOF | OP_NO_TLSv1_2 | OP_NO_TLSv1_3)
/* verify_flags の旗：検証（br_x509_minimal）がいつもそうする形。信頼の根で鎖を終え（部分の鎖）、根を先に見て、
   証明書を厳しく読む。 */
#define VERIFY_DEFAULT 0L
#define VERIFY_X509_STRICT 0x20L
#define VERIFY_X509_TRUSTED_FIRST 0x8000L
#define VERIFY_X509_PARTIAL_CHAIN 0x80000L
#define VERIFY_ALWAYS (VERIFY_X509_STRICT | VERIFY_X509_TRUSTED_FIRST | VERIFY_X509_PARTIAL_CHAIN)

#define IDENTITY_CAPSULE "_ssl.identity"

typedef struct {
    PyTypeObject *context_type, *socket_type, *bio_type, *python_socket_type;
    PyObject *error, *zero_return_error, *want_read_error, *want_write_error, *syscall_error, *eof_error;
    PyObject *cert_verification_error;
} ssl_state;

static struct PyModuleDef sslmodule;

static inline ssl_state *
get_state(PyObject *module)
{
    return (ssl_state *)PyModule_GetState(module);
}

static ssl_state *
type_state(PyTypeObject *type)
{
    PyObject *module = PyType_GetModuleByDef(type, &sslmodule);
    return module == NULL ? NULL : get_state(module);
}

typedef struct {
    PyObject_HEAD
    int protocol;
    int verify_mode;
    bool check_hostname;
    long options, verify_flags;
    int minimum_version, maximum_version;
    PyObject *alpn;               /* bytes：ProtocolNameList の中身、NULL は無し */
    PyObject *identity;           /* server の身元（IDENTITY_CAPSULE の capsule）、NULL は無し */
    PyObject *sni_callback;
    bool system_anchors;          /* set_default_verify_paths */
    PyObject *anchors;            /* list of bytes：load_verify_locations の証明書（DER） */
    PyObject *anchor_document;    /* bytes：anchors の PEM の文書（net_stream に渡す）、NULL は作り直す */
} context_object;

typedef struct {
    PyObject_HEAD
    unsigned char *buf;
    size_t start, len, cap;       /* [start, len) がまだ読まれていない */
    bool eof_written;
} bio_object;

typedef struct {
    PyObject_HEAD
    context_object *ctx;
    PyObject *sock_ref;           /* socket の流れ：Python の socket への weakref。MemoryBIO の流れは NULL */
    PyObject *owner_ref;          /* SSLSocket か SSLObject への weakref、NULL は無し */
    bio_object *incoming, *outgoing;
    PyObject *identity_in_use;    /* server：net_stream が使う身元の capsule */
    net_stream *ns;               /* shutdown の後は NULL */
    n_handle handle;              /* socket の流れ：今の呼出しの TCP の handle */
    bool server_side, handshake_done, verified, no_anchors;
    PyObject *server_hostname;    /* str か None */
    mtx_t lock;                   /* net_stream の呼出しを一つずつに（GIL を放してから取る） */
    PyThreadState *running;       /* 錠の中の呼出しの thread state（server_name の callback が GIL を取り戻す） */
} socket_object;

/* ---- 誤り ---- */

static PyObject *
sslerror_str(PyObject *self)
{
    PyOSErrorObject *e = (PyOSErrorObject *)self;
    if (e->strerror != NULL && PyUnicode_Check(e->strerror)) {
        return Py_NewRef(e->strerror);
    }
    return PyObject_Str(e->args);
}

static PyType_Slot sslerror_slots[] = {
    {Py_tp_str, sslerror_str},
    {Py_tp_doc, (void *)"An error occurred in the TLS implementation."},
    {0, NULL}
};

static PyType_Spec sslerror_spec = {
    .name = "ssl.SSLError",
    .basicsize = sizeof(PyOSErrorObject),
    .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_IMMUTABLETYPE,
    .slots = sslerror_slots,
};

/* type(code, "[reason] text")、reason と library の属性つき。 */
static void
raise_ssl(PyObject *type, int code, const char *reason, const char *text)
{
    PyObject *message = reason ? PyUnicode_FromFormat("[%s] %s", reason, text) : PyUnicode_FromString(text);
    if (message == NULL) {
        return;
    }
    PyObject *exc = PyObject_CallFunction(type, "iN", code, message);
    if (exc == NULL) {
        return;
    }
    PyObject *r = reason ? PyUnicode_FromString(reason) : Py_NewRef(Py_None);
    if (r == NULL || PyObject_SetAttrString(exc, "reason", r) < 0 ||
        PyObject_SetAttrString(exc, "library", Py_None) < 0) {
        Py_XDECREF(r);
        Py_DECREF(exc);
        return;
    }
    Py_DECREF(r);
    PyErr_SetObject((PyObject *)Py_TYPE(exc), exc);
    Py_DECREF(exc);
}

static void
raise_certificate(ssl_state *state, const char *text)
{
    raise_ssl(state->cert_verification_error, SSL_ERROR_SSL, "CERTIFICATE_VERIFY_FAILED", text);
    PyObject *exc = PyErr_GetRaisedException();
    PyObject *message = PyUnicode_FromString(text);
    if (exc != NULL && message != NULL) {
        (void)PyObject_SetAttrString(exc, "verify_message", message);
        (void)PyObject_SetAttrString(exc, "verify_code", Py_None);
    }
    Py_XDECREF(message);
    PyErr_SetRaisedException(exc);
}

/* ---- DER（X.690）と証明書（RFC 5280）の読み ---- */

struct der { const unsigned char *p; size_t n; };

/* 次の TLV。証明書に出ない形（高い tag の番号、定まらない長さ）は読めない。 */
static bool
der_take(struct der *d, unsigned *tag, struct der *value)
{
    if (d->n < 2 || (d->p[0] & 0x1f) == 0x1f) {
        return false;
    }
    size_t len = d->p[1], at = 2;
    if (len & 0x80) {
        size_t k = len & 0x7f;
        if (k == 0 || k > 4 || d->n < 2 + k) {
            return false;
        }
        len = 0;
        for (size_t i = 0; i < k; i++) {
            len = len << 8 | d->p[2 + i];
        }
        at = 2 + k;
    }
    if (d->n - at < len) {
        return false;
    }
    *tag = d->p[0];
    *value = (struct der){d->p + at, len};
    d->p += at + len;
    d->n -= at + len;
    return true;
}

static bool
der_expect(struct der *d, unsigned want, struct der *value)
{
    unsigned tag;
    return der_take(d, &tag, value) && tag == want;
}

/* 一つの証明書の DER（外の SEQUENCE が丁度）。 */
static bool
der_certificate(const unsigned char *p, size_t n)
{
    struct der d = {p, n}, cert;
    return der_expect(&d, 0x30, &cert) && d.n == 0;
}

/* OID の点の書き方。 */
static bool
oid_dotted(struct der oid, char *out, size_t cap)
{
    size_t at = 0;
    unsigned long long v = 0;
    bool first = true;
    if (oid.n == 0) {
        return false;
    }
    for (size_t i = 0; i < oid.n; i++) {
        if (v >> 57) {
            return false;
        }
        v = v << 7 | (oid.p[i] & 0x7f);
        if (oid.p[i] & 0x80) {
            continue;
        }
        int w;
        if (first) {
            unsigned long long a = v < 40 ? 0 : v < 80 ? 1 : 2;
            w = snprintf(out + at, cap - at, "%llu.%llu", a, v - 40 * a);
            first = false;
        }
        else {
            w = snprintf(out + at, cap - at, ".%llu", v);
        }
        if (w < 0 || (size_t)w >= cap - at) {
            return false;
        }
        at += (size_t)w;
        v = 0;
    }
    return (oid.p[oid.n - 1] & 0x80) == 0;
}

/* 名の表（txt2obj、nid2obj、getpeercert の名の属性）。nid は表の番目 + 1。 */
static const struct oid_name {
    const char *oid, *short_name, *long_name;
} oid_names[] = {
    {"1.3.6.1.5.5.7.3.1", "serverAuth", "TLS Web Server Authentication"},
    {"1.3.6.1.5.5.7.3.2", "clientAuth", "TLS Web Client Authentication"},
    {"2.5.4.3", "CN", "commonName"},
    {"2.5.4.4", "SN", "surname"},
    {"2.5.4.5", "serialNumber", "serialNumber"},
    {"2.5.4.6", "C", "countryName"},
    {"2.5.4.7", "L", "localityName"},
    {"2.5.4.8", "ST", "stateOrProvinceName"},
    {"2.5.4.9", "street", "streetAddress"},
    {"2.5.4.10", "O", "organizationName"},
    {"2.5.4.11", "OU", "organizationalUnitName"},
    {"2.5.4.12", "title", "title"},
    {"2.5.4.15", "businessCategory", "businessCategory"},
    {"2.5.4.17", "postalCode", "postalCode"},
    {"2.5.4.42", "GN", "givenName"},
    {"2.5.4.43", "initials", "initials"},
    {"2.5.4.46", "dnQualifier", "dnQualifier"},
    {"2.5.4.65", "pseudonym", "pseudonym"},
    {"2.5.4.97", "organizationIdentifier", "organizationIdentifier"},
    {"1.2.840.113549.1.9.1", "emailAddress", "emailAddress"},
    {"0.9.2342.19200300.100.1.1", "UID", "userId"},
    {"0.9.2342.19200300.100.1.25", "DC", "domainComponent"},
    {"1.3.6.1.4.1.311.60.2.1.1", "jurisdictionL", "jurisdictionLocalityName"},
    {"1.3.6.1.4.1.311.60.2.1.2", "jurisdictionST", "jurisdictionStateOrProvinceName"},
    {"1.3.6.1.4.1.311.60.2.1.3", "jurisdictionC", "jurisdictionCountryName"},
};
#define OID_NAME_COUNT (sizeof oid_names / sizeof *oid_names)

static const struct oid_name *
oid_lookup(const char *dotted)
{
    for (size_t i = 0; i < OID_NAME_COUNT; i++) {
        if (!strcmp(oid_names[i].oid, dotted)) {
            return &oid_names[i];
        }
    }
    return NULL;
}

/* 属性の値の文字列（X.520 の DirectoryString と IA5String など）。 */
static PyObject *
der_string(unsigned tag, struct der v)
{
    int order = 1;
    switch (tag) {
    case 0x0c: return PyUnicode_DecodeUTF8((const char *)v.p, (Py_ssize_t)v.n, "replace");
    case 0x1e: return PyUnicode_DecodeUTF16((const char *)v.p, (Py_ssize_t)v.n, "replace", &order);
    case 0x1c: return PyUnicode_DecodeUTF32((const char *)v.p, (Py_ssize_t)v.n, "replace", &order);
    default: return PyUnicode_DecodeLatin1((const char *)v.p, (Py_ssize_t)v.n, NULL);
    }
}

/* Name（RFC 5280 §4.1.2.4）：RDN の tuple、RDN は (名, 値) の tuple。 */
static PyObject *
name_tuple(struct der name)
{
    PyObject *rdns = PyList_New(0);
    if (rdns == NULL) {
        return NULL;
    }
    while (name.n) {
        struct der set, atv;
        if (!der_expect(&name, 0x31, &set)) {
            goto bad;
        }
        PyObject *pairs = PyList_New(0);
        if (pairs == NULL) {
            goto fail;
        }
        while (set.n) {
            struct der type, value;
            unsigned value_tag;
            char dotted[128];
            if (!der_expect(&set, 0x30, &atv) || !der_expect(&atv, 0x06, &type) ||
                !der_take(&atv, &value_tag, &value) || !oid_dotted(type, dotted, sizeof dotted)) {
                Py_DECREF(pairs);
                goto bad;
            }
            const struct oid_name *known = oid_lookup(dotted);
            PyObject *pair = Py_BuildValue("(sN)", known ? known->long_name : dotted, der_string(value_tag, value));
            if (pair == NULL || PyList_Append(pairs, pair) < 0) {
                Py_XDECREF(pair);
                Py_DECREF(pairs);
                goto fail;
            }
            Py_DECREF(pair);
        }
        PyObject *rdn = PyList_AsTuple(pairs);
        Py_DECREF(pairs);
        if (rdn == NULL || PyList_Append(rdns, rdn) < 0) {
            Py_XDECREF(rdn);
            goto fail;
        }
        Py_DECREF(rdn);
    }
    PyObject *out = PyList_AsTuple(rdns);
    Py_DECREF(rdns);
    return out;
bad:
    PyErr_SetString(PyExc_ValueError, "malformed certificate name");
fail:
    Py_DECREF(rdns);
    return NULL;
}

/* Time（RFC 5280 §4.1.2.5）を "Mon DD HH:MM:SS YYYY GMT" に。 */
static PyObject *
der_time(unsigned tag, struct der v)
{
    static const char *const months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    size_t year_digits = tag == 0x17 ? 2 : tag == 0x18 ? 4 : 0;
    if (!year_digits || v.n != year_digits + 11 || v.p[v.n - 1] != 'Z') {
        PyErr_SetString(PyExc_ValueError, "malformed certificate time");
        return NULL;
    }
    int digits[14];
    for (size_t i = 0; i < year_digits + 10; i++) {
        if (v.p[i] < '0' || v.p[i] > '9') {
            PyErr_SetString(PyExc_ValueError, "malformed certificate time");
            return NULL;
        }
        digits[i] = v.p[i] - '0';
    }
    int year = 0;
    for (size_t i = 0; i < year_digits; i++) {
        year = year * 10 + digits[i];
    }
    if (year_digits == 2) {
        year += year >= 50 ? 1900 : 2000;   /* §4.1.2.5.1 */
    }
    const int *d = digits + year_digits;
    int month = d[0] * 10 + d[1];
    if (month < 1 || month > 12) {
        PyErr_SetString(PyExc_ValueError, "malformed certificate time");
        return NULL;
    }
    char text[32];
    snprintf(text, sizeof text, "%s %2d %d%d:%d%d:%d%d %d GMT", months[month - 1], d[2] * 10 + d[3],
             d[4], d[5], d[6], d[7], d[8], d[9], year);
    return PyUnicode_FromString(text);
}

static PyObject *
ip_text(struct der v)
{
    char text[48];
    if (v.n == 4) {
        snprintf(text, sizeof text, "%u.%u.%u.%u", v.p[0], v.p[1], v.p[2], v.p[3]);
    }
    else if (v.n == 16) {
        size_t at = 0;
        for (int i = 0; i < 8; i++) {
            at += (size_t)snprintf(text + at, sizeof text - at, i ? ":%X" : "%X", (unsigned)(v.p[2 * i] << 8 | v.p[2 * i + 1]));
        }
    }
    else {
        return PyUnicode_FromString("<invalid>");
    }
    return PyUnicode_FromString(text);
}

/* GeneralNames（§4.2.1.6）を (種類, 値) の list へ。 */
static int
general_names(struct der names, PyObject *list)
{
    while (names.n) {
        unsigned tag;
        struct der v;
        if (!der_take(&names, &tag, &v)) {
            PyErr_SetString(PyExc_ValueError, "malformed GeneralNames");
            return -1;
        }
        PyObject *item = NULL;
        char dotted[128];
        struct der inner;
        switch (tag) {
        case 0x81: item = Py_BuildValue("(sN)", "email", der_string(0x16, v)); break;
        case 0x82: item = Py_BuildValue("(sN)", "DNS", der_string(0x16, v)); break;
        case 0x86: item = Py_BuildValue("(sN)", "URI", der_string(0x16, v)); break;
        case 0x87: item = Py_BuildValue("(sN)", "IP Address", ip_text(v)); break;
        case 0x88:
            item = oid_dotted(v, dotted, sizeof dotted) ? Py_BuildValue("(ss)", "Registered ID", dotted)
                                                        : Py_BuildValue("(ss)", "Registered ID", "<invalid>");
            break;
        case 0xa4:
            if (!der_expect(&v, 0x30, &inner)) {
                PyErr_SetString(PyExc_ValueError, "malformed directoryName");
                return -1;
            }
            item = Py_BuildValue("(sN)", "DirName", name_tuple(inner));
            break;
        case 0xa0: item = Py_BuildValue("(ss)", "othername", "<unsupported>"); break;
        case 0xa3: item = Py_BuildValue("(ss)", "X400Name", "<unsupported>"); break;
        case 0xa5: item = Py_BuildValue("(ss)", "EdiPartyName", "<unsupported>"); break;
        default: continue;
        }
        if (item == NULL || PyList_Append(list, item) < 0) {
            Py_XDECREF(item);
            return -1;
        }
        Py_DECREF(item);
    }
    return 0;
}

static int
dict_set_tuple(PyObject *dict, const char *key, PyObject *list)
{
    if (PyList_GET_SIZE(list) == 0) {
        return 0;
    }
    PyObject *t = PyList_AsTuple(list);
    int r = t == NULL ? -1 : PyDict_SetItemString(dict, key, t);
    Py_XDECREF(t);
    return r;
}

/* 拡張の中の場所の URI：AuthorityInfoAccess（§4.2.2.1）の OCSP と caIssuers、CRLDistributionPoints（§4.2.1.13）。 */
static int
access_locations(struct der value, PyObject *ocsp, PyObject *issuers)
{
    struct der seq, ad, method, location = {0};
    unsigned tag;
    if (!der_expect(&value, 0x30, &seq)) {
        return 0;
    }
    while (seq.n) {
        char dotted[64];
        if (!der_expect(&seq, 0x30, &ad) || !der_expect(&ad, 0x06, &method) || !der_take(&ad, &tag, &location) ||
            !oid_dotted(method, dotted, sizeof dotted)) {
            return 0;
        }
        PyObject *list = !strcmp(dotted, "1.3.6.1.5.5.7.48.1") ? ocsp : !strcmp(dotted, "1.3.6.1.5.5.7.48.2") ? issuers : NULL;
        if (list == NULL || tag != 0x86) {
            continue;
        }
        PyObject *uri = der_string(0x16, location);
        if (uri == NULL || PyList_Append(list, uri) < 0) {
            Py_XDECREF(uri);
            return -1;
        }
        Py_DECREF(uri);
    }
    return 0;
}

static int
crl_points(struct der value, PyObject *points)
{
    struct der seq, dp, name, full;
    if (!der_expect(&value, 0x30, &seq)) {
        return 0;
    }
    while (seq.n) {
        if (!der_expect(&seq, 0x30, &dp)) {
            return 0;
        }
        if (!dp.n || dp.p[0] != 0xa0 || !der_expect(&dp, 0xa0, &name) || !name.n || name.p[0] != 0xa0 ||
            !der_expect(&name, 0xa0, &full)) {
            continue;
        }
        while (full.n) {
            unsigned tag;
            struct der v;
            if (!der_take(&full, &tag, &v)) {
                return 0;
            }
            if (tag != 0x86) {
                continue;
            }
            PyObject *uri = der_string(0x16, v);
            if (uri == NULL || PyList_Append(points, uri) < 0) {
                Py_XDECREF(uri);
                return -1;
            }
            Py_DECREF(uri);
        }
    }
    return 0;
}

/* BasicConstraints（§4.2.1.9）の cA。 */
static bool
basic_constraints_ca(struct der value)
{
    struct der seq, flag;
    return der_expect(&value, 0x30, &seq) && seq.n && seq.p[0] == 0x01 && der_expect(&seq, 0x01, &flag) &&
           flag.n == 1 && flag.p[0] != 0;
}

/* 証明書の dict（ssl の getpeercert の形）。is_ca は BasicConstraints の cA。 */
static PyObject *
certificate_dict(const unsigned char *der, size_t len, bool *is_ca)
{
    struct der all = {der, len}, cert, tbs, v, issuer, validity, subject, before, after;
    unsigned tag, before_tag, after_tag;
    long version = 1;
    *is_ca = false;
    if (!der_expect(&all, 0x30, &cert) || !der_expect(&cert, 0x30, &tbs)) {
        goto bad;
    }
    if (tbs.n && tbs.p[0] == 0xa0) {
        struct der explicit_version, number;
        if (!der_expect(&tbs, 0xa0, &explicit_version) || !der_expect(&explicit_version, 0x02, &number) ||
            number.n != 1) {
            goto bad;
        }
        version = number.p[0] + 1;
    }
    struct der serial;
    if (!der_expect(&tbs, 0x02, &serial) || !der_expect(&tbs, 0x30, &v) || !der_expect(&tbs, 0x30, &issuer) ||
        !der_expect(&tbs, 0x30, &validity) || !der_take(&validity, &before_tag, &before) ||
        !der_take(&validity, &after_tag, &after) || !der_expect(&tbs, 0x30, &subject) || !der_expect(&tbs, 0x30, &v)) {
        goto bad;
    }
    while (serial.n > 1 && serial.p[0] == 0) {
        serial.p++;
        serial.n--;
    }
    char serial_text[2 * 20 + 1];
    if (serial.n > 20) {
        goto bad;
    }
    for (size_t i = 0; i < serial.n; i++) {
        snprintf(serial_text + 2 * i, 3, "%02X", serial.p[i]);
    }
    serial_text[2 * serial.n] = 0;
    PyObject *dict = Py_BuildValue("{sNsNsisssNsN}", "subject", name_tuple(subject), "issuer", name_tuple(issuer),
                                   "version", (int)version, "serialNumber", serial_text,
                                   "notBefore", der_time(before_tag, before), "notAfter", der_time(after_tag, after));
    if (dict == NULL) {
        return NULL;
    }
    PyObject *san = PyList_New(0), *ocsp = PyList_New(0), *issuers = PyList_New(0), *crls = PyList_New(0);
    if (san == NULL || ocsp == NULL || issuers == NULL || crls == NULL) {
        goto fail;
    }
    while (tbs.n) {
        if (!der_take(&tbs, &tag, &v)) {
            goto bad_dict;
        }
        if (tag != 0xa3) {
            continue;   /* issuerUniqueID、subjectUniqueID */
        }
        struct der extensions, extension, id, value;
        if (!der_expect(&v, 0x30, &extensions)) {
            goto bad_dict;
        }
        while (extensions.n) {
            char dotted[64];
            if (!der_expect(&extensions, 0x30, &extension) || !der_expect(&extension, 0x06, &id) ||
                !oid_dotted(id, dotted, sizeof dotted)) {
                goto bad_dict;
            }
            if (extension.n && extension.p[0] == 0x01 && !der_take(&extension, &tag, &value)) {
                goto bad_dict;   /* critical */
            }
            if (!der_expect(&extension, 0x04, &value)) {
                goto bad_dict;
            }
            struct der names;
            if (!strcmp(dotted, "2.5.29.17")) {
                if (!der_expect(&value, 0x30, &names) || general_names(names, san) < 0) {
                    if (!PyErr_Occurred()) {
                        goto bad_dict;
                    }
                    goto fail;
                }
            }
            else if (!strcmp(dotted, "1.3.6.1.5.5.7.1.1")) {
                if (access_locations(value, ocsp, issuers) < 0) {
                    goto fail;
                }
            }
            else if (!strcmp(dotted, "2.5.29.31")) {
                if (crl_points(value, crls) < 0) {
                    goto fail;
                }
            }
            else if (!strcmp(dotted, "2.5.29.19")) {
                *is_ca = basic_constraints_ca(value);
            }
        }
    }
    if (dict_set_tuple(dict, "subjectAltName", san) < 0 || dict_set_tuple(dict, "OCSP", ocsp) < 0 ||
        dict_set_tuple(dict, "caIssuers", issuers) < 0 || dict_set_tuple(dict, "crlDistributionPoints", crls) < 0) {
        goto fail;
    }
    Py_DECREF(san);
    Py_DECREF(ocsp);
    Py_DECREF(issuers);
    Py_DECREF(crls);
    return dict;
bad_dict:
    PyErr_SetString(PyExc_ValueError, "malformed certificate");
fail:
    Py_XDECREF(san);
    Py_XDECREF(ocsp);
    Py_XDECREF(issuers);
    Py_XDECREF(crls);
    Py_DECREF(dict);
    return NULL;
bad:
    PyErr_SetString(PyExc_ValueError, "malformed certificate");
    return NULL;
}

/* ---- PEM（RFC 7468）と base64（RFC 4648） ---- */

static int
base64_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* 空白を除いた base64 の本文の bytes。誤りは NULL（例外なし）。 */
static PyObject *
base64_decode(const char *p, size_t n)
{
    PyObject *out = PyBytes_FromStringAndSize(NULL, (Py_ssize_t)(n / 4 * 3 + 3));
    if (out == NULL) {
        PyErr_Clear();
        return NULL;
    }
    unsigned char *o = (unsigned char *)PyBytes_AS_STRING(out);
    size_t len = 0, pad = 0, count = 0;
    unsigned acc = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)p[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            continue;
        }
        if (c == '=') {
            pad++;
            continue;
        }
        int v = base64_value(c);
        if (v < 0 || pad) {
            Py_DECREF(out);
            return NULL;
        }
        acc = acc << 6 | (unsigned)v;
        if (++count % 4 == 0) {
            o[len++] = (unsigned char)(acc >> 16);
            o[len++] = (unsigned char)(acc >> 8);
            o[len++] = (unsigned char)acc;
            acc = 0;
        }
    }
    size_t rest = count % 4;
    if (rest == 1 || (rest && pad != 4 - rest) || (!rest && pad)) {
        Py_DECREF(out);
        return NULL;
    }
    if (rest == 2) {
        o[len++] = (unsigned char)(acc >> 4);
    }
    else if (rest == 3) {
        o[len++] = (unsigned char)(acc >> 10);
        o[len++] = (unsigned char)(acc >> 2);
    }
    if (_PyBytes_Resize(&out, (Py_ssize_t)len) < 0) {
        PyErr_Clear();
        return NULL;
    }
    return out;
}

/* 文書の証明書（PEM の CERTIFICATE、X509 CERTIFICATE、TRUSTED CERTIFICATE か、DER の一つ）を DER にして list へ。
   足した数か、例外つきの -1。 */
static Py_ssize_t
document_certificates(PyObject *list, const char *text, size_t len)
{
    static const char begin[] = "-----BEGIN ", end_mark[] = "-----END ";
    Py_ssize_t added = 0;
    bool pem = false;
    size_t at = 0;
    for (;;) {
        const char *b = NULL;
        for (size_t i = at; i + sizeof begin - 1 <= len; i++) {
            if (!memcmp(text + i, begin, sizeof begin - 1)) {
                b = text + i;
                break;
            }
        }
        if (b == NULL) {
            break;
        }
        pem = true;
        const char *label = b + sizeof begin - 1, *label_end = memchr(label, '-', (size_t)(text + len - label));
        if (label_end == NULL || (size_t)(text + len - label_end) < 5 || memcmp(label_end, "-----", 5)) {
            break;
        }
        size_t label_len = (size_t)(label_end - label);
        const char *body = label_end + 5, *e = NULL;
        for (const char *q = body; q + sizeof end_mark - 1 <= text + len; q++) {
            if (!memcmp(q, end_mark, sizeof end_mark - 1)) {
                e = q;
                break;
            }
        }
        if (e == NULL) {
            break;
        }
        at = (size_t)(e - text) + sizeof end_mark - 1;
        bool trusted = label_len == 19 && !memcmp(label, "TRUSTED CERTIFICATE", 19);
        bool plain = (label_len == 11 && !memcmp(label, "CERTIFICATE", 11)) ||
                     (label_len == 16 && !memcmp(label, "X509 CERTIFICATE", 16));
        if (!trusted && !plain) {
            continue;
        }
        PyObject *der = base64_decode(body, (size_t)(e - body));
        if (der == NULL) {
            continue;
        }
        /* TRUSTED CERTIFICATE は証明書の後に信頼の情報が続く：先頭の SEQUENCE が証明書 */
        struct der d = {(const unsigned char *)PyBytes_AS_STRING(der), (size_t)PyBytes_GET_SIZE(der)}, cert;
        size_t whole = d.n;
        if (!der_expect(&d, 0x30, &cert) || (plain && d.n)) {
            Py_DECREF(der);
            continue;
        }
        if (d.n && _PyBytes_Resize(&der, (Py_ssize_t)(whole - d.n)) < 0) {
            return -1;
        }
        int r = PyList_Append(list, der);
        Py_DECREF(der);
        if (r < 0) {
            return -1;
        }
        added++;
    }
    if (!pem && der_certificate((const unsigned char *)text, len)) {
        PyObject *der = PyBytes_FromStringAndSize(text, (Py_ssize_t)len);
        if (der == NULL || PyList_Append(list, der) < 0) {
            Py_XDECREF(der);
            return -1;
        }
        Py_DECREF(der);
        added++;
    }
    return added;
}

/* 文書の全部の bytes（errno つきの NULL）。 */
static PyObject *
read_document(PyObject *path)
{
    FILE *f = Py_fopen(path, "rb");
    if (f == NULL) {
        return NULL;
    }
    PyObject *data = PyBytes_FromStringAndSize(NULL, 0);
    char chunk[16384];
    size_t got;
    while (data != NULL && (got = fread(chunk, 1, sizeof chunk, f)) > 0) {
        Py_ssize_t old = PyBytes_GET_SIZE(data);
        if (_PyBytes_Resize(&data, old + (Py_ssize_t)got) == 0) {
            memcpy(PyBytes_AS_STRING(data) + old, chunk, got);
        }
    }
    if (data != NULL && ferror(f)) {
        Py_CLEAR(data);
        PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError, path);
    }
    Py_fclose(f);
    return data;
}

/* folder の文書の証明書を全部 list へ（読めない文書は飛ばす）。足した数か、例外つきの -1。 */
static Py_ssize_t
folder_certificates(PyObject *list, const char *name)
{
    char folder[_PY_PATH_MAX];
    if (_Py_complete_path(name, folder) < 0) {
        PyErr_SetFromErrnoWithFilename(PyExc_OSError, name);
        return -1;
    }
    struct kabi_entry *entries = NULL;
    n_result count = n_folder_entries(folder, &entries);
    if (count < 0) {
        errno = (int)-count;
        PyErr_SetFromErrnoWithFilename(PyExc_OSError, name);
        return -1;
    }
    Py_ssize_t added = 0;
    for (n_result i = 0; i < count; i++) {
        char path[_PY_PATH_MAX];
        if (entries[i].kind == KABI_KIND_FOLDER || n_path_join(folder, entries[i].name, path, sizeof path) < 0) {
            continue;
        }
        PyObject *name = PyUnicode_DecodeFSDefault(path);
        PyObject *data = name == NULL ? NULL : read_document(name);
        Py_XDECREF(name);
        if (data == NULL) {
            PyErr_Clear();
            continue;
        }
        Py_ssize_t n = document_certificates(list, PyBytes_AS_STRING(data), (size_t)PyBytes_GET_SIZE(data));
        Py_DECREF(data);
        if (n < 0) {
            free(entries);
            return -1;
        }
        added += n;
    }
    free(entries);
    return added;
}

/* DER の証明書の list を PEM の CERTIFICATE の並びに（net_stream の信頼の根の文書）。 */
static PyObject *
pem_document(PyObject *ders)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const char head[] = "-----BEGIN CERTIFICATE-----\n", tail[] = "-----END CERTIFICATE-----\n";
    size_t size = 0;
    for (Py_ssize_t i = 0; i < PyList_GET_SIZE(ders); i++) {
        size_t n = (size_t)PyBytes_GET_SIZE(PyList_GET_ITEM(ders, i)), chars = (n + 2) / 3 * 4;
        size += sizeof head + sizeof tail + chars + chars / 64 + 2;
    }
    PyObject *out = PyBytes_FromStringAndSize(NULL, (Py_ssize_t)size);
    if (out == NULL) {
        return NULL;
    }
    char *o = PyBytes_AS_STRING(out);
    size_t at = 0;
    for (Py_ssize_t i = 0; i < PyList_GET_SIZE(ders); i++) {
        PyObject *der = PyList_GET_ITEM(ders, i);
        const unsigned char *p = (const unsigned char *)PyBytes_AS_STRING(der);
        size_t n = (size_t)PyBytes_GET_SIZE(der), line = 0;
        memcpy(o + at, head, sizeof head - 1);
        at += sizeof head - 1;
        for (size_t j = 0; j < n; j += 3) {
            unsigned v = (unsigned)p[j] << 16 | (j + 1 < n ? (unsigned)p[j + 1] << 8 : 0) | (j + 2 < n ? p[j + 2] : 0);
            o[at++] = alphabet[v >> 18 & 63];
            o[at++] = alphabet[v >> 12 & 63];
            o[at++] = j + 1 < n ? alphabet[v >> 6 & 63] : '=';
            o[at++] = j + 2 < n ? alphabet[v & 63] : '=';
            if ((line += 4) == 64) {
                o[at++] = '\n';
                line = 0;
            }
        }
        if (line) {
            o[at++] = '\n';
        }
        memcpy(o + at, tail, sizeof tail - 1);
        at += sizeof tail - 1;
    }
    if (_PyBytes_Resize(&out, (Py_ssize_t)at) < 0) {
        return NULL;
    }
    return out;
}

/* ---- MemoryBIO ---- */

static PyObject *
bio_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    if (!_PyArg_NoPositional("MemoryBIO", args) || !_PyArg_NoKeywords("MemoryBIO", kwds)) {
        return NULL;
    }
    return type->tp_alloc(type, 0);
}

static void
bio_dealloc(PyObject *self)
{
    bio_object *b = (bio_object *)self;
    PyTypeObject *type = Py_TYPE(self);
    free(b->buf);
    type->tp_free(self);
    Py_DECREF(type);
}

static size_t
bio_pending(const bio_object *b)
{
    return b->len - b->start;
}

static bool
bio_put(bio_object *b, const void *p, size_t n)
{
    if (b->start == b->len) {
        b->start = b->len = 0;
    }
    if (b->cap - b->len < n) {
        if (b->start) {
            memmove(b->buf, b->buf + b->start, b->len - b->start);
            b->len -= b->start;
            b->start = 0;
        }
        if (b->cap - b->len < n) {
            size_t cap = b->cap ? b->cap : 16384;
            while (cap - b->len < n) {
                if (cap > SIZE_MAX / 2) {
                    return false;
                }
                cap *= 2;
            }
            unsigned char *grown = realloc(b->buf, cap);
            if (grown == NULL) {
                return false;
            }
            b->buf = grown;
            b->cap = cap;
        }
    }
    memcpy(b->buf + b->len, p, n);
    b->len += n;
    return true;
}

static PyObject *
bio_read(PyObject *self, PyObject *args)
{
    bio_object *b = (bio_object *)self;
    Py_ssize_t size = -1;
    if (!PyArg_ParseTuple(args, "|n:read", &size)) {
        return NULL;
    }
    size_t n = bio_pending(b);
    if (size >= 0 && (size_t)size < n) {
        n = (size_t)size;
    }
    PyObject *out = PyBytes_FromStringAndSize((const char *)b->buf + b->start, (Py_ssize_t)n);
    if (out != NULL) {
        b->start += n;
    }
    return out;
}

static PyObject *
bio_write(PyObject *self, PyObject *arg)
{
    bio_object *b = (bio_object *)self;
    Py_buffer data;
    if (PyObject_GetBuffer(arg, &data, PyBUF_SIMPLE) < 0) {
        return NULL;
    }
    PyObject *r = NULL;
    if (b->eof_written) {
        ssl_state *state = type_state(Py_TYPE(self));
        if (state != NULL) {
            raise_ssl(state->error, SSL_ERROR_SSL, NULL, "cannot write() after write_eof()");
        }
    }
    else if (!bio_put(b, data.buf, (size_t)data.len)) {
        PyErr_NoMemory();
    }
    else {
        r = PyLong_FromSsize_t(data.len);
    }
    PyBuffer_Release(&data);
    return r;
}

static PyObject *
bio_write_eof(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    ((bio_object *)self)->eof_written = true;
    Py_RETURN_NONE;
}

static PyObject *
bio_get_pending(PyObject *self, void *Py_UNUSED(closure))
{
    return PyLong_FromSize_t(bio_pending((bio_object *)self));
}

static PyObject *
bio_get_eof(PyObject *self, void *Py_UNUSED(closure))
{
    bio_object *b = (bio_object *)self;
    return PyBool_FromLong(b->eof_written && bio_pending(b) == 0);
}

static PyMethodDef bio_methods[] = {
    {"read", bio_read, METH_VARARGS, "read(size=-1) -> bytes\n\nRead up to size bytes from the memory BIO."},
    {"write", bio_write, METH_O, "write(b) -> int\n\nWrites the bytes b into the memory BIO."},
    {"write_eof", bio_write_eof, METH_NOARGS, "write_eof()\n\nWrite an EOF marker to the memory BIO."},
    {NULL, NULL}
};

static PyGetSetDef bio_getset[] = {
    {"pending", bio_get_pending, NULL, "The number of bytes pending in the memory BIO.", NULL},
    {"eof", bio_get_eof, NULL, "Whether the memory BIO is at EOF.", NULL},
    {NULL}
};

static PyType_Slot bio_slots[] = {
    {Py_tp_new, bio_new},
    {Py_tp_dealloc, bio_dealloc},
    {Py_tp_methods, bio_methods},
    {Py_tp_getset, bio_getset},
    {0, NULL}
};

static PyType_Spec bio_spec = {
    .name = "_ssl.MemoryBIO",
    .basicsize = sizeof(bio_object),
    .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_IMMUTABLETYPE,
    .slots = bio_slots,
};

/* ---- net_stream の運び手 ---- */

static n_result
socket_receive(void *arg, void *buf, size_t len, uint64_t deadline)
{
    return tcp_recv(((socket_object *)arg)->handle, buf, len, deadline);
}

static n_result
socket_send(void *arg, const void *buf, size_t len, uint64_t deadline)
{
    n_handle h = ((socket_object *)arg)->handle;
    return deadline ? tcp_send_until(h, buf, len, deadline) : tcp_send_some(h, buf, len);
}

/* MemoryBIO の流れは GIL を持ったまま net_stream を呼ぶので、BIO はほかのスレッドと取り合わない。 */
static n_result
bio_receive(void *arg, void *buf, size_t len, uint64_t Py_UNUSED(deadline))
{
    bio_object *in = ((socket_object *)arg)->incoming;
    size_t n = bio_pending(in);
    if (n == 0) {
        return in->eof_written ? 0 : -KABI_ERR_NOT_READY;
    }
    if (n > len) {
        n = len;
    }
    memcpy(buf, in->buf + in->start, n);
    in->start += n;
    return (n_result)n;
}

static n_result
bio_send(void *arg, const void *buf, size_t len, uint64_t Py_UNUSED(deadline))
{
    return bio_put(((socket_object *)arg)->outgoing, buf, len) ? (n_result)len : -KABI_ERR_NO_MEMORY;
}

/* ---- 流れの呼出し ---- */

enum step_kind { STEP_HANDSHAKE, STEP_READ, STEP_WRITE, STEP_CLOSE };

struct step {
    enum step_kind kind;
    void *buf;
    size_t len;
    long result;
    int err;
};

static void
step_run(socket_object *self, struct step *st)
{
    errno = 0;
    switch (st->kind) {
    case STEP_HANDSHAKE: st->result = ns_handshake(self->ns, 0); break;
    case STEP_READ: st->result = ns_try_read(self->ns, st->buf, st->len); break;
    case STEP_WRITE: st->result = ns_try_write(self->ns, st->buf, st->len); break;
    case STEP_CLOSE: st->result = ns_try_close(self->ns); break;
    }
    st->err = errno;
}

/* 待たない net_stream の呼出しを一つ。socket の流れは GIL を放し、流れの錠の中で。 */
static void
step(socket_object *self, struct step *st)
{
    if (self->sock_ref == NULL) {
        step_run(self, st);
        return;
    }
    PyThreadState *ts = PyEval_SaveThread();
    mtx_lock(&self->lock);
    self->running = ts;
    step_run(self, st);
    ts = self->running;
    self->running = NULL;
    mtx_unlock(&self->lock);
    PyEval_RestoreThread(ts);
}

static void
stream_free(socket_object *self)
{
    if (self->ns == NULL) {
        return;
    }
    if (self->sock_ref == NULL) {
        ns_abort(self->ns);
    }
    else {
        Py_BEGIN_ALLOW_THREADS
        mtx_lock(&self->lock);
        ns_abort(self->ns);
        mtx_unlock(&self->lock);
        Py_END_ALLOW_THREADS
    }
    self->ns = NULL;
}

/* net_stream の失敗（err は呼出しの直後の errno）を例外に。 */
static void
raise_stream(socket_object *self, int err)
{
    ssl_state *state = type_state(Py_TYPE(self));
    if (state == NULL) {
        return;
    }
    const char *text = ns_error(self->ns);
    if (err == ENOMEM) {
        PyErr_NoMemory();
    }
    else if (err == EACCES) {
        raise_certificate(state, text);
    }
    else if (ns_peer_truncated(self->ns)) {
        raise_ssl(state->eof_error, SSL_ERROR_EOF, "UNEXPECTED_EOF_WHILE_READING", "EOF occurred in violation of protocol");
    }
    else if (err == EPROTO || err == EINVAL || err == 0) {
        raise_ssl(state->error, SSL_ERROR_SSL, NULL, text[0] ? text : "TLS error");
    }
    else {
        errno = err;
        PyErr_SetFromErrno(PyExc_OSError);
    }
}

/* 一つの公開の呼出しの準備：socket の流れは socket の handle と timeout の期限。 */
struct op {
    bool bio;
    uint64_t deadline;            /* 0：待たない、KABI_CLOCK_NEVER：限りなし */
    PyObject *sock;               /* 呼出しの間の socket（新しい参照） */
};

static int
op_begin(socket_object *self, struct op *op)
{
    *op = (struct op){.bio = self->sock_ref == NULL};
    ssl_state *state = type_state(Py_TYPE(self));
    if (state == NULL) {
        return -1;
    }
    if (self->ns == NULL) {
        PyErr_SetString(PyExc_ValueError, "the TLS connection has been shut down");
        return -1;
    }
    if (op->bio) {
        return 0;
    }
    PyObject *sock;
    if (PyWeakref_GetRef(self->sock_ref, &sock) <= 0) {
        if (!PyErr_Occurred()) {
            raise_ssl(state->error, SSL_ERROR_SSL, NULL, "Underlying socket connection gone");
        }
        return -1;
    }
    op->sock = sock;
    PyObject *fd_object = PyObject_CallMethod(sock, "fileno", NULL);
    int fd = fd_object == NULL ? -1 : PyLong_AsInt(fd_object);
    Py_XDECREF(fd_object);
    if (fd == -1 && PyErr_Occurred()) {
        goto fail;
    }
    if (fd < 0) {
        raise_ssl(state->error, SSL_ERROR_SSL, NULL, "Underlying socket has been closed.");
        goto fail;
    }
    n_handle h = _Py_fd_handle(fd);
    if (h < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto fail;
    }
    PyObject *timeout = PyObject_CallMethod(sock, "gettimeout", NULL);
    if (timeout == NULL) {
        goto fail;
    }
    if (timeout == Py_None) {
        op->deadline = KABI_CLOCK_NEVER;
    }
    else {
        PyTime_t t;
        int r = _PyTime_FromSecondsObject(&t, timeout, _PyTime_ROUND_TIMEOUT);
        if (r < 0) {
            Py_DECREF(timeout);
            goto fail;
        }
        op->deadline = t <= 0 ? 0 : n_clock_after((uint64_t)t);
    }
    Py_DECREF(timeout);
    self->handle = h;
    return 0;
fail:
    Py_CLEAR(op->sock);
    return -1;
}

static void
op_end(struct op *op)
{
    Py_CLEAR(op->sock);
}

/* 流れが進めない時：待たない socket と MemoryBIO は SSLWantReadError か SSLWantWriteError、ほかは socket の handle
   を期限まで待つ。0 は続ける、-1 は例外。 */
static int
op_wait(socket_object *self, struct op *op, bool want_write, const char *what)
{
    if (op->bio || op->deadline == 0) {
        ssl_state *state = type_state(Py_TYPE(self));
        if (state != NULL) {
            raise_ssl(want_write ? state->want_write_error : state->want_read_error,
                      want_write ? SSL_ERROR_WANT_WRITE : SSL_ERROR_WANT_READ, NULL,
                      want_write ? "The operation did not complete (write)" : "The operation did not complete (read)");
        }
        return -1;
    }
    unsigned interest = (want_write ? KABI_EVENT_SENDABLE : KABI_EVENT_RECEIVABLE) | KABI_EVENT_CLOSED;
    for (;;) {
        int woke;
        Py_BEGIN_ALLOW_THREADS
        woke = _PyOS_NocturneWait(self->handle, interest, NULL, 0, op->deadline);
        Py_END_ALLOW_THREADS
        if (woke > 0) {
            return 0;
        }
        if (woke == 0) {
            PyErr_Format(PyExc_TimeoutError, "The %s operation timed out", what);
            return -1;
        }
        if (PyErr_CheckSignals() < 0) {
            return -1;
        }
    }
}

static int
handshake_run(socket_object *self, struct op *op)
{
    if (self->handshake_done) {
        return 0;
    }
    if (self->no_anchors) {
        ssl_state *state = type_state(Py_TYPE(self));
        if (state != NULL) {
            raise_certificate(state, "no trust anchors (load_default_certs or load_verify_locations)");
        }
        return -1;
    }
    for (;;) {
        struct step st = {STEP_HANDSHAKE};
        step(self, &st);
        if (st.result == 1) {
            self->handshake_done = true;
            return 0;
        }
        if (st.result != NS_WANT_READ && st.result != NS_WANT_WRITE) {
            raise_stream(self, st.err);
            return -1;
        }
        if (op_wait(self, op, st.result == NS_WANT_WRITE, "handshake") < 0) {
            return -1;
        }
    }
}

/* ---- _SSLSocket ---- */

static PyObject *
socket_do_handshake(PyObject *op_self, PyObject *Py_UNUSED(ignored))
{
    socket_object *self = (socket_object *)op_self;
    struct op op;
    if (op_begin(self, &op) < 0) {
        return NULL;
    }
    int r = handshake_run(self, &op);
    op_end(&op);
    if (r < 0) {
        return NULL;
    }
    Py_RETURN_NONE;
}

/* 平文を n byte まで p へ：数（0 は相手の close_notify）か、例外つきの -1。 */
static Py_ssize_t
read_into(socket_object *self, struct op *op, void *p, size_t n)
{
    for (;;) {
        struct step st = {STEP_READ, p, n};
        step(self, &st);
        if (st.result >= 0) {
            return st.result;
        }
        if (st.result == -2) {
            if (op_wait(self, op, false, "read") < 0) {
                return -1;
            }
            continue;
        }
        if (ns_peer_truncated(self->ns) && (self->ctx->options & OP_IGNORE_UNEXPECTED_EOF)) {
            return 0;
        }
        raise_stream(self, st.err);
        return -1;
    }
}

static PyObject *
socket_read(PyObject *op_self, PyObject *args)
{
    socket_object *self = (socket_object *)op_self;
    Py_ssize_t len;
    Py_buffer buffer = {0};
    if (!PyArg_ParseTuple(args, "n|w*:read", &len, &buffer)) {
        return NULL;
    }
    PyObject *bytes = NULL;
    void *p;
    if (buffer.buf != NULL) {
        if (len <= 0 || len > buffer.len) {
            len = buffer.len;
        }
        p = buffer.buf;
    }
    else {
        if (len < 0) {
            PyErr_SetString(PyExc_ValueError, "size should not be negative");
            return NULL;
        }
        bytes = PyBytes_FromStringAndSize(NULL, len);
        if (bytes == NULL) {
            return NULL;
        }
        p = PyBytes_AS_STRING(bytes);
    }
    struct op op;
    Py_ssize_t got = -1;
    if (op_begin(self, &op) == 0) {
        if (handshake_run(self, &op) == 0) {
            got = len == 0 ? 0 : read_into(self, &op, p, (size_t)len);
        }
        op_end(&op);
    }
    if (buffer.buf != NULL) {
        PyBuffer_Release(&buffer);
        return got < 0 ? NULL : PyLong_FromSsize_t(got);
    }
    if (got < 0 || _PyBytes_Resize(&bytes, got) < 0) {
        Py_XDECREF(bytes);
        return NULL;
    }
    return bytes;
}

/* 送りの列を全部送るまで（待つ流れの write の終わり）。 */
static int
write_drain(socket_object *self, struct op *op)
{
    for (;;) {
        struct step st = {STEP_WRITE, NULL, 0};
        step(self, &st);
        if (st.result == 0) {
            return 0;
        }
        if (st.result != -2) {
            raise_stream(self, st.err);
            return -1;
        }
        if (op_wait(self, op, true, "write") < 0) {
            return -1;
        }
    }
}

static PyObject *
socket_write(PyObject *op_self, PyObject *arg)
{
    socket_object *self = (socket_object *)op_self;
    Py_buffer data;
    if (PyObject_GetBuffer(arg, &data, PyBUF_SIMPLE) < 0) {
        return NULL;
    }
    struct op op;
    Py_ssize_t done = 0;
    bool failed = true;
    if (op_begin(self, &op) == 0) {
        if (handshake_run(self, &op) == 0) {
            failed = false;
            while (done < data.len) {
                struct step st = {STEP_WRITE, (char *)data.buf + done, (size_t)(data.len - done)};
                step(self, &st);
                if (st.result > 0) {
                    done += st.result;
                    continue;
                }
                if (st.result == -2 && done > 0 && (op.bio || op.deadline == 0)) {
                    break;   /* 待たない流れは受けた分を返す */
                }
                if (st.result == -2 && op_wait(self, &op, true, "write") == 0) {
                    continue;
                }
                if (st.result != -2) {
                    raise_stream(self, st.err);
                }
                failed = true;
                break;
            }
            if (!failed && !op.bio && op.deadline != 0 && write_drain(self, &op) < 0) {
                failed = true;
            }
        }
        op_end(&op);
    }
    PyBuffer_Release(&data);
    return failed ? NULL : PyLong_FromSsize_t(done);
}

static PyObject *
socket_pending(PyObject *op_self, PyObject *Py_UNUSED(ignored))
{
    socket_object *self = (socket_object *)op_self;
    return PyLong_FromSize_t(self->ns ? ns_pending(self->ns) : 0);
}

/* 送りの列の残りと close_notify を送り終えるまで（RFC 8446 §6.1）。0 は送り終えた、-1 は例外。 */
static int
close_notify_send(socket_object *self, struct op *op)
{
    for (;;) {
        struct step st = {STEP_CLOSE};
        step(self, &st);
        if (st.result == 1) {
            return 0;
        }
        if (st.result != -2) {
            raise_stream(self, st.err);
            return -1;
        }
        if (op_wait(self, op, true, "write") < 0) {
            return -1;
        }
    }
}

/* close_notify を送り、相手の close_notify は待たない。RFC 8446 §6.1 は書きの側を閉じる前に close_notify を送ることを
   求め、RFC 9112 §9.8 は Content-Length も chunked も無い応答の終わりを、close_notify を受けた時だけ完了とする。ssl.py
   の SSLSocket は socket の書きの側を閉じる前（shutdown と close）にこれを呼ぶ。握手の前は送るものが無い。 */
static PyObject *
socket_close_notify(PyObject *op_self, PyObject *Py_UNUSED(ignored))
{
    socket_object *self = (socket_object *)op_self;
    if (!self->handshake_done || self->ns == NULL) {
        Py_RETURN_NONE;
    }
    struct op op;
    if (op_begin(self, &op) < 0) {
        return NULL;
    }
    int r = close_notify_send(self, &op);
    op_end(&op);
    if (r < 0) {
        return NULL;
    }
    Py_RETURN_NONE;
}

/* close_notify を送り、相手の close_notify まで読む（その間の平文は捨てる）。socket の流れは socket を返す。 */
static PyObject *
socket_shutdown(PyObject *op_self, PyObject *Py_UNUSED(ignored))
{
    socket_object *self = (socket_object *)op_self;
    struct op op;
    if (op_begin(self, &op) < 0) {
        return NULL;
    }
    ssl_state *state = type_state(Py_TYPE(self));
    if (!self->handshake_done) {
        raise_ssl(state->error, SSL_ERROR_SSL, NULL, "shutdown before the TLS handshake finished");
        goto fail;
    }
    if (close_notify_send(self, &op) < 0) {
        goto fail;
    }
    unsigned char scratch[4096];
    for (;;) {
        Py_ssize_t got = read_into(self, &op, scratch, sizeof scratch);
        if (got == 0) {
            break;
        }
        if (got < 0) {
            goto fail;
        }
    }
    stream_free(self);
    PyObject *sock = op.sock;
    op.sock = NULL;
    return sock ? sock : Py_NewRef(Py_None);
fail:
    op_end(&op);
    return NULL;
}

static PyObject *
socket_getpeercert(PyObject *op_self, PyObject *args)
{
    socket_object *self = (socket_object *)op_self;
    int binary = 0;
    if (!PyArg_ParseTuple(args, "|p:getpeercert", &binary)) {
        return NULL;
    }
    if (!self->handshake_done || self->ns == NULL) {
        PyErr_SetString(PyExc_ValueError, "handshake not done yet");
        return NULL;
    }
    size_t len;
    const unsigned char *der = ns_peer_certificate(self->ns, &len);
    if (der == NULL) {
        Py_RETURN_NONE;
    }
    if (binary) {
        return PyBytes_FromStringAndSize((const char *)der, (Py_ssize_t)len);
    }
    if (!self->verified) {
        return PyDict_New();   /* 確かめていない証明書の中身は見せない */
    }
    bool is_ca;
    return certificate_dict(der, len, &is_ca);
}

static const char *
version_name(unsigned version)
{
    return version == 0x0304 ? "TLSv1.3" : version == 0x0303 ? "TLSv1.2" : NULL;
}

static PyObject *
socket_version(PyObject *op_self, PyObject *Py_UNUSED(ignored))
{
    socket_object *self = (socket_object *)op_self;
    const char *name = self->handshake_done && self->ns ? version_name(ns_tls_version(self->ns)) : NULL;
    return name ? PyUnicode_FromString(name) : Py_NewRef(Py_None);
}

static PyObject *
cipher_tuple(net_stream *ns)
{
    unsigned bits;
    const char *name = ns_tls_suite_name(ns_tls_suite(ns), &bits);
    if (name == NULL) {
        Py_RETURN_NONE;
    }
    return Py_BuildValue("(ssi)", name, version_name(ns_tls_version(ns)), (int)bits);
}

static PyObject *
socket_cipher(PyObject *op_self, PyObject *Py_UNUSED(ignored))
{
    socket_object *self = (socket_object *)op_self;
    if (!self->handshake_done || self->ns == NULL) {
        Py_RETURN_NONE;
    }
    return cipher_tuple(self->ns);
}

/* server：client と共にする cipher suite（この server が受ける一つ）。 */
static PyObject *
socket_shared_ciphers(PyObject *op_self, PyObject *Py_UNUSED(ignored))
{
    socket_object *self = (socket_object *)op_self;
    if (!self->server_side || !self->handshake_done || self->ns == NULL) {
        Py_RETURN_NONE;
    }
    PyObject *cipher = cipher_tuple(self->ns);
    if (cipher == NULL) {
        return NULL;
    }
    PyObject *list = PyList_New(1);
    if (list == NULL) {
        Py_DECREF(cipher);
        return NULL;
    }
    PyList_SET_ITEM(list, 0, cipher);
    return list;
}

static PyObject *
socket_selected_alpn_protocol(PyObject *op_self, PyObject *Py_UNUSED(ignored))
{
    socket_object *self = (socket_object *)op_self;
    const char *name = self->handshake_done && self->ns ? ns_alpn(self->ns) : "";
    return name[0] ? PyUnicode_FromString(name) : Py_NewRef(Py_None);
}

static PyObject *
socket_compression(PyObject *Py_UNUSED(self), PyObject *Py_UNUSED(ignored))
{
    Py_RETURN_NONE;   /* TLS 1.3 に圧縮は無く、TLS 1.2 でも申し出ない */
}

static PyObject *
socket_uses_ktls(PyObject *Py_UNUSED(self), PyObject *Py_UNUSED(ignored))
{
    Py_RETURN_FALSE;  /* 記録の暗号はいつも app の中（net_stream） */
}

/* tls-unique（RFC 5929）：TLS 1.3 には定めが無く（RFC 9266 §1）、TLS 1.2 の Finished も持たないので、いつも None。 */
static PyObject *
socket_get_channel_binding(PyObject *Py_UNUSED(self), PyObject *args, PyObject *kwds)
{
    static char *keywords[] = {"cb_type", NULL};
    const char *type = "tls-unique";
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|s:get_channel_binding", keywords, &type)) {
        return NULL;
    }
    if (strcmp(type, "tls-unique")) {
        PyErr_Format(PyExc_ValueError, "'%s' channel binding type not implemented", type);
        return NULL;
    }
    Py_RETURN_NONE;
}

/* server は CertificateRequest を送らない（HAS_PHA は False）。 */
static PyObject *
socket_verify_client_post_handshake(PyObject *op_self, PyObject *Py_UNUSED(ignored))
{
    ssl_state *state = type_state(Py_TYPE(op_self));
    if (state != NULL) {
        raise_ssl(state->error, SSL_ERROR_SSL, NULL, "post-handshake authentication is not supported");
    }
    return NULL;
}

static PyObject *
socket_get_context(PyObject *op_self, void *Py_UNUSED(closure))
{
    return Py_NewRef((PyObject *)((socket_object *)op_self)->ctx);
}

static int
socket_set_context(PyObject *op_self, PyObject *value, void *Py_UNUSED(closure))
{
    socket_object *self = (socket_object *)op_self;
    ssl_state *state = type_state(Py_TYPE(self));
    if (state == NULL) {
        return -1;
    }
    if (value == NULL || !PyObject_TypeCheck(value, state->context_type)) {
        PyErr_SetString(PyExc_TypeError, "The value must be a SSLContext");
        return -1;
    }
    Py_SETREF(self->ctx, (context_object *)Py_NewRef(value));
    return 0;
}

static PyObject *
socket_get_server_side(PyObject *op_self, void *Py_UNUSED(closure))
{
    return PyBool_FromLong(((socket_object *)op_self)->server_side);
}

static PyObject *
socket_get_server_hostname(PyObject *op_self, void *Py_UNUSED(closure))
{
    return Py_NewRef(((socket_object *)op_self)->server_hostname);
}

static PyObject *
socket_get_owner(PyObject *op_self, void *Py_UNUSED(closure))
{
    socket_object *self = (socket_object *)op_self;
    PyObject *owner;
    if (self->owner_ref == NULL || PyWeakref_GetRef(self->owner_ref, &owner) <= 0) {
        if (PyErr_Occurred()) {
            return NULL;
        }
        Py_RETURN_NONE;
    }
    return owner;
}

static int
socket_set_owner(PyObject *op_self, PyObject *value, void *Py_UNUSED(closure))
{
    socket_object *self = (socket_object *)op_self;
    PyObject *ref = value == NULL || value == Py_None ? NULL : PyWeakref_NewRef(value, NULL);
    if (ref == NULL && PyErr_Occurred()) {
        return -1;
    }
    Py_XSETREF(self->owner_ref, ref);
    return 0;
}

static PyObject *
socket_get_session(PyObject *Py_UNUSED(self), void *Py_UNUSED(closure))
{
    Py_RETURN_NONE;   /* 再開の session は渡さない */
}

static int
socket_set_session(PyObject *Py_UNUSED(self), PyObject *value, void *Py_UNUSED(closure))
{
    if (value == Py_None) {
        return 0;
    }
    PyErr_SetString(PyExc_ValueError, "TLS sessions are not supported");
    return -1;
}

static PyObject *
socket_get_session_reused(PyObject *op_self, void *Py_UNUSED(closure))
{
    socket_object *self = (socket_object *)op_self;
    return PyBool_FromLong(self->ns != NULL && ns_session_resumed(self->ns));
}

static int
socket_traverse(PyObject *op_self, visitproc visit, void *arg)
{
    socket_object *self = (socket_object *)op_self;
    Py_VISIT(Py_TYPE(self));
    Py_VISIT(self->ctx);
    Py_VISIT(self->sock_ref);
    Py_VISIT(self->owner_ref);
    Py_VISIT(self->incoming);
    Py_VISIT(self->outgoing);
    Py_VISIT(self->identity_in_use);
    Py_VISIT(self->server_hostname);
    return 0;
}

static int
socket_clear(PyObject *op_self)
{
    socket_object *self = (socket_object *)op_self;
    Py_CLEAR(self->sock_ref);
    Py_CLEAR(self->owner_ref);
    return 0;
}

static void
socket_dealloc(PyObject *op_self)
{
    socket_object *self = (socket_object *)op_self;
    PyTypeObject *type = Py_TYPE(self);
    PyObject_GC_UnTrack(self);
    if (self->ns != NULL) {
        ns_abort(self->ns);   /* 運び手は閉じない：socket は Python の socket が持つ */
    }
    mtx_destroy(&self->lock);
    (void)socket_clear(op_self);
    Py_CLEAR(self->ctx);
    Py_CLEAR(self->incoming);
    Py_CLEAR(self->outgoing);
    Py_CLEAR(self->identity_in_use);
    Py_CLEAR(self->server_hostname);
    type->tp_free(self);
    Py_DECREF(type);
}

static PyMethodDef socket_methods[] = {
    {"do_handshake", socket_do_handshake, METH_NOARGS, NULL},
    {"read", socket_read, METH_VARARGS, "read(size, [buffer])\nRead up to size bytes from the TLS socket."},
    {"write", socket_write, METH_O, "write(b)\nWrites the bytes-like object b into the TLS object."},
    {"pending", socket_pending, METH_NOARGS, "Returns the number of already decrypted bytes available for read."},
    {"shutdown", socket_shutdown, METH_NOARGS, "Does the TLS shutdown handshake with the peer."},
    {"close_notify", socket_close_notify, METH_NOARGS, "Sends close_notify without waiting for the peer's."},
    {"getpeercert", socket_getpeercert, METH_VARARGS, "Returns the certificate for the peer."},
    {"version", socket_version, METH_NOARGS, NULL},
    {"cipher", socket_cipher, METH_NOARGS, NULL},
    {"shared_ciphers", socket_shared_ciphers, METH_NOARGS, NULL},
    {"selected_alpn_protocol", socket_selected_alpn_protocol, METH_NOARGS, NULL},
    {"compression", socket_compression, METH_NOARGS, NULL},
    {"uses_ktls_for_send", socket_uses_ktls, METH_NOARGS, NULL},
    {"uses_ktls_for_recv", socket_uses_ktls, METH_NOARGS, NULL},
    {"get_channel_binding", (PyCFunction)(void (*)(void))socket_get_channel_binding, METH_VARARGS | METH_KEYWORDS, NULL},
    {"verify_client_post_handshake", socket_verify_client_post_handshake, METH_NOARGS, NULL},
    {NULL, NULL}
};

static PyGetSetDef socket_getset[] = {
    {"context", socket_get_context, socket_set_context, NULL, NULL},
    {"server_side", socket_get_server_side, NULL, "Whether this is a server-side socket.", NULL},
    {"server_hostname", socket_get_server_hostname, NULL, "The currently set server hostname (for SNI).", NULL},
    {"owner", socket_get_owner, socket_set_owner, "The Python-level owner of this object.", NULL},
    {"session", socket_get_session, socket_set_session, "The TLS session (none is kept).", NULL},
    {"session_reused", socket_get_session_reused, NULL, "Was the client session reused during handshake?", NULL},
    {NULL}
};

static PyType_Slot socket_slots[] = {
    {Py_tp_methods, socket_methods},
    {Py_tp_getset, socket_getset},
    {Py_tp_dealloc, socket_dealloc},
    {Py_tp_traverse, socket_traverse},
    {Py_tp_clear, socket_clear},
    {0, NULL}
};

static PyType_Spec socket_spec = {
    .name = "_ssl._SSLSocket",
    .basicsize = sizeof(socket_object),
    .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC | Py_TPFLAGS_IMMUTABLETYPE | Py_TPFLAGS_DISALLOW_INSTANTIATION,
    .slots = socket_slots,
};

/* server の握手の途中で client の server_name を見た時（net_stream.h の server_name_seen）。sni_callback を呼び、
   その後の文脈の身元を渡す。 */
static int
server_name_seen(void *arg, const char *server_name, const ns_tls_identity **identity)
{
    socket_object *self = arg;
    PyThreadState *ts = self->running;
    if (ts != NULL) {
        PyEval_RestoreThread(ts);
    }
    int alert = 0;
    PyObject *callback = self->ctx->sni_callback;
    if (callback != NULL) {
        Py_INCREF(callback);
        PyObject *owner = socket_get_owner((PyObject *)self, NULL);
        if (owner == Py_None) {
            Py_SETREF(owner, Py_NewRef((PyObject *)self));
        }
        PyObject *name = server_name ? PyUnicode_DecodeASCII(server_name, (Py_ssize_t)strlen(server_name), "strict")
                                     : Py_NewRef(Py_None);
        PyObject *result = owner && name ? PyObject_CallFunctionObjArgs(callback, owner, name, (PyObject *)self->ctx, NULL)
                                         : NULL;
        if (result == NULL) {
            PyErr_FormatUnraisable("Exception ignored in sni_callback %R", callback);
            alert = 40;   /* handshake_failure */
        }
        else if (result != Py_None) {
            long value = PyLong_Check(result) ? PyLong_AsLong(result) : -1;
            alert = value > 0 && value < 256 ? (int)value : 80;   /* internal_error */
            PyErr_Clear();
        }
        Py_XDECREF(result);
        Py_XDECREF(name);
        Py_XDECREF(owner);
        Py_DECREF(callback);
    }
    PyObject *capsule = self->ctx->identity;
    if (alert == 0 && capsule == NULL) {
        alert = 40;
    }
    if (alert == 0) {
        Py_XSETREF(self->identity_in_use, Py_NewRef(capsule));
        *identity = PyCapsule_GetPointer(capsule, IDENTITY_CAPSULE);
    }
    if (ts != NULL) {
        self->running = PyEval_SaveThread();
    }
    return alert;
}

/* ---- _SSLContext ---- */

static uint16_t
range_low(const context_object *c)
{
    int v = c->minimum_version == PROTO_MINIMUM_SUPPORTED ? PROTO_TLSv1_2 : c->minimum_version;
    if (v <= PROTO_TLSv1_2 && (c->options & OP_NO_TLSv1_2)) {
        v = PROTO_TLSv1_3;
    }
    return (uint16_t)(v < PROTO_TLSv1_2 ? PROTO_TLSv1_2 : v);
}

static uint16_t
range_high(const context_object *c)
{
    int v = c->maximum_version == PROTO_MAXIMUM_SUPPORTED ? PROTO_TLSv1_3 : c->maximum_version;
    if (v >= PROTO_TLSv1_3 && (c->options & OP_NO_TLSv1_3)) {
        v = PROTO_TLSv1_2;
    }
    return (uint16_t)v;
}

/* net_stream に渡す信頼の根の文書（NULL はシステムの根）。 */
static int
anchor_document(context_object *c, const void **doc, size_t *len)
{
    *doc = NULL;
    *len = 0;
    if (PyList_GET_SIZE(c->anchors) == 0) {
        return 0;
    }
    if (c->anchor_document == NULL) {
        PyObject *all = PyList_GetSlice(c->anchors, 0, PyList_GET_SIZE(c->anchors));
        if (all == NULL) {
            return -1;
        }
        if (c->system_anchors && folder_certificates(all, KABI_FOLDER_CERTIFICATES) < 0) {
            Py_DECREF(all);
            return -1;
        }
        c->anchor_document = pem_document(all);
        Py_DECREF(all);
        if (c->anchor_document == NULL) {
            return -1;
        }
    }
    *doc = PyBytes_AS_STRING(c->anchor_document);
    *len = (size_t)PyBytes_GET_SIZE(c->anchor_document);
    return 0;
}

static PyObject *
socket_new(context_object *c, PyObject *sock, bio_object *incoming, bio_object *outgoing, int server_side,
           PyObject *hostname, PyObject *owner, PyObject *session)
{
    ssl_state *state = type_state(Py_TYPE(c));
    if (state == NULL) {
        return NULL;
    }
    if (session != Py_None) {
        PyErr_SetString(PyExc_ValueError, "TLS sessions are not supported");
        return NULL;
    }
    const char *host = NULL;
    if (hostname != Py_None) {
        if (!PyUnicode_Check(hostname) || server_side) {
            PyErr_SetString(server_side ? PyExc_ValueError : PyExc_TypeError,
                            server_side ? "server_hostname can only be specified in client mode"
                                        : "server_hostname must be a str");
            return NULL;
        }
        Py_ssize_t n;
        host = PyUnicode_AsUTF8AndSize(hostname, &n);
        if (host == NULL) {
            return NULL;
        }
        if (n == 0 || host[0] == '.' || (Py_ssize_t)strlen(host) != n) {
            PyErr_SetString(PyExc_ValueError, "server_hostname cannot be an empty string or start with a leading dot.");
            return NULL;
        }
    }
    if (c->protocol == PROTOCOL_TLS_CLIENT && server_side) {
        PyErr_SetString(PyExc_ValueError, "Cannot create a server socket with a PROTOCOL_TLS_CLIENT context");
        return NULL;
    }
    if (c->protocol == PROTOCOL_TLS_SERVER && !server_side) {
        PyErr_SetString(PyExc_ValueError, "Cannot create a client socket with a PROTOCOL_TLS_SERVER context");
        return NULL;
    }
    socket_object *self = PyObject_GC_New(socket_object, state->socket_type);
    if (self == NULL) {
        return NULL;
    }
    memset((char *)self + sizeof(PyObject), 0, sizeof *self - sizeof(PyObject));
    if (mtx_init(&self->lock, mtx_plain) != thrd_success) {
        PyObject_GC_Del(self);
        return PyErr_NoMemory();
    }
    self->ctx = (context_object *)Py_NewRef((PyObject *)c);
    self->server_side = server_side;
    self->server_hostname = Py_NewRef(hostname);
    self->handle = -1;
    if (sock != NULL && (self->sock_ref = PyWeakref_NewRef(sock, NULL)) == NULL) {
        goto fail;
    }
    if (incoming != NULL) {
        self->incoming = (bio_object *)Py_NewRef((PyObject *)incoming);
        self->outgoing = (bio_object *)Py_NewRef((PyObject *)outgoing);
    }
    if (socket_set_owner((PyObject *)self, owner, NULL) < 0) {
        goto fail;
    }
    PyObject_GC_Track(self);
    struct ns_transport transport = sock ? (struct ns_transport){socket_receive, socket_send, self}
                                         : (struct ns_transport){bio_receive, bio_send, self};
    const unsigned char *alpn = c->alpn ? (const unsigned char *)PyBytes_AS_STRING(c->alpn) : NULL;
    size_t alpn_len = c->alpn ? (size_t)PyBytes_GET_SIZE(c->alpn) : 0;
    uint16_t low = range_low(c), high = range_high(c);
    char err[160];
    if (low > high) {
        raise_ssl(state->error, SSL_ERROR_SSL, NULL, "no TLS version is left between minimum_version and maximum_version");
        goto fail_tracked;
    }
    if (server_side) {
        if (c->verify_mode != CERT_NONE) {
            raise_ssl(state->error, SSL_ERROR_SSL, NULL,
                      "the TLS server does not request client certificates (verify_mode must be CERT_NONE)");
            goto fail_tracked;
        }
        if (high < PROTO_TLSv1_3) {
            raise_ssl(state->error, SSL_ERROR_SSL, NULL, "the TLS server speaks TLS 1.3 only");
            goto fail_tracked;
        }
        if (c->identity == NULL && c->sni_callback == NULL) {
            raise_ssl(state->error, SSL_ERROR_SSL, NULL, "the context has no server certificate (load_cert_chain)");
            goto fail_tracked;
        }
        self->identity_in_use = Py_XNewRef(c->identity);
        struct ns_tls_server_config config = {
            .identity = c->identity ? PyCapsule_GetPointer(c->identity, IDENTITY_CAPSULE) : NULL,
            .server_name_seen = c->sni_callback ? server_name_seen : NULL,
            .ctx = self,
            .alpn = alpn,
            .alpn_len = alpn_len,
            .timeout_ms = -1,
        };
        self->ns = ns_tls_server(&transport, &config, err, sizeof err);
    }
    else {
        const void *doc;
        size_t doc_len;
        if (anchor_document(c, &doc, &doc_len) < 0) {
            goto fail_tracked;
        }
        self->verified = c->verify_mode != CERT_NONE;
        self->no_anchors = self->verified && doc == NULL && !c->system_anchors;
        struct ns_tls_config config = {
            .host = host,
            .alpn = alpn,
            .alpn_len = alpn_len,
            .version_min = low,
            .version_max = high,
            .verify_peer = self->verified,
            .verify_host = self->verified && c->check_hostname,
            .anchors = doc,
            .anchors_len = doc_len,
            .timeout_ms = -1,
        };
        self->ns = ns_tls_client(&transport, &config, err, sizeof err);
    }
    if (self->ns == NULL) {
        if (errno == ENOMEM) {
            PyErr_NoMemory();
        }
        else {
            raise_ssl(state->error, SSL_ERROR_SSL, NULL, err);
        }
        goto fail_tracked;
    }
    return (PyObject *)self;
fail:
    PyObject_GC_Track(self);
fail_tracked:
    Py_DECREF(self);
    return NULL;
}

static PyObject *
context_wrap_socket(PyObject *op_self, PyObject *args, PyObject *kwds)
{
    context_object *c = (context_object *)op_self;
    static char *keywords[] = {"sock", "server_side", "server_hostname", "owner", "session", NULL};
    ssl_state *state = type_state(Py_TYPE(c));
    PyObject *sock, *hostname = Py_None, *owner = Py_None, *session = Py_None;
    int server_side;
    if (state == NULL || !PyArg_ParseTupleAndKeywords(args, kwds, "O!p|O$OO:_wrap_socket", keywords,
                                                      state->python_socket_type, &sock, &server_side, &hostname,
                                                      &owner, &session)) {
        return NULL;
    }
    return socket_new(c, sock, NULL, NULL, server_side, hostname, owner, session);
}

static PyObject *
context_wrap_bio(PyObject *op_self, PyObject *args, PyObject *kwds)
{
    context_object *c = (context_object *)op_self;
    static char *keywords[] = {"incoming", "outgoing", "server_side", "server_hostname", "owner", "session", NULL};
    ssl_state *state = type_state(Py_TYPE(c));
    PyObject *incoming, *outgoing, *hostname = Py_None, *owner = Py_None, *session = Py_None;
    int server_side;
    if (state == NULL || !PyArg_ParseTupleAndKeywords(args, kwds, "O!O!p|O$OO:_wrap_bio", keywords,
                                                      state->bio_type, &incoming, state->bio_type, &outgoing,
                                                      &server_side, &hostname, &owner, &session)) {
        return NULL;
    }
    return socket_new(c, NULL, (bio_object *)incoming, (bio_object *)outgoing, server_side, hostname, owner, session);
}

static PyObject *
context_set_alpn_protocols(PyObject *op_self, PyObject *arg)
{
    context_object *c = (context_object *)op_self;
    Py_buffer protos;
    if (PyObject_GetBuffer(arg, &protos, PyBUF_SIMPLE) < 0) {
        return NULL;
    }
    const unsigned char *p = protos.buf;
    for (Py_ssize_t i = 0; i < protos.len; i += 1 + p[i]) {
        if (p[i] == 0 || p[i] >= HTTP_PROTOCOL_MAX || i + 1 + p[i] > protos.len) {
            PyBuffer_Release(&protos);
            PyErr_Format(PyExc_ValueError, "ALPN protocols must be 1 to %u bytes long", HTTP_PROTOCOL_MAX - 1);
            return NULL;
        }
    }
    PyObject *copy = protos.len ? PyBytes_FromStringAndSize(protos.buf, protos.len) : NULL;
    PyBuffer_Release(&protos);
    if (copy == NULL && PyErr_Occurred()) {
        return NULL;
    }
    Py_XSETREF(c->alpn, copy);
    Py_RETURN_NONE;
}

static void
identity_destroy(PyObject *capsule)
{
    ns_tls_identity_free(PyCapsule_GetPointer(capsule, IDENTITY_CAPSULE));
}

static PyObject *
context_load_cert_chain(PyObject *op_self, PyObject *args, PyObject *kwds)
{
    context_object *c = (context_object *)op_self;
    static char *keywords[] = {"certfile", "keyfile", "password", NULL};
    PyObject *certfile, *keyfile = Py_None, *password = Py_None;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|OO:load_cert_chain", keywords, &certfile, &keyfile, &password)) {
        return NULL;
    }
    ssl_state *state = type_state(Py_TYPE(c));
    if (state == NULL) {
        return NULL;
    }
    if (c->protocol == PROTOCOL_TLS_CLIENT) {
        raise_ssl(state->error, SSL_ERROR_SSL, NULL, "the TLS client sends no certificate");
        return NULL;
    }
    PyObject *chain = read_document(certfile);
    if (chain == NULL) {
        return NULL;
    }
    PyObject *key = keyfile == Py_None ? Py_NewRef(chain) : read_document(keyfile);
    if (key == NULL) {
        Py_DECREF(chain);
        return NULL;
    }
    char err[160];
    ns_tls_identity *id = ns_tls_identity_new(PyBytes_AS_STRING(chain), (size_t)PyBytes_GET_SIZE(chain),
                                              PyBytes_AS_STRING(key), (size_t)PyBytes_GET_SIZE(key), err, sizeof err);
    Py_DECREF(chain);
    Py_DECREF(key);   /* 鍵の写しは bytes の放しで消えない：Python の bytes は消さない */
    if (id == NULL) {
        if (errno == ENOMEM) {
            return PyErr_NoMemory();
        }
        raise_ssl(state->error, SSL_ERROR_SSL, NULL, err);
        return NULL;
    }
    PyObject *capsule = PyCapsule_New(id, IDENTITY_CAPSULE, identity_destroy);
    if (capsule == NULL) {
        ns_tls_identity_free(id);
        return NULL;
    }
    Py_XSETREF(c->identity, capsule);
    Py_RETURN_NONE;
}

static PyObject *
context_load_verify_locations(PyObject *op_self, PyObject *args, PyObject *kwds)
{
    context_object *c = (context_object *)op_self;
    static char *keywords[] = {"cafile", "capath", "cadata", NULL};
    PyObject *cafile = Py_None, *capath = Py_None, *cadata = Py_None;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|OOO:load_verify_locations", keywords, &cafile, &capath, &cadata)) {
        return NULL;
    }
    ssl_state *state = type_state(Py_TYPE(c));
    if (state == NULL) {
        return NULL;
    }
    if (cafile == Py_None && capath == Py_None && cadata == Py_None) {
        PyErr_SetString(PyExc_TypeError, "cafile, capath and cadata cannot be all omitted");
        return NULL;
    }
    Py_CLEAR(c->anchor_document);
    if (cadata != Py_None) {
        Py_ssize_t added;
        if (PyUnicode_Check(cadata)) {
            Py_ssize_t n;
            const char *text = PyUnicode_AsUTF8AndSize(cadata, &n);
            if (text == NULL) {
                return NULL;
            }
            added = document_certificates(c->anchors, text, (size_t)n);
        }
        else {
            Py_buffer data;
            if (PyObject_GetBuffer(cadata, &data, PyBUF_SIMPLE) < 0) {
                PyErr_SetString(PyExc_TypeError, "cadata should be an ASCII string or a bytes-like object");
                return NULL;
            }
            /* DER の証明書の並び */
            struct der d = {data.buf, (size_t)data.len}, cert;
            const unsigned char *start = d.p;
            added = 0;
            while (d.n && der_expect(&d, 0x30, &cert)) {
                PyObject *der = PyBytes_FromStringAndSize((const char *)start, d.p - start);
                if (der == NULL || PyList_Append(c->anchors, der) < 0) {
                    Py_XDECREF(der);
                    added = -1;
                    break;
                }
                Py_DECREF(der);
                added++;
                start = d.p;
            }
            if (added >= 0 && d.n) {
                added = 0;
            }
            PyBuffer_Release(&data);
        }
        if (added < 0) {
            return NULL;
        }
        if (added == 0) {
            raise_ssl(state->error, SSL_ERROR_SSL, "NO_CERTIFICATE_OR_CRL_FOUND", "no certificate or crl found");
            return NULL;
        }
    }
    if (cafile != Py_None) {
        PyObject *data = read_document(cafile);
        if (data == NULL) {
            return NULL;
        }
        Py_ssize_t added = document_certificates(c->anchors, PyBytes_AS_STRING(data), (size_t)PyBytes_GET_SIZE(data));
        Py_DECREF(data);
        if (added < 0) {
            return NULL;
        }
        if (added == 0) {
            raise_ssl(state->error, SSL_ERROR_SSL, "NO_CERTIFICATE_OR_CRL_FOUND", "no certificate or crl found");
            return NULL;
        }
    }
    if (capath != Py_None) {
        PyObject *path;
        if (!PyUnicode_FSConverter(capath, &path)) {
            return NULL;
        }
        Py_ssize_t added = folder_certificates(c->anchors, PyBytes_AS_STRING(path));
        Py_DECREF(path);
        if (added < 0) {
            return NULL;
        }
    }
    Py_RETURN_NONE;
}

static PyObject *
context_set_default_verify_paths(PyObject *op_self, PyObject *Py_UNUSED(ignored))
{
    context_object *c = (context_object *)op_self;
    c->system_anchors = true;
    Py_CLEAR(c->anchor_document);
    Py_RETURN_NONE;
}

static PyObject *
context_cert_store_stats(PyObject *op_self, PyObject *Py_UNUSED(ignored))
{
    context_object *c = (context_object *)op_self;
    Py_ssize_t ca = 0;
    for (Py_ssize_t i = 0; i < PyList_GET_SIZE(c->anchors); i++) {
        PyObject *der = PyList_GET_ITEM(c->anchors, i);
        bool is_ca;
        PyObject *dict = certificate_dict((const unsigned char *)PyBytes_AS_STRING(der), (size_t)PyBytes_GET_SIZE(der), &is_ca);
        if (dict == NULL) {
            PyErr_Clear();
            continue;
        }
        Py_DECREF(dict);
        ca += is_ca;
    }
    return Py_BuildValue("{sn,si,sn}", "x509", PyList_GET_SIZE(c->anchors), "crl", 0, "x509_ca", ca);
}

static PyObject *
context_get_ca_certs(PyObject *op_self, PyObject *args, PyObject *kwds)
{
    context_object *c = (context_object *)op_self;
    static char *keywords[] = {"binary_form", NULL};
    int binary = 0;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|p:get_ca_certs", keywords, &binary)) {
        return NULL;
    }
    PyObject *list = PyList_New(0);
    for (Py_ssize_t i = 0; list != NULL && i < PyList_GET_SIZE(c->anchors); i++) {
        PyObject *der = PyList_GET_ITEM(c->anchors, i);
        bool is_ca;
        PyObject *dict = certificate_dict((const unsigned char *)PyBytes_AS_STRING(der), (size_t)PyBytes_GET_SIZE(der), &is_ca);
        if (dict == NULL) {
            PyErr_Clear();
            continue;
        }
        PyObject *item = is_ca ? (binary ? Py_NewRef(der) : Py_NewRef(dict)) : NULL;
        Py_DECREF(dict);
        if (item != NULL && PyList_Append(list, item) < 0) {
            Py_CLEAR(list);
        }
        Py_XDECREF(item);
    }
    return list;
}

static PyObject *
context_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    int protocol;
    if (!_PyArg_NoKeywords("_SSLContext", kwds) || !PyArg_ParseTuple(args, "i:_SSLContext", &protocol)) {
        return NULL;
    }
    if (protocol != PROTOCOL_TLS && protocol != PROTOCOL_TLS_CLIENT && protocol != PROTOCOL_TLS_SERVER) {
        PyErr_Format(PyExc_ValueError, "invalid or unsupported protocol version %i", protocol);
        return NULL;
    }
    if (protocol == PROTOCOL_TLS && PyErr_WarnEx(PyExc_DeprecationWarning, "ssl.PROTOCOL_TLS is deprecated", 2) < 0) {
        return NULL;
    }
    context_object *c = (context_object *)type->tp_alloc(type, 0);
    if (c == NULL) {
        return NULL;
    }
    c->protocol = protocol;
    c->check_hostname = protocol == PROTOCOL_TLS_CLIENT;
    c->verify_mode = protocol == PROTOCOL_TLS_CLIENT ? CERT_REQUIRED : CERT_NONE;
    c->options = OPTIONS_ALWAYS;
    c->verify_flags = VERIFY_ALWAYS;
    c->minimum_version = protocol == PROTOCOL_TLS_SERVER ? PROTO_TLSv1_3 : PROTO_TLSv1_2;
    c->maximum_version = PROTO_MAXIMUM_SUPPORTED;
    c->anchors = PyList_New(0);
    if (c->anchors == NULL) {
        Py_DECREF(c);
        return NULL;
    }
    return (PyObject *)c;
}

static PyObject *
context_get_protocol(PyObject *self, void *Py_UNUSED(closure))
{
    return PyLong_FromLong(((context_object *)self)->protocol);
}

static PyObject *
context_get_verify_mode(PyObject *self, void *Py_UNUSED(closure))
{
    return PyLong_FromLong(((context_object *)self)->verify_mode);
}

static int
context_set_verify_mode(PyObject *self, PyObject *value, void *Py_UNUSED(closure))
{
    context_object *c = (context_object *)self;
    int mode = value == NULL ? -1 : PyLong_AsInt(value);
    if (mode == -1 && PyErr_Occurred()) {
        return -1;
    }
    if (mode != CERT_NONE && mode != CERT_OPTIONAL && mode != CERT_REQUIRED) {
        PyErr_SetString(PyExc_ValueError, "invalid value for verify_mode");
        return -1;
    }
    if (mode == CERT_NONE && c->check_hostname) {
        PyErr_SetString(PyExc_ValueError, "Cannot set verify_mode to CERT_NONE when check_hostname is enabled.");
        return -1;
    }
    if (mode != CERT_NONE && c->protocol == PROTOCOL_TLS_SERVER) {
        PyErr_SetString(PyExc_ValueError, "the TLS server does not request client certificates");
        return -1;
    }
    c->verify_mode = mode;
    return 0;
}

static PyObject *
context_get_check_hostname(PyObject *self, void *Py_UNUSED(closure))
{
    return PyBool_FromLong(((context_object *)self)->check_hostname);
}

static int
context_set_check_hostname(PyObject *self, PyObject *value, void *Py_UNUSED(closure))
{
    context_object *c = (context_object *)self;
    int on = value == NULL ? -1 : PyObject_IsTrue(value);
    if (on < 0) {
        return -1;
    }
    if (on && c->verify_mode == CERT_NONE) {
        if (c->protocol == PROTOCOL_TLS_SERVER) {
            PyErr_SetString(PyExc_ValueError, "the TLS server does not check client host names");
            return -1;
        }
        c->verify_mode = CERT_REQUIRED;
    }
    c->check_hostname = on;
    return 0;
}

static PyObject *
context_get_options(PyObject *self, void *Py_UNUSED(closure))
{
    return PyLong_FromLong(((context_object *)self)->options);
}

static int
context_set_options(PyObject *self, PyObject *value, void *Py_UNUSED(closure))
{
    long v = value == NULL ? -1 : PyLong_AsLong(value);
    if (v == -1 && PyErr_Occurred()) {
        return -1;
    }
    if (v & ~OPTIONS_KNOWN) {
        PyErr_Format(PyExc_ValueError, "unknown options 0x%lx", v & ~OPTIONS_KNOWN);
        return -1;
    }
    ((context_object *)self)->options = v | OPTIONS_ALWAYS;
    return 0;
}

static PyObject *
context_get_verify_flags(PyObject *self, void *Py_UNUSED(closure))
{
    return PyLong_FromLong(((context_object *)self)->verify_flags);
}

static int
context_set_verify_flags(PyObject *self, PyObject *value, void *Py_UNUSED(closure))
{
    long v = value == NULL ? -1 : PyLong_AsLong(value);
    if (v == -1 && PyErr_Occurred()) {
        return -1;
    }
    if (v & ~VERIFY_ALWAYS) {
        PyErr_Format(PyExc_ValueError, "unsupported verify flags 0x%lx", v & ~VERIFY_ALWAYS);
        return -1;
    }
    ((context_object *)self)->verify_flags = VERIFY_ALWAYS;
    return 0;
}

static int
set_version(PyObject *value, int *slot, bool minimum)
{
    int v = value == NULL ? 0 : PyLong_AsInt(value);
    if (v == -1 && PyErr_Occurred()) {
        return -1;
    }
    if (v == PROTO_MINIMUM_SUPPORTED || v == PROTO_MAXIMUM_SUPPORTED) {
        v = minimum == (v == PROTO_MINIMUM_SUPPORTED) ? v : v == PROTO_MINIMUM_SUPPORTED ? PROTO_TLSv1_2 : PROTO_TLSv1_3;
    }
    else if (v != PROTO_TLSv1_2 && v != PROTO_TLSv1_3) {
        PyErr_Format(PyExc_ValueError, "Unsupported TLS/SSL version 0x%x", (unsigned)v);
        return -1;
    }
    *slot = v;
    return 0;
}

static PyObject *
context_get_minimum_version(PyObject *self, void *Py_UNUSED(closure))
{
    return PyLong_FromLong(((context_object *)self)->minimum_version);
}

static int
context_set_minimum_version(PyObject *self, PyObject *value, void *Py_UNUSED(closure))
{
    return set_version(value, &((context_object *)self)->minimum_version, true);
}

static PyObject *
context_get_maximum_version(PyObject *self, void *Py_UNUSED(closure))
{
    return PyLong_FromLong(((context_object *)self)->maximum_version);
}

static int
context_set_maximum_version(PyObject *self, PyObject *value, void *Py_UNUSED(closure))
{
    return set_version(value, &((context_object *)self)->maximum_version, false);
}

static PyObject *
context_get_sni_callback(PyObject *self, void *Py_UNUSED(closure))
{
    PyObject *callback = ((context_object *)self)->sni_callback;
    return Py_NewRef(callback ? callback : Py_None);
}

static int
context_set_sni_callback(PyObject *self, PyObject *value, void *Py_UNUSED(closure))
{
    context_object *c = (context_object *)self;
    if (c->protocol == PROTOCOL_TLS_CLIENT) {
        PyErr_SetString(PyExc_ValueError, "sni_callback cannot be set on TLS_CLIENT context");
        return -1;
    }
    if (value != NULL && value != Py_None && !PyCallable_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "not a callable object");
        return -1;
    }
    Py_XSETREF(c->sni_callback, value == NULL || value == Py_None ? NULL : Py_NewRef(value));
    return 0;
}

/* post-handshake の認証（RFC 8446 §4.6.2）は無い：None は「この TLS に無い」（http.client が見る）。 */
static PyObject *
context_get_post_handshake_auth(PyObject *Py_UNUSED(self), void *Py_UNUSED(closure))
{
    Py_RETURN_NONE;
}

static int
context_set_post_handshake_auth(PyObject *Py_UNUSED(self), PyObject *value, void *Py_UNUSED(closure))
{
    int on = value == NULL ? 0 : PyObject_IsTrue(value);
    if (on < 0) {
        return -1;
    }
    if (on) {
        PyErr_SetString(PyExc_ValueError, "post-handshake authentication is not supported");
        return -1;
    }
    return 0;
}

static int
context_traverse(PyObject *self, visitproc visit, void *arg)
{
    context_object *c = (context_object *)self;
    Py_VISIT(Py_TYPE(self));
    Py_VISIT(c->alpn);
    Py_VISIT(c->identity);
    Py_VISIT(c->sni_callback);
    Py_VISIT(c->anchors);
    Py_VISIT(c->anchor_document);
    return 0;
}

static int
context_clear(PyObject *self)
{
    context_object *c = (context_object *)self;
    Py_CLEAR(c->sni_callback);
    return 0;
}

static void
context_dealloc(PyObject *self)
{
    context_object *c = (context_object *)self;
    PyTypeObject *type = Py_TYPE(self);
    PyObject_GC_UnTrack(self);
    (void)context_clear(self);
    Py_CLEAR(c->alpn);
    Py_CLEAR(c->identity);
    Py_CLEAR(c->anchors);
    Py_CLEAR(c->anchor_document);
    type->tp_free(self);
    Py_DECREF(type);
}

static PyMethodDef context_methods[] = {
    {"_wrap_socket", (PyCFunction)(void (*)(void))context_wrap_socket, METH_VARARGS | METH_KEYWORDS, NULL},
    {"_wrap_bio", (PyCFunction)(void (*)(void))context_wrap_bio, METH_VARARGS | METH_KEYWORDS, NULL},
    {"_set_alpn_protocols", context_set_alpn_protocols, METH_O, NULL},
    {"load_cert_chain", (PyCFunction)(void (*)(void))context_load_cert_chain, METH_VARARGS | METH_KEYWORDS, NULL},
    {"load_verify_locations", (PyCFunction)(void (*)(void))context_load_verify_locations, METH_VARARGS | METH_KEYWORDS,
     NULL},
    {"set_default_verify_paths", context_set_default_verify_paths, METH_NOARGS, NULL},
    {"cert_store_stats", context_cert_store_stats, METH_NOARGS, NULL},
    {"get_ca_certs", (PyCFunction)(void (*)(void))context_get_ca_certs, METH_VARARGS | METH_KEYWORDS, NULL},
    {NULL, NULL}
};

static PyGetSetDef context_getset[] = {
    {"protocol", context_get_protocol, NULL, NULL, NULL},
    {"verify_mode", context_get_verify_mode, context_set_verify_mode, NULL, NULL},
    {"check_hostname", context_get_check_hostname, context_set_check_hostname, NULL, NULL},
    {"options", context_get_options, context_set_options, NULL, NULL},
    {"verify_flags", context_get_verify_flags, context_set_verify_flags, NULL, NULL},
    {"minimum_version", context_get_minimum_version, context_set_minimum_version, NULL, NULL},
    {"maximum_version", context_get_maximum_version, context_set_maximum_version, NULL, NULL},
    {"sni_callback", context_get_sni_callback, context_set_sni_callback, NULL, NULL},
    {"post_handshake_auth", context_get_post_handshake_auth, context_set_post_handshake_auth, NULL, NULL},
    {NULL}
};

static PyType_Slot context_slots[] = {
    {Py_tp_new, context_new},
    {Py_tp_dealloc, context_dealloc},
    {Py_tp_traverse, context_traverse},
    {Py_tp_clear, context_clear},
    {Py_tp_methods, context_methods},
    {Py_tp_getset, context_getset},
    {0, NULL}
};

static PyType_Spec context_spec = {
    .name = "_ssl._SSLContext",
    .basicsize = sizeof(context_object),
    .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC | Py_TPFLAGS_IMMUTABLETYPE,
    .slots = context_slots,
};

/* ---- module の関数 ---- */

static PyObject *
ssl_rand_bytes(PyObject *module, PyObject *arg)
{
    Py_ssize_t n = PyLong_AsSsize_t(arg);
    if (n == -1 && PyErr_Occurred()) {
        return NULL;
    }
    if (n < 0) {
        PyErr_SetString(PyExc_ValueError, "num must be positive");
        return NULL;
    }
    PyObject *out = PyBytes_FromStringAndSize(NULL, n);
    if (out == NULL) {
        return NULL;
    }
    n_result r = n ? n_random(PyBytes_AS_STRING(out), (size_t)n) : 0;
    if (r < 0) {
        Py_DECREF(out);
        raise_ssl(get_state(module)->error, SSL_ERROR_SSL, NULL, "the system entropy source failed");
        return NULL;
    }
    return out;
}

static PyObject *
ssl_rand_status(PyObject *Py_UNUSED(module), PyObject *Py_UNUSED(ignored))
{
    Py_RETURN_TRUE;   /* n_random はシステムの entropy の pool */
}

/* (cafile の環境変数, cafile, capath の環境変数, capath)：環境変数は無く、根はシステムの証明書の folder。 */
static PyObject *
ssl_get_default_verify_paths(PyObject *Py_UNUSED(module), PyObject *Py_UNUSED(ignored))
{
    return Py_BuildValue("(ssss)", "", "", "", KABI_FOLDER_CERTIFICATES);
}

static PyObject *
oid_tuple(Py_ssize_t index, const char *dotted)
{
    if (index < 0) {
        return Py_BuildValue("(iOOs)", 0, Py_None, Py_None, dotted);
    }
    const struct oid_name *o = &oid_names[index];
    return Py_BuildValue("(nsss)", index + 1, o->short_name, o->long_name, o->oid);
}

static PyObject *
ssl_txt2obj(PyObject *Py_UNUSED(module), PyObject *args, PyObject *kwds)
{
    static char *keywords[] = {"txt", "name", NULL};
    const char *txt;
    int name = 0;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|p:txt2obj", keywords, &txt, &name)) {
        return NULL;
    }
    for (size_t i = 0; i < OID_NAME_COUNT; i++) {
        const struct oid_name *o = &oid_names[i];
        if (!strcmp(o->oid, txt) || (name && (!strcmp(o->short_name, txt) || !strcmp(o->long_name, txt)))) {
            return oid_tuple((Py_ssize_t)i, o->oid);
        }
    }
    bool dotted = txt[0] >= '0' && txt[0] <= '2' && txt[1] == '.';
    for (const char *p = txt; dotted && *p; p++) {
        dotted = (*p >= '0' && *p <= '9') || (*p == '.' && p[1] >= '0' && p[1] <= '9');
    }
    if (!dotted) {
        PyErr_Format(PyExc_ValueError, "unknown object '%.100s'", txt);
        return NULL;
    }
    return oid_tuple(-1, txt);
}

static PyObject *
ssl_nid2obj(PyObject *Py_UNUSED(module), PyObject *arg)
{
    int nid = PyLong_AsInt(arg);
    if (nid == -1 && PyErr_Occurred()) {
        return NULL;
    }
    if (nid < 1 || (size_t)nid > OID_NAME_COUNT) {
        PyErr_Format(PyExc_ValueError, "unknown NID %i", nid);
        return NULL;
    }
    return oid_tuple(nid - 1, oid_names[nid - 1].oid);
}

/* 署名の方式（RFC 8446 §4.2.3 の名）：client が確かめるものと、server が作るもの（ECDSA）。 */
static PyObject *
ssl_get_sigalgs(PyObject *Py_UNUSED(module), PyObject *Py_UNUSED(ignored))
{
    return Py_BuildValue("[sssssssss]", "ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384", "ecdsa_secp521r1_sha512",
                         "rsa_pss_rsae_sha256", "rsa_pss_rsae_sha384", "rsa_pss_rsae_sha512", "rsa_pkcs1_sha256",
                         "rsa_pkcs1_sha384", "rsa_pkcs1_sha512");
}

static PyMethodDef ssl_functions[] = {
    {"RAND_bytes", ssl_rand_bytes, METH_O, "RAND_bytes(n)\nGenerate n cryptographically strong pseudo-random bytes."},
    {"RAND_status", ssl_rand_status, METH_NOARGS, "Returns True: the system entropy pool is always seeded."},
    {"get_default_verify_paths", ssl_get_default_verify_paths, METH_NOARGS,
     "Return search paths and environment vars that are used by SSLContext's set_default_verify_paths()."},
    {"txt2obj", (PyCFunction)(void (*)(void))ssl_txt2obj, METH_VARARGS | METH_KEYWORDS, NULL},
    {"nid2obj", ssl_nid2obj, METH_O, NULL},
    {"get_sigalgs", ssl_get_sigalgs, METH_NOARGS, NULL},
    {NULL, NULL}
};

/* ---- module ---- */

static int
add_exception(PyObject *module, PyObject **slot, const char *name, const char *doc, PyObject *bases)
{
    char qualified[64];
    snprintf(qualified, sizeof qualified, "ssl.%s", name);
    *slot = PyErr_NewExceptionWithDoc(qualified, doc, bases, NULL);
    return *slot == NULL ? -1 : PyModule_AddObjectRef(module, name, *slot);
}

static int
ssl_exec(PyObject *module)
{
    ssl_state *state = get_state(module);
    PyObject *socket_module = PyImport_ImportModule("_socket");
    if (socket_module == NULL) {
        return -1;
    }
    state->python_socket_type = (PyTypeObject *)PyObject_GetAttrString(socket_module, "socket");
    Py_DECREF(socket_module);
    if (state->python_socket_type == NULL) {
        return -1;
    }
    state->context_type = (PyTypeObject *)PyType_FromModuleAndSpec(module, &context_spec, NULL);
    state->socket_type = (PyTypeObject *)PyType_FromModuleAndSpec(module, &socket_spec, NULL);
    state->bio_type = (PyTypeObject *)PyType_FromModuleAndSpec(module, &bio_spec, NULL);
    if (state->context_type == NULL || state->socket_type == NULL || state->bio_type == NULL ||
        PyModule_AddObjectRef(module, "_SSLContext", (PyObject *)state->context_type) < 0 ||
        PyModule_AddObjectRef(module, "_SSLSocket", (PyObject *)state->socket_type) < 0 ||
        PyModule_AddObjectRef(module, "MemoryBIO", (PyObject *)state->bio_type) < 0) {
        return -1;
    }
    state->error = PyType_FromModuleAndSpec(module, &sslerror_spec, PyExc_OSError);
    if (state->error == NULL || PyModule_AddObjectRef(module, "SSLError", state->error) < 0) {
        return -1;
    }
    PyObject *both = PyTuple_Pack(2, state->error, PyExc_ValueError);
    int r = both == NULL ? -1 :
        add_exception(module, &state->cert_verification_error, "SSLCertVerificationError",
                      "A certificate could not be verified.", both);
    Py_XDECREF(both);
    if (r < 0 ||
        add_exception(module, &state->zero_return_error, "SSLZeroReturnError",
                      "SSL/TLS session closed cleanly.", state->error) < 0 ||
        add_exception(module, &state->want_read_error, "SSLWantReadError",
                      "Non-blocking SSL socket needs to read more data before the requested operation can be completed.",
                      state->error) < 0 ||
        add_exception(module, &state->want_write_error, "SSLWantWriteError",
                      "Non-blocking SSL socket needs to write more data before the requested operation can be completed.",
                      state->error) < 0 ||
        add_exception(module, &state->syscall_error, "SSLSyscallError",
                      "System error when attempting SSL operation.", state->error) < 0 ||
        add_exception(module, &state->eof_error, "SSLEOFError",
                      "SSL/TLS connection terminated abruptly.", state->error) < 0) {
        return -1;
    }
#define ADD(name) if (PyModule_AddIntConstant(module, #name, name) < 0) return -1
    ADD(PROTOCOL_TLS); ADD(PROTOCOL_TLS_CLIENT); ADD(PROTOCOL_TLS_SERVER);
    ADD(CERT_NONE); ADD(CERT_OPTIONAL); ADD(CERT_REQUIRED);
    ADD(PROTO_MINIMUM_SUPPORTED); ADD(PROTO_MAXIMUM_SUPPORTED); ADD(PROTO_SSLv3); ADD(PROTO_TLSv1);
    ADD(PROTO_TLSv1_1); ADD(PROTO_TLSv1_2); ADD(PROTO_TLSv1_3);
    ADD(SSL_ERROR_SSL); ADD(SSL_ERROR_WANT_READ); ADD(SSL_ERROR_WANT_WRITE); ADD(SSL_ERROR_SYSCALL);
    ADD(SSL_ERROR_ZERO_RETURN); ADD(SSL_ERROR_EOF);
    ADD(OP_ALL); ADD(OP_NO_SSLv2); ADD(OP_NO_SSLv3); ADD(OP_NO_TLSv1); ADD(OP_NO_TLSv1_1); ADD(OP_NO_TLSv1_2);
    ADD(OP_NO_TLSv1_3); ADD(OP_NO_COMPRESSION); ADD(OP_NO_TICKET); ADD(OP_NO_RENEGOTIATION);
    ADD(OP_CIPHER_SERVER_PREFERENCE); ADD(OP_SINGLE_DH_USE); ADD(OP_SINGLE_ECDH_USE);
    ADD(OP_ENABLE_MIDDLEBOX_COMPAT); ADD(OP_IGNORE_UNEXPECTED_EOF);
    ADD(VERIFY_DEFAULT); ADD(VERIFY_X509_STRICT); ADD(VERIFY_X509_TRUSTED_FIRST); ADD(VERIFY_X509_PARTIAL_CHAIN);
#undef ADD
    /* alert の番号（RFC 8446 §6、RFC 5246 §7.2、RFC 6066 §8） */
    static const struct { const char *name; int value; } alerts[] = {
        {"CLOSE_NOTIFY", 0}, {"UNEXPECTED_MESSAGE", 10}, {"BAD_RECORD_MAC", 20}, {"RECORD_OVERFLOW", 22},
        {"DECOMPRESSION_FAILURE", 30}, {"HANDSHAKE_FAILURE", 40}, {"BAD_CERTIFICATE", 42},
        {"UNSUPPORTED_CERTIFICATE", 43}, {"CERTIFICATE_REVOKED", 44}, {"CERTIFICATE_EXPIRED", 45},
        {"CERTIFICATE_UNKNOWN", 46}, {"ILLEGAL_PARAMETER", 47}, {"UNKNOWN_CA", 48}, {"ACCESS_DENIED", 49},
        {"DECODE_ERROR", 50}, {"DECRYPT_ERROR", 51}, {"PROTOCOL_VERSION", 70}, {"INSUFFICIENT_SECURITY", 71},
        {"INTERNAL_ERROR", 80}, {"USER_CANCELLED", 90}, {"NO_RENEGOTIATION", 100}, {"UNSUPPORTED_EXTENSION", 110},
        {"CERTIFICATE_UNOBTAINABLE", 111}, {"UNRECOGNIZED_NAME", 112}, {"BAD_CERTIFICATE_STATUS_RESPONSE", 113},
        {"BAD_CERTIFICATE_HASH_VALUE", 114}, {"UNKNOWN_PSK_IDENTITY", 115},
    };
    for (size_t i = 0; i < sizeof alerts / sizeof *alerts; i++) {
        char name[64];
        snprintf(name, sizeof name, "ALERT_DESCRIPTION_%s", alerts[i].name);
        if (PyModule_AddIntConstant(module, name, alerts[i].value) < 0) {
            return -1;
        }
    }
    static const struct { const char *name; bool value; } has[] = {
        {"HAS_SNI", true}, {"HAS_ECDH", true}, {"HAS_NPN", false}, {"HAS_ALPN", true}, {"HAS_SSLv2", false},
        {"HAS_SSLv3", false}, {"HAS_TLSv1", false}, {"HAS_TLSv1_1", false}, {"HAS_TLSv1_2", true},
        {"HAS_TLSv1_3", true}, {"HAS_PSK", false}, {"HAS_PSK_TLS13", false}, {"HAS_PHA", false},
    };
    for (size_t i = 0; i < sizeof has / sizeof *has; i++) {
        if (PyModule_AddObjectRef(module, has[i].name, has[i].value ? Py_True : Py_False) < 0) {
            return -1;
        }
    }
    if (PyModule_AddStringConstant(module, "OPENSSL_VERSION", "Nocturne TLS") < 0) {
        return -1;
    }
    return 0;
}

static int
ssl_traverse(PyObject *module, visitproc visit, void *arg)
{
    ssl_state *state = get_state(module);
    Py_VISIT(state->context_type);
    Py_VISIT(state->socket_type);
    Py_VISIT(state->bio_type);
    Py_VISIT(state->python_socket_type);
    Py_VISIT(state->error);
    Py_VISIT(state->zero_return_error);
    Py_VISIT(state->want_read_error);
    Py_VISIT(state->want_write_error);
    Py_VISIT(state->syscall_error);
    Py_VISIT(state->eof_error);
    Py_VISIT(state->cert_verification_error);
    return 0;
}

static int
ssl_clear(PyObject *module)
{
    ssl_state *state = get_state(module);
    Py_CLEAR(state->context_type);
    Py_CLEAR(state->socket_type);
    Py_CLEAR(state->bio_type);
    Py_CLEAR(state->python_socket_type);
    Py_CLEAR(state->error);
    Py_CLEAR(state->zero_return_error);
    Py_CLEAR(state->want_read_error);
    Py_CLEAR(state->want_write_error);
    Py_CLEAR(state->syscall_error);
    Py_CLEAR(state->eof_error);
    Py_CLEAR(state->cert_verification_error);
    return 0;
}

static void
ssl_free(void *module)
{
    (void)ssl_clear((PyObject *)module);
}

static PyModuleDef_Slot ssl_slots[] = {
    {Py_mod_exec, ssl_exec},
    {Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
    {Py_mod_gil, Py_MOD_GIL_NOT_USED},
    {0, NULL}
};

static struct PyModuleDef sslmodule = {
    PyModuleDef_HEAD_INIT,
    .m_name = "_ssl",
    .m_doc = "Implementation module for TLS socket operations.  See the socket module\nfor documentation.",
    .m_size = sizeof(ssl_state),
    .m_methods = ssl_functions,
    .m_slots = ssl_slots,
    .m_traverse = ssl_traverse,
    .m_clear = ssl_clear,
    .m_free = ssl_free,
};

PyMODINIT_FUNC
PyInit__ssl(void)
{
    return PyModuleDef_Init(&sslmodule);
}
