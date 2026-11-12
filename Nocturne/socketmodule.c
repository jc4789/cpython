/* _socket：Nocturne の Python の socket。システムの TCP と UDP（nocturne.h の網）の上に書き、BSD socket は使わない
   （ports/cpython/README.md）。

   socket は Python が思うとおり socket() の時から descriptor（Nocturne/descriptors.h）だが、TCP と UDP の handle は
   名指す物ができた時に付く：tcp_connect_start は接続を、tcp_listen は住所の上の listener を、udp_open は住所に立つ
   socket を返す。だから TCP の bind() はシステムの listen で、port はすぐ決まり（server は listen() の前に
   getsockname() を聞く）、その時から接続を受ける。listen() は accept() を許すだけ。bind() して listen() していない
   TCP の socket の connect() は、listener を閉じてその手元の端から繋ぐ。UDP の socket は bind() で handle を得るか、
   最初の sendto()、connect()、recv() で空いた port に立つ。connect() は <SYN> を出してすぐ戻る tcp_connect_start で、
   待たない socket は握手を進めたまま EINPROGRESS で返り、終わりは select() と SO_ERROR（tcp_result）が教える。

   族は AF_INET（IPv4）と AF_INET6（IPv6）。AF_INET6 の住所は (host, port, flowinfo, scope_id) で、scope_id は住所の
   zone（RFC 4007 の 11）。流れの label は送りの元のシステムが決める（RFC 6437 の 3）ので、flowinfo は読んで使わず、
   0 を返す。AF_INET6 の socket は IPv6 だけを扱い、IPV6_V6ONLY を 0 にすると "::" で両方の族に立ち、IPv4 の相手には
   IPv4-mapped の住所（RFC 4291 の 2.5.5.2）で届く。

   閉じかけの接続は listener を拒まない（SO_REUSEADDR はいつもその形）。TCP_NODELAY、SO_KEEPALIVE、TCP_KEEPIDLE、
   TCP_KEEPINTVL、TCP_KEEPCNT、SO_SNDBUF、SO_RCVBUF は TCP の選び（tcp_options）で、handle の前に置いたものは
   handle ができた時に置く。

   主のスレッドの待ちは Ctrl+C で終わり（_PyOS_NocturneWait、名前引きは _PyOS_NocturneNetCancel の取り消しの
   channel）、Python が SIGINT の処理を走らせ、処理が例外を上げなければ呼出しは続く（PEP 475）。

   Nocturne に機械の名前は無い：gethostname() は RFC 6761 が機械そのものに与える "localhost"。逆引きとサービスの表も
   無い：getnameinfo() と gethostbyaddr() は数の住所を返し（名前が要るなら失敗する）、サービスは port の数。 */
#include "Python.h"
#include "pycore_signal.h"        // _PyOS_NocturneWait(), _PyOS_NocturneNetCancel()
#include "pycore_time.h"          // _PyTime_FromSecondsObject()
#include "descriptors.h"
#include "nocturne_services.h"    // net_resolve()

#include <errno.h>
#include <stdbool.h>
#include <string.h>

/* この module の数。Python のコードはこれをそのまま返して渡す。 */
#define AF_UNSPEC 0
#define AF_INET 2
#define AF_INET6 23
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define IPPROTO_IP 0
#define IPPROTO_TCP 6             /* IANA の protocol の番号 */
#define IPPROTO_UDP 17
#define IPPROTO_IPV6 41
#define SOL_SOCKET 0xffff
#define SO_REUSEADDR 0x0004
#define SO_KEEPALIVE 0x0008
#define SO_SNDBUF 0x1001
#define SO_RCVBUF 0x1002
#define SO_ERROR 0x1007
#define SO_TYPE 0x1008
#define TCP_NODELAY 0x01
#define TCP_KEEPIDLE 0x03
#define TCP_KEEPCNT 0x10
#define TCP_KEEPINTVL 0x11
#define IPV6_V6ONLY 0x1b
#define SHUT_RD 0
#define SHUT_WR 1
#define SHUT_RDWR 2
#define AI_PASSIVE 0x01
#define AI_CANONNAME 0x02
#define AI_NUMERICHOST 0x04
#define AI_NUMERICSERV 0x08
#define NI_NUMERICHOST 0x01
#define NI_NUMERICSERV 0x02
#define NI_NOFQDN 0x04
#define NI_NAMEREQD 0x08
#define NI_DGRAM 0x10
#define NI_MAXHOST 1025
#define NI_MAXSERV 32
#define EAI_AGAIN 2
#define EAI_BADFLAGS 3
#define EAI_FAIL 4
#define EAI_FAMILY 5
#define EAI_MEMORY 6
#define EAI_NODATA 7
#define EAI_NONAME 8
#define EAI_SERVICE 9
#define EAI_SOCKTYPE 10
#define INADDR_ANY 0x00000000u
#define INADDR_LOOPBACK 0x7f000001u
#define INADDR_BROADCAST 0xffffffffu
#define INADDR_NONE 0xffffffffu

#define NS_PER_SECOND 1000000000ull

typedef struct {
    PyTypeObject *socket_type;
    PyObject *herror;
    PyObject *gaierror;
    PyTime_t default_timeout;     /* -1：待つ */
} socket_state;

static struct PyModuleDef socketmodule;

static inline socket_state *
get_state(PyObject *module)
{
    return (socket_state *)PyModule_GetState(module);
}

static socket_state *
type_state(PyTypeObject *type)
{
    PyObject *module = PyType_GetModuleByDef(type, &socketmodule);
    return module == NULL ? NULL : get_state(module);
}

typedef struct {
    PyObject_HEAD
    int fd;                       /* 閉じるか外した後は -1 */
    int family, type, proto;
    PyTime_t timeout;             /* -1：待つ、0：待たない */
    struct n_net_endpoint bound;  /* bind() の端 */
    bool has_bound;
    struct n_net_endpoint peer;   /* UDP の socket の connect() の相手 */
    bool has_peer;
    bool listener;                /* handle は TCP の listener（bind、listen） */
    bool listening;               /* listen() が来た */
    bool read_shut;               /* shutdown(SHUT_RD) */
    bool only_v6;                 /* AF_INET6：IPv6 だけ（IPV6_V6ONLY） */
    int reuse_address;
    struct n_net_tcp_options options; /* handle の前に置いた TCP の選び */
    bool options_kept;
} sock_object;

/* TCP の選びの初めの値（net_abi.h）。輪の大きさの 0 はシステムが決める大きさ。 */
static const struct n_net_tcp_options tcp_options_start = {
    .keepalive_idle = N_TCP_KEEPALIVE_START_IDLE,
    .keepalive_interval = N_TCP_KEEPALIVE_START_INTERVAL,
    .give_up = N_TCP_GIVE_UP_START,
    .keepalive_probes = N_TCP_KEEPALIVE_START_PROBES,
};

/* ---- 誤り ---- */

/* 網の呼出しの負の n_result の errno。 */
static int
net_errno(n_result r)
{
    switch (r) {
    case -N_ERR_TOO_LARGE: return EMSGSIZE;
    case -N_ERR_NOT_READY: return EAGAIN;
    case -N_ERR_NOT_FOUND: return EADDRNOTAVAIL;  /* この機械の住所でない */
    default: return (int)-r;
    }
}

static PyObject *
set_error(n_result r)
{
    errno = net_errno(r);
    return PyErr_SetFromErrno(PyExc_OSError);
}

static PyObject *
set_timeout(void)
{
    PyErr_SetString(PyExc_TimeoutError, "timed out");
    return NULL;
}

static PyObject *
set_gaierror(socket_state *state, int code)
{
    const char *text;
    switch (code) {
    case EAI_AGAIN: text = "Temporary failure in name resolution"; break;
    case EAI_BADFLAGS: text = "Bad value for ai_flags"; break;
    case EAI_FAIL: text = "Non-recoverable failure in name resolution"; break;
    case EAI_FAMILY: text = "Address family not supported"; break;
    case EAI_MEMORY: text = "Memory allocation failure"; break;
    case EAI_NODATA: text = "No address associated with hostname"; break;
    case EAI_NONAME: text = "Name or service not known"; break;
    case EAI_SERVICE: text = "Servname not supported for ai_socktype"; break;
    case EAI_SOCKTYPE: text = "ai_socktype not supported"; break;
    default: text = "Unknown error"; break;
    }
    PyObject *value = Py_BuildValue("(is)", code, text);
    if (value != NULL) {
        PyErr_SetObject(state->gaierror, value);
        Py_DECREF(value);
    }
    return NULL;
}

/* ---- 住所 ---- */

static uint8_t
ip_family(int family)
{
    return family == AF_INET6 ? N_NET_IPV6 : N_NET_IPV4;
}

static int
address_family(const struct n_net_ip *ip)
{
    return ip->family == N_NET_IPV6 ? AF_INET6 : AF_INET;
}

static struct n_net_ip
ipv6_loopback(void)
{
    struct n_net_ip ip = {.family = N_NET_IPV6};
    ip.bytes[15] = 1;
    return ip;
}

/* IPv4-mapped の IPv6 の住所か（RFC 4291 の 2.5.5.2：::ffff:0:0/96）。 */
static bool
is_mapped(const struct n_net_ip *ip)
{
    static const uint8_t prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    return ip->family == N_NET_IPV6 && memcmp(ip->bytes, prefix, sizeof prefix) == 0;
}

static struct n_net_ip
mapped(const struct n_net_ip *v4)
{
    struct n_net_ip ip = {.family = N_NET_IPV6};
    ip.bytes[10] = ip.bytes[11] = 0xff;
    memcpy(ip.bytes + 12, v4->bytes, 4);
    return ip;
}

/* 住所の文字（zone は付けない）。 */
static PyObject *
ip_text(struct n_net_ip ip)
{
    char text[N_NET_IP_TEXT_BYTES];
    ip.zone = 0;
    n_net_ip_format(&ip, text, sizeof text);
    return PyUnicode_FromString(text);
}

/* 端を族 family の Python の住所に：AF_INET は (host, port)、AF_INET6 は (host, port, flowinfo, scope_id)。
   AF_INET6 は IPv4 の端を IPv4-mapped の住所で、どの族でもない端（N_NET_ANY）を "::" で見せる。 */
static PyObject *
make_address(int family, const struct n_net_endpoint *e)
{
    struct n_net_ip ip = e->ip;
    if (ip.family == N_NET_ANY) {
        ip = (struct n_net_ip){.family = ip_family(family)};
    }
    else if (family == AF_INET6 && ip.family == N_NET_IPV4) {
        ip = mapped(&ip);
    }
    PyObject *host = ip_text(ip);
    if (host == NULL) {
        return NULL;
    }
    if (family == AF_INET6) {
        return Py_BuildValue("(NiII)", host, (int)e->port, 0u, (unsigned int)ip.zone);
    }
    return Py_BuildValue("(Ni)", host, (int)e->port);
}

/* 名前 name の族 family（AF_UNSPEC は両方）の住所を RFC 6724 の順で *out（PyMem_Free する）に。数か、gaierror（か
   Python の SIGINT の処理の例外）つきの -1。網のサービスの答えを GIL を放して待ち、Ctrl+C は待ちを取り消す。 */
static Py_ssize_t
resolve(socket_state *state, const char *name, int family, struct n_net_ip **out)
{
    uint32_t families = family == AF_INET ? N_DNS_FAMILY_IPV4 : family == AF_INET6 ? N_DNS_FAMILY_IPV6 : 0;
    size_t cap = 8;
    struct n_net_ip *list = NULL;
    for (;;) {
        struct n_net_ip *grown = PyMem_Realloc(list, cap * sizeof *list);
        if (grown == NULL) {
            PyMem_Free(list);
            PyErr_NoMemory();
            return -1;
        }
        list = grown;
        n_handle cancel;
        if (_PyOS_NocturneNetCancel(&cancel) < 0) {
            if (errno != EINTR) {
                PyErr_SetFromErrno(PyExc_OSError);
            }
            else if (PyErr_CheckSignals() == 0) {
                continue;
            }
            PyMem_Free(list);
            return -1;
        }
        struct n_dns_result result;
        n_result r;
        Py_BEGIN_ALLOW_THREADS
        r = net_resolve(name, families, list, cap, &result, NULL, cancel);
        Py_END_ALLOW_THREADS
        if (r >= 0 && result.count > cap) {
            /* 全部が入る場所で引き直す（答えはサービスの cache にある） */
            cap = result.count;
            continue;
        }
        if (r >= 0 && result.count > 0) {
            *out = list;
            return (Py_ssize_t)result.count;
        }
        int code;
        switch (result.status) {
        case N_DNS_CANCELLED:
            if (PyErr_CheckSignals() < 0) {
                PyMem_Free(list);
                return -1;
            }
            continue;
        case N_DNS_OK:
        case N_DNS_NODATA: code = EAI_NODATA; break;
        case N_DNS_NXDOMAIN: code = EAI_NONAME; break;
        case N_DNS_SERVFAIL:
        case N_DNS_TIMEOUT:
        case N_DNS_UNREACHABLE: code = EAI_AGAIN; break;
        case N_DNS_RESOURCE: code = EAI_MEMORY; break;
        default: code = EAI_FAIL; break;
        }
        PyMem_Free(list);
        set_gaierror(state, code);
        return -1;
    }
}

/* host の名前の文字（str は IDNA で）。*bytes は放す物（NULL 可）。NULL は例外つき。 */
static const char *
host_name(PyObject *host, PyObject **bytes)
{
    *bytes = NULL;
    if (PyUnicode_Check(host)) {
        *bytes = PyUnicode_AsEncodedString(host, "idna", NULL);
        return *bytes == NULL ? NULL : PyBytes_AS_STRING(*bytes);
    }
    if (PyBytes_Check(host)) {
        return PyBytes_AS_STRING(host);
    }
    PyErr_Format(PyExc_TypeError, "str, bytes or bytearray expected, not %T", host);
    return NULL;
}

/* 住所の組の host を族 family の住所に：''（どの住所でもない）、'<broadcast>'（IPv4 の limited broadcast）、住所の
   文字、引く名前。0 か、例外つきの -1。 */
static int
host_address(socket_state *state, PyObject *host, int family, struct n_net_ip *ip)
{
    PyObject *bytes;
    const char *name = host_name(host, &bytes);
    if (name == NULL) {
        return -1;
    }
    int r = 0;
    if (name[0] == '\0') {
        *ip = (struct n_net_ip){.family = ip_family(family)};
    }
    else if (strcmp(name, "<broadcast>") == 0) {
        if (family != AF_INET) {
            PyErr_SetString(PyExc_OSError, "address family mismatched");
            r = -1;
        }
        else {
            *ip = n_net_ip_v4(255, 255, 255, 255);
        }
    }
    else if (n_net_ip_parse(name, ip)) {
        if (ip->family != ip_family(family)) {
            set_gaierror(state, EAI_FAMILY);
            r = -1;
        }
    }
    else {
        struct n_net_ip *list;
        if (resolve(state, name, family, &list) < 0) {
            r = -1;
        }
        else {
            *ip = list[0];
            PyMem_Free(list);
        }
    }
    Py_XDECREF(bytes);
    return r;
}

/* 族 family の Python の住所：AF_INET は (host, port)、AF_INET6 は (host, port[, flowinfo[, scope_id]])。0 か、
   例外つきの -1。 */
static int
parse_address(socket_state *state, int family, PyObject *object, const char *caller, struct n_net_endpoint *out)
{
    const char *name = family == AF_INET6 ? "AF_INET6" : "AF_INET";
    if (!PyTuple_Check(object)) {
        PyErr_Format(PyExc_TypeError, "%s(): %s address must be tuple, not %T", caller, name, object);
        return -1;
    }
    PyObject *host;
    int port;
    unsigned int flowinfo = 0, scope_id = 0;
    if (family == AF_INET6) {
        if (!PyArg_ParseTuple(object, "Oi|II;AF_INET6 address must be a tuple (host, port[, flowinfo[, scopeid]])",
                              &host, &port, &flowinfo, &scope_id)) {
            return -1;
        }
        if (flowinfo > 0xfffff) {
            PyErr_Format(PyExc_OverflowError, "%s(): flowinfo must be 0-1048575.", caller);
            return -1;
        }
    }
    else if (!PyArg_ParseTuple(object, "Oi;AF_INET address must be a pair (host, port)", &host, &port)) {
        return -1;
    }
    if (port < 0 || port > 0xffff) {
        PyErr_Format(PyExc_OverflowError, "%s(): port must be 0-65535.", caller);
        return -1;
    }
    struct n_net_ip ip;
    if (host_address(state, host, family, &ip) < 0) {
        return -1;
    }
    if (scope_id != 0) {
        ip.zone = scope_id;
    }
    *out = (struct n_net_endpoint){.ip = ip, .port = (uint16_t)port};
    return 0;
}

/* socket が使う端：両方の族の AF_INET6 の socket（IPV6_V6ONLY が 0）は IPv4-mapped の住所で IPv4 に届き、"::" で
   両方の族に立つ。 */
static struct n_net_endpoint
sock_endpoint(const sock_object *s, struct n_net_endpoint e)
{
    if (s->family == AF_INET6 && !s->only_v6) {
        if (is_mapped(&e.ip)) {
            e.ip = n_net_ip_v4(e.ip.bytes[12], e.ip.bytes[13], e.ip.bytes[14], e.ip.bytes[15]);
        }
        else if (n_net_ip_is_unspecified(&e.ip)) {
            e.ip = (struct n_net_ip){.family = N_NET_ANY};
        }
    }
    return e;
}

/* bind() の前の socket の端：族のどの住所でもない住所と、システムが選ぶ port。 */
static struct n_net_endpoint
sock_unbound(const sock_object *s)
{
    return sock_endpoint(s, (struct n_net_endpoint){.ip = {.family = ip_family(s->family)}});
}

static int
sock_address(socket_state *state, const sock_object *s, PyObject *object, const char *caller,
             struct n_net_endpoint *out)
{
    if (parse_address(state, s->family, object, caller, out) < 0) {
        return -1;
    }
    *out = sock_endpoint(s, *out);
    return 0;
}

static bool
same_endpoint(const struct n_net_endpoint *a, const struct n_net_endpoint *b)
{
    return a->port == b->port && n_net_ip_equal(&a->ip, &b->ip);
}

/* ---- 待ち ---- */

/* socket の handle への呼出しの一度：結果か、deadline（0：待たない）が先に来れば -N_ERR_NOT_READY か
   -N_ERR_TIMEOUT。 */
typedef n_result (*sock_try)(n_handle h, void *data, uint64_t deadline);

static uint64_t
sock_deadline(const sock_object *s)
{
    if (s->timeout < 0) {
        return N_CLOCK_NEVER;
    }
    return s->timeout == 0 ? 0 : n_clock_after((uint64_t)s->timeout);
}

static bool
not_yet(n_result r)
{
    return r == -N_ERR_NOT_READY || r == -N_ERR_TIMEOUT;
}

/* 済むか socket の timeout が過ぎるまで h に call を繰り返し、間に interest（N_EVENT_*）を GIL を放して待つ。結果か、
   例外つきの -1：待たない socket は BlockingIOError、TimeoutError、OSError、SIGINT の処理の例外。 */
static n_result
sock_call(sock_object *s, n_handle h, unsigned interest, sock_try call, void *data)
{
    uint64_t deadline = sock_deadline(s);
    for (;;) {
        bool interruptible = deadline != 0 && _PyOS_NocturneInterruptible();
        bool interrupted = false;
        n_result r;
        Py_BEGIN_ALLOW_THREADS
        for (;;) {
            r = call(h, data, interruptible ? 0 : deadline);
            if (!interruptible || !not_yet(r)) {
                break;
            }
            int woke = _PyOS_NocturneWait(h, interest | N_EVENT_CLOSED, NULL, 0, deadline);
            if (woke < 0) {
                interrupted = true;
                break;
            }
            if (woke == 0) {
                r = -N_ERR_TIMEOUT;
                break;
            }
        }
        Py_END_ALLOW_THREADS
        if (interrupted) {
            if (PyErr_CheckSignals() < 0) {
                return -1;
            }
            continue;
        }
        if (not_yet(r)) {
            if (deadline == 0) {
                errno = EAGAIN;
                PyErr_SetFromErrno(PyExc_OSError);
            }
            else {
                set_timeout();
            }
            return -1;
        }
        if (r < 0) {
            set_error(r);
            return -1;
        }
        return r;
    }
}

/* ---- socket の handle ---- */

static int
sock_check(sock_object *s)
{
    if (s->fd < 0) {
        errno = EBADF;
        PyErr_SetFromErrno(PyExc_OSError);
        return -1;
    }
    return 0;
}

/* UDP の socket の handle。まだ無ければ bind() の端（無ければ空いた port）に立てる。 */
static n_handle
udp_handle(sock_object *s)
{
    if (sock_check(s) < 0) {
        return -1;
    }
    n_handle h = _Py_fd_handle(s->fd);
    if (h >= 0) {
        return h;
    }
    struct n_net_endpoint at = s->has_bound ? s->bound : sock_unbound(s);
    h = udp_open(&at);
    if (h < 0) {
        set_error(h);
        return -1;
    }
    if (_Py_fd_attach(s->fd, h) < 0) {
        /* ほかのスレッドが先に付けた */
        n_handle_close(h);
        h = _Py_fd_handle(s->fd);
        if (h < 0) {
            PyErr_SetFromErrno(PyExc_OSError);
        }
    }
    return h;
}

static void
sock_set_timeout(sock_object *s, PyTime_t timeout)
{
    s->timeout = timeout;
    if (s->fd >= 0) {
        /* descriptor の os.read と os.write は待つ socket でだけ待つ */
        (void)_Py_fd_set_blocking(s->fd, timeout < 0);
    }
}

/* ---- TCP の選び ---- */

/* TCP の socket の選び：handle（接続か listener）のものか、handle の前に置いたもの。handle があれば 1、無ければ 0、
   例外つきの -1。 */
static int
sock_tcp_options(sock_object *s, struct n_net_tcp_options *out)
{
    n_handle h = _Py_fd_handle(s->fd);
    if (h < 0) {
        *out = s->options;
        return 0;
    }
    n_result r = tcp_options(h, NULL, out);
    if (r < 0) {
        set_error(r);
        return -1;
    }
    return 1;
}

/* 選びを handle に置くか、handle が無ければ handle ができた時に置く分として持つ。0 か、例外つきの -1。 */
static int
sock_set_tcp_options(sock_object *s, const struct n_net_tcp_options *set)
{
    n_handle h = _Py_fd_handle(s->fd);
    if (h < 0) {
        s->options = *set;
        s->options_kept = true;
        return 0;
    }
    n_result r = tcp_options(h, set, NULL);
    if (r < 0) {
        set_error(r);
        return -1;
    }
    return 0;
}

/* できたばかりの TCP の handle を socket に付ける：handle の前に置いた選びを置いてから。0 か、例外つきの -1（h は
   閉じた）。 */
static int
tcp_attach(sock_object *s, n_handle h)
{
    n_result r = s->options_kept ? tcp_options(h, &s->options, NULL) : 0;
    if (r < 0) {
        n_handle_close(h);
        set_error(r);
        return -1;
    }
    if (_Py_fd_attach(s->fd, h) < 0) {
        n_handle_close(h);
        PyErr_SetFromErrno(PyExc_OSError);
        return -1;
    }
    return 0;
}

/* ---- socket の型 ---- */

static int
sock_init(PyObject *self, PyObject *args, PyObject *kwargs)
{
    sock_object *s = (sock_object *)self;
    static char *keywords[] = {"family", "type", "proto", "fileno", NULL};
    int family = -1, type = -1, proto = -1;
    PyObject *fileno = Py_None;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|iiiO:socket", keywords,
                                     &family, &type, &proto, &fileno)) {
        return -1;
    }
    socket_state *state = type_state(Py_TYPE(self));
    if (state == NULL) {
        return -1;
    }
    if (PySys_Audit("socket.__new__", "Oiii", self, family, type, proto) < 0) {
        return -1;
    }
    int fd;
    int kind;
    /* 渡された descriptor の handle の端：族、IPv6 だけか、listener か */
    struct n_net_endpoint local = {0}, remote = {0};
    bool known = false;
    if (fileno != Py_None) {
        if (PyFloat_Check(fileno)) {
            PyErr_SetString(PyExc_TypeError, "integer argument expected, got float");
            return -1;
        }
        fd = PyLong_AsInt(fileno);
        if (fd == -1 && PyErr_Occurred()) {
            return -1;
        }
        if (fd < 0) {
            PyErr_SetString(PyExc_ValueError, "negative file descriptor");
            return -1;
        }
        kind = _Py_fd_kind(fd);
        if (kind < 0) {
            PyErr_SetFromErrno(PyExc_OSError);
            return -1;
        }
        if (kind != N_KIND_TCP && kind != N_KIND_UDP) {
            errno = ENOTSOCK;
            PyErr_SetFromErrno(PyExc_OSError);
            return -1;
        }
        n_handle h = _Py_fd_handle(fd);
        known = h >= 0 && n_net_endpoints(h, &local, &remote) >= 0;
        if (family == -1) {
            family = known && local.ip.family != N_NET_IPV4 ? AF_INET6 : AF_INET;
        }
        if (type == -1) {
            type = kind == N_KIND_TCP ? SOCK_STREAM : SOCK_DGRAM;
        }
        if (proto == -1) {
            proto = kind == N_KIND_TCP ? IPPROTO_TCP : IPPROTO_UDP;
        }
    }
    else {
        if (family == -1) {
            family = AF_INET;
        }
        if (type == -1) {
            type = SOCK_STREAM;
        }
        if (proto == -1) {
            proto = 0;
        }
        if (family != AF_INET && family != AF_INET6) {
            errno = EAFNOSUPPORT;
            PyErr_SetFromErrno(PyExc_OSError);
            return -1;
        }
        if (type == SOCK_STREAM && (proto == 0 || proto == IPPROTO_TCP)) {
            kind = N_KIND_TCP;
        }
        else if (type == SOCK_DGRAM && (proto == 0 || proto == IPPROTO_UDP)) {
            kind = N_KIND_UDP;
        }
        else {
            errno = type == SOCK_STREAM || type == SOCK_DGRAM ? EPROTONOSUPPORT : EPROTOTYPE;
            PyErr_SetFromErrno(PyExc_OSError);
            return -1;
        }
        fd = _Py_fd_socket(kind);
        if (fd < 0) {
            PyErr_SetFromErrno(PyExc_OSError);
            return -1;
        }
    }
    if (s->fd >= 0) {
        (void)_Py_fd_close(s->fd);
    }
    s->fd = fd;
    s->family = family;
    s->type = type;
    s->proto = proto;
    s->has_bound = s->has_peer = s->read_shut = false;
    /* listener の handle の相手の端はどの族でもない（n_net_endpoints） */
    s->listener = s->listening = known && kind == N_KIND_TCP && remote.ip.family == N_NET_ANY;
    s->only_v6 = !known || local.ip.family == N_NET_IPV6;
    s->reuse_address = 0;
    s->options = tcp_options_start;
    s->options_kept = false;
    sock_set_timeout(s, state->default_timeout);
    return 0;
}

static PyObject *
sock_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    sock_object *s = (sock_object *)type->tp_alloc(type, 0);
    if (s != NULL) {
        s->fd = -1;
        s->timeout = -1;
    }
    return (PyObject *)s;
}

static void
sock_finalize(PyObject *self)
{
    sock_object *s = (sock_object *)self;
    if (s->fd < 0) {
        return;
    }
    PyObject *exc = PyErr_GetRaisedException();
    if (PyErr_ResourceWarning(self, 1, "unclosed %R", self)) {
        if (PyErr_ExceptionMatches(PyExc_Warning)) {
            PyErr_FormatUnraisable("Exception ignored while finalizing socket %R", self);
        }
        PyErr_Clear();
    }
    (void)_Py_fd_close(s->fd);
    s->fd = -1;
    PyErr_SetRaisedException(exc);
}

/* 型は GC の型（__slots__ のある下位の型と同じ）：subtype_dealloc はここを呼ぶ前に object をまた追う。 */
static int
sock_traverse(PyObject *self, visitproc visit, void *arg)
{
    Py_VISIT(Py_TYPE(self));
    return 0;
}

static void
sock_dealloc(PyObject *self)
{
    if (PyObject_CallFinalizerFromDealloc(self) < 0) {
        return;
    }
    PyTypeObject *type = Py_TYPE(self);
    PyObject_GC_UnTrack(self);
    type->tp_free(self);
    Py_DECREF(type);
}

static PyObject *
sock_repr(PyObject *self)
{
    sock_object *s = (sock_object *)self;
    return PyUnicode_FromFormat("<socket object, fd=%d, family=%d, type=%d, proto=%d>",
                                s->fd, s->family, s->type, s->proto);
}

static bool
is_tcp(const sock_object *s)
{
    return s->type == SOCK_STREAM;
}

/* ---- 接続 ---- */

static n_result
try_accept(n_handle h, void *data, uint64_t deadline)
{
    return tcp_accept(h, (struct n_net_endpoint *)data, deadline);
}

static PyObject *
sock_accept(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    sock_object *s = (sock_object *)self;
    if (!is_tcp(s)) {
        errno = EOPNOTSUPP;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    if (sock_check(s) < 0) {
        return NULL;
    }
    if (!s->listening) {
        errno = EINVAL;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    n_handle h = _Py_fd_handle(s->fd);
    if (h < 0) {
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    struct n_net_endpoint remote = {0};
    n_result c = sock_call(s, h, N_EVENT_RECEIVABLE, try_accept, &remote);
    if (c < 0) {
        return NULL;
    }
    int fd = _Py_fd_adopt((n_handle)c, 1, 1);
    if (fd < 0) {
        n_handle_close((n_handle)c);
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    PyObject *address = make_address(s->family, &remote);
    if (address == NULL) {
        (void)_Py_fd_close(fd);
        return NULL;
    }
    return Py_BuildValue("(iN)", fd, address);
}

/* socket の bind() の端（無ければ族のどの住所でもない住所とシステムが選ぶ port）のシステムの listener。accept() が
   取る前に backlog 個（0：システムの数）の接続を持つ。0 か、例外つきの -1。 */
static int
tcp_listener(sock_object *s, int backlog)
{
    if (_Py_fd_handle(s->fd) >= 0) {
        errno = EISCONN;
        PyErr_SetFromErrno(PyExc_OSError);
        return -1;
    }
    struct n_net_endpoint at = s->has_bound ? s->bound : sock_unbound(s);
    n_handle h = tcp_listen(&at, backlog);
    if (h < 0) {
        set_error(h);
        return -1;
    }
    if (tcp_attach(s, h) < 0) {
        return -1;
    }
    s->listener = true;
    return 0;
}

static PyObject *
sock_bind(PyObject *self, PyObject *object)
{
    sock_object *s = (sock_object *)self;
    socket_state *state = type_state(Py_TYPE(self));
    struct n_net_endpoint at;
    if (state == NULL || sock_check(s) < 0 || sock_address(state, s, object, "bind", &at) < 0) {
        return NULL;
    }
    if (PySys_Audit("socket.bind", "OO", self, object) < 0) {
        return NULL;
    }
    if (s->has_bound || _Py_fd_handle(s->fd) >= 0) {
        errno = EINVAL;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    s->bound = at;
    s->has_bound = true;
    if (!is_tcp(s)) {
        if (udp_handle(s) < 0) {
            s->has_bound = false;
            return NULL;
        }
        Py_RETURN_NONE;
    }
    if (tcp_listener(s, 0) < 0) {
        s->has_bound = false;
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *
sock_listen(PyObject *self, PyObject *args)
{
    sock_object *s = (sock_object *)self;
    int backlog = 0;  /* システムの既定 */
    if (!PyArg_ParseTuple(args, "|i:listen", &backlog) || sock_check(s) < 0) {
        return NULL;
    }
    if (!is_tcp(s)) {
        errno = EOPNOTSUPP;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    if (!s->listener && tcp_listener(s, backlog < 0 ? 0 : backlog) < 0) {
        return NULL;
    }
    s->listening = true;
    Py_RETURN_NONE;
}

/* connect の終わり方：0 か、例外つきの -1。error があれば例外の代わりに errno をそこへ置く（connect_ex）。 */
static int
connect_failed(int code, int *error)
{
    if (error != NULL) {
        *error = code;
        return 0;
    }
    if (code == ETIMEDOUT) {
        set_timeout();
    }
    else {
        errno = code;
        PyErr_SetFromErrno(PyExc_OSError);
    }
    return -1;
}

/* at への TCP の接続。待たない socket は握手を進めたまま返り（BlockingIOError EINPROGRESS）、select() は握手が
   終わると書けると言い、SO_ERROR が終わり方を言う。失敗した接続は socket のもので、socket はその後に閉じる。 */
static int
sock_tcp_connect(sock_object *s, struct n_net_endpoint at, int *error)
{
    n_handle h = _Py_fd_handle(s->fd);
    if (h >= 0 && (!s->listener || s->listening)) {
        return connect_failed(!s->listener && tcp_result(h) == -N_ERR_NOT_READY ? EALREADY : EISCONN, error);
    }
    struct n_net_endpoint local;
    const struct n_net_endpoint *from = NULL;
    if (h >= 0) {
        /* bind() した socket：listener を閉じ、その手元の端から繋ぐ */
        n_result r = n_net_endpoints(h, &local, NULL);
        if (r < 0) {
            set_error(r);
            return -1;
        }
        if (_Py_fd_detach(s->fd, h) < 0) {
            PyErr_SetFromErrno(PyExc_OSError);
            return -1;
        }
        n_handle_close(h);
        s->listener = false;
        from = &local;
    }
    h = tcp_connect_start(&at, from);
    if (h < 0) {
        return connect_failed(net_errno(h), error);
    }
    if (tcp_attach(s, h) < 0) {
        return -1;
    }
    uint64_t deadline = sock_deadline(s);
    for (;;) {
        n_result result = tcp_result(h);
        if (result == 0) {
            return 0;
        }
        if (result != -N_ERR_NOT_READY) {
            return connect_failed(net_errno(result), error);
        }
        if (s->timeout == 0) {
            return connect_failed(EINPROGRESS, error);
        }
        int woke;
        Py_BEGIN_ALLOW_THREADS
        woke = _PyOS_NocturneWait(h, N_EVENT_SENDABLE | N_EVENT_CLOSED, NULL, 0, deadline);
        Py_END_ALLOW_THREADS
        if (woke < 0) {
            if (PyErr_CheckSignals() < 0) {
                return -1;
            }
        }
        else if (woke == 0) {
            /* 諦めた呼出しが握手を終える */
            (void)tcp_cancel(h);
            return connect_failed(ETIMEDOUT, error);
        }
    }
}

static int
sock_connect_common(sock_object *s, PyObject *object, int *error)
{
    socket_state *state = type_state(Py_TYPE(s));
    struct n_net_endpoint at;
    if (state == NULL || sock_check(s) < 0 || sock_address(state, s, object, "connect", &at) < 0) {
        return -1;
    }
    if (PySys_Audit("socket.connect", "OO", (PyObject *)s, object) < 0) {
        return -1;
    }
    if (is_tcp(s)) {
        return sock_tcp_connect(s, at, error);
    }
    if (udp_handle(s) < 0) {
        return -1;
    }
    s->peer = at;
    s->has_peer = true;
    return 0;
}

static PyObject *
sock_connect(PyObject *self, PyObject *object)
{
    if (sock_connect_common((sock_object *)self, object, NULL) < 0) {
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *
sock_connect_ex(PyObject *self, PyObject *object)
{
    int error = 0;
    if (sock_connect_common((sock_object *)self, object, &error) < 0) {
        return NULL;
    }
    return PyLong_FromLong(error);
}

/* ---- descriptor ---- */

static PyObject *
sock_close(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    sock_object *s = (sock_object *)self;
    int fd = s->fd;
    if (fd >= 0) {
        s->fd = -1;
        if (_Py_fd_close(fd) < 0) {
            return PyErr_SetFromErrno(PyExc_OSError);
        }
    }
    Py_RETURN_NONE;
}

static PyObject *
sock_detach(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    sock_object *s = (sock_object *)self;
    int fd = s->fd;
    s->fd = -1;
    return PyLong_FromLong(fd);
}

static PyObject *
sock_fileno(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    return PyLong_FromLong(((sock_object *)self)->fd);
}

static PyObject *
sock_getsockname(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    sock_object *s = (sock_object *)self;
    if (sock_check(s) < 0) {
        return NULL;
    }
    n_handle h = _Py_fd_handle(s->fd);
    struct n_net_endpoint local;
    if (h < 0) {
        local = s->has_bound ? s->bound : sock_unbound(s);
    }
    else {
        n_result r = n_net_endpoints(h, &local, NULL);
        if (r < 0) {
            return set_error(r);
        }
    }
    return make_address(s->family, &local);
}

static PyObject *
sock_getpeername(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    sock_object *s = (sock_object *)self;
    if (sock_check(s) < 0) {
        return NULL;
    }
    if (!is_tcp(s)) {
        if (!s->has_peer) {
            errno = ENOTCONN;
            return PyErr_SetFromErrno(PyExc_OSError);
        }
        return make_address(s->family, &s->peer);
    }
    n_handle h = s->listener ? -1 : _Py_fd_handle(s->fd);
    if (h < 0) {
        errno = ENOTCONN;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    struct n_net_endpoint remote;
    n_result r = n_net_endpoints(h, NULL, &remote);
    if (r < 0) {
        return set_error(r);
    }
    return make_address(s->family, &remote);
}

/* TCP の選び（tcp_options）の欄の一つか。 */
static bool
is_tcp_option(int level, int option)
{
    return (level == IPPROTO_TCP &&
            (option == TCP_NODELAY || option == TCP_KEEPIDLE || option == TCP_KEEPINTVL || option == TCP_KEEPCNT)) ||
           (level == SOL_SOCKET && (option == SO_KEEPALIVE || option == SO_SNDBUF || option == SO_RCVBUF));
}

static PyObject *
sock_getsockopt(PyObject *self, PyObject *args)
{
    sock_object *s = (sock_object *)self;
    int level, option, buflen = 0;
    if (!PyArg_ParseTuple(args, "ii|i:getsockopt", &level, &option, &buflen) || sock_check(s) < 0) {
        return NULL;
    }
    long long value;
    if (level == SOL_SOCKET && option == SO_REUSEADDR) {
        value = s->reuse_address;
    }
    else if (level == SOL_SOCKET && option == SO_TYPE) {
        value = s->type;
    }
    else if (level == SOL_SOCKET && option == SO_ERROR) {
        /* 接続の終わり方。待たない connect はここで知る */
        n_handle h = is_tcp(s) && !s->listener ? _Py_fd_handle(s->fd) : -1;
        n_result result = h >= 0 ? tcp_result(h) : 0;
        value = result < 0 && result != -N_ERR_NOT_READY ? net_errno(result) : 0;
    }
    else if (level == IPPROTO_IPV6 && option == IPV6_V6ONLY && s->family == AF_INET6) {
        value = s->only_v6;
    }
    else if (is_tcp(s) && is_tcp_option(level, option)) {
        struct n_net_tcp_options o;
        if (sock_tcp_options(s, &o) < 0) {
            return NULL;
        }
        switch (option) {
        case TCP_NODELAY: value = o.no_delay != 0; break;
        case SO_KEEPALIVE: value = o.keepalive_on != 0; break;
        case TCP_KEEPIDLE: value = (long long)(o.keepalive_idle / NS_PER_SECOND); break;
        case TCP_KEEPINTVL: value = (long long)(o.keepalive_interval / NS_PER_SECOND); break;
        case TCP_KEEPCNT: value = o.keepalive_probes; break;
        /* handle の前の 0 はシステムが決める大きさ */
        case SO_SNDBUF: value = (long long)o.send_bytes; break;
        default: value = (long long)o.receive_bytes; break;
        }
    }
    else {
        errno = ENOPROTOOPT;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    if (buflen > 0) {
        int32_t word = (int32_t)value;
        return PyBytes_FromStringAndSize((const char *)&word, Py_MIN(buflen, (int)sizeof word));
    }
    return PyLong_FromLongLong(value);
}

static PyObject *
sock_setsockopt(PyObject *self, PyObject *args)
{
    sock_object *s = (sock_object *)self;
    int level, option;
    PyObject *object;
    if (!PyArg_ParseTuple(args, "iiO:setsockopt", &level, &option, &object) || sock_check(s) < 0) {
        return NULL;
    }
    long long value;
    if (PyIndex_Check(object)) {
        value = PyLong_AsLongLong(object);
        if (value == -1 && PyErr_Occurred()) {
            return NULL;
        }
    }
    else {
        Py_buffer view;
        if (PyObject_GetBuffer(object, &view, PyBUF_SIMPLE) < 0) {
            return NULL;
        }
        int32_t word = 0;
        memcpy(&word, view.buf, Py_MIN((size_t)view.len, sizeof word));
        PyBuffer_Release(&view);
        value = word;
    }
    if (level == SOL_SOCKET && option == SO_REUSEADDR) {
        s->reuse_address = value != 0;
        Py_RETURN_NONE;
    }
    if (level == IPPROTO_IPV6 && option == IPV6_V6ONLY && s->family == AF_INET6) {
        /* 立った後の socket の族は変わらない */
        if (_Py_fd_handle(s->fd) >= 0) {
            errno = EINVAL;
            return PyErr_SetFromErrno(PyExc_OSError);
        }
        s->only_v6 = value != 0;
        Py_RETURN_NONE;
    }
    if (!is_tcp(s) || !is_tcp_option(level, option)) {
        errno = ENOPROTOOPT;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    bool flag = option == TCP_NODELAY || option == SO_KEEPALIVE;
    if (!flag && (value <= 0 || (unsigned long long)value > UINT64_MAX / NS_PER_SECOND ||
                  (option == TCP_KEEPCNT && value > UINT32_MAX))) {
        errno = EINVAL;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    struct n_net_tcp_options o;
    int held = sock_tcp_options(s, &o);
    if (held < 0) {
        return NULL;
    }
    if (held) {
        /* handle の輪の大きさの 0 は変えない */
        o.send_bytes = o.receive_bytes = 0;
    }
    switch (option) {
    case TCP_NODELAY: o.no_delay = value != 0; break;
    case SO_KEEPALIVE: o.keepalive_on = value != 0; break;
    case TCP_KEEPIDLE: o.keepalive_idle = (uint64_t)value * NS_PER_SECOND; break;
    case TCP_KEEPINTVL: o.keepalive_interval = (uint64_t)value * NS_PER_SECOND; break;
    case TCP_KEEPCNT: o.keepalive_probes = (uint32_t)value; break;
    case SO_SNDBUF: o.send_bytes = (uint64_t)value; break;
    default: o.receive_bytes = (uint64_t)value; break;
    }
    if (sock_set_tcp_options(s, &o) < 0) {
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *
sock_gettimeout(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    sock_object *s = (sock_object *)self;
    if (s->timeout < 0) {
        Py_RETURN_NONE;
    }
    return PyFloat_FromDouble(PyTime_AsSecondsDouble(s->timeout));
}

/* Python が渡す timeout：None（-1）か、0 以上の秒。 */
static int
parse_timeout(PyObject *object, PyTime_t *timeout)
{
    if (object == Py_None) {
        *timeout = -1;
        return 0;
    }
    if (_PyTime_FromSecondsObject(timeout, object, _PyTime_ROUND_TIMEOUT) < 0) {
        return -1;
    }
    if (*timeout < 0) {
        PyErr_SetString(PyExc_ValueError, "Timeout value out of range");
        return -1;
    }
    return 0;
}

static PyObject *
sock_settimeout(PyObject *self, PyObject *object)
{
    PyTime_t timeout;
    if (parse_timeout(object, &timeout) < 0) {
        return NULL;
    }
    sock_set_timeout((sock_object *)self, timeout);
    Py_RETURN_NONE;
}

static PyObject *
sock_getblocking(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    sock_object *s = (sock_object *)self;
    if (sock_check(s) < 0) {
        return NULL;
    }
    return PyBool_FromLong(s->timeout != 0);
}

static PyObject *
sock_setblocking(PyObject *self, PyObject *object)
{
    int blocking = PyObject_IsTrue(object);
    if (blocking < 0) {
        return NULL;
    }
    sock_set_timeout((sock_object *)self, blocking ? -1 : 0);
    Py_RETURN_NONE;
}

/* ---- データ ---- */

struct transfer {
    char *buf;
    size_t len;
    struct n_net_endpoint address;    /* 受けは送り手、送りは宛先 */
};

static n_result
try_tcp_recv(n_handle h, void *data, uint64_t deadline)
{
    struct transfer *t = data;
    return tcp_recv(h, t->buf, t->len, deadline);
}

static n_result
try_udp_recv(n_handle h, void *data, uint64_t deadline)
{
    struct transfer *t = data;
    struct n_net_received info;
    n_result r = udp_receive(h, t->buf, t->len, &info, deadline, -1);
    if (r >= 0) {
        t->address = info.from;
        /* 長い datagram は buf に入った分だけ */
        if ((uint64_t)r > t->len) {
            r = (n_result)t->len;
        }
    }
    return r;
}

/* 流れのバイトか、一つの datagram（繋いだ UDP の socket は繋いだ相手のものだけ）とその送り手（from、NULL：要らない）
   を buf に：数か、例外つきの -1。 */
static Py_ssize_t
sock_receive(sock_object *s, char *buf, size_t len, struct n_net_endpoint *from)
{
    if (sock_check(s) < 0) {
        return -1;
    }
    if (s->read_shut) {
        return 0;
    }
    struct transfer t = {.buf = buf, .len = len};
    if (is_tcp(s)) {
        n_handle h = s->listener ? -1 : _Py_fd_handle(s->fd);
        if (h < 0) {
            errno = ENOTCONN;
            PyErr_SetFromErrno(PyExc_OSError);
            return -1;
        }
        if (len == 0) {
            return 0;
        }
        return sock_call(s, h, N_EVENT_RECEIVABLE, try_tcp_recv, &t);
    }
    n_handle h = udp_handle(s);
    if (h < 0) {
        return -1;
    }
    for (;;) {
        n_result r = sock_call(s, h, N_EVENT_RECEIVABLE, try_udp_recv, &t);
        if (r < 0) {
            return -1;
        }
        if (s->has_peer && !same_endpoint(&t.address, &s->peer)) {
            continue;
        }
        if (from != NULL) {
            *from = t.address;
        }
        return r;
    }
}

static PyObject *
sock_recv(PyObject *self, PyObject *args)
{
    Py_ssize_t size;
    int flags = 0;
    if (!PyArg_ParseTuple(args, "n|i:recv", &size, &flags)) {
        return NULL;
    }
    if (size < 0) {
        PyErr_SetString(PyExc_ValueError, "negative buffersize in recv");
        return NULL;
    }
    if (flags != 0) {
        errno = EOPNOTSUPP;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    PyBytesWriter *writer = PyBytesWriter_Create(size);
    if (writer == NULL) {
        return NULL;
    }
    Py_ssize_t got = sock_receive((sock_object *)self, PyBytesWriter_GetData(writer), (size_t)size, NULL);
    if (got < 0) {
        PyBytesWriter_Discard(writer);
        return NULL;
    }
    return PyBytesWriter_FinishWithSize(writer, got);
}

static PyObject *
sock_recv_into(PyObject *self, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"buffer", "nbytes", "flags", NULL};
    Py_buffer view;
    Py_ssize_t nbytes = 0;
    int flags = 0;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "w*|ni:recv_into", keywords, &view, &nbytes, &flags)) {
        return NULL;
    }
    PyObject *result = NULL;
    if (nbytes < 0) {
        PyErr_SetString(PyExc_ValueError, "negative buffersize in recv_into");
    }
    else if (nbytes > view.len) {
        PyErr_SetString(PyExc_ValueError, "buffer too small for requested bytes");
    }
    else if (flags != 0) {
        errno = EOPNOTSUPP;
        PyErr_SetFromErrno(PyExc_OSError);
    }
    else {
        Py_ssize_t got = sock_receive((sock_object *)self, view.buf, (size_t)(nbytes ? nbytes : view.len), NULL);
        if (got >= 0) {
            result = PyLong_FromSsize_t(got);
        }
    }
    PyBuffer_Release(&view);
    return result;
}

/* 受けたものの送り手：流れのバイトには言う送り手が無い。 */
static PyObject *
sender_address(sock_object *s, const struct n_net_endpoint *from)
{
    return is_tcp(s) ? Py_NewRef(Py_None) : make_address(s->family, from);
}

static PyObject *
sock_recvfrom(PyObject *self, PyObject *args)
{
    Py_ssize_t size;
    int flags = 0;
    if (!PyArg_ParseTuple(args, "n|i:recvfrom", &size, &flags)) {
        return NULL;
    }
    if (size < 0) {
        PyErr_SetString(PyExc_ValueError, "negative buffersize in recvfrom");
        return NULL;
    }
    if (flags != 0) {
        errno = EOPNOTSUPP;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    PyBytesWriter *writer = PyBytesWriter_Create(size);
    if (writer == NULL) {
        return NULL;
    }
    struct n_net_endpoint from = {0};
    Py_ssize_t got = sock_receive((sock_object *)self, PyBytesWriter_GetData(writer), (size_t)size, &from);
    if (got < 0) {
        PyBytesWriter_Discard(writer);
        return NULL;
    }
    PyObject *data = PyBytesWriter_FinishWithSize(writer, got);
    if (data == NULL) {
        return NULL;
    }
    return Py_BuildValue("(NN)", data, sender_address((sock_object *)self, &from));
}

static PyObject *
sock_recvfrom_into(PyObject *self, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"buffer", "nbytes", "flags", NULL};
    Py_buffer view;
    Py_ssize_t nbytes = 0;
    int flags = 0;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "w*|ni:recvfrom_into", keywords, &view, &nbytes, &flags)) {
        return NULL;
    }
    PyObject *result = NULL;
    if (nbytes < 0) {
        PyErr_SetString(PyExc_ValueError, "negative buffersize in recvfrom_into");
    }
    else if (nbytes > view.len) {
        PyErr_SetString(PyExc_ValueError, "nbytes is greater than the length of the buffer");
    }
    else if (flags != 0) {
        errno = EOPNOTSUPP;
        PyErr_SetFromErrno(PyExc_OSError);
    }
    else {
        struct n_net_endpoint from = {0};
        Py_ssize_t got = sock_receive((sock_object *)self, view.buf, (size_t)(nbytes ? nbytes : view.len), &from);
        if (got >= 0) {
            result = Py_BuildValue("(nN)", got, sender_address((sock_object *)self, &from));
        }
    }
    PyBuffer_Release(&view);
    return result;
}

static n_result
try_tcp_send(n_handle h, void *data, uint64_t deadline)
{
    struct transfer *t = data;
    return deadline == 0 ? tcp_send_some(h, t->buf, t->len) : tcp_send_until(h, t->buf, t->len, deadline);
}

/* 一つの datagram を送る。送りの輪に入らなければ deadline まで空きを待つ。 */
static n_result
try_udp_send(n_handle h, void *data, uint64_t deadline)
{
    struct transfer *t = data;
    for (;;) {
        n_result r = udp_send_to(h, &t->address, t->buf, t->len);
        if (r != -N_ERR_NOT_READY || deadline == 0) {
            return r;
        }
        n_result woke = n_net_wait(h, N_EVENT_SENDABLE, deadline, -1);
        if (woke < 0) {
            return woke;
        }
        if (woke == 0) {
            return -N_ERR_TIMEOUT;
        }
    }
}

/* buf の先頭を流れに、または全部を一つの datagram で to（NULL：繋いだ相手）へ送る：数か、例外つきの -1。 */
static Py_ssize_t
sock_send_bytes(sock_object *s, const char *buf, size_t len, const struct n_net_endpoint *to)
{
    if (sock_check(s) < 0) {
        return -1;
    }
    struct transfer t = {.buf = (char *)buf, .len = len};
    if (is_tcp(s)) {
        if (to != NULL) {
            errno = EISCONN;
            PyErr_SetFromErrno(PyExc_OSError);
            return -1;
        }
        n_handle h = s->listener ? -1 : _Py_fd_handle(s->fd);
        if (h < 0) {
            errno = ENOTCONN;
            PyErr_SetFromErrno(PyExc_OSError);
            return -1;
        }
        return sock_call(s, h, N_EVENT_SENDABLE, try_tcp_send, &t);
    }
    if (to == NULL) {
        if (!s->has_peer) {
            errno = EDESTADDRREQ;
            PyErr_SetFromErrno(PyExc_OSError);
            return -1;
        }
        to = &s->peer;
    }
    n_handle h = udp_handle(s);
    if (h < 0) {
        return -1;
    }
    t.address = *to;
    return sock_call(s, h, N_EVENT_SENDABLE, try_udp_send, &t);
}

static PyObject *
sock_send(PyObject *self, PyObject *args)
{
    Py_buffer view;
    int flags = 0;
    if (!PyArg_ParseTuple(args, "y*|i:send", &view, &flags)) {
        return NULL;
    }
    PyObject *result = NULL;
    if (flags != 0) {
        errno = EOPNOTSUPP;
        PyErr_SetFromErrno(PyExc_OSError);
    }
    else {
        Py_ssize_t sent = sock_send_bytes((sock_object *)self, view.buf, (size_t)view.len, NULL);
        if (sent >= 0) {
            result = PyLong_FromSsize_t(sent);
        }
    }
    PyBuffer_Release(&view);
    return result;
}

static PyObject *
sock_sendall(PyObject *self, PyObject *args)
{
    sock_object *s = (sock_object *)self;
    Py_buffer view;
    int flags = 0;
    if (!PyArg_ParseTuple(args, "y*|i:sendall", &view, &flags)) {
        return NULL;
    }
    PyObject *result = NULL;
    if (flags != 0) {
        errno = EOPNOTSUPP;
        PyErr_SetFromErrno(PyExc_OSError);
        goto done;
    }
    if (!is_tcp(s)) {
        if (sock_send_bytes(s, view.buf, (size_t)view.len, NULL) >= 0) {
            result = Py_NewRef(Py_None);
        }
        goto done;
    }
    /* timeout は全体に掛かる */
    PyTime_t timeout = s->timeout;
    PyTime_t deadline = 0;
    if (timeout > 0) {
        deadline = _PyDeadline_Init(timeout);
    }
    const char *at = view.buf;
    Py_ssize_t left = view.len;
    while (left > 0) {
        if (timeout > 0) {
            s->timeout = _PyDeadline_Get(deadline);
            if (s->timeout <= 0) {
                s->timeout = timeout;
                set_timeout();
                goto done;
            }
        }
        Py_ssize_t sent = sock_send_bytes(s, at, (size_t)left, NULL);
        s->timeout = timeout;
        if (sent < 0) {
            goto done;
        }
        at += sent;
        left -= sent;
        if (left > 0 && PyErr_CheckSignals() < 0) {
            goto done;
        }
    }
    result = Py_NewRef(Py_None);
done:
    PyBuffer_Release(&view);
    return result;
}

static PyObject *
sock_sendto(PyObject *self, PyObject *args)
{
    sock_object *s = (sock_object *)self;
    socket_state *state = type_state(Py_TYPE(self));
    if (state == NULL) {
        return NULL;
    }
    Py_buffer view;
    int flags = 0;
    PyObject *address;
    Py_ssize_t count = PyTuple_GET_SIZE(args);
    if (count == 2) {
        if (!PyArg_ParseTuple(args, "y*O:sendto", &view, &address)) {
            return NULL;
        }
    }
    else if (count == 3) {
        if (!PyArg_ParseTuple(args, "y*iO:sendto", &view, &flags, &address)) {
            return NULL;
        }
    }
    else {
        PyErr_Format(PyExc_TypeError, "sendto() takes 2 or 3 arguments (%zd given)", count);
        return NULL;
    }
    PyObject *result = NULL;
    struct n_net_endpoint to;
    if (flags != 0) {
        errno = EOPNOTSUPP;
        PyErr_SetFromErrno(PyExc_OSError);
    }
    else if (sock_address(state, s, address, "sendto", &to) == 0 &&
             PySys_Audit("socket.sendto", "OO", self, address) == 0) {
        Py_ssize_t sent = sock_send_bytes(s, view.buf, (size_t)view.len, &to);
        if (sent >= 0) {
            result = PyLong_FromSsize_t(sent);
        }
    }
    PyBuffer_Release(&view);
    return result;
}

static PyObject *
sock_shutdown(PyObject *self, PyObject *object)
{
    sock_object *s = (sock_object *)self;
    int how = PyLong_AsInt(object);
    if (how == -1 && PyErr_Occurred()) {
        return NULL;
    }
    if (how != SHUT_RD && how != SHUT_WR && how != SHUT_RDWR) {
        errno = EINVAL;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    if (sock_check(s) < 0) {
        return NULL;
    }
    n_handle h = s->listener ? -1 : _Py_fd_handle(s->fd);
    if (h < 0 && !(!is_tcp(s) && s->has_peer)) {
        errno = ENOTCONN;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    if (how != SHUT_WR) {
        s->read_shut = true;
    }
    if (how != SHUT_RD && is_tcp(s)) {
        n_result r = tcp_finish(h);
        if (r < 0) {
            return set_error(r);
        }
    }
    Py_RETURN_NONE;
}

static PyMethodDef sock_methods[] = {
    {"_accept", sock_accept, METH_NOARGS,
     "_accept() -> (integer, address info)\n\n"
     "Wait for an incoming connection.  Return a new socket file descriptor\n"
     "representing the connection, and the address of the client."},
    {"bind", sock_bind, METH_O,
     "bind(address)\n\nBind the socket to a local address: a pair (host, port) for AF_INET,\n"
     "a tuple (host, port[, flowinfo[, scope_id]]) for AF_INET6."},
    {"close", sock_close, METH_NOARGS, "close()\n\nClose the socket."},
    {"connect", sock_connect, METH_O,
     "connect(address)\n\nConnect the socket to a remote address."},
    {"connect_ex", sock_connect_ex, METH_O,
     "connect_ex(address) -> errno\n\nThis is like connect(address), but returns an error code\n"
     "instead of raising an exception when an error occurs."},
    {"detach", sock_detach, METH_NOARGS,
     "detach()\n\nClose the socket object without closing the underlying file descriptor."},
    {"fileno", sock_fileno, METH_NOARGS, "fileno() -> integer\n\nReturn the socket's file descriptor."},
    {"getpeername", sock_getpeername, METH_NOARGS,
     "getpeername() -> address info\n\nReturn the address of the remote endpoint."},
    {"getsockname", sock_getsockname, METH_NOARGS,
     "getsockname() -> address info\n\nReturn the address of the local endpoint."},
    {"getsockopt", sock_getsockopt, METH_VARARGS,
     "getsockopt(level, option[, buffersize]) -> value\n\nGet a socket option."},
    {"setsockopt", sock_setsockopt, METH_VARARGS,
     "setsockopt(level, option, value: int | buffer)\n\nSet a socket option."},
    {"gettimeout", sock_gettimeout, METH_NOARGS,
     "gettimeout() -> timeout\n\nReturns the timeout in seconds (float) associated with socket\n"
     "operations. A timeout of None indicates that timeouts on socket\n"
     "operations are disabled."},
    {"settimeout", sock_settimeout, METH_O,
     "settimeout(timeout)\n\nSet a timeout on socket operations.  'timeout' can be a float,\n"
     "giving in seconds, or None.  Setting a timeout of None disables\n"
     "the timeout feature and is equivalent to setblocking(1).\n"
     "Setting a timeout of zero is the same as setblocking(0)."},
    {"getblocking", sock_getblocking, METH_NOARGS,
     "getblocking()\n\nReturns True if socket is in blocking mode, or False if it\nis in non-blocking mode."},
    {"setblocking", sock_setblocking, METH_O,
     "setblocking(flag)\n\nSet the socket to blocking (flag is true) or non-blocking (false)."},
    {"listen", sock_listen, METH_VARARGS,
     "listen([backlog])\n\nEnable a server to accept connections.  A socket that bind() gave\n"
     "an address takes connections from then on, as many as the system holds;\n"
     "on one without, backlog is the number of connections the system holds\n"
     "before refusing new ones, and without it the system chooses."},
    {"recv", sock_recv, METH_VARARGS,
     "recv(buffersize[, flags]) -> data\n\nReceive up to buffersize bytes from the socket."},
    {"recv_into", _PyCFunction_CAST(sock_recv_into), METH_VARARGS | METH_KEYWORDS,
     "recv_into(buffer, [nbytes[, flags]]) -> nbytes_read\n\n"
     "A version of recv() that stores its data into a buffer rather than creating\na new string."},
    {"recvfrom", sock_recvfrom, METH_VARARGS,
     "recvfrom(buffersize[, flags]) -> (data, address info)\n\n"
     "Like recv(buffersize, flags) but also return the sender's address info."},
    {"recvfrom_into", _PyCFunction_CAST(sock_recvfrom_into), METH_VARARGS | METH_KEYWORDS,
     "recvfrom_into(buffer[, nbytes[, flags]]) -> (nbytes, address info)\n\n"
     "Like recv_into(buffer[, nbytes[, flags]]) but also return the sender's address info."},
    {"send", sock_send, METH_VARARGS,
     "send(data[, flags]) -> count\n\nSend a data string to the socket.  Return the number of bytes\n"
     "sent; this may be less than len(data) if the network is busy."},
    {"sendall", sock_sendall, METH_VARARGS,
     "sendall(data[, flags])\n\nSend a data string to the socket.  This calls send() repeatedly\n"
     "until all data is sent.  If an error occurs, it's impossible\n"
     "to tell how much data has been sent."},
    {"sendto", sock_sendto, METH_VARARGS,
     "sendto(data[, flags], address) -> count\n\n"
     "Like send(data, flags) but allows specifying the destination address."},
    {"shutdown", sock_shutdown, METH_O,
     "shutdown(flag)\n\nShut down the reading side of the socket (flag == SHUT_RD), the writing side\n"
     "of the socket (flag == SHUT_WR), or both ends (flag == SHUT_RDWR)."},
    {NULL, NULL}
};

static PyMemberDef sock_members[] = {
    {"family", Py_T_INT, offsetof(sock_object, family), Py_READONLY, "the socket family"},
    {"type", Py_T_INT, offsetof(sock_object, type), Py_READONLY, "the socket type"},
    {"proto", Py_T_INT, offsetof(sock_object, proto), Py_READONLY, "the socket protocol"},
    {NULL}
};

static PyGetSetDef sock_getset[] = {
    {"timeout", (getter)sock_gettimeout, NULL, "the socket timeout"},
    {NULL}
};

static PyType_Slot sock_slots[] = {
    {Py_tp_new, sock_new},
    {Py_tp_init, sock_init},
    {Py_tp_finalize, sock_finalize},
    {Py_tp_dealloc, sock_dealloc},
    {Py_tp_traverse, sock_traverse},
    {Py_tp_repr, sock_repr},
    {Py_tp_methods, sock_methods},
    {Py_tp_members, sock_members},
    {Py_tp_getset, sock_getset},
    {Py_tp_doc, (void *)
     "socket(family=AF_INET, type=SOCK_STREAM, proto=0) -> socket object\n"
     "socket(family=-1, type=-1, proto=-1, fileno=None) -> socket object\n\n"
     "Open a socket of the given type.  The family argument specifies the\n"
     "address family: AF_INET (the default) or AF_INET6.  The type\n"
     "argument specifies whether this is a stream (SOCK_STREAM, this is the\n"
     "default) or datagram (SOCK_DGRAM) socket.  If a file descriptor is given\n"
     "as fileno, the socket is made of it."},
    {0, NULL}
};

static PyType_Spec sock_spec = {
    .name = "_socket.socket",
    .basicsize = sizeof(sock_object),
    .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC | Py_TPFLAGS_IMMUTABLETYPE,
    .slots = sock_slots,
};

/* ---- module の関数 ---- */

static PyObject *
socket_getaddrinfo(PyObject *module, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {"host", "port", "family", "type", "proto", "flags", NULL};
    socket_state *state = get_state(module);
    PyObject *host, *port_object;
    int family = AF_UNSPEC, type = 0, proto = 0, flags = 0;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OO|iiii:getaddrinfo", keywords,
                                     &host, &port_object, &family, &type, &proto, &flags)) {
        return NULL;
    }
    if (PySys_Audit("socket.getaddrinfo", "OOiii", host, port_object, family, type, proto) < 0) {
        return NULL;
    }
    long port = 0;
    if (PyLong_Check(port_object)) {
        port = PyLong_AsLong(port_object);
        if (port == -1 && PyErr_Occurred()) {
            return NULL;
        }
    }
    else if (PyUnicode_Check(port_object) || PyBytes_Check(port_object)) {
        const char *text = PyUnicode_Check(port_object) ? PyUnicode_AsUTF8(port_object)
                                                         : PyBytes_AS_STRING(port_object);
        if (text == NULL) {
            return NULL;
        }
        char *end;
        port = strtol(text, &end, 10);
        if (text[0] == '\0' || *end != '\0') {
            /* サービスの表は無い */
            return set_gaierror(state, EAI_SERVICE);
        }
    }
    else if (port_object != Py_None) {
        PyErr_SetString(PyExc_OSError, "Int or String expected");
        return NULL;
    }
    if (port < 0 || port > 0xffff) {
        return set_gaierror(state, EAI_SERVICE);
    }
    if (family != AF_UNSPEC && family != AF_INET && family != AF_INET6) {
        return set_gaierror(state, EAI_FAMILY);
    }
    if (type != 0 && type != SOCK_STREAM && type != SOCK_DGRAM) {
        return set_gaierror(state, EAI_SOCKTYPE);
    }
    if ((type == SOCK_STREAM && proto != 0 && proto != IPPROTO_TCP) ||
        (type == SOCK_DGRAM && proto != 0 && proto != IPPROTO_UDP) ||
        (type == 0 && proto != 0 && proto != IPPROTO_TCP && proto != IPPROTO_UDP)) {
        return set_gaierror(state, EAI_SERVICE);
    }
    if (flags & ~(AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST | AI_NUMERICSERV)) {
        return set_gaierror(state, EAI_BADFLAGS);
    }

    struct n_net_ip fixed[2];
    struct n_net_ip *ips = fixed;
    Py_ssize_t count = 0;
    PyObject *name_bytes = NULL;
    const char *name = NULL;
    if (host == Py_None) {
        /* 名前の無い host：AI_PASSIVE はどの住所でもない住所、ほかは loopback（RFC 6724 の順で IPv6 が先） */
        bool passive = flags & AI_PASSIVE;
        if (family != AF_INET) {
            fixed[count++] = passive ? (struct n_net_ip){.family = N_NET_IPV6} : ipv6_loopback();
        }
        if (family != AF_INET6) {
            fixed[count++] = passive ? (struct n_net_ip){.family = N_NET_IPV4} : n_net_ip_v4(127, 0, 0, 1);
        }
    }
    else {
        if (PyUnicode_Check(host) || PyBytes_Check(host)) {
            name = host_name(host, &name_bytes);
            if (name == NULL) {
                return NULL;
            }
        }
        else {
            PyErr_SetString(PyExc_TypeError, "getaddrinfo() argument 1 must be string or None");
            return NULL;
        }
        if (n_net_ip_parse(name, &fixed[0])) {
            if (family != AF_UNSPEC && fixed[0].family != ip_family(family)) {
                Py_XDECREF(name_bytes);
                return set_gaierror(state, EAI_FAMILY);
            }
            count = 1;
        }
        else if (flags & AI_NUMERICHOST) {
            Py_XDECREF(name_bytes);
            return set_gaierror(state, EAI_NONAME);
        }
        else {
            count = resolve(state, name, family, &ips);
            if (count < 0) {
                Py_XDECREF(name_bytes);
                return NULL;
            }
        }
    }
    PyObject *list = PyList_New(0);
    for (Py_ssize_t i = 0; list != NULL && i < count; i++) {
        static const int types[] = {SOCK_STREAM, SOCK_DGRAM};
        int af = address_family(&ips[i]);
        struct n_net_endpoint e = {.ip = ips[i], .port = (uint16_t)port};
        for (size_t k = 0; k < Py_ARRAY_LENGTH(types); k++) {
            if (type != 0 && type != types[k]) {
                continue;
            }
            int protocol = types[k] == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP;
            if (proto != 0 && proto != protocol) {
                continue;
            }
            const char *canonical = i == 0 && (flags & AI_CANONNAME) && name != NULL ? name : "";
            PyObject *entry = Py_BuildValue("(iiisN)", af, types[k], protocol, canonical, make_address(af, &e));
            if (entry == NULL || PyList_Append(list, entry) < 0) {
                Py_XDECREF(entry);
                Py_CLEAR(list);
                break;
            }
            Py_DECREF(entry);
        }
    }
    if (ips != fixed) {
        PyMem_Free(ips);
    }
    Py_XDECREF(name_bytes);
    return list;
}

static PyObject *
socket_getnameinfo(PyObject *module, PyObject *args)
{
    socket_state *state = get_state(module);
    PyObject *address;
    int flags;
    if (!PyArg_ParseTuple(args, "Oi:getnameinfo", &address, &flags)) {
        return NULL;
    }
    if (!PyTuple_Check(address)) {
        PyErr_SetString(PyExc_TypeError, "getnameinfo() argument 1 must be a tuple");
        return NULL;
    }
    const char *host;
    int port;
    unsigned int flowinfo = 0, scope_id = 0;
    if (!PyArg_ParseTuple(address, "si|II;getnameinfo(): illegal sockaddr argument",
                          &host, &port, &flowinfo, &scope_id)) {
        return NULL;
    }
    if (flowinfo > 0xfffff) {
        PyErr_SetString(PyExc_OverflowError, "getnameinfo(): flowinfo must be 0-1048575.");
        return NULL;
    }
    if (port < 0 || port > 0xffff) {
        PyErr_SetString(PyExc_OverflowError, "getnameinfo(): port must be 0-65535.");
        return NULL;
    }
    if (PySys_Audit("socket.getnameinfo", "(O)", address) < 0) {
        return NULL;
    }
    /* 住所は数の文字だけ（名前は引かない） */
    struct n_net_ip ip;
    if (!n_net_ip_parse(host, &ip)) {
        return set_gaierror(state, EAI_NONAME);
    }
    if (ip.family == N_NET_IPV4 && PyTuple_GET_SIZE(address) != 2) {
        PyErr_SetString(PyExc_OSError, "IPv4 sockaddr must be 2 tuple");
        return NULL;
    }
    if (ip.family == N_NET_IPV6 && scope_id != 0) {
        ip.zone = scope_id;
    }
    /* 逆引きは無い：数の形。名前を求めるなら失敗する */
    if (flags & NI_NAMEREQD) {
        return set_gaierror(state, EAI_NONAME);
    }
    char text[N_NET_IP_TEXT_BYTES];
    n_net_ip_format(&ip, text, sizeof text);
    return Py_BuildValue("(sN)", text, PyUnicode_FromFormat("%d", port));
}

static PyObject *
socket_gethostbyname(PyObject *module, PyObject *args)
{
    socket_state *state = get_state(module);
    PyObject *host;
    if (!PyArg_ParseTuple(args, "O:gethostbyname", &host)) {
        return NULL;
    }
    if (PySys_Audit("socket.gethostbyname", "O", args) < 0) {
        return NULL;
    }
    struct n_net_ip ip;
    if (host_address(state, host, AF_INET, &ip) < 0) {
        return NULL;
    }
    return ip_text(ip);
}

static PyObject *
socket_gethostbyname_ex(PyObject *module, PyObject *args)
{
    socket_state *state = get_state(module);
    const char *name;
    if (!PyArg_ParseTuple(args, "et:gethostbyname_ex", "idna", &name)) {
        return NULL;
    }
    PyObject *result = NULL;
    struct n_net_ip literal;
    struct n_net_ip *ips = &literal;
    Py_ssize_t count = 1;
    if (PySys_Audit("socket.gethostbyname", "O", args) < 0) {
        goto done;
    }
    if (!n_net_ip_parse(name, &literal)) {
        count = resolve(state, name, AF_INET, &ips);
        if (count < 0) {
            goto done;
        }
    }
    else if (literal.family != N_NET_IPV4) {
        set_gaierror(state, EAI_FAMILY);
        goto done;
    }
    PyObject *addresses = PyList_New(count);
    if (addresses == NULL) {
        goto done;
    }
    for (Py_ssize_t i = 0; i < count; i++) {
        PyObject *item = ip_text(ips[i]);
        if (item == NULL) {
            Py_DECREF(addresses);
            goto done;
        }
        PyList_SET_ITEM(addresses, i, item);
    }
    result = Py_BuildValue("(s[]N)", name, addresses);
done:
    if (ips != &literal) {
        PyMem_Free(ips);
    }
    PyMem_Free((void *)name);
    return result;
}

static PyObject *
socket_gethostbyaddr(PyObject *module, PyObject *args)
{
    socket_state *state = get_state(module);
    const char *name;
    if (!PyArg_ParseTuple(args, "et:gethostbyaddr", "idna", &name)) {
        return NULL;
    }
    PyObject *result = NULL;
    struct n_net_ip ip;
    if (PySys_Audit("socket.gethostbyaddr", "O", args) < 0) {
        goto done;
    }
    if (!n_net_ip_parse(name, &ip)) {
        struct n_net_ip *list;
        if (resolve(state, name, AF_UNSPEC, &list) < 0) {
            goto done;
        }
        ip = list[0];
        PyMem_Free(list);
    }
    if (n_net_ip_is_loopback(&ip)) {
        /* RFC 6761 の 6.3：loopback の住所は機械そのもの、"localhost" */
        result = Py_BuildValue("(s[][N])", "localhost", ip_text(ip));
    }
    else {
        /* 逆引きは無い */
        PyObject *value = Py_BuildValue("(is)", 1, "Unknown host");
        if (value != NULL) {
            PyErr_SetObject(state->herror, value);
            Py_DECREF(value);
        }
    }
done:
    PyMem_Free((void *)name);
    return result;
}

static PyObject *
socket_gethostname(PyObject *module, PyObject *Py_UNUSED(ignored))
{
    if (PySys_Audit("socket.gethostname", NULL) < 0) {
        return NULL;
    }
    /* Nocturne に機械の名前は無い。RFC 6761 はそれを "localhost" と呼ぶ */
    return PyUnicode_FromString("localhost");
}

static PyObject *
socket_getservbyname(PyObject *module, PyObject *args)
{
    const char *name, *proto = NULL;
    if (!PyArg_ParseTuple(args, "s|s:getservbyname", &name, &proto)) {
        return NULL;
    }
    if (PySys_Audit("socket.getservbyname", "ss", name, proto) < 0) {
        return NULL;
    }
    /* Nocturne にサービスの表は無い */
    PyErr_SetString(PyExc_OSError, "service/proto not found");
    return NULL;
}

static PyObject *
socket_getservbyport(PyObject *module, PyObject *args)
{
    int port;
    const char *proto = NULL;
    if (!PyArg_ParseTuple(args, "i|s:getservbyport", &port, &proto)) {
        return NULL;
    }
    if (port < 0 || port > 0xffff) {
        PyErr_SetString(PyExc_OverflowError, "getservbyport: port must be 0-65535.");
        return NULL;
    }
    if (PySys_Audit("socket.getservbyport", "is", port, proto) < 0) {
        return NULL;
    }
    PyErr_SetString(PyExc_OSError, "port/proto not found");
    return NULL;
}

static PyObject *
socket_getprotobyname(PyObject *module, PyObject *args)
{
    const char *name;
    if (!PyArg_ParseTuple(args, "s:getprotobyname", &name)) {
        return NULL;
    }
    /* システムにある protocol の IANA の番号 */
    if (strcmp(name, "ip") == 0) {
        return PyLong_FromLong(IPPROTO_IP);
    }
    if (strcmp(name, "tcp") == 0) {
        return PyLong_FromLong(IPPROTO_TCP);
    }
    if (strcmp(name, "udp") == 0) {
        return PyLong_FromLong(IPPROTO_UDP);
    }
    if (strcmp(name, "ipv6") == 0) {
        return PyLong_FromLong(IPPROTO_IPV6);
    }
    PyErr_SetString(PyExc_OSError, "protocol not found");
    return NULL;
}

static PyObject *
socket_close(PyObject *module, PyObject *object)
{
    int fd = PyLong_AsInt(object);
    if (fd == -1 && PyErr_Occurred()) {
        return NULL;
    }
    if (_Py_fd_close(fd) < 0) {
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    Py_RETURN_NONE;
}

static PyObject *
socket_dup(PyObject *module, PyObject *object)
{
    int fd = PyLong_AsInt(object);
    if (fd == -1 && PyErr_Occurred()) {
        return NULL;
    }
    int copy = _Py_fd_dup(fd);
    if (copy < 0) {
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    return PyLong_FromLong(copy);
}

static PyObject *
socket_ntohs(PyObject *module, PyObject *object)
{
    unsigned long x = PyLong_AsUnsignedLong(object);
    if (x == (unsigned long)-1 && PyErr_Occurred()) {
        return NULL;
    }
    if (x > 0xffff) {
        PyErr_SetString(PyExc_OverflowError, "ntohs: Python int too large to convert to C 16-bit unsigned integer");
        return NULL;
    }
    return PyLong_FromUnsignedLong(__builtin_bswap16((uint16_t)x));
}

static PyObject *
socket_ntohl(PyObject *module, PyObject *object)
{
    unsigned long x = PyLong_AsUnsignedLong(object);
    if (x == (unsigned long)-1 && PyErr_Occurred()) {
        return NULL;
    }
    if (x > 0xffffffffUL) {
        PyErr_SetString(PyExc_OverflowError, "int larger than 32 bits");
        return NULL;
    }
    return PyLong_FromUnsignedLong(__builtin_bswap32((uint32_t)x));
}

/* inet_aton の形：a、a.b（b は 24 bit）、a.b.c（c は 16 bit）、a.b.c.d。数はそれぞれ 10 進、8 進（0...）、16 進
   （0x...）。 */
static bool
aton(const char *s, uint32_t *ip)
{
    uint32_t parts[4];
    int n = 0;
    for (;;) {
        if (*s < '0' || *s > '9') {
            return false;
        }
        int base = 10;
        if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
            base = 16;
            s += 2;
        }
        else if (s[0] == '0') {
            base = 8;
        }
        uint64_t v = 0;
        bool digits = base == 8;
        for (;; s++) {
            int d;
            if (*s >= '0' && *s <= '9') {
                d = *s - '0';
            }
            else if (base == 16 && *s >= 'a' && *s <= 'f') {
                d = *s - 'a' + 10;
            }
            else if (base == 16 && *s >= 'A' && *s <= 'F') {
                d = *s - 'A' + 10;
            }
            else {
                break;
            }
            if (d >= base) {
                return false;
            }
            v = v * (uint64_t)base + (uint64_t)d;
            if (v > 0xffffffffu) {
                return false;
            }
            digits = true;
        }
        if (!digits || n == 4) {
            return false;
        }
        parts[n++] = (uint32_t)v;
        if (*s == '\0') {
            break;
        }
        if (*s++ != '.') {
            return false;
        }
    }
    static const uint32_t last_max[] = {0xffffffffu, 0xffffffu, 0xffffu, 0xffu};
    for (int i = 0; i < n - 1; i++) {
        if (parts[i] > 0xff) {
            return false;
        }
    }
    if (parts[n - 1] > last_max[n - 1]) {
        return false;
    }
    uint32_t v = parts[n - 1];
    for (int i = 0; i < n - 1; i++) {
        v |= parts[i] << (24 - 8 * i);
    }
    *ip = v;
    return true;
}

static PyObject *
socket_inet_aton(PyObject *module, PyObject *args)
{
    const char *text;
    if (!PyArg_ParseTuple(args, "s:inet_aton", &text)) {
        return NULL;
    }
    uint32_t ip;
    if (!aton(text, &ip)) {
        PyErr_SetString(PyExc_OSError, "illegal IP address string passed to inet_aton");
        return NULL;
    }
    uint32_t network = __builtin_bswap32(ip);
    return PyBytes_FromStringAndSize((const char *)&network, 4);
}

static PyObject *
socket_inet_ntoa(PyObject *module, PyObject *args)
{
    Py_buffer view;
    if (!PyArg_ParseTuple(args, "y*:inet_ntoa", &view)) {
        return NULL;
    }
    if (view.len != 4) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_OSError, "packed IP wrong length for inet_ntoa");
        return NULL;
    }
    const unsigned char *b = view.buf;
    struct n_net_ip ip = n_net_ip_v4(b[0], b[1], b[2], b[3]);
    PyBuffer_Release(&view);
    return ip_text(ip);
}

static PyObject *
socket_inet_pton(PyObject *module, PyObject *args)
{
    int family;
    const char *text;
    if (!PyArg_ParseTuple(args, "is:inet_pton", &family, &text)) {
        return NULL;
    }
    if (family != AF_INET && family != AF_INET6) {
        errno = EAFNOSUPPORT;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    /* 住所だけ（zone の "%" は住所の外） */
    struct n_net_ip ip;
    if (strchr(text, '%') != NULL || !n_net_ip_parse(text, &ip) || ip.family != ip_family(family)) {
        PyErr_SetString(PyExc_OSError, "illegal IP address string passed to inet_pton");
        return NULL;
    }
    return PyBytes_FromStringAndSize((const char *)ip.bytes, family == AF_INET6 ? 16 : 4);
}

static PyObject *
socket_inet_ntop(PyObject *module, PyObject *args)
{
    int family;
    Py_buffer view;
    if (!PyArg_ParseTuple(args, "iy*:inet_ntop", &family, &view)) {
        return NULL;
    }
    PyObject *result = NULL;
    Py_ssize_t length = family == AF_INET6 ? 16 : 4;
    if (family != AF_INET && family != AF_INET6) {
        PyErr_Format(PyExc_ValueError, "unknown address family %d", family);
    }
    else if (view.len != length) {
        PyErr_SetString(PyExc_ValueError, "invalid length of packed IP address string");
    }
    else {
        struct n_net_ip ip = {.family = ip_family(family)};
        memcpy(ip.bytes, view.buf, (size_t)length);
        result = ip_text(ip);
    }
    PyBuffer_Release(&view);
    return result;
}

static PyObject *
socket_getdefaulttimeout(PyObject *module, PyObject *Py_UNUSED(ignored))
{
    socket_state *state = get_state(module);
    if (state->default_timeout < 0) {
        Py_RETURN_NONE;
    }
    return PyFloat_FromDouble(PyTime_AsSecondsDouble(state->default_timeout));
}

static PyObject *
socket_setdefaulttimeout(PyObject *module, PyObject *object)
{
    PyTime_t timeout;
    if (parse_timeout(object, &timeout) < 0) {
        return NULL;
    }
    get_state(module)->default_timeout = timeout;
    Py_RETURN_NONE;
}

static PyMethodDef socket_functions[] = {
    {"getaddrinfo", _PyCFunction_CAST(socket_getaddrinfo), METH_VARARGS | METH_KEYWORDS,
     "getaddrinfo(host, port [, family, type, proto, flags])\n    -> list of (family, type, proto, canonname, sockaddr)\n\n"
     "Resolve host and port into addrinfo struct."},
    {"getnameinfo", socket_getnameinfo, METH_VARARGS,
     "getnameinfo(sockaddr, flags) --> (host, port)\n\nGet host and port for a sockaddr."},
    {"gethostbyname", socket_gethostbyname, METH_VARARGS,
     "gethostbyname(host) -> address\n\nReturn the IP address (a string of the form '255.255.255.255') for a host."},
    {"gethostbyname_ex", socket_gethostbyname_ex, METH_VARARGS,
     "gethostbyname_ex(host) -> (name, aliaslist, addresslist)\n\n"
     "Return the true host name, a list of aliases, and a list of IP addresses,\nfor a host."},
    {"gethostbyaddr", socket_gethostbyaddr, METH_VARARGS,
     "gethostbyaddr(host) -> (name, aliaslist, addresslist)\n\n"
     "Return the true host name, a list of aliases, and a list of IP addresses,\nfor a host."},
    {"gethostname", socket_gethostname, METH_NOARGS,
     "gethostname() -> string\n\nReturn the current host name."},
    {"getservbyname", socket_getservbyname, METH_VARARGS,
     "getservbyname(servicename[, protocolname]) -> integer\n\nReturn a port number from a service name and protocol name."},
    {"getservbyport", socket_getservbyport, METH_VARARGS,
     "getservbyport(port[, protocolname]) -> string\n\nReturn the service name from a port number and protocol name."},
    {"getprotobyname", socket_getprotobyname, METH_VARARGS,
     "getprotobyname(name) -> integer\n\nReturn the protocol number for the named protocol."},
    {"close", socket_close, METH_O, "close(integer) -> None\n\nClose an integer socket file descriptor."},
    {"dup", socket_dup, METH_O, "dup(integer) -> integer\n\nDuplicate an integer socket file descriptor."},
    {"ntohs", socket_ntohs, METH_O, "ntohs(integer) -> integer\n\nConvert a 16-bit unsigned integer from network to host byte order."},
    {"ntohl", socket_ntohl, METH_O, "ntohl(integer) -> integer\n\nConvert a 32-bit integer from network to host byte order."},
    {"htons", socket_ntohs, METH_O, "htons(integer) -> integer\n\nConvert a 16-bit unsigned integer from host to network byte order."},
    {"htonl", socket_ntohl, METH_O, "htonl(integer) -> integer\n\nConvert a 32-bit integer from host to network byte order."},
    {"inet_aton", socket_inet_aton, METH_VARARGS,
     "inet_aton(string) -> bytes giving packed 32-bit IP representation\n\n"
     "Convert an IP address in string format (123.45.67.89) to the 32-bit packed\nbinary format used in low-level network functions."},
    {"inet_ntoa", socket_inet_ntoa, METH_VARARGS,
     "inet_ntoa(packed_ip) -> ip_address_string\n\n"
     "Convert an IP address from 32-bit packed binary format to string format"},
    {"inet_pton", socket_inet_pton, METH_VARARGS,
     "inet_pton(af, ip) -> packed IP address string\n\n"
     "Convert an IP address from string format to a packed string suitable\nfor use with low-level network functions."},
    {"inet_ntop", socket_inet_ntop, METH_VARARGS,
     "inet_ntop(af, packed_ip) -> string formatted IP address\n\n"
     "Convert a packed IP address of the given family to string format."},
    {"getdefaulttimeout", socket_getdefaulttimeout, METH_NOARGS,
     "getdefaulttimeout() -> timeout\n\nReturns the default timeout in seconds (float) for new socket objects.\n"
     "A value of None indicates that new socket objects have no timeout."},
    {"setdefaulttimeout", socket_setdefaulttimeout, METH_O,
     "setdefaulttimeout(timeout)\n\nSet the default timeout in seconds (float) for new socket objects.\n"
     "A value of None indicates that new socket objects have no timeout."},
    {NULL, NULL}
};

static int
socket_exec(PyObject *module)
{
    socket_state *state = get_state(module);
    state->default_timeout = -1;
    state->socket_type = (PyTypeObject *)PyType_FromModuleAndSpec(module, &sock_spec, NULL);
    if (state->socket_type == NULL) {
        return -1;
    }
    if (PyModule_AddObjectRef(module, "socket", (PyObject *)state->socket_type) < 0 ||
        PyModule_AddObjectRef(module, "SocketType", (PyObject *)state->socket_type) < 0) {
        return -1;
    }
    state->herror = PyErr_NewException("socket.herror", PyExc_OSError, NULL);
    if (state->herror == NULL || PyModule_AddObjectRef(module, "herror", state->herror) < 0) {
        return -1;
    }
    state->gaierror = PyErr_NewException("socket.gaierror", PyExc_OSError, NULL);
    if (state->gaierror == NULL || PyModule_AddObjectRef(module, "gaierror", state->gaierror) < 0) {
        return -1;
    }
    if (PyModule_AddObjectRef(module, "error", PyExc_OSError) < 0 ||
        PyModule_AddObjectRef(module, "timeout", PyExc_TimeoutError) < 0 ||
        PyModule_AddObjectRef(module, "has_ipv6", Py_True) < 0) {
        return -1;
    }
#define ADD(name) if (PyModule_AddIntConstant(module, #name, name) < 0) return -1
    ADD(AF_UNSPEC); ADD(AF_INET); ADD(AF_INET6);
    ADD(SOCK_STREAM); ADD(SOCK_DGRAM);
    ADD(IPPROTO_IP); ADD(IPPROTO_TCP); ADD(IPPROTO_UDP); ADD(IPPROTO_IPV6);
    ADD(SOL_SOCKET); ADD(SO_REUSEADDR); ADD(SO_KEEPALIVE); ADD(SO_SNDBUF); ADD(SO_RCVBUF);
    ADD(SO_TYPE); ADD(SO_ERROR);
    ADD(TCP_NODELAY); ADD(TCP_KEEPIDLE); ADD(TCP_KEEPINTVL); ADD(TCP_KEEPCNT);
    ADD(IPV6_V6ONLY);
    ADD(SHUT_RD); ADD(SHUT_WR); ADD(SHUT_RDWR);
    ADD(AI_PASSIVE); ADD(AI_CANONNAME); ADD(AI_NUMERICHOST); ADD(AI_NUMERICSERV);
    ADD(NI_NUMERICHOST); ADD(NI_NUMERICSERV); ADD(NI_NOFQDN); ADD(NI_NAMEREQD); ADD(NI_DGRAM);
    ADD(NI_MAXHOST); ADD(NI_MAXSERV);
    ADD(EAI_AGAIN); ADD(EAI_BADFLAGS); ADD(EAI_FAIL); ADD(EAI_FAMILY); ADD(EAI_MEMORY);
    ADD(EAI_NODATA); ADD(EAI_NONAME); ADD(EAI_SERVICE); ADD(EAI_SOCKTYPE);
#undef ADD
    if (PyModule_Add(module, "INADDR_ANY", PyLong_FromUnsignedLong(INADDR_ANY)) < 0 ||
        PyModule_Add(module, "INADDR_LOOPBACK", PyLong_FromUnsignedLong(INADDR_LOOPBACK)) < 0 ||
        PyModule_Add(module, "INADDR_BROADCAST", PyLong_FromUnsignedLong(INADDR_BROADCAST)) < 0 ||
        PyModule_Add(module, "INADDR_NONE", PyLong_FromUnsignedLong(INADDR_NONE)) < 0) {
        return -1;
    }
    return 0;
}

static int
socket_traverse(PyObject *module, visitproc visit, void *arg)
{
    socket_state *state = get_state(module);
    Py_VISIT(state->socket_type);
    Py_VISIT(state->herror);
    Py_VISIT(state->gaierror);
    return 0;
}

static int
socket_clear(PyObject *module)
{
    socket_state *state = get_state(module);
    Py_CLEAR(state->socket_type);
    Py_CLEAR(state->herror);
    Py_CLEAR(state->gaierror);
    return 0;
}

static void
socket_free(void *module)
{
    (void)socket_clear((PyObject *)module);
}

static PyModuleDef_Slot socket_slots[] = {
    {Py_mod_exec, socket_exec},
    {Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
    {Py_mod_gil, Py_MOD_GIL_NOT_USED},
    {0, NULL}
};

static struct PyModuleDef socketmodule = {
    PyModuleDef_HEAD_INIT,
    .m_name = "_socket",
    .m_doc = "Implementation module for socket operations.\n\nSee the socket module for documentation.",
    .m_size = sizeof(socket_state),
    .m_methods = socket_functions,
    .m_slots = socket_slots,
    .m_traverse = socket_traverse,
    .m_clear = socket_clear,
    .m_free = socket_free,
};

PyMODINIT_FUNC
PyInit__socket(void)
{
    return PyModuleDef_Init(&socketmodule);
}
