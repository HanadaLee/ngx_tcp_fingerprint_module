/*
 * Copyright (C) 2026, Vitalyn
 *
 * ngx_http_tcp_fingerprint_module: passive fingerprint of the client's TCP/IP
 * stack, read from the SYN that opened the connection, the way p0f does it.
 *
 * Linux only. "tcp_fingerprint on;" sets TCP_SAVE_SYN on the HTTP listening
 * sockets (in the master process, at each configuration load). The kernel
 * then keeps the IP and TCP headers of each accepted connection's SYN, and
 * TCP_SAVED_SYN hands them over once. The first request that reads one of the
 * variables on a connection fetches them; the result stays in the connection
 * pool for the following requests (keepalive, HTTP/2 streams). HTTP/3 has no
 * TCP SYN.
 *
 * TLS 1.3 also gives one round trip to time: the server waits for the
 * client's Finished right after sending its own. That round trip ends at the
 * holder of the TLS keys, the kernel's TCP RTT at whoever acknowledges the
 * segments: the same machine for a direct client, but the exit node of a
 * tunnel (CONNECT or SOCKS proxy) for a proxied one. A message callback on
 * the server's SSL contexts timestamps both Finished and reads TCP_INFO when
 * the client's arrives, then removes itself from the connection.
 *
 * Variables:
 *   $tcpfp_signature  ver:ttl+hops:olen:mss:wsize,scale:options:quirks:pclass,
 *                     the layout of p0f v3 raw signatures, e.g.
 *                     4:57+7:0:1460:mss*44,7:mss,sok,ts,nop,ws:df:0
 *   $tcpfp_ttl        TTL (IPv4) or hop limit (IPv6) the SYN arrived with
 *   $tcpfp_ittl       initial TTL guessed from it: 32, 64, 128 or 255
 *   $tcpfp_hops       $tcpfp_ittl - $tcpfp_ttl
 *   $tcpfp_win        TCP window
 *   $tcpfp_mss        MSS option
 *   $tcpfp_wscale     window scale option
 *   $tcpfp_options    option layout: mss, ws, sok, sack, ts, nop, eol+N
 *                     (N padding bytes after it), ?K (unknown kind K)
 *   $tcpfp_quirks     oddities of the headers, in this order: df, id+, id-,
 *                     ecn, 0+, flow, seq-, ack+, ack-, uptr+, urgf+, pushf+,
 *                     ts1-, ts2+, opt+, exws, bad
 *   $tcpfp_tls_rtt    TLS 1.3 handshake round trip, server Finished sent to
 *                     client Finished read, in microseconds
 *   $tcpfp_tcp_rtt    kernel smoothed TCP RTT at that moment, in microseconds
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <netinet/tcp.h>
#include <time.h>


#ifndef TCP_SAVE_SYN
#define TCP_SAVE_SYN   27
#endif

#ifndef TCP_SAVED_SYN
#define TCP_SAVED_SYN  28
#endif


/* largest SYN without link header: IPv4 with options (60) + TCP (60) */
#define NGX_HTTP_TCPFP_SYN_LEN        128

/* at most 40 option bytes, each written as ",eol+39" at worst */
#define NGX_HTTP_TCPFP_OPTIONS_LEN    (40 * 7)

/* every quirk name and its comma */
#define NGX_HTTP_TCPFP_QUIRKS_LEN     128

/* "mss*65535" */
#define NGX_HTTP_TCPFP_WSIZE_LEN      16

/* "6:255+255:40:65535:" wsize ",255:" options ":" quirks ":+" */
#define NGX_HTTP_TCPFP_SIGNATURE_LEN                                          \
    (32 + NGX_HTTP_TCPFP_WSIZE_LEN + NGX_HTTP_TCPFP_OPTIONS_LEN               \
     + NGX_HTTP_TCPFP_QUIRKS_LEN)


#define NGX_HTTP_TCPFP_FIN   0x01
#define NGX_HTTP_TCPFP_PSH   0x08
#define NGX_HTTP_TCPFP_ACK   0x10
#define NGX_HTTP_TCPFP_URG   0x20
#define NGX_HTTP_TCPFP_ECE   0x40
#define NGX_HTTP_TCPFP_CWR   0x80


/* bit numbers in the order of the quirk names below */
enum {
    NGX_HTTP_TCPFP_Q_DF = 0,
    NGX_HTTP_TCPFP_Q_ID_PLUS,
    NGX_HTTP_TCPFP_Q_ID_MINUS,
    NGX_HTTP_TCPFP_Q_ECN,
    NGX_HTTP_TCPFP_Q_ZERO_PLUS,
    NGX_HTTP_TCPFP_Q_FLOW,
    NGX_HTTP_TCPFP_Q_SEQ_MINUS,
    NGX_HTTP_TCPFP_Q_ACK_PLUS,
    NGX_HTTP_TCPFP_Q_ACK_MINUS,
    NGX_HTTP_TCPFP_Q_UPTR_PLUS,
    NGX_HTTP_TCPFP_Q_URGF_PLUS,
    NGX_HTTP_TCPFP_Q_PUSHF_PLUS,
    NGX_HTTP_TCPFP_Q_TS1_MINUS,
    NGX_HTTP_TCPFP_Q_TS2_PLUS,
    NGX_HTTP_TCPFP_Q_OPT_PLUS,
    NGX_HTTP_TCPFP_Q_EXWS,
    NGX_HTTP_TCPFP_Q_BAD
};


static const char  *ngx_http_tcp_fingerprint_quirk_names[] = {
    "df",       /* IPv4 "don't fragment" */
    "id+",      /* DF with a non-zero IP ID */
    "id-",      /* no DF and a zero IP ID */
    "ecn",      /* ECN bits in the IP header, or ECE/CWR in the SYN */
    "0+",       /* IPv4 reserved ("must be zero") flag set */
    "flow",     /* non-zero IPv6 flow label */
    "seq-",     /* zero sequence number */
    "ack+",     /* non-zero ACK number without the ACK flag */
    "ack-",     /* ACK flag with a zero ACK number */
    "uptr+",    /* non-zero urgent pointer without the URG flag */
    "urgf+",    /* URG flag */
    "pushf+",   /* PSH flag */
    "ts1-",     /* timestamp option with a zero own timestamp */
    "ts2+",     /* timestamp option echoing a non-zero peer timestamp */
    "opt+",     /* non-zero bytes after the end of options */
    "exws",     /* window scale above 14 */
    "bad",      /* malformed options */
    NULL
};


typedef struct {
    ngx_flag_t  enable;
} ngx_http_tcp_fingerprint_main_conf_t;


typedef struct {
    ngx_str_t   signature;
    ngx_str_t   ttl;
    ngx_str_t   ittl;
    ngx_str_t   hops;
    ngx_str_t   win;
    ngx_str_t   mss;
    ngx_str_t   wscale;
    ngx_str_t   options;
    ngx_str_t   quirks;
    ngx_str_t   tls_rtt;
    ngx_str_t   tcp_rtt;
    uint64_t    finished;           /* server Finished sent, microseconds */
    unsigned    syn_read:1;
} ngx_http_tcp_fingerprint_ctx_t;


static ngx_int_t ngx_http_tcp_fingerprint_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_http_tcp_fingerprint_ctx_t *ngx_http_tcp_fingerprint_get_ctx(
    ngx_http_request_t *r);
static ngx_http_tcp_fingerprint_ctx_t *
    ngx_http_tcp_fingerprint_connection_ctx(ngx_connection_t *c);
static ngx_int_t ngx_http_tcp_fingerprint_parse(ngx_pool_t *pool,
    ngx_http_tcp_fingerprint_ctx_t *ctx, u_char *syn, size_t len);
static ngx_int_t ngx_http_tcp_fingerprint_set(ngx_pool_t *pool, ngx_str_t *s,
    size_t size, const char *fmt, ...);
static void ngx_http_tcp_fingerprint_cleanup(void *data);
#if (NGX_HTTP_SSL)
static void ngx_http_tcp_fingerprint_ssl_msg(int write_p, int version,
    int content_type, const void *buf, size_t len, SSL *ssl, void *arg);
static ngx_int_t ngx_http_tcp_fingerprint_tls_rtt(ngx_connection_t *c,
    ngx_http_tcp_fingerprint_ctx_t *ctx, uint64_t now);
#endif
static ngx_int_t ngx_http_tcp_fingerprint_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_tcp_fingerprint_init(ngx_conf_t *cf);
static void *ngx_http_tcp_fingerprint_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_tcp_fingerprint_init_main_conf(ngx_conf_t *cf,
    void *conf);
static ngx_int_t ngx_http_tcp_fingerprint_init_module(ngx_cycle_t *cycle);


static ngx_command_t  ngx_http_tcp_fingerprint_commands[] = {

    { ngx_string("tcp_fingerprint"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_tcp_fingerprint_main_conf_t, enable),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_tcp_fingerprint_module_ctx = {
    ngx_http_tcp_fingerprint_add_variables,    /* preconfiguration */
    ngx_http_tcp_fingerprint_init,             /* postconfiguration */

    ngx_http_tcp_fingerprint_create_main_conf, /* create main configuration */
    ngx_http_tcp_fingerprint_init_main_conf,   /* init main configuration */

    NULL,                                      /* create server configuration */
    NULL,                                      /* merge server configuration */

    NULL,                                      /* create location configuration */
    NULL                                       /* merge location configuration */
};


ngx_module_t  ngx_http_tcp_fingerprint_module = {
    NGX_MODULE_V1,
    &ngx_http_tcp_fingerprint_module_ctx,  /* module context */
    ngx_http_tcp_fingerprint_commands,     /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_http_tcp_fingerprint_init_module,  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_tcp_fingerprint_vars[] = {

    { ngx_string("tcpfp_signature"), NULL, ngx_http_tcp_fingerprint_variable,
      offsetof(ngx_http_tcp_fingerprint_ctx_t, signature), 0, 0 },

    { ngx_string("tcpfp_ttl"), NULL, ngx_http_tcp_fingerprint_variable,
      offsetof(ngx_http_tcp_fingerprint_ctx_t, ttl), 0, 0 },

    { ngx_string("tcpfp_ittl"), NULL, ngx_http_tcp_fingerprint_variable,
      offsetof(ngx_http_tcp_fingerprint_ctx_t, ittl), 0, 0 },

    { ngx_string("tcpfp_hops"), NULL, ngx_http_tcp_fingerprint_variable,
      offsetof(ngx_http_tcp_fingerprint_ctx_t, hops), 0, 0 },

    { ngx_string("tcpfp_win"), NULL, ngx_http_tcp_fingerprint_variable,
      offsetof(ngx_http_tcp_fingerprint_ctx_t, win), 0, 0 },

    { ngx_string("tcpfp_mss"), NULL, ngx_http_tcp_fingerprint_variable,
      offsetof(ngx_http_tcp_fingerprint_ctx_t, mss), 0, 0 },

    { ngx_string("tcpfp_wscale"), NULL, ngx_http_tcp_fingerprint_variable,
      offsetof(ngx_http_tcp_fingerprint_ctx_t, wscale), 0, 0 },

    { ngx_string("tcpfp_options"), NULL, ngx_http_tcp_fingerprint_variable,
      offsetof(ngx_http_tcp_fingerprint_ctx_t, options), 0, 0 },

    { ngx_string("tcpfp_quirks"), NULL, ngx_http_tcp_fingerprint_variable,
      offsetof(ngx_http_tcp_fingerprint_ctx_t, quirks), 0, 0 },

    { ngx_string("tcpfp_tls_rtt"), NULL, ngx_http_tcp_fingerprint_variable,
      offsetof(ngx_http_tcp_fingerprint_ctx_t, tls_rtt), 0, 0 },

    { ngx_string("tcpfp_tcp_rtt"), NULL, ngx_http_tcp_fingerprint_variable,
      offsetof(ngx_http_tcp_fingerprint_ctx_t, tcp_rtt), 0, 0 },

      ngx_http_null_variable
};


static ngx_int_t
ngx_http_tcp_fingerprint_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t                       *s;
    ngx_http_tcp_fingerprint_ctx_t  *ctx;

    ctx = ngx_http_tcp_fingerprint_get_ctx(r);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    s = (ngx_str_t *) ((char *) ctx + data);

    if (s->len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = s->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = s->data;

    return NGX_OK;
}


static ngx_http_tcp_fingerprint_ctx_t *
ngx_http_tcp_fingerprint_get_ctx(ngx_http_request_t *r)
{
    u_char                                 syn[NGX_HTTP_TCPFP_SYN_LEN];
    socklen_t                              len;
    ngx_connection_t                      *c;
    ngx_http_tcp_fingerprint_ctx_t        *ctx;
    ngx_http_tcp_fingerprint_main_conf_t  *tmcf;

    tmcf = ngx_http_get_module_main_conf(r, ngx_http_tcp_fingerprint_module);

    if (!tmcf->enable) {
        return NULL;
    }

    c = r->main->connection;

    if (c->type != SOCK_STREAM || c->fd == (ngx_socket_t) -1) {
        return NULL;
    }

#if (NGX_HTTP_V3)
    if (c->quic) {
        return NULL;
    }
#endif

    ctx = ngx_http_tcp_fingerprint_connection_ctx(c);

    if (ctx == NULL || ctx->syn_read) {
        return ctx;
    }

    ctx->syn_read = 1;

    len = sizeof(syn);

    if (getsockopt(c->fd, IPPROTO_TCP, TCP_SAVED_SYN, syn, &len) == -1) {
        /*
         * ENOENT: nothing saved (connection accepted before
         * "tcp_fingerprint on", or not a TCP socket); EINVAL: SYN larger
         * than the buffer
         */
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, ngx_socket_errno,
                       "tcp_fingerprint: getsockopt(TCP_SAVED_SYN) failed");
        return ctx;
    }

    if (ngx_http_tcp_fingerprint_parse(c->pool, ctx, syn, len) != NGX_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "tcp_fingerprint: unparsable SYN of %uz bytes",
                       (size_t) len);
        ngx_str_null(&ctx->signature);
        ngx_str_null(&ctx->ttl);
        ngx_str_null(&ctx->ittl);
        ngx_str_null(&ctx->hops);
        ngx_str_null(&ctx->win);
        ngx_str_null(&ctx->mss);
        ngx_str_null(&ctx->wscale);
        ngx_str_null(&ctx->options);
        ngx_str_null(&ctx->quirks);
    }

    return ctx;
}


/*
 * Everything is kept once per TCP connection, in a pool cleanup found by
 * its handler: TCP_SAVED_SYN answers only once, the TLS handshake happens
 * once. An HTTP/2 stream works on a copy of the TCP connection (same fd,
 * same pool).
 */

static ngx_http_tcp_fingerprint_ctx_t *
ngx_http_tcp_fingerprint_connection_ctx(ngx_connection_t *c)
{
    ngx_pool_cleanup_t              *cln;
    ngx_http_tcp_fingerprint_ctx_t  *ctx;

    for (cln = c->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler == ngx_http_tcp_fingerprint_cleanup) {
            return cln->data;
        }
    }

    cln = ngx_pool_cleanup_add(c->pool,
                               sizeof(ngx_http_tcp_fingerprint_ctx_t));
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_http_tcp_fingerprint_cleanup;

    ctx = cln->data;
    ngx_memzero(ctx, sizeof(ngx_http_tcp_fingerprint_ctx_t));

    return ctx;
}


static ngx_int_t
ngx_http_tcp_fingerprint_parse(ngx_pool_t *pool,
    ngx_http_tcp_fingerprint_ctx_t *ctx, u_char *syn, size_t len)
{
    u_char       *tcp, *opt, *end, *p, *last;
    u_char        options[NGX_HTTP_TCPFP_OPTIONS_LEN];
    u_char        quirks[NGX_HTTP_TCPFP_QUIRKS_LEN];
    u_char        wsize[NGX_HTTP_TCPFP_WSIZE_LEN];
    size_t        iphl, thl, olen, total, n, wlen;
    uint32_t      seq, ack, ts1, ts2;
    ngx_uint_t    version, ttl, ittl, window, mss, wscale, flags, mtu, i, q;
    ngx_uint_t    has_mss, has_wscale;
    const char   *sep;

    if (len < 1) {
        return NGX_ERROR;
    }

    q = 0;
    version = syn[0] >> 4;

    switch (version) {

    case 4:
        iphl = (syn[0] & 0x0f) * 4;

        if (iphl < 20 || len < iphl || syn[9] != IPPROTO_TCP) {
            return NGX_ERROR;
        }

        ttl = syn[8];
        total = (syn[2] << 8) | syn[3];
        olen = iphl - 20;
        mtu = 40;

        if (syn[6] & 0x40) {
            q |= 1 << NGX_HTTP_TCPFP_Q_DF;

            if (syn[4] || syn[5]) {
                q |= 1 << NGX_HTTP_TCPFP_Q_ID_PLUS;
            }

        } else if (syn[4] == 0 && syn[5] == 0) {
            q |= 1 << NGX_HTTP_TCPFP_Q_ID_MINUS;
        }

        if (syn[6] & 0x80) {
            q |= 1 << NGX_HTTP_TCPFP_Q_ZERO_PLUS;
        }

        if (syn[1] & 0x03) {
            q |= 1 << NGX_HTTP_TCPFP_Q_ECN;
        }

        break;

    case 6:
        /* a SYN carries no extension header between IPv6 and TCP */
        iphl = 40;

        if (len < iphl || syn[6] != IPPROTO_TCP) {
            return NGX_ERROR;
        }

        ttl = syn[7];
        total = iphl + ((syn[4] << 8) | syn[5]);
        olen = 0;
        mtu = 60;

        if ((syn[1] & 0x0f) || syn[2] || syn[3]) {
            q |= 1 << NGX_HTTP_TCPFP_Q_FLOW;
        }

        /* the two low bits of the traffic class */
        if ((syn[1] >> 4) & 0x03) {
            q |= 1 << NGX_HTTP_TCPFP_Q_ECN;
        }

        break;

    default:
        return NGX_ERROR;
    }

    if (len < iphl + 20) {
        return NGX_ERROR;
    }

    tcp = syn + iphl;
    thl = (tcp[12] >> 4) * 4;

    if (thl < 20 || len < iphl + thl) {
        return NGX_ERROR;
    }

    seq = ((uint32_t) tcp[4] << 24) | (tcp[5] << 16) | (tcp[6] << 8) | tcp[7];
    ack = ((uint32_t) tcp[8] << 24) | (tcp[9] << 16) | (tcp[10] << 8)
          | tcp[11];
    flags = tcp[13];
    window = (tcp[14] << 8) | tcp[15];

    if (flags & (NGX_HTTP_TCPFP_ECE|NGX_HTTP_TCPFP_CWR)) {
        q |= 1 << NGX_HTTP_TCPFP_Q_ECN;
    }

    if (seq == 0) {
        q |= 1 << NGX_HTTP_TCPFP_Q_SEQ_MINUS;
    }

    if (flags & NGX_HTTP_TCPFP_ACK) {
        if (ack == 0) {
            q |= 1 << NGX_HTTP_TCPFP_Q_ACK_MINUS;
        }

    } else if (ack) {
        q |= 1 << NGX_HTTP_TCPFP_Q_ACK_PLUS;
    }

    if (flags & NGX_HTTP_TCPFP_URG) {
        q |= 1 << NGX_HTTP_TCPFP_Q_URGF_PLUS;

    } else if (tcp[18] || tcp[19]) {
        q |= 1 << NGX_HTTP_TCPFP_Q_UPTR_PLUS;
    }

    if (flags & NGX_HTTP_TCPFP_PSH) {
        q |= 1 << NGX_HTTP_TCPFP_Q_PUSHF_PLUS;
    }

    mss = 0;
    wscale = 0;
    has_mss = 0;
    has_wscale = 0;

    p = options;
    last = options + sizeof(options);

    opt = tcp + 20;
    end = tcp + thl;

    while (opt < end) {

        sep = (p == options) ? "" : ",";

        if (*opt == 0) {
            /* EOL: what follows is padding, and should be zero */
            p = ngx_slprintf(p, last, "%seol+%uz", sep,
                             (size_t) (end - opt - 1));

            for (opt++; opt < end; opt++) {
                if (*opt) {
                    q |= 1 << NGX_HTTP_TCPFP_Q_OPT_PLUS;
                    break;
                }
            }

            break;
        }

        if (*opt == 1) {
            p = ngx_slprintf(p, last, "%snop", sep);
            opt++;
            continue;
        }

        if (end - opt < 2 || opt[1] < 2 || opt[1] > (size_t) (end - opt)) {
            q |= 1 << NGX_HTTP_TCPFP_Q_BAD;
            break;
        }

        n = opt[1];

        switch (*opt) {

        case 2:
            p = ngx_slprintf(p, last, "%smss", sep);

            if (n != 4) {
                q |= 1 << NGX_HTTP_TCPFP_Q_BAD;
                break;
            }

            mss = (opt[2] << 8) | opt[3];
            has_mss = 1;
            break;

        case 3:
            p = ngx_slprintf(p, last, "%sws", sep);

            if (n != 3) {
                q |= 1 << NGX_HTTP_TCPFP_Q_BAD;
                break;
            }

            wscale = opt[2];
            has_wscale = 1;

            if (wscale > 14) {
                q |= 1 << NGX_HTTP_TCPFP_Q_EXWS;
            }

            break;

        case 4:
            p = ngx_slprintf(p, last, "%ssok", sep);

            if (n != 2) {
                q |= 1 << NGX_HTTP_TCPFP_Q_BAD;
            }

            break;

        case 5:
            p = ngx_slprintf(p, last, "%ssack", sep);

            if (n < 10 || (n - 2) % 8) {
                q |= 1 << NGX_HTTP_TCPFP_Q_BAD;
            }

            break;

        case 8:
            p = ngx_slprintf(p, last, "%sts", sep);

            if (n != 10) {
                q |= 1 << NGX_HTTP_TCPFP_Q_BAD;
                break;
            }

            ts1 = ((uint32_t) opt[2] << 24) | (opt[3] << 16) | (opt[4] << 8)
                  | opt[5];
            ts2 = ((uint32_t) opt[6] << 24) | (opt[7] << 16) | (opt[8] << 8)
                  | opt[9];

            if (ts1 == 0) {
                q |= 1 << NGX_HTTP_TCPFP_Q_TS1_MINUS;
            }

            if (ts2) {
                q |= 1 << NGX_HTTP_TCPFP_Q_TS2_PLUS;
            }

            break;

        default:
            p = ngx_slprintf(p, last, "%s?%ui", sep, (ngx_uint_t) *opt);
            break;
        }

        opt += n;
    }

    ctx->options.len = 0;

    if (p != options
        && ngx_http_tcp_fingerprint_set(pool, &ctx->options, p - options,
                                        "%*s", (size_t) (p - options),
                                        options)
           != NGX_OK)
    {
        return NGX_ERROR;
    }

    p = quirks;
    last = quirks + sizeof(quirks);

    for (i = 0; ngx_http_tcp_fingerprint_quirk_names[i]; i++) {
        if (q & (1 << i)) {
            p = ngx_slprintf(p, last, "%s%s", p == quirks ? "" : ",",
                             ngx_http_tcp_fingerprint_quirk_names[i]);
        }
    }

    ctx->quirks.len = 0;

    if (p != quirks
        && ngx_http_tcp_fingerprint_set(pool, &ctx->quirks, p - quirks,
                                        "%*s", (size_t) (p - quirks), quirks)
           != NGX_OK)
    {
        return NGX_ERROR;
    }

    ittl = ttl <= 32 ? 32 : ttl <= 64 ? 64 : ttl <= 128 ? 128 : 255;

    /* the window as p0f writes it: a multiple of the MSS or of the MTU */

    if (has_mss && mss && window && window % mss == 0) {
        wlen = ngx_sprintf(wsize, "mss*%ui", window / mss) - wsize;

    } else if (has_mss && window && window % (mss + mtu) == 0) {
        wlen = ngx_sprintf(wsize, "mtu*%ui", window / (mss + mtu)) - wsize;

    } else {
        wlen = ngx_sprintf(wsize, "%ui", window) - wsize;
    }

    if (ngx_http_tcp_fingerprint_set(pool, &ctx->signature,
                                     NGX_HTTP_TCPFP_SIGNATURE_LEN,
                                     "%ui:%ui+%ui:%uz:%ui:%*s,%ui:%V:%V:%c",
                                     version, ttl, ittl - ttl, olen, mss,
                                     wlen, wsize, wscale, &ctx->options,
                                     &ctx->quirks,
                                     total > iphl + thl ? '+' : '0')
        != NGX_OK
        || ngx_http_tcp_fingerprint_set(pool, &ctx->ttl, NGX_INT_T_LEN,
                                        "%ui", ttl) != NGX_OK
        || ngx_http_tcp_fingerprint_set(pool, &ctx->ittl, NGX_INT_T_LEN,
                                        "%ui", ittl) != NGX_OK
        || ngx_http_tcp_fingerprint_set(pool, &ctx->hops, NGX_INT_T_LEN,
                                        "%ui", ittl - ttl) != NGX_OK
        || ngx_http_tcp_fingerprint_set(pool, &ctx->win, NGX_INT_T_LEN,
                                        "%ui", window) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (has_mss
        && ngx_http_tcp_fingerprint_set(pool, &ctx->mss, NGX_INT_T_LEN,
                                        "%ui", mss) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (has_wscale
        && ngx_http_tcp_fingerprint_set(pool, &ctx->wscale, NGX_INT_T_LEN,
                                        "%ui", wscale) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_tcp_fingerprint_set(ngx_pool_t *pool, ngx_str_t *s, size_t size,
    const char *fmt, ...)
{
    u_char   *p;
    va_list   args;

    s->data = ngx_pnalloc(pool, size);
    if (s->data == NULL) {
        return NGX_ERROR;
    }

    va_start(args, fmt);
    p = ngx_vslprintf(s->data, s->data + size, fmt, args);
    va_end(args);

    s->len = p - s->data;

    return NGX_OK;
}


static void
ngx_http_tcp_fingerprint_cleanup(void *data)
{
    /* nothing to free: the handler only marks the connection's context */
}


#if (NGX_HTTP_SSL)

/*
 * Called by OpenSSL for every message and record of the connection until it
 * removes itself. Only the two TLS 1.3 Finished matter; TLS 1.2 waits on the
 * client's key exchange (its computation would count) and is left out.
 */

static void
ngx_http_tcp_fingerprint_ssl_msg(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
    uint64_t                         now;
    struct timespec                  ts;
    ngx_connection_t                *c;
    ngx_http_tcp_fingerprint_ctx_t  *ctx;

    if (content_type != SSL3_RT_HANDSHAKE
        || len < 1
        || ((const u_char *) buf)[0] != SSL3_MT_FINISHED)
    {
        return;
    }

    c = ngx_ssl_get_connection(ssl);

    if (c == NULL
        || c->type != SOCK_STREAM
        || SSL_version(ssl) != TLS1_3_VERSION)
    {
        SSL_set_msg_callback(ssl, NULL);
        return;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1) {
        SSL_set_msg_callback(ssl, NULL);
        return;
    }

    now = (uint64_t) ts.tv_sec * 1000000 + ts.tv_nsec / 1000;

    ctx = ngx_http_tcp_fingerprint_connection_ctx(c);

    if (ctx == NULL) {
        SSL_set_msg_callback(ssl, NULL);
        return;
    }

    if (write_p) {
        ctx->finished = now;
        return;
    }

    if (ctx->finished
        && ngx_http_tcp_fingerprint_tls_rtt(c, ctx, now) != NGX_OK)
    {
        ngx_str_null(&ctx->tls_rtt);
        ngx_str_null(&ctx->tcp_rtt);
    }

    SSL_set_msg_callback(ssl, NULL);
}


static ngx_int_t
ngx_http_tcp_fingerprint_tls_rtt(ngx_connection_t *c,
    ngx_http_tcp_fingerprint_ctx_t *ctx, uint64_t now)
{
    socklen_t        len;
    struct tcp_info  ti;

    len = sizeof(struct tcp_info);

    if (getsockopt(c->fd, IPPROTO_TCP, TCP_INFO, &ti, &len) == -1) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, ngx_socket_errno,
                       "tcp_fingerprint: getsockopt(TCP_INFO) failed");
        return NGX_ERROR;
    }

    if (ngx_http_tcp_fingerprint_set(c->pool, &ctx->tls_rtt, NGX_INT64_LEN,
                                     "%uL", now - ctx->finished)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return ngx_http_tcp_fingerprint_set(c->pool, &ctx->tcp_rtt,
                                        NGX_INT32_LEN, "%uD",
                                        (uint32_t) ti.tcpi_rtt);
}

#endif


static ngx_int_t
ngx_http_tcp_fingerprint_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_tcp_fingerprint_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


/*
 * Sets the message callback on the SSL context of every server: SSL objects
 * copy it at creation, and keep it when SNI switches them to another
 * server's context.
 */

static ngx_int_t
ngx_http_tcp_fingerprint_init(ngx_conf_t *cf)
{
#if (NGX_HTTP_SSL)
    ngx_uint_t                              s;
    ngx_http_ssl_srv_conf_t                *sscf;
    ngx_http_core_srv_conf_t              **cscfp;
    ngx_http_core_main_conf_t              *cmcf;
    ngx_http_tcp_fingerprint_main_conf_t   *tmcf;

    tmcf = ngx_http_conf_get_module_main_conf(cf,
                                              ngx_http_tcp_fingerprint_module);

    if (!tmcf->enable) {
        return NGX_OK;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        sscf = cscfp[s]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];

        if (sscf->ssl.ctx) {
            SSL_CTX_set_msg_callback(sscf->ssl.ctx,
                                     ngx_http_tcp_fingerprint_ssl_msg);
        }
    }
#endif

    return NGX_OK;
}


static void *
ngx_http_tcp_fingerprint_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_tcp_fingerprint_main_conf_t  *tmcf;

    tmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_tcp_fingerprint_main_conf_t));
    if (tmcf == NULL) {
        return NULL;
    }

    tmcf->enable = NGX_CONF_UNSET;

    return tmcf;
}


static char *
ngx_http_tcp_fingerprint_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_tcp_fingerprint_main_conf_t  *tmcf = conf;

    ngx_conf_init_value(tmcf->enable, 0);

    return NGX_CONF_OK;
}


/*
 * Runs in the master process once the listening sockets are open, at start
 * and at each reload: turns TCP_SAVE_SYN on every TCP socket that serves
 * HTTP. Accepted connections inherit the option. "off" leaves the sockets
 * alone, so that another module reading the SYN keeps it: a socket kept
 * across a reload from "on" goes on saving SYNs (about 100 bytes per
 * connection, freed at close) until nginx restarts.
 */

static ngx_int_t
ngx_http_tcp_fingerprint_init_module(ngx_cycle_t *cycle)
{
    int                                    on;
    ngx_uint_t                             i;
    ngx_listening_t                       *ls;
    ngx_http_tcp_fingerprint_main_conf_t  *tmcf;

    tmcf = ngx_http_cycle_get_module_main_conf(cycle,
                                               ngx_http_tcp_fingerprint_module);
    if (tmcf == NULL || !tmcf->enable) {
        return NGX_OK;
    }

    on = 1;

    ls = cycle->listening.elts;

    for (i = 0; i < cycle->listening.nelts; i++) {

        if (ls[i].fd == (ngx_socket_t) -1
            || ls[i].type != SOCK_STREAM
            || ls[i].handler != ngx_http_init_connection)
        {
            continue;
        }

        switch (ls[i].sockaddr->sa_family) {

        case AF_INET:
#if (NGX_HAVE_INET6)
        case AF_INET6:
#endif
            break;

        default:
            continue;
        }

        if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_SAVE_SYN,
                       (const void *) &on, sizeof(int))
            == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
                          "setsockopt(TCP_SAVE_SYN) %V failed, ignored",
                          &ls[i].addr_text);
        }
    }

    return NGX_OK;
}
