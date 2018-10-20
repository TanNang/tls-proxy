#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libbase64.h"
#include "uthash.h"

#define PRINT_COMMAND_HELP \
    printf("usage: tls-client <OPTIONS>. OPTIONS have these:\n"\
           " -s <server_host>        server host. can't use IP address\n"\
           " -p <server_port>        server port. the default port is 443\n"\
           " -c <cafile_path>        CA file location. eg: /etc/ssl/cert.pem\n"\
           " -P <request_uri>        websocket request line uri. eg: /tls-proxy\n"\
           " -H <request_header>     websocket request headers. allow multi line\n"\
           " -b <listen_address>     tcp & udp listen address. default: 127.0.0.1\n"\
           " -t <tcp_proxy_port>     tcp port (iptables xt_tproxy). default: 60080\n"\
           " -u <udp_proxy_port>     udp port (iptables xt_tproxy). default: 60080\n"\
           " -j <thread_numbers>     number of worker thread (for tcp). default: 1\n"\
           " -T                      disable tcp transparent proxy\n"\
           " -U                      disable udp transparent proxy\n"\
           " -v                      show version and exit\n"\
           " -h                      show help and exit\n")

#define TCP_TYPE_GEN 1
#define TCP_TYPE_SSL 2
#define UDP_HASH_PRE 10
#define UDP_HASH_LEN 500
#define UDP_RAW_BUFSIZ 1472
#define UDP_ENC_BUFSIZ 1960
#define BUFSIZ_FOR_BEV 65536
#define WEBSOCKET_STATUS_LINE "HTTP/1.1 101 Switching Protocols"
#define SSL_CIPHERS "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305"

void *service(void *arg);

void tcp_read_cb(struct bufferevent *bev, void *arg);
void tcp_write_cb(struct bufferevent *bev, void *arg);
void tcp_events_cb(struct bufferevent *bev, short events, void *arg);
void tcp_timeout_cb(int sock, short events, void *arg);
void tcp_recvres_cb(struct bufferevent *bev, void *arg);
void tcp_newconn_cb(struct evconnlistener *listener, int sock, struct sockaddr *addr, int addrlen, void *arg);

void udp_sendreq_cb(struct bufferevent *bev, short events, void *arg);
void udp_recvres_cb(struct bufferevent *bev, void *arg);
void udp_timeout_cb(int sock, short events, void *arg);
void udp_release_cb(int sock, short events, void *arg);
void udp_request_cb(int sock, short events, void *arg);
void udp_response_cb(struct bufferevent *bev, void *arg);

typedef struct {
    struct event       *ev;
    struct bufferevent *bev;
    char                type;
} EVArg;

typedef struct {
    char                addr[16];
    char                port[6];
    struct bufferevent *bev;
    char                type;
} TCPArg;

typedef struct {
    char           addr[22];
    int            port;
    struct event  *ev;
    UT_hash_handle hh;
} UDPNode;

/* UDP Proxy 全局数据 */
static void               *udprbuff    = NULL;
static char               *udpebuff    = NULL;
static int                 udplsock    = -1;
static struct event       *udplev      = NULL;
static struct event       *udptev      = NULL;
static struct bufferevent *udpbev      = NULL;
static UDPNode            *udphash     = NULL;
static struct event_base  *udpbase     = NULL;
static char                udpcntl[64] = {0};

void udpnode_put(char *addr, int port) {
    UDPNode *node = NULL;
    HASH_FIND_STR(udphash, addr, node);
    if (node == NULL) {
        node = calloc(1, sizeof(UDPNode));
        strcpy(node->addr, addr);
        node->port = port;
        node->ev = event_new(udpbase, -1, EV_TIMEOUT, udp_timeout_cb, node->addr);
        struct timeval tv = {180, 0};
        event_add(node->ev, &tv);
        HASH_ADD_STR(udphash, addr, node);
        if (HASH_COUNT(udphash) > UDP_HASH_LEN) {
            int cnt = 0;
            UDPNode *node = NULL, *temp = NULL;
            HASH_ITER(hh, udphash, node, temp) {
                HASH_DEL(udphash, node);
                event_free(node->ev);
                free(node);
                if (++cnt == UDP_HASH_PRE) return;
            }
        }
    } else {
        node->port = port;
        struct timeval tv = {180, 0};
        event_add(node->ev, &tv);
        HASH_DEL(udphash, node);
        HASH_ADD_STR(udphash, addr, node);
    }
}

UDPNode *udpnode_get(char *addr) {
    UDPNode *node = NULL;
    HASH_FIND_STR(udphash, addr, node);
    if (node == NULL) return node;
    struct timeval tv = {180, 0};
    event_add(node->ev, &tv);
    HASH_DEL(udphash, node);
    HASH_ADD_STR(udphash, addr, node);
    return node;
}

int udpnode_getport(char *addr) {
    UDPNode *node = udpnode_get(addr);
    return (node == NULL) ? 0 : (node->port);
}

void udpnode_del(char *addr) {
    UDPNode *node = NULL;
    HASH_FIND_STR(udphash, addr, node);
    if (node == NULL) return;
    HASH_DEL(udphash, node);
    event_free(node->ev);
    free(node);
}

void udpnode_clear() {
    UDPNode *node = NULL, *temp = NULL;
    HASH_ITER(hh, udphash, node, temp) {
        HASH_DEL(udphash, node);
        event_free(node->ev);
        free(node);
    }
}

/* 线程共享的全局数据 */
static char               *servhost     = NULL;
static int                 servport     = 443;
static struct sockaddr_in  servaddr     = {0};
static char               *cafile       = NULL;
static char                servreq[256] = {0};
static struct sockaddr_in  tcpladdr     = {0};
static struct sockaddr_in  udpladdr     = {0};

/* 线程私有的全局数据 */
typedef struct {
    pthread_t    tid;
    SSL_CTX     *ctx;
    SSL_SESSION *sess;
} THREAD_DATA;

static int          thread_nums  = 1;
static THREAD_DATA *thread_datas = NULL;

/* 获取当前线程的 SSL_CTX */
SSL_CTX *get_ssl_ctx() {
    pthread_t tid = pthread_self();
    for (int i = 0; i < thread_nums; ++i) {
        if (thread_datas[i].tid == tid) {
            return thread_datas[i].ctx;
        }
    }
    return NULL;
}
/* 设置当前线程的 SSL_CTX */
void set_ssl_ctx(SSL_CTX *ctx) {
    pthread_t tid = pthread_self();
    for (int i = 0; i < thread_nums; ++i) {
        if (thread_datas[i].tid == tid) {
            thread_datas[i].ctx = ctx;
            return;
        }
    }
}

/* 获取当前线程的 SSL_SESSION */
SSL_SESSION *get_ssl_sess() {
    pthread_t tid = pthread_self();
    for (int i = 0; i < thread_nums; ++i) {
        if (thread_datas[i].tid == tid) {
            return thread_datas[i].sess;
        }
    }
    return NULL;
}
/* 设置当前线程的 SSL_SESSION */
void set_ssl_sess(SSL_SESSION *sess) {
    pthread_t tid = pthread_self();
    for (int i = 0; i < thread_nums; ++i) {
        if (thread_datas[i].tid == tid) {
            thread_datas[i].sess = sess;
            return;
        }
    }
}

// sizeof(str) = 36
char *loginf(char *str) {
    time_t rawtime;
    time(&rawtime);
    struct tm curtm;
    localtime_r(&rawtime, &curtm);
    sprintf(str, "\e[1;32m%04d-%02d-%02d %02d:%02d:%02d INF:\e[0m",
            curtm.tm_year + 1900, curtm.tm_mon + 1, curtm.tm_mday,
            curtm.tm_hour,        curtm.tm_min,     curtm.tm_sec);
    return str;
}

// sizeof(str) = 36
char *logerr(char *str) {
    time_t rawtime;
    time(&rawtime);
    struct tm curtm;
    localtime_r(&rawtime, &curtm);
    sprintf(str, "\e[1;35m%04d-%02d-%02d %02d:%02d:%02d ERR:\e[0m",
            curtm.tm_year + 1900, curtm.tm_mon + 1, curtm.tm_mday,
            curtm.tm_hour,        curtm.tm_min,     curtm.tm_sec);
    return str;
}

void setsockopt_tcp(int sock) {
    char ctime[36] = {0};
    char error[64] = {0};

    int optval = 1;
    if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval)) == -1) {
        printf("%s [tcp] setsockopt(TCP_NODELAY) for %d: (%d) %s\n", logerr(ctime), sock, errno, strerror_r(errno, error, 64));
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
        printf("%s [tcp] setsockopt(SO_REUSEADDR) for %d: (%d) %s\n", logerr(ctime), sock, errno, strerror_r(errno, error, 64));
    }

    if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) == -1) {
        printf("%s [tcp] setsockopt(SO_KEEPALIVE) for %d: (%d) %s\n", logerr(ctime), sock, errno, strerror_r(errno, error, 64));
    }

    optval = 15;
    if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &optval, sizeof(optval)) == -1) {
        printf("%s [tcp] setsockopt(TCP_KEEPIDLE) for %d: (%d) %s\n", logerr(ctime), sock, errno, strerror_r(errno, error, 64));
    }

    if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &optval, sizeof(optval)) == -1) {
        printf("%s [tcp] setsockopt(TCP_KEEPINTVL) for %d: (%d) %s\n", logerr(ctime), sock, errno, strerror_r(errno, error, 64));
    }

    optval = 2;
    if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &optval, sizeof(optval)) == -1) {
        printf("%s [tcp] setsockopt(TCP_KEEPCNT) for %d: (%d) %s\n", logerr(ctime), sock, errno, strerror_r(errno, error, 64));
    }
}

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IONBF, 0);

    char *requri = NULL;
    char *reqext = NULL;
    char *listen = "127.0.0.1";
    int   tcport = 60080;
    int   udport = 60080;

    opterr = 0;
    char *optstr = "s:p:c:P:H:b:t:u:j:TUvh";
    int opt = -1;
    while ((opt = getopt(argc, argv, optstr)) != -1) {
        switch (opt) {
            case 'v':
                printf("tls-client v1.1\n");
                return 0;
            case 'h':
                PRINT_COMMAND_HELP;
                return 0;
            case 'T':
                tcport = 0;
                break;
            case 'U':
                udport = 0;
                break;
            case 's':
                servhost = optarg;
                break;
            case 'p':
                servport = strtol(optarg, NULL, 10);
                if (servport <= 0 || servport > 65535) {
                    printf("invalid server port: %d\n", servport);
                    PRINT_COMMAND_HELP;
                    return 1;
                }
                break;
            case 'c':
                cafile = optarg;
                if (access(cafile, F_OK) == -1) {
                    printf("CA file can't access: %s\n", cafile);
                    PRINT_COMMAND_HELP;
                    return 1;
                }
                break;
            case 'P':
                requri = optarg;
                break;
            case 'H':
                reqext = optarg;
                break;
            case 'b':
                listen = optarg;
                break;
            case 't':
                tcport = strtol(optarg, NULL, 10);
                if (tcport <= 0 || tcport > 65535) {
                    printf("invalid tcp port: %d\n", tcport);
                    PRINT_COMMAND_HELP;
                    return 1;
                }
                break;
            case 'u':
                udport = strtol(optarg, NULL, 10);
                if (udport <= 0 || udport > 65535) {
                    printf("invalid udp port: %d\n", udport);
                    PRINT_COMMAND_HELP;
                    return 1;
                }
                break;
            case 'j':
                thread_nums = strtol(optarg, NULL, 10);
                if (thread_nums < 1) {
                    printf("invalid thread nums: %d\n", thread_nums);
                    PRINT_COMMAND_HELP;
                    return 1;
                }
                break;
            case '?':
                if (strchr(optstr, optopt) == NULL) {
                    printf("unknown option '-%c'\n", optopt);
                    PRINT_COMMAND_HELP;
                    return 1;
                } else {
                    printf("missing optval '-%c'\n", optopt);
                    PRINT_COMMAND_HELP;
                    return 1;
                }
        }
    }

    if (tcport == 0 && udport == 0) {
        printf("nothing to do (-TU)\n");
        return 0;
    }
    if (servhost == NULL) {
        printf("missing option '-s'\n");
        PRINT_COMMAND_HELP;
        return 1;
    }
    if (cafile == NULL) {
        printf("missing option '-c'\n");
        PRINT_COMMAND_HELP;
        return 1;
    }
    if (requri == NULL) {
        printf("missing option '-P'\n");
        PRINT_COMMAND_HELP;
        return 1;
    }

    strcpy(servreq + strlen(servreq), "GET ");
    strcpy(servreq + strlen(servreq), requri);
    strcpy(servreq + strlen(servreq), " HTTP/1.1\r\n");
    strcpy(servreq + strlen(servreq), "Host: ");
    strcpy(servreq + strlen(servreq), servhost);
    strcpy(servreq + strlen(servreq), "\r\n");
    strcpy(servreq + strlen(servreq), "Upgrade: websocket\r\n");
    strcpy(servreq + strlen(servreq), "Connection: Upgrade\r\n");
    if (reqext != NULL) {
        strcpy(servreq + strlen(servreq), reqext); // must end with '\r\n'
    }

    SSL_library_init();
    SSL_load_error_strings();

    struct hostent *ent = gethostbyname(servhost);
    if (ent == NULL) {
        printf("can't resolve host %s: (%d) %s\n", servhost, errno, strerror(errno));
        return errno;
    }
    servaddr.sin_family = AF_INET;
    memcpy(&servaddr.sin_addr, ent->h_addr_list[0], ent->h_length);
    servaddr.sin_port = htons(servport);

    if (tcport != 0) {
        tcpladdr.sin_family = AF_INET;
        tcpladdr.sin_addr.s_addr = inet_addr(listen);
        tcpladdr.sin_port = htons(tcport);
    }

    if (udport != 0) {
        udpladdr.sin_family = AF_INET;
        udpladdr.sin_addr.s_addr = inet_addr(listen);
        udpladdr.sin_port = htons(udport);

        udprbuff = calloc(1, UDP_RAW_BUFSIZ);
        udpebuff = calloc(1, UDP_ENC_BUFSIZ);
    }

    char ctime[36] = {0};
    printf("%s [srv] thread nums: %d\n",    loginf(ctime), thread_nums);
    printf("%s [srv] server host: %s\n",    loginf(ctime), servhost);
    printf("%s [srv] server addr: %s:%d\n", loginf(ctime), inet_ntoa(servaddr.sin_addr), servport);
    if (tcport != 0) printf("%s [srv] tcp address: %s:%d\n", loginf(ctime), listen, tcport);
    if (udport != 0) printf("%s [srv] udp address: %s:%d\n", loginf(ctime), listen, udport);

    thread_datas = calloc(thread_nums, sizeof(THREAD_DATA));
    thread_datas[0].tid = pthread_self();
    if (tcport != 0) {
        for (int i = 1; i < thread_nums; ++i) {
            if (pthread_create(&thread_datas[i].tid, NULL, service, NULL) != 0) {
                printf("%s [srv] create thread: (%d) %s\n", logerr(ctime), errno, strerror(errno));
                return errno;
            }
        }
        if (udport == 0) service(NULL);      // tcponly
        if (udport != 0) service((void *)1); // tcp&udp
    } else {
        service((void *)2); // udponly
    }

    if (tcport != 0) {
        for (int i = 1; i < thread_nums; ++i) {
            pthread_join(thread_datas[i].tid, NULL);
        }
    }

    if (udport != 0) {
        free(udprbuff);
        free(udpebuff);
    }

    free(thread_datas);
    ERR_free_strings();
    EVP_cleanup();

    return 0;
}

// arg = 0 -> tcponly
// arg = 1 -> tcp&udp
// arg = 2 -> udponly
void *service(void *arg) {
    char ctime[36] = {0};
    char error[64] = {0};

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
    SSL_CTX_load_verify_locations(ctx, cafile, NULL);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_cipher_list(ctx, SSL_CIPHERS);
    set_ssl_ctx(ctx);

    struct event_config *cfg = event_config_new();
    event_config_set_flag(cfg, EVENT_BASE_FLAG_NOLOCK | EVENT_BASE_FLAG_IGNORE_ENV);
    struct event_base *base = event_base_new_with_config(cfg);
    event_config_free(cfg);
    if (arg != NULL) udpbase = base;

    int optval = 1;
    struct evconnlistener *tcplistener = NULL;

    if (arg != (void *)2) {
        tcplistener = evconnlistener_new_bind(
                base, tcp_newconn_cb, NULL,
                LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE | LEV_OPT_REUSEABLE_PORT,
                SOMAXCONN, (struct sockaddr *)&tcpladdr, sizeof(struct sockaddr_in)
        );

        if (tcplistener == NULL) {
            printf("%s [tcp] listen socket: (%d) %s\n", logerr(ctime), errno, strerror_r(errno, error, 64));
            exit(errno);
        }

        if (setsockopt(evconnlistener_get_fd(tcplistener), SOL_IP, IP_TRANSPARENT, &optval, sizeof(optval)) == -1) {
            printf("%s [tcp] setsockopt(IP_TRANSPARENT) for %d: (%d) %s\n", logerr(ctime), evconnlistener_get_fd(tcplistener), errno, strerror_r(errno, error, 64));
            exit(errno);
        }
    }

    if (arg != NULL) {
        udplsock = socket(AF_INET, SOCK_DGRAM, 0);
        evutil_make_socket_nonblocking(udplsock);

        if (setsockopt(udplsock, SOL_IP, IP_TRANSPARENT, &optval, sizeof(optval)) == -1) {
            printf("%s [udp] setsockopt(IP_TRANSPARENT) for %d: (%d) %s\n", logerr(ctime), udplsock, errno, strerror_r(errno, error, 64));
            exit(errno);
        }
        if (setsockopt(udplsock, IPPROTO_IP, IP_RECVORIGDSTADDR, &optval, sizeof(optval)) == -1) {
            printf("%s [udp] setsockopt(IP_RECVORIGDSTADDR) for %d: (%d) %s\n", logerr(ctime), udplsock, errno, strerror_r(errno, error, 64));
            exit(errno);
        }

        if (bind(udplsock, (struct sockaddr *)&udpladdr, sizeof(udpladdr)) == -1) {
            printf("%s [udp] bind socket: (%d) %s\n", logerr(ctime), errno, strerror_r(errno, error, 64));
            exit(errno);
        }

        udptev = event_new(base, -1, EV_TIMEOUT, udp_release_cb, NULL);
        udplev = event_new(base, udplsock, EV_READ | EV_PERSIST, udp_request_cb, NULL);

        SSL *ssl = SSL_new(ctx);
        SSL_set_tlsext_host_name(ssl, servhost);
        X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), servhost, 0);
        if (get_ssl_sess() != NULL) SSL_set_session(ssl, get_ssl_sess());

        udpbev = bufferevent_openssl_socket_new(base, -1, ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
        bufferevent_setcb(udpbev, NULL, NULL, udp_sendreq_cb, NULL);
        bufferevent_enable(udpbev, EV_READ | EV_WRITE);
        bufferevent_setwatermark(udpbev, EV_READ, 0, BUFSIZ_FOR_BEV);
        printf("%s [udp] connecting to %s:%d\n", loginf(ctime), servhost, servport);
        bufferevent_socket_connect(udpbev, (struct sockaddr *)&servaddr, sizeof(servaddr));
        setsockopt_tcp(bufferevent_getfd(udpbev));
    }

    event_base_dispatch(base);

    if (arg != NULL) {
        udpnode_clear();
        close(udplsock);
        event_free(udplev);
        event_free(udptev);
        bufferevent_free(udpbev);
    }

    if (arg != (void *)2) {
        evconnlistener_free(tcplistener);
    }

    event_base_free(base);
    libevent_global_shutdown();

    if (get_ssl_sess() != NULL) SSL_SESSION_free(get_ssl_sess());
    SSL_CTX_free(ctx);

    return NULL;
}

void tcp_newconn_cb(struct evconnlistener *listener, int sock, struct sockaddr *addr, int addrlen, void *arg) {
    (void) listener; (void) sock; (void) addr; (void) addrlen; (void) arg;

    char ctime[36] = {0};
    setsockopt_tcp(sock);

    struct sockaddr_in *clntaddr = (struct sockaddr_in *)addr;
    printf("%s [tcp] new connect: %s:%d\n", loginf(ctime), inet_ntoa(clntaddr->sin_addr), ntohs(clntaddr->sin_port));

    struct sockaddr_in destaddr = {0};
    getsockname(sock, (struct sockaddr *)&destaddr, (socklen_t *)&addrlen);
    printf("%s [tcp] dest address: %s:%d\n", loginf(ctime), inet_ntoa(destaddr.sin_addr), ntohs(destaddr.sin_port));

    SSL *ssl = SSL_new(get_ssl_ctx());                               
    SSL_set_tlsext_host_name(ssl, servhost);
    X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), servhost, 0);
    if (get_ssl_sess() != NULL) SSL_set_session(ssl, get_ssl_sess());

    struct bufferevent *clntbev = bufferevent_socket_new(evconnlistener_get_base(listener), sock, BEV_OPT_CLOSE_ON_FREE);                                       
    struct bufferevent *destbev = bufferevent_openssl_socket_new(evconnlistener_get_base(listener), -1, ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
    
    TCPArg *clntarg = calloc(1, sizeof(TCPArg));
    strcpy(clntarg->addr, inet_ntoa(destaddr.sin_addr));
    sprintf(clntarg->port, "%d", ntohs(destaddr.sin_port));
    clntarg->bev = destbev;
    clntarg->type = TCP_TYPE_GEN;
    
    TCPArg *destarg = calloc(1, sizeof(TCPArg));
    strcpy(destarg->addr, inet_ntoa(destaddr.sin_addr));
    sprintf(destarg->port, "%d", ntohs(destaddr.sin_port));
    destarg->bev = clntbev;
    destarg->type = TCP_TYPE_SSL;
    
    bufferevent_setcb(clntbev, NULL, NULL, tcp_events_cb, clntarg);
    bufferevent_setcb(destbev, NULL, NULL, tcp_events_cb, destarg);

    bufferevent_enable(clntbev, EV_WRITE);
    bufferevent_enable(destbev, EV_READ | EV_WRITE);
    
    bufferevent_setwatermark(clntbev, EV_READ, 0, BUFSIZ_FOR_BEV);
    bufferevent_setwatermark(destbev, EV_READ, 0, BUFSIZ_FOR_BEV);
    
    printf("%s [tcp] connecting to: %s:%d\n", loginf(ctime), servhost, servport);
    bufferevent_socket_connect(destbev, (struct sockaddr *)&servaddr, sizeof(servaddr));
    setsockopt_tcp(bufferevent_getfd(destbev));
}

void tcp_events_cb(struct bufferevent *bev, short events, void *arg) {
    (void) bev; (void) events; (void) arg;

    char ctime[36] = {0};
    TCPArg *thisarg = arg;

    if (events & BEV_EVENT_CONNECTED) {
        printf("%s [tcp] connected to %s:%d\n", loginf(ctime), servhost, servport);
        printf("%s [tcp] send request to %s:%d\n", loginf(ctime), servhost, servport);

        bufferevent_write(bev, servreq, strlen(servreq));
        bufferevent_write(bev, "ConnectionType: tcp; addr=", strlen("ConnectionType: tcp; addr="));
        bufferevent_write(bev, thisarg->addr, strlen(thisarg->addr));
        bufferevent_write(bev, "; port=", strlen("; port="));
        bufferevent_write(bev, thisarg->port, strlen(thisarg->port));
        bufferevent_write(bev, "\r\n\r\n", 4);
        bufferevent_setcb(bev, tcp_recvres_cb, NULL, tcp_events_cb, arg);

        if (get_ssl_sess() != NULL) SSL_SESSION_free(get_ssl_sess());
        set_ssl_sess(SSL_get1_session(bufferevent_openssl_get_ssl(bev)));
        return;
    }

    if (events & BEV_EVENT_ERROR) {
        unsigned long sslerror = bufferevent_get_openssl_error(bev);
        if (sslerror != 0) {
            printf("%s [tcp] openssl error: (%lu) %s\n", logerr(ctime), sslerror, ERR_reason_error_string(sslerror));
        } else {
            if (errno != 0) {
                char error[64] = {0};
                printf("%s [tcp] socket error: (%d) %s\n", logerr(ctime), errno, strerror_r(errno, error, 64));
            }
        }
    }

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {                                                                            
        struct sockaddr_in thisaddr = {0};
        struct sockaddr_in othraddr = {0};
        socklen_t addrlen = sizeof(struct sockaddr_in);

        getpeername(bufferevent_getfd(bev),          (struct sockaddr *)&thisaddr, &addrlen);
        getpeername(bufferevent_getfd(thisarg->bev), (struct sockaddr *)&othraddr, &addrlen);

        if (thisarg->type == TCP_TYPE_SSL) {
            printf("%s [tcp] closed connect: %s:%d\n", loginf(ctime), servhost, servport);
            printf("%s [tcp] closed connect: %s:%d\n", loginf(ctime), inet_ntoa(othraddr.sin_addr), ntohs(othraddr.sin_port));
            SSL *ssl = bufferevent_openssl_get_ssl(bev);
            SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
            SSL_shutdown(ssl);
        } else {
            printf("%s [tcp] closed connect: %s:%d\n", loginf(ctime), inet_ntoa(thisaddr.sin_addr), ntohs(thisaddr.sin_port));
            printf("%s [tcp] closed connect: %s:%d\n", loginf(ctime), servhost, servport);
        }

        TCPArg *othrarg = NULL;
        bufferevent_getcb(thisarg->bev, NULL, NULL, NULL, (void **)&othrarg);

        bufferevent_free(bev);
        bufferevent_setcb(thisarg->bev, NULL, NULL, NULL, NULL);

        EVArg *evarg = calloc(1, sizeof(EVArg));
        struct event *ev = event_new(bufferevent_get_base(thisarg->bev), -1, EV_TIMEOUT, tcp_timeout_cb, evarg);
        evarg->ev = ev; evarg->bev = thisarg->bev; evarg->type = othrarg->type;
        struct timeval tv = {3, 0};
        event_add(ev, &tv);

        free(thisarg);
        free(othrarg);
    }
}

void tcp_recvres_cb(struct bufferevent *bev, void *arg) {
    (void) bev; (void) arg;

    char ctime[36] = {0};
    TCPArg *thisarg = arg;

    struct evbuffer *input = bufferevent_get_input(bev);
    char *statusline = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF);
    evbuffer_drain(input, evbuffer_get_length(input));

    struct sockaddr_in clntaddr = {0};
    socklen_t addrlen = sizeof(clntaddr);
    getpeername(bufferevent_getfd(thisarg->bev), (struct sockaddr *)&clntaddr, &addrlen);

    if (statusline == NULL || strcmp(statusline, WEBSOCKET_STATUS_LINE) != 0) {
        free(statusline);

        printf("%s [tcp] bad response: %s:%d\n",   logerr(ctime), servhost, servport);
        printf("%s [tcp] closed connect: %s:%d\n", loginf(ctime), servhost, servport);
        printf("%s [tcp] closed connect: %s:%d\n", loginf(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));

        SSL *ssl = bufferevent_openssl_get_ssl(bev);
        SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
        SSL_shutdown(ssl);                           

        TCPArg *othrarg = NULL;
        bufferevent_getcb(thisarg->bev, NULL, NULL, NULL, (void **)&othrarg);

        bufferevent_free(bev);
        bufferevent_free(thisarg->bev);

        free(thisarg);
        free(othrarg);
        return;
    }

    free(statusline);
    printf("%s [tcp] %s:%d <-> %s:%s\n", loginf(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port), thisarg->addr, thisarg->port);
    bufferevent_setcb(bev, tcp_read_cb, NULL, tcp_events_cb, arg);

    TCPArg *othrarg = NULL;
    bufferevent_getcb(thisarg->bev, NULL, NULL, NULL, (void **)&othrarg);
    bufferevent_setcb(thisarg->bev, tcp_read_cb, NULL, tcp_events_cb, othrarg);
    bufferevent_enable(thisarg->bev, EV_READ);
}

void tcp_read_cb(struct bufferevent *bev, void *arg) {
    TCPArg *thisarg = arg;
    struct evbuffer *input = bufferevent_get_input(bev);
    struct evbuffer *output = bufferevent_get_output(thisarg->bev);
    evbuffer_add_buffer(output, input);
    if (evbuffer_get_length(output) >= BUFSIZ_FOR_BEV) {                             
        TCPArg *othrarg = NULL;
        bufferevent_getcb(thisarg->bev, NULL, NULL, NULL, (void **)&othrarg);
        bufferevent_disable(bev, EV_READ);
        bufferevent_setwatermark(thisarg->bev, EV_WRITE, BUFSIZ_FOR_BEV / 2, 0);
        bufferevent_setcb(thisarg->bev, tcp_read_cb, tcp_write_cb, tcp_events_cb, othrarg);
    }
}

void tcp_write_cb(struct bufferevent *bev, void *arg) {
    TCPArg *thisarg = arg;
    bufferevent_enable(thisarg->bev, EV_READ);
    bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
    bufferevent_setcb(bev, tcp_read_cb, NULL, tcp_events_cb, arg);
}

void tcp_timeout_cb(int sock, short events, void *arg) {
    (void) sock; (void) events;
    EVArg *evarg = arg;
    if (evarg->type == TCP_TYPE_SSL) {
        SSL *ssl = bufferevent_openssl_get_ssl(evarg->bev);
        SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
        SSL_shutdown(ssl);
    }
    bufferevent_free(evarg->bev);
    event_free(evarg->ev);
    free(evarg);
}

void udp_sendreq_cb(struct bufferevent *bev, short events, void *arg) {
    (void) bev; (void) events; (void) arg;
    char ctime[36] = {0};

    if (events & BEV_EVENT_CONNECTED) {
        printf("%s [udp] connected to %s:%d\n", loginf(ctime), servhost, servport);
        printf("%s [udp] send request to %s:%d\n", loginf(ctime), servhost, servport);

        bufferevent_write(bev, servreq, strlen(servreq));
        bufferevent_write(bev, "ConnectionType: udp\r\n\r\n", strlen("ConnectionType: udp\r\n\r\n"));
        bufferevent_setcb(bev, udp_recvres_cb, NULL, udp_sendreq_cb, NULL);

        if (get_ssl_sess() != NULL) SSL_SESSION_free(get_ssl_sess());
        set_ssl_sess(SSL_get1_session(bufferevent_openssl_get_ssl(bev)));
        return;
    }

    if (events & BEV_EVENT_ERROR) {
        unsigned long sslerror = bufferevent_get_openssl_error(bev);
        if (sslerror != 0) {
            printf("%s [udp] openssl error: (%lu) %s\n", logerr(ctime), sslerror, ERR_reason_error_string(sslerror));
        } else {
            if (errno != 0) {
                char error[64] = {0};
                printf("%s [udp] socket error: (%d) %s\n", logerr(ctime), errno, strerror_r(errno, error, 64));
            }
        }
    }

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        printf("%s [udp] closed connect: %s:%d\n", loginf(ctime), servhost, servport);
        SSL *ssl = bufferevent_openssl_get_ssl(bev);
        SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
        SSL_shutdown(ssl);

        udpnode_clear();
        bufferevent_free(bev);
        if (event_pending(udplev, EV_READ, NULL)) event_del(udplev);
        if (event_pending(udptev, EV_TIMEOUT, NULL)) event_del(udptev);

        ssl = SSL_new(get_ssl_ctx());
        SSL_set_tlsext_host_name(ssl, servhost);
        X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), servhost, 0);
        if (get_ssl_sess() != NULL) SSL_set_session(ssl, get_ssl_sess());

        udpbev = bufferevent_openssl_socket_new(udpbase, -1, ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
        bufferevent_setcb(udpbev, NULL, NULL, udp_sendreq_cb, NULL);
        bufferevent_enable(udpbev, EV_READ | EV_WRITE);
        bufferevent_setwatermark(udpbev, EV_READ, 0, BUFSIZ_FOR_BEV);
        printf("%s [udp] connecting to %s:%d\n", loginf(ctime), servhost, servport);
        bufferevent_socket_connect(udpbev, (struct sockaddr *)&servaddr, sizeof(servaddr));
        setsockopt_tcp(bufferevent_getfd(udpbev));
    }
}

void udp_recvres_cb(struct bufferevent *bev, void *arg) {
    (void) arg;
    char ctime[36] = {0};

    struct evbuffer *input = bufferevent_get_input(bev);
    char *statusline = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF);
    evbuffer_drain(input, evbuffer_get_length(input));

    if (statusline == NULL || strcmp(statusline, WEBSOCKET_STATUS_LINE) != 0) {
        free(statusline);
        printf("%s [udp] bad response: %s:%d\n", logerr(ctime), servhost, servport);
        printf("%s [udp] closed connect: %s:%d\n", loginf(ctime), servhost, servport);

        SSL *ssl = bufferevent_openssl_get_ssl(bev);
        SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
        SSL_shutdown(ssl);

        udpnode_clear();
        bufferevent_free(bev);
        if (event_pending(udplev, EV_READ, NULL)) event_del(udplev);
        if (event_pending(udptev, EV_TIMEOUT, NULL)) event_del(udptev);

        ssl = SSL_new(get_ssl_ctx());
        SSL_set_tlsext_host_name(ssl, servhost);
        X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), servhost, 0);
        if (get_ssl_sess() != NULL) SSL_set_session(ssl, get_ssl_sess());

        udpbev = bufferevent_openssl_socket_new(udpbase, -1, ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
        bufferevent_setcb(udpbev, NULL, NULL, udp_sendreq_cb, NULL);
        bufferevent_enable(udpbev, EV_READ | EV_WRITE);
        bufferevent_setwatermark(udpbev, EV_READ, 0, BUFSIZ_FOR_BEV);
        printf("%s [udp] connecting to %s:%d\n", loginf(ctime), servhost, servport);
        bufferevent_socket_connect(udpbev, (struct sockaddr *)&servaddr, sizeof(servaddr));
        setsockopt_tcp(bufferevent_getfd(udpbev));
        return;
    }
    free(statusline);

    struct sockaddr_in selfaddr = {0};
    socklen_t addrlen = sizeof(selfaddr);
    getsockname(bufferevent_getfd(bev), (struct sockaddr *)&selfaddr, &addrlen);
    printf("%s [udp] %s:%d <-> %s:%d\n", loginf(ctime), inet_ntoa(selfaddr.sin_addr), ntohs(selfaddr.sin_port), servhost, servport);

    struct timeval tv = {900, 0};
    event_add(udptev, &tv);
    event_add(udplev, NULL);
    bufferevent_setcb(bev, udp_response_cb, NULL, udp_sendreq_cb, NULL);
}

void udp_request_cb(int sock, short events, void *arg) {
    (void) sock; (void) events; (void) arg;
    memset(udpcntl, 0, sizeof(udpcntl));
    char ctime[36] = {0};
    char error[64] = {0};

    struct sockaddr_in clntaddr = {0};
    socklen_t addrlen = sizeof(clntaddr);
    struct iovec iov = {udprbuff, UDP_RAW_BUFSIZ};

    struct msghdr msg = {0};
    msg.msg_name = &clntaddr;
    msg.msg_namelen = addrlen;
    msg.msg_control = udpcntl;
    msg.msg_controllen = 64;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;

    int rawlen = recvmsg(sock, &msg, 0);
    if (rawlen == -1) {
        printf("%s [udp] recvmsg socket: (%d) %s\n", logerr(ctime), errno, strerror_r(errno, error, 64));
        return;
    }
    printf("%s [udp] recv %d bytes data from %s:%d\n", loginf(ctime), rawlen, inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));

    int found = 0;
    struct sockaddr_in destaddr = {0};
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVORIGDSTADDR) {
            memcpy(&destaddr, CMSG_DATA(cmsg), addrlen);
            found = 1;
            break;
        }
    }
    if (!found) {
        printf("%s [udp] can't get destaddr of %s:%d\n", logerr(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
        return;
    }
    char iaddrstr[22] = {0};
    sprintf(iaddrstr, "%s:%d", inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));

    size_t enclen = 0;
    base64_encode(udprbuff, rawlen, udpebuff, &enclen, 0);
    udpebuff[enclen] = 0;

    char eportstr[6] = {0};
    sprintf(eportstr, "%d", udpnode_getport(iaddrstr));

    char raddrstr[22] = {0};
    sprintf(raddrstr, "%s:%d", inet_ntoa(destaddr.sin_addr), ntohs(destaddr.sin_port));

    bufferevent_write(udpbev, iaddrstr, strlen(iaddrstr));
    bufferevent_write(udpbev, ":", 1);
    bufferevent_write(udpbev, raddrstr, strlen(raddrstr));
    bufferevent_write(udpbev, ":", 1);
    bufferevent_write(udpbev, eportstr, strlen(eportstr));
    bufferevent_write(udpbev, ":", 1);
    bufferevent_write(udpbev, udpebuff, strlen(udpebuff));
    bufferevent_write(udpbev, "\r\n", 2);

    printf("%s [udp] send %d bytes data to %s\n", loginf(ctime), rawlen, raddrstr);
}

void udp_response_cb(struct bufferevent *bev, void *arg) {
    (void) bev; (void) arg;
    char ctime[36] = {0};

    char *response = NULL;
    struct evbuffer *input = bufferevent_get_input(bev);
    while ((response = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF)) != NULL) {
        int colon_cnt = 0;
        for (int i = 0, l = strlen(response); i < l; ++i) {
            if (response[i] == ':') ++colon_cnt;
        }

        if (colon_cnt != 5 || strlen(response) < 23) {
            printf("%s [udp] bad response: %s:%d\n", logerr(ctime), servhost, servport);
            free(response);
            continue;
        }

        char *iaddrptr = response;
        char *iportptr = strchr(iaddrptr, ':'); *iportptr = 0; ++iportptr;
        char *raddrptr = strchr(iportptr, ':'); *raddrptr = 0; ++raddrptr;
        char *rportptr = strchr(raddrptr, ':'); *rportptr = 0; ++rportptr;
        char *eportptr = strchr(rportptr, ':'); *eportptr = 0; ++eportptr;
        char *edataptr = strchr(eportptr, ':'); *edataptr = 0; ++edataptr;

        if (strlen(iaddrptr) < 7 || strlen(iaddrptr) > 15) {
            printf("%s [udp] bad response: %s:%d\n", logerr(ctime), servhost, servport);
            free(response);
            continue;
        }

        if (strlen(iportptr) < 1 || strlen(iportptr) > 5) {
            printf("%s [udp] bad response: %s:%d\n", logerr(ctime), servhost, servport);
            free(response);
            continue;
        }

        if (strlen(raddrptr) < 7 || strlen(raddrptr) > 15) {
            printf("%s [udp] bad response: %s:%d\n", logerr(ctime), servhost, servport);
            free(response);
            continue;
        }

        if (strlen(rportptr) < 1 || strlen(rportptr) > 5) {
            printf("%s [udp] bad response: %s:%d\n", logerr(ctime), servhost, servport);
            free(response);
            continue;
        }

        if (strlen(eportptr) < 1 || strlen(eportptr) > 5) {
            printf("%s [udp] bad response: %s:%d\n", logerr(ctime), servhost, servport);
            free(response);
            continue;
        }

        if (strlen(edataptr) < 1) {
            printf("%s [udp] bad response: %s:%d\n", logerr(ctime), servhost, servport);
            free(response);
            continue;
        }

        uint32_t iaddr = inet_addr(iaddrptr);
        if (iaddr == INADDR_NONE) {
            printf("%s [udp] bad response: %s:%d\n", logerr(ctime), servhost, servport);
            free(response);
            continue;
        }

        uint16_t iport = htons(strtol(iportptr, NULL, 10));
        if (iport == 0) {
            printf("%s [udp] bad response: %s:%d\n", logerr(ctime), servhost, servport);
            free(response);
            continue;
        }

        uint32_t raddr = inet_addr(raddrptr);
        if (raddr == INADDR_NONE) {
            printf("%s [udp] bad response: %s:%d\n", logerr(ctime), servhost, servport);
            free(response);
            continue;
        }

        uint16_t rport = htons(strtol(rportptr, NULL, 10));
        if (rport == 0) {
            printf("%s [udp] bad response: %s:%d\n", logerr(ctime), servhost, servport);
            free(response);
            continue;
        }

        int eport = strtol(eportptr, NULL, 10);
        if (eport <= 0 || eport > 65535) {
            printf("%s [udp] bad response: %s:%d\n", logerr(ctime), servhost, servport);
            free(response);
            continue;
        }

        size_t rawlen = 0;
        if (base64_decode(edataptr, strlen(edataptr), udprbuff, &rawlen, 0) != 1) {
            printf("%s [udp] bad response: %s:%d\n", logerr(ctime), servhost, servport);
            free(response);
            continue;
        }
        printf("%s [udp] recv %ld bytes data from %s:%s\n", loginf(ctime), rawlen, raddrptr, rportptr);

        *--iportptr = ':';
        udpnode_put(iaddrptr, eport);

        struct sockaddr_in clntaddr = {0};
        clntaddr.sin_family = AF_INET;
        clntaddr.sin_addr.s_addr = iaddr;
        clntaddr.sin_port = iport;

        struct sockaddr_in destaddr = {0};
        destaddr.sin_family = AF_INET;
        destaddr.sin_addr.s_addr = raddr;
        destaddr.sin_port = rport;

        int destsock = socket(AF_INET, SOCK_DGRAM, 0);
        evutil_make_socket_nonblocking(destsock);

        int optval = 1;
        setsockopt(destsock, SOL_IP, IP_TRANSPARENT, &optval, sizeof(optval));

        if (bind(destsock, (struct sockaddr *)&destaddr, sizeof(destaddr)) == -1) {
            char error[64] = {0};
            printf("%s [udp] bind socket: (%d) %s\n", logerr(ctime), errno, strerror_r(errno, error, 64));
            close(destsock);
            free(response);
            continue;
        }

        if (sendto(destsock, udprbuff, rawlen, 0, (struct sockaddr *)&clntaddr, sizeof(clntaddr)) == -1) {
            char error[64] = {0};
            printf("%s [udp] sendto socket: (%d) %s\n", logerr(ctime), errno, strerror_r(errno, error, 64));
            close(destsock);
            free(response);
            continue;
        }

        printf("%s [udp] send %ld bytes data to %s\n", loginf(ctime), rawlen, iaddrptr);
        close(destsock);
        free(response);
    }
}

void udp_release_cb(int sock, short events, void *arg) {
    (void) sock; (void) events; (void) arg;

    char ctime[36] = {0};
    printf("%s [udp] tunnel timeout: %s:%d\n", loginf(ctime), servhost, servport);
    printf("%s [udp] closed connect: %s:%d\n", loginf(ctime), servhost, servport);

    SSL *ssl = bufferevent_openssl_get_ssl(udpbev);
    SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
    SSL_shutdown(ssl);

    udpnode_clear();
    bufferevent_free(udpbev);
    if (event_pending(udplev, EV_READ, NULL)) event_del(udplev);

    ssl = SSL_new(get_ssl_ctx());
    SSL_set_tlsext_host_name(ssl, servhost);
    X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), servhost, 0);
    if (get_ssl_sess() != NULL) SSL_set_session(ssl, get_ssl_sess());

    udpbev = bufferevent_openssl_socket_new(udpbase, -1, ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(udpbev, NULL, NULL, udp_sendreq_cb, NULL);
    bufferevent_enable(udpbev, EV_READ | EV_WRITE);
    bufferevent_setwatermark(udpbev, EV_READ, 0, BUFSIZ_FOR_BEV);
    printf("%s [udp] connecting to %s:%d\n", loginf(ctime), servhost, servport);
    bufferevent_socket_connect(udpbev, (struct sockaddr *)&servaddr, sizeof(servaddr));
    setsockopt_tcp(bufferevent_getfd(udpbev));
}

void udp_timeout_cb(int sock, short events, void *arg) {
    (void) sock; (void) events;
    char ctime[36] = {0};
    printf("%s [udp] socket timeout: %s\n", loginf(ctime), (char *)arg);
    udpnode_del(arg);
}
