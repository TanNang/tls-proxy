#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
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
#include <linux/netfilter_ipv4.h>
#include "libbase64.h"

#define PRINT_COMMAND_HELP \
    printf("usage: tls-client <OPTIONS>. OPTIONS have these:\n"\
           " -s <server_host>        server host. can't use IP address\n"\
           " -p <server_port>        server port. the default port is 443\n"\
           " -c <cafile_path>        CA file location. eg: /etc/ssl/cert.pem\n"\
           " -P <request_uri>        websocket request line uri. eg: /tls-proxy\n"\
           " -H <request_header>     websocket request headers. allow multiple lines\n"\
           " -b <listen_address>     tcp & udp & dns listen address. default: 0.0.0.0\n"\
           " -t <tcp_proxy_port>     tcp proxy port (iptables redirect).  default: 60080\n"\
           " -u <udp_proxy_port>     udp proxy port (iptables xt_tproxy). default: 60080\n"\
           " -d <dns_proxy_port>     dns proxy port (local port forward). default: 60053\n"\
           " -D <dns_remote_addr>    remote dns server address. default addr: 8.8.8.8:53\n"\
           "                         if not specify server port, 53 will used by default\n"\
           " -j <thread_numbers>     number of worker threads. default is number of CPUs\n"\
           " -v                      show current version and exit\n"\
           " -h                      show current message and exit\n")

#define BUFSIZ_FOR_BEV 524288 // 512k
#define UDP_RAW_BUFSIZ 1472
#define UDP_ENC_BUFSIZ 1960
#define WEBSOCKET_STATUS_LINE "HTTP/1.1 101 Switching Protocols"
#define SSL_CIPHERS "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305"

/* 线程共享的全局数据 */
static char               *servhost     = NULL;
static int                 servport     = 443;
static struct sockaddr_in  servaddr     = {0};
static char               *cafile       = NULL;
static char                servreq[256] = {0};
static struct sockaddr_in  tcpladdr     = {0};
static struct sockaddr_in  udpladdr     = {0};
static struct sockaddr_in  dnsladdr     = {0};
static char                dnsraddr[16] = "8.8.8.8";
static char                dnsrport[6]  = "53";

/* 线程私有的全局数据 */
typedef struct {
    pthread_t    tid;
    SSL_CTX     *ctx;
    SSL_SESSION *sess;
    void        *udprbuf;
    int          dnslsock;
} THREAD_DATA;

static int          thread_nums  = 0;
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

/* 获取当前线程的 udp raw buf */
void *get_udp_rawbuf() {
    pthread_t tid = pthread_self();
    for (int i = 0; i < thread_nums; ++i) {
        if (thread_datas[i].tid == tid) {
            return thread_datas[i].udprbuf;
        }
    }
    return NULL;
}
void set_udp_rawbuf(void *udprbuf) {
    pthread_t tid = pthread_self();
    for (int i = 0; i < thread_nums; ++i) {
        if (thread_datas[i].tid == tid) {
            thread_datas[i].udprbuf = udprbuf;
            return;
        }
    }
}

/* 获取当前线程的 dns listen sock */
int get_dns_lsock() {
    pthread_t tid = pthread_self();
    for (int i = 0; i < thread_nums; ++i) {
        if (thread_datas[i].tid == tid) {
            return thread_datas[i].dnslsock;
        }
    }
    return -1;
}
void set_dns_lsock(int dnslsock) {
    pthread_t tid = pthread_self();
    for (int i = 0; i < thread_nums; ++i) {
        if (thread_datas[i].tid == tid) {
            thread_datas[i].dnslsock = dnslsock;
            return;
        }
    }
}

// sizeof(ctime) = 20
char *curtime(char *ctime) {
    time_t rawtime;
    time(&rawtime);

    struct tm curtm;
    localtime_r(&rawtime, &curtm);

    sprintf(ctime, "%04d-%02d-%02d %02d:%02d:%02d",
            curtm.tm_year + 1900, curtm.tm_mon + 1, curtm.tm_mday,
            curtm.tm_hour,        curtm.tm_min,     curtm.tm_sec);

    return ctime;
}

// setsockopt for tcp connect
void set_tcp_sockopt(int sock) {
    char ctime[20] = {0};
    char error[64] = {0};

    int optval = 1;
    if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval)) == -1) {
        printf("[%s] [WRN] setsockopt(TCP_NODELAY): (%d) %s\n", curtime(ctime), errno, strerror_r(errno, error, 64));
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
        printf("[%s] [WRN] setsockopt(SO_REUSEADDR): (%d) %s\n", curtime(ctime), errno, strerror_r(errno, error, 64));
    }

    if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) == -1) {
        printf("[%s] [WRN] setsockopt(SO_KEEPALIVE): (%d) %s\n", curtime(ctime), errno, strerror_r(errno, error, 64));
    }

    optval = 30;
    if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &optval, sizeof(optval)) == -1) {
        printf("[%s] [WRN] setsockopt(TCP_KEEPIDLE): (%d) %s\n", curtime(ctime), errno, strerror_r(errno, error, 64));
    }

    if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &optval, sizeof(optval)) == -1) {
        printf("[%s] [WRN] setsockopt(TCP_KEEPINTVL): (%d) %s\n", curtime(ctime), errno, strerror_r(errno, error, 64));
    }

    optval = 3;
    if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &optval, sizeof(optval)) == -1) {
        printf("[%s] [WRN] setsockopt(TCP_KEEPCNT): (%d) %s\n", curtime(ctime), errno, strerror_r(errno, error, 64));
    }
}

// worker thread function
void *service(void *arg);

int main(int argc, char *argv[]) {
    /* 选项默认值 */
    char *request_uripath = NULL;
    char *request_headers = NULL;
    char *listen_address  = "0.0.0.0";
    int   tcp_proxy_port  = 60080;
    int   udp_proxy_port  = 60080;
    int   dns_proxy_port  = 60053;
          thread_nums     = get_nprocs();

    /* 解析命令行 */
    opterr = 0;
    char *optstr = "s:p:c:P:H:b:t:u:d:D:j:vh";
    int opt = -1;
    while ((opt = getopt(argc, argv, optstr)) != -1) {
        switch (opt) {
            case 'v':
                printf("tls-client v1.0\n");
                return 0;
            case 'h':
                PRINT_COMMAND_HELP;
                return 0;
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
                    printf("CA file not exists: %s\n", cafile);
                    PRINT_COMMAND_HELP;
                    return 1;
                }
                break;
            case 'P':
                request_uripath = optarg;
                break;
            case 'H':
                request_headers = optarg;
                break;
            case 'b':
                listen_address = optarg;
                break;
            case 't':
                tcp_proxy_port = strtol(optarg, NULL, 10);
                if (tcp_proxy_port <= 0 || tcp_proxy_port > 65535) {
                    printf("invalid tcp port: %d\n", tcp_proxy_port);
                    PRINT_COMMAND_HELP;
                    return 1;
                }
                break;
            case 'u':
                udp_proxy_port = strtol(optarg, NULL, 10);
                if (udp_proxy_port <= 0 || udp_proxy_port > 65535) {
                    printf("invalid udp port: %d\n", udp_proxy_port);
                    PRINT_COMMAND_HELP;
                    return 1;
                }
                break;
            case 'd':
                dns_proxy_port = strtol(optarg, NULL, 10);
                if (dns_proxy_port <= 0 || dns_proxy_port > 65535) {
                    printf("invalid dns port: %d\n", dns_proxy_port);
                    PRINT_COMMAND_HELP;
                    return 1;
                }
                break;
            case 'D': {
                char *ptr = strchr(optarg, ':');
                if (ptr == NULL) {
                    strcpy(dnsraddr, optarg);
                    break;
                }
                strncpy(dnsraddr, optarg, ptr - optarg);
                strncpy(dnsrport, ptr + 1, optarg + strlen(optarg) - ptr - 1);
                break;
            }
            case 'j':
                thread_nums = strtol(optarg, NULL, 10);
                if (thread_nums <= 0) {
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

    /* 处理选项值 */
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
    if (request_uripath == NULL) {
        printf("missing option '-P'\n");
        PRINT_COMMAND_HELP;
        return 1;
    }

    /* websocket 请求头 */
    strcpy(servreq + strlen(servreq), "GET ");
    strcpy(servreq + strlen(servreq), request_uripath);
    strcpy(servreq + strlen(servreq), " HTTP/1.1\r\n");
    strcpy(servreq + strlen(servreq), "Host: ");
    strcpy(servreq + strlen(servreq), servhost);
    strcpy(servreq + strlen(servreq), "\r\n");
    strcpy(servreq + strlen(servreq), "Upgrade: websocket\r\n");
    strcpy(servreq + strlen(servreq), "Connection: Upgrade\r\n");
    if (request_headers != NULL) {
        strcpy(servreq + strlen(servreq), request_headers); // must end with '\r\n'
    }

    /* init openssl libs */
    SSL_library_init();
    SSL_load_error_strings();

    /* tls-server sockaddr */
    struct hostent *ent = gethostbyname(servhost);
    if (ent == NULL) {
        printf("can't resolve host: %s: (%d) %s\n", servhost, errno, strerror(errno));
        return errno;
    }
    servaddr.sin_family = AF_INET;
    memcpy(&servaddr.sin_addr, ent->h_addr_list[0], ent->h_length);
    servaddr.sin_port = htons(servport);

    /* tcp listen sockaddr */
    tcpladdr.sin_family = AF_INET;
    tcpladdr.sin_addr.s_addr = inet_addr(listen_address);
    tcpladdr.sin_port = htons(tcp_proxy_port);

    /* udp listen sockaddr */
    udpladdr.sin_family = AF_INET;
    udpladdr.sin_addr.s_addr = inet_addr(listen_address);
    udpladdr.sin_port = htons(udp_proxy_port);

    /* dns listen sockaddr */
    dnsladdr.sin_family = AF_INET;
    dnsladdr.sin_addr.s_addr = inet_addr(listen_address);
    dnsladdr.sin_port = htons(dns_proxy_port);

    /* print start message */
    char ctime[20] = {0};
    printf("[%s] [INF] thread nums: %d\n",    curtime(ctime), thread_nums);
    printf("[%s] [INF] server host: %s\n",    curtime(ctime), servhost);
    printf("[%s] [INF] server addr: %s:%d\n", curtime(ctime), inet_ntoa(servaddr.sin_addr), servport);
    printf("[%s] [INF] tcp address: %s:%d\n", curtime(ctime), listen_address, tcp_proxy_port);
    printf("[%s] [INF] udp address: %s:%d\n", curtime(ctime), listen_address, udp_proxy_port);
    printf("[%s] [INF] dns address: %s:%d\n", curtime(ctime), listen_address, dns_proxy_port);
    printf("[%s] [INF] dns resolve: %s:%s\n", curtime(ctime), dnsraddr, dnsrport);

    /* create worker thread */
    thread_datas = calloc(thread_nums, sizeof(THREAD_DATA));
    thread_datas[0].tid = pthread_self();
    for (int i = 1; i < thread_nums; ++i) {
        if (pthread_create(&thread_datas[i].tid, NULL, service, NULL) != 0) {
            printf("[%s] [ERR] create thread: (%d) %s\n", curtime(ctime), errno, strerror(errno));
            return errno;
        }
    }
    service(NULL);

    /* wait for other threads */
    for (int i = 1; i < thread_nums; ++i) {
        pthread_join(thread_datas[i].tid, NULL);
    }

    free(thread_datas);
    ERR_free_strings();
    EVP_cleanup();

    return 0;
}

struct tcp_arg {
    char                addr[16];
    char                port[6];
    struct bufferevent *bev;
};

struct udp_arg {
    char  srcaddr[16];
    int   srcport;
    char  dstaddr[16];
    int   dstport;
    char *udpebuf;
};

struct dns_arg {
    char  srcaddr[16];
    int   srcport;
    char *udpebuf;
};

/* TCP 相关回调 */
void tcp_new_cb(struct evconnlistener *listener, int sock, struct sockaddr *addr, int addrlen, void *arg);
void tcp_req_cb(struct bufferevent *bev, short events, void *arg);
void tcp_res_cb(struct bufferevent *bev, void *arg);
void tcp_fwd_cb(struct bufferevent *bev, void *arg);
void tcp_del_cb(struct bufferevent *bev, void *arg);

/* UDP 相关回调 */
void udp_new_cb(int sock, short events, void *arg);
void udp_req_cb(struct bufferevent *bev, short events, void *arg);
void udp_res_cb(struct bufferevent *bev, void *arg);

/* DNS 相关回调 */
void dns_new_cb(int sock, short events, void *arg);
void dns_req_cb(struct bufferevent *bev, short events, void *arg);
void dns_res_cb(struct bufferevent *bev, void *arg);

void *service(void *arg) {
    (void) arg;
    char ctime[20] = {0};
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

    // tcp proxy
    struct evconnlistener *tcplistener = evconnlistener_new_bind(
            base, tcp_new_cb, NULL,
            LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE | LEV_OPT_REUSEABLE_PORT,
            SOMAXCONN, (struct sockaddr *)&tcpladdr, sizeof(struct sockaddr_in)
    );
    if (tcplistener == NULL) {
        printf("[%s] [ERR] listen socket: (%d) %s\n", curtime(ctime), errno, strerror_r(errno, error, 64));
        exit(errno);
    }

    // udp proxy
    int udplsock = socket(AF_INET, SOCK_DGRAM, 0);
    evutil_make_socket_nonblocking(udplsock);
    set_udp_rawbuf(malloc(UDP_RAW_BUFSIZ));

    int on = 1;
    if (setsockopt(udplsock, SOL_IP, IP_TRANSPARENT, &on, sizeof(on)) == -1) {
        printf("[%s] [ERR] setsockopt(IP_TRANSPARENT): (%d) %s\n", curtime(ctime), errno, strerror_r(errno, error, 64));
        exit(errno);
    }
    if (setsockopt(udplsock, IPPROTO_IP, IP_RECVORIGDSTADDR, &on, sizeof(on)) == -1) {
        printf("[%s] [ERR] setsockopt(IP_RECVORIGDSTADDR): (%d) %s\n", curtime(ctime), errno, strerror_r(errno, error, 64));
        exit(errno);
    }
    if (setsockopt(udplsock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) == -1) {
        printf("[%s] [ERR] setsockopt(SO_REUSEPORT): (%d) %s\n", curtime(ctime), errno, strerror_r(errno, error, 64));
        exit(errno);
    }

    if (bind(udplsock, (struct sockaddr *)&udpladdr, sizeof(udpladdr)) == -1) {
        printf("[%s] [ERR] bind address: (%d) %s\n", curtime(ctime), errno, strerror_r(errno, error, 64));
        exit(errno);
    }

    struct event *udplev = event_new(base, udplsock, EV_READ | EV_PERSIST, udp_new_cb, event_self_cbarg());
    event_add(udplev, NULL);

    // dns proxy
    int dnslsock = socket(AF_INET, SOCK_DGRAM, 0);
    evutil_make_socket_nonblocking(dnslsock);
    set_dns_lsock(dnslsock);

    if (setsockopt(dnslsock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) == -1) {
        printf("[%s] [ERR] setsockopt(SO_REUSEPORT): (%d) %s\n", curtime(ctime), errno, strerror_r(errno, error, 64));
        exit(errno);
    }

    if (bind(dnslsock, (struct sockaddr *)&dnsladdr, sizeof(dnsladdr)) == -1) {
        printf("[%s] [ERR] bind address: (%d) %s\n", curtime(ctime), errno, strerror_r(errno, error, 64));
        exit(errno);
    }

    struct event *dnslev = event_new(base, dnslsock, EV_READ | EV_PERSIST, dns_new_cb, event_self_cbarg());
    event_add(dnslev, NULL);

    // event loop ...
    event_base_dispatch(base);

    // 清理相关资源
    close(dnslsock);
    close(udplsock);
    event_free(dnslev);
    event_free(udplev);
    free(get_udp_rawbuf());
    evconnlistener_free(tcplistener);
    event_base_free(base);
    libevent_global_shutdown();
    SSL_CTX_free(ctx);

    return NULL;
}

void tcp_new_cb(struct evconnlistener *listener, int sock, struct sockaddr *addr, int addrlen, void *arg) {
    (void) listener;
    (void) sock;
    (void) addr;
    (void) addrlen;
    (void) arg;

    char ctime[20] = {0};
    set_tcp_sockopt(sock);
    struct sockaddr_in *clntaddr = (struct sockaddr_in *)addr;
    printf("[%s] [INF] new connect: %s:%d\n", curtime(ctime), inet_ntoa(clntaddr->sin_addr), ntohs(clntaddr->sin_port));

    struct sockaddr_in destaddr = {0};
    getsockopt(sock, SOL_IP, SO_ORIGINAL_DST, &destaddr, (socklen_t *)&addrlen);
    printf("[%s] [INF] dest address: %s:%d\n", curtime(ctime), inet_ntoa(destaddr.sin_addr), ntohs(destaddr.sin_port));

    SSL *ssl = SSL_new(get_ssl_ctx());
    SSL_set_tlsext_host_name(ssl, servhost);
    X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), servhost, 0);
    if (get_ssl_sess() != NULL) SSL_set_session(ssl, get_ssl_sess());

    struct bufferevent *clntbev = bufferevent_socket_new(evconnlistener_get_base(listener), sock, BEV_OPT_CLOSE_ON_FREE);
    struct bufferevent *destbev = bufferevent_openssl_socket_new(evconnlistener_get_base(listener), -1, ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);

    struct tcp_arg *clntarg = calloc(1, sizeof(struct tcp_arg));
    strcpy(clntarg->addr, inet_ntoa(destaddr.sin_addr));
    sprintf(clntarg->port, "%d", ntohs(destaddr.sin_port));
    clntarg->bev = destbev;

    struct tcp_arg *destarg = calloc(1, sizeof(struct tcp_arg));
    strcpy(destarg->addr, inet_ntoa(destaddr.sin_addr));
    sprintf(destarg->port, "%d", ntohs(destaddr.sin_port));
    destarg->bev = clntbev;

    bufferevent_setcb(clntbev, NULL, NULL, tcp_req_cb, clntarg);
    bufferevent_setcb(destbev, NULL, NULL, tcp_req_cb, destarg);
    bufferevent_enable(clntbev, EV_WRITE);
    bufferevent_enable(destbev, EV_READ | EV_WRITE);

    bufferevent_setwatermark(clntbev, EV_READ, 0, BUFSIZ_FOR_BEV);
    bufferevent_setwatermark(destbev, EV_READ, 0, BUFSIZ_FOR_BEV);

    printf("[%s] [INF] connecting to: %s:%d\n", curtime(ctime), servhost, servport);
    bufferevent_socket_connect(destbev, (struct sockaddr *)&servaddr, sizeof(servaddr));
    set_tcp_sockopt(bufferevent_getfd(destbev));
}

void tcp_req_cb(struct bufferevent *bev, short events, void *arg) {
    (void) bev;
    (void) events;
    (void) arg;
    char ctime[20] = {0};
    struct tcp_arg *thisarg = arg;

    if (events & BEV_EVENT_CONNECTED) {
        printf("[%s] [INF] connected to %s:%d\n", curtime(ctime), servhost, servport);
        printf("[%s] [INF] send request to %s:%d\n", curtime(ctime), servhost, servport);
        bufferevent_write(bev, servreq, strlen(servreq));
        bufferevent_write(bev, "ConnectionType: tcp; addr=", strlen("ConnectionType: tcp; addr="));
        bufferevent_write(bev, thisarg->addr, strlen(thisarg->addr));
        bufferevent_write(bev, "; port=", strlen("; port="));
        bufferevent_write(bev, thisarg->port, strlen(thisarg->port));
        bufferevent_write(bev, "\r\n\r\n", 4);
        bufferevent_setcb(bev, tcp_res_cb, NULL, tcp_req_cb, arg);
        if (get_ssl_sess() != NULL) SSL_SESSION_free(get_ssl_sess());
        set_ssl_sess(SSL_get1_session(bufferevent_openssl_get_ssl(bev)));
        return;
    }

    if (events & BEV_EVENT_ERROR) {
        unsigned long sslerror = bufferevent_get_openssl_error(bev);
        if (sslerror != 0) {
            printf("[%s] [ERR] openssl error: (%lu) %s\n", curtime(ctime), sslerror, ERR_reason_error_string(sslerror));
        } else {
            char error[64] = {0};
            printf("[%s] [ERR] socket error: (%d) %s\n", curtime(ctime), errno, strerror_r(errno, error, 64));
        }
    }

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        struct sockaddr_in thisaddr = {0};
        struct sockaddr_in othraddr = {0};
        socklen_t addrlen = sizeof(struct sockaddr_in);
        getpeername(bufferevent_getfd(bev),          (struct sockaddr *)&thisaddr, &addrlen);
        getpeername(bufferevent_getfd(thisarg->bev), (struct sockaddr *)&othraddr, &addrlen);
        if (memcmp(&thisaddr, &servaddr, addrlen) == 0) {
            printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), servhost, servport);
            printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(othraddr.sin_addr), ntohs(othraddr.sin_port));
            SSL *ssl = bufferevent_openssl_get_ssl(bev);
            SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
            SSL_shutdown(ssl);
        } else {
            printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), servhost, servport);
            printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(thisaddr.sin_addr), ntohs(thisaddr.sin_port));
        }
        struct tcp_arg *othrarg = NULL;
        bufferevent_getcb(thisarg->bev, NULL, NULL, NULL, (void **)&othrarg);
        bufferevent_free(bev);
        bufferevent_free(thisarg->bev);
        free(thisarg);
        free(othrarg);
    }
}

void tcp_res_cb(struct bufferevent *bev, void *arg) {
    (void) bev;
    (void) arg;

    char ctime[20] = {0};
    struct tcp_arg *thisarg = arg;
    struct evbuffer *input = bufferevent_get_input(bev);
    char *statusline = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF);
    evbuffer_drain(input, evbuffer_get_length(input));

    struct sockaddr_in clntaddr = {0};
    socklen_t addrlen = sizeof(clntaddr);
    getpeername(bufferevent_getfd(thisarg->bev), (struct sockaddr *)&clntaddr, &addrlen);

    if (statusline == NULL || strcmp(statusline, WEBSOCKET_STATUS_LINE) != 0) {
        free(statusline);
        printf("[%s] [ERR] bad response: %s:%d\n",   curtime(ctime), servhost, servport);
        printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), servhost, servport);
        printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
        SSL *ssl = bufferevent_openssl_get_ssl(bev);
        SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
        SSL_shutdown(ssl);
        struct tcp_arg *othrarg = NULL;
        bufferevent_getcb(thisarg->bev, NULL, NULL, NULL, (void **)&othrarg);
        bufferevent_free(bev);
        bufferevent_free(thisarg->bev);
        free(thisarg);
        free(othrarg);
        return;
    }
    free(statusline);

    printf("[%s] [INF] forward data: %s:%d <-> %s:%s\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port), thisarg->addr, thisarg->port);
    bufferevent_setcb(bev, tcp_fwd_cb, NULL, tcp_req_cb, arg);
    struct tcp_arg *othrarg = NULL;
    bufferevent_getcb(thisarg->bev, NULL, NULL, NULL, (void **)&othrarg);
    bufferevent_setcb(thisarg->bev, tcp_fwd_cb, NULL, tcp_req_cb, othrarg);
    bufferevent_enable(thisarg->bev, EV_READ | EV_WRITE);
}

void tcp_fwd_cb(struct bufferevent *bev, void *arg) {
    struct tcp_arg *thisarg = arg;
    struct evbuffer *input = bufferevent_get_input(bev);
    struct evbuffer *output = bufferevent_get_output(thisarg->bev);

    evbuffer_add_buffer(output, input);

    if (evbuffer_get_length(output) >= BUFSIZ_FOR_BEV) {
        struct tcp_arg *othrarg = NULL;
        bufferevent_getcb(thisarg->bev, NULL, NULL, NULL, (void **)&othrarg);
        bufferevent_setcb(thisarg->bev, tcp_fwd_cb, tcp_del_cb, tcp_req_cb, othrarg);
        bufferevent_setwatermark(thisarg->bev, EV_WRITE, BUFSIZ_FOR_BEV / 2, 0);
        bufferevent_disable(bev, EV_READ);
    }
}

void tcp_del_cb(struct bufferevent *bev, void *arg) {
    struct tcp_arg *thisarg = arg;
    bufferevent_setcb(bev, tcp_fwd_cb, NULL, tcp_req_cb, arg);
    bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
    bufferevent_enable(thisarg->bev, EV_READ);
}

void udp_new_cb(int sock, short events, void *arg) {
    (void) sock;
    (void) events;
    (void) arg;
    char ctime[20] = {0};
    char error[64] = {0};
    char control[64] = {0};

    struct sockaddr_in clntaddr = {0};
    socklen_t addrlen = sizeof(clntaddr);
    struct iovec iov = {get_udp_rawbuf(), UDP_RAW_BUFSIZ};

    struct msghdr msg;
    msg.msg_name = &clntaddr;
    msg.msg_namelen = addrlen;
    msg.msg_control = control;
    msg.msg_controllen = 64;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;

    int rawlen = recvmsg(sock, &msg, 0);
    if (rawlen == -1) {
        printf("[%s] [ERR] recv from %s:%d: (%d) %s\n", curtime(ctime), inet_ntoa(udpladdr.sin_addr), ntohs(udpladdr.sin_port), errno, strerror_r(errno, error, 64));
        return;
    }
    printf("[%s] [INF] recv %d bytes data from %s:%d\n", curtime(ctime), rawlen, inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));

    int found = 0;
    struct sockaddr_in destaddr = {0};
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVORIGDSTADDR) {
            found = 1;
            memcpy(&destaddr, CMSG_DATA(cmsg), addrlen);
            break;
        }
    }
    if (!found) {
        printf("[%s] [ERR] can't get destaddr of %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
        return;
    }
    printf("[%s] [INF] %s:%d destaddr is %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port), inet_ntoa(destaddr.sin_addr), ntohs(destaddr.sin_port));

    struct udp_arg *udparg = calloc(1, sizeof(struct udp_arg));
    strcpy(udparg->srcaddr, inet_ntoa(clntaddr.sin_addr));
    strcpy(udparg->dstaddr, inet_ntoa(destaddr.sin_addr));
    udparg->srcport = ntohs(clntaddr.sin_port);
    udparg->dstport = ntohs(destaddr.sin_port);
    udparg->udpebuf = malloc(UDP_ENC_BUFSIZ);

    size_t enclen = 0;
    base64_encode(get_udp_rawbuf(), rawlen, udparg->udpebuf, &enclen, 0);
    udparg->udpebuf[enclen] = 0;

    SSL *ssl = SSL_new(get_ssl_ctx());
    SSL_set_tlsext_host_name(ssl, servhost);
    X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), servhost, 0);
    if (get_ssl_sess() != NULL) SSL_set_session(ssl, get_ssl_sess());

    struct bufferevent *bev = bufferevent_openssl_socket_new(event_get_base(arg), -1, ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(bev, NULL, NULL, udp_req_cb, udparg);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
    printf("[%s] [INF] connecting to %s:%d\n", curtime(ctime), servhost, servport);
    bufferevent_socket_connect(bev, (struct sockaddr *)&servaddr, sizeof(servaddr));
    set_tcp_sockopt(bufferevent_getfd(bev));
}

void udp_req_cb(struct bufferevent *bev, short events, void *arg) {
    (void) bev;
    (void) events;
    (void) arg;

    char ctime[20] = {0};
    struct udp_arg *udparg = arg;

    if (events & BEV_EVENT_CONNECTED) {
        printf("[%s] [INF] connected to %s:%d\n",    curtime(ctime), servhost, servport);
        printf("[%s] [INF] send request to %s:%d\n", curtime(ctime), servhost, servport);
        bufferevent_write(bev, servreq, strlen(servreq));
        bufferevent_write(bev, "ConnectionType: udp; addr=", strlen("ConnectionType: udp; addr="));
        bufferevent_write(bev, udparg->dstaddr, strlen(udparg->dstaddr));
        bufferevent_write(bev, "; port=", strlen("; port="));
        char portstr[6] = {0};
        sprintf(portstr, "%d", udparg->dstport);
        bufferevent_write(bev, portstr, strlen(portstr));
        bufferevent_write(bev, "; data=", strlen("; data="));
        bufferevent_write(bev, udparg->udpebuf, strlen(udparg->udpebuf));
        bufferevent_write(bev, "\r\n\r\n", 4);
        free(udparg->udpebuf);
        udparg->udpebuf = NULL;
        bufferevent_setcb(bev, udp_res_cb, NULL, udp_req_cb, arg);
        if (get_ssl_sess() != NULL) SSL_SESSION_free(get_ssl_sess());
        set_ssl_sess(SSL_get1_session(bufferevent_openssl_get_ssl(bev)));
        return;
    }

    if (events & BEV_EVENT_ERROR) {
        unsigned long sslerror = bufferevent_get_openssl_error(bev);
        if (sslerror != 0) {
            printf("[%s] [ERR] openssl error: (%lu) %s\n", curtime(ctime), sslerror, ERR_reason_error_string(sslerror));
        } else {
            char error[64] = {0};
            printf("[%s] [ERR] socket error: (%d) %s\n", curtime(ctime), errno, strerror_r(errno, error, 64));
        }
    }

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), servhost, servport);
        SSL *ssl = bufferevent_openssl_get_ssl(bev);
        SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
        SSL_shutdown(ssl);
        bufferevent_free(bev);
        free(udparg->udpebuf);
        free(udparg);
    }
}

void udp_res_cb(struct bufferevent *bev, void *arg) {
    (void) bev;
    (void) arg;

    char ctime[20] = {0};
    struct udp_arg *udparg = arg;

    struct evbuffer *input = bufferevent_get_input(bev);
    char *respline = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF);

    if (respline == NULL || strcmp(respline, WEBSOCKET_STATUS_LINE) != 0) {
        printf("[%s] [ERR] bad response: %s:%d\n",   curtime(ctime), servhost, servport);
        printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), servhost, servport);
        free(udparg);
        free(respline);
        SSL *ssl = bufferevent_openssl_get_ssl(bev);
        SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
        SSL_shutdown(ssl);
        bufferevent_free(bev);
        return;
    }
    free(respline);
    
    while ((respline = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF)) != NULL) {
        char *header = strstr(respline, "ConnectionType: ");
        if (header == respline) {
            header += strlen("ConnectionType: ");
            size_t rawlen = 0;
            if (base64_decode(header, strlen(header), get_udp_rawbuf(), &rawlen, 0) != 1) {
                printf("[%s] [ERR] bad response: %s:%d\n", curtime(ctime), servhost, servport);
                printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), servhost, servport);
                free(udparg);
                free(respline);
                SSL *ssl = bufferevent_openssl_get_ssl(bev);
                SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
                SSL_shutdown(ssl);
                bufferevent_free(bev);
                return;
            }
            free(respline);

            struct sockaddr_in clntaddr = {0};
            clntaddr.sin_family = AF_INET;
            clntaddr.sin_addr.s_addr = inet_addr(udparg->srcaddr);
            clntaddr.sin_port = htons(udparg->srcport);

            struct sockaddr_in destaddr = {0};
            destaddr.sin_family = AF_INET;
            destaddr.sin_addr.s_addr = inet_addr(udparg->dstaddr);
            destaddr.sin_port = htons(udparg->dstport);

            int destsock = socket(AF_INET, SOCK_DGRAM, 0);
            evutil_make_socket_nonblocking(destsock);

            int on = 1;
            setsockopt(destsock, SOL_IP, IP_TRANSPARENT, &on, sizeof(on));

            if (bind(destsock, (struct sockaddr *)&destaddr, sizeof(destaddr)) == -1) {
                char error[64] = {0};
                printf("[%s] [ERR] bind socket: (%d) %s\n", curtime(ctime), errno, strerror_r(errno, error, 64));
                printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), servhost, servport);
                free(udparg);
                close(destsock);
                SSL *ssl = bufferevent_openssl_get_ssl(bev);
                SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
                SSL_shutdown(ssl);
                bufferevent_free(bev);
                return;
            }

            if (sendto(destsock, get_udp_rawbuf(), rawlen, 0, (struct sockaddr *)&clntaddr, sizeof(clntaddr)) == -1) {
                char error[64] = {0};
                printf("[%s] [ERR] sendto socket: (%d) %s\n", curtime(ctime), errno, strerror_r(errno, error, 64));
                printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), servhost, servport);
                free(udparg);
                close(destsock);
                SSL *ssl = bufferevent_openssl_get_ssl(bev);
                SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
                SSL_shutdown(ssl);
                bufferevent_free(bev);
                return;
            }
            printf("[%s] [INF] send %ld bytes data to %s:%d\n", curtime(ctime), rawlen, udparg->srcaddr, udparg->srcport);

            printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), servhost, servport);
            free(udparg);
            close(destsock);
            SSL *ssl = bufferevent_openssl_get_ssl(bev);
            SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
            SSL_shutdown(ssl);
            bufferevent_free(bev);
            return;
        }
        free(respline);
    }

    printf("[%s] [ERR] bad response: %s:%d\n",   curtime(ctime), servhost, servport);
    printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), servhost, servport);
    SSL *ssl = bufferevent_openssl_get_ssl(bev);
    SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
    SSL_shutdown(ssl);
    bufferevent_free(bev);
    free(udparg);
    return;
}

void dns_new_cb(int sock, short events, void *arg) {
    (void) sock;
    (void) events;
    (void) arg;
    char ctime[20] = {0};
    char error[64] = {0};

    struct sockaddr_in clntaddr = {0};
    socklen_t addrlen = sizeof(clntaddr);
    int rawlen = recvfrom(sock, get_udp_rawbuf(), UDP_RAW_BUFSIZ, 0, (struct sockaddr *)&clntaddr, &addrlen);
    if (rawlen == -1) {
        printf("[%s] [ERR] recv from %s:%d: (%d) %s\n", curtime(ctime), inet_ntoa(dnsladdr.sin_addr), ntohs(dnsladdr.sin_port), errno, strerror_r(errno, error, 64));
        return;
    }
    printf("[%s] [INF] recv %d bytes data from %s:%d\n", curtime(ctime), rawlen, inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));

    struct dns_arg *dnsarg = calloc(1, sizeof(struct dns_arg));
    strcpy(dnsarg->srcaddr, inet_ntoa(clntaddr.sin_addr));
    dnsarg->srcport = ntohs(clntaddr.sin_port);
    dnsarg->udpebuf = malloc(UDP_ENC_BUFSIZ);

    size_t enclen = 0;
    base64_encode(get_udp_rawbuf(), rawlen, dnsarg->udpebuf, &enclen, 0);
    dnsarg->udpebuf[enclen] = 0;

    SSL *ssl = SSL_new(get_ssl_ctx());
    SSL_set_tlsext_host_name(ssl, servhost);
    X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), servhost, 0);
    if (get_ssl_sess() != NULL) SSL_set_session(ssl, get_ssl_sess());

    struct bufferevent *bev = bufferevent_openssl_socket_new(event_get_base(arg), -1, ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(bev, NULL, NULL, dns_req_cb, dnsarg);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
    printf("[%s] [INF] connecting to %s:%d\n", curtime(ctime), servhost, servport);
    bufferevent_socket_connect(bev, (struct sockaddr *)&servaddr, sizeof(servaddr));
    set_tcp_sockopt(bufferevent_getfd(bev));
}

void dns_req_cb(struct bufferevent *bev, short events, void *arg) {
    (void) bev;
    (void) events;
    (void) arg;

    char ctime[20] = {0};
    struct dns_arg *dnsarg = arg;

    if (events & BEV_EVENT_CONNECTED) {
        printf("[%s] [INF] connected to %s:%d\n",    curtime(ctime), servhost, servport);
        printf("[%s] [INF] send request to %s:%d\n", curtime(ctime), servhost, servport);
        bufferevent_write(bev, servreq, strlen(servreq));
        bufferevent_write(bev, "ConnectionType: udp; addr=", strlen("ConnectionType: udp; addr="));
        bufferevent_write(bev, dnsraddr, strlen(dnsraddr));
        bufferevent_write(bev, "; port=", strlen("; port="));
        bufferevent_write(bev, dnsrport, strlen(dnsrport));
        bufferevent_write(bev, "; data=", strlen("; data="));
        bufferevent_write(bev, dnsarg->udpebuf, strlen(dnsarg->udpebuf));
        bufferevent_write(bev, "\r\n\r\n", 4);
        free(dnsarg->udpebuf);
        dnsarg->udpebuf = NULL;
        bufferevent_setcb(bev, dns_res_cb, NULL, dns_req_cb, arg);
        if (get_ssl_sess() != NULL) SSL_SESSION_free(get_ssl_sess());
        set_ssl_sess(SSL_get1_session(bufferevent_openssl_get_ssl(bev)));
        return;
    }

    if (events & BEV_EVENT_ERROR) {
        unsigned long sslerror = bufferevent_get_openssl_error(bev);
        if (sslerror != 0) {
            printf("[%s] [ERR] openssl error: (%lu) %s\n", curtime(ctime), sslerror, ERR_reason_error_string(sslerror));
        } else {
            char error[64] = {0};
            printf("[%s] [ERR] socket error: (%d) %s\n", curtime(ctime), errno, strerror_r(errno, error, 64));
        }
    }

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), servhost, servport);
        SSL *ssl = bufferevent_openssl_get_ssl(bev);
        SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
        SSL_shutdown(ssl);
        bufferevent_free(bev);
        free(dnsarg->udpebuf);
        free(dnsarg);
    }
}

void dns_res_cb(struct bufferevent *bev, void *arg) {
    (void) bev;
    (void) arg;

    char ctime[20] = {0};
    struct dns_arg *dnsarg = arg;

    struct evbuffer *input = bufferevent_get_input(bev);
    char *respline = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF);

    if (respline == NULL || strcmp(respline, WEBSOCKET_STATUS_LINE) != 0) {
        printf("[%s] [ERR] bad response: %s:%d\n",   curtime(ctime), servhost, servport);
        printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), servhost, servport);
        free(dnsarg);
        free(respline);
        SSL *ssl = bufferevent_openssl_get_ssl(bev);
        SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
        SSL_shutdown(ssl);
        bufferevent_free(bev);
        return;
    }
    free(respline);
    
    while ((respline = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF)) != NULL) {
        char *header = strstr(respline, "ConnectionType: ");
        if (header == respline) {
            header += strlen("ConnectionType: ");
            size_t rawlen = 0;
            if (base64_decode(header, strlen(header), get_udp_rawbuf(), &rawlen, 0) != 1) {
                printf("[%s] [ERR] bad response: %s:%d\n", curtime(ctime), servhost, servport);
                printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), servhost, servport);
                free(dnsarg);
                free(respline);
                SSL *ssl = bufferevent_openssl_get_ssl(bev);
                SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
                SSL_shutdown(ssl);
                bufferevent_free(bev);
                return;
            }
            free(respline);

            struct sockaddr_in clntaddr = {0};
            clntaddr.sin_family = AF_INET;
            clntaddr.sin_addr.s_addr = inet_addr(dnsarg->srcaddr);
            clntaddr.sin_port = htons(dnsarg->srcport);

            if (sendto(get_dns_lsock(), get_udp_rawbuf(), rawlen, 0, (struct sockaddr *)&clntaddr, sizeof(clntaddr)) == -1) {
                char error[64] = {0};
                printf("[%s] [ERR] sendto socket: (%d) %s\n", curtime(ctime), errno, strerror_r(errno, error, 64));
                printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), servhost, servport);
                SSL *ssl = bufferevent_openssl_get_ssl(bev);
                SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
                SSL_shutdown(ssl);
                bufferevent_free(bev);
                free(dnsarg);
                return;
            }
            printf("[%s] [INF] send %ld bytes data to %s:%d\n", curtime(ctime), rawlen, dnsarg->srcaddr, dnsarg->srcport);

            printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), servhost, servport);
            SSL *ssl = bufferevent_openssl_get_ssl(bev);
            SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
            SSL_shutdown(ssl);
            bufferevent_free(bev);
            free(dnsarg);
            return;
        }
        free(respline);
    }

    printf("[%s] [ERR] bad response: %s:%d\n",   curtime(ctime), servhost, servport);
    printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), servhost, servport);
    SSL *ssl = bufferevent_openssl_get_ssl(bev);
    SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
    SSL_shutdown(ssl);
    bufferevent_free(bev);
    free(dnsarg);
    return;
}
