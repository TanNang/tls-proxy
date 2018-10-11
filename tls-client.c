#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
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
           " -v                      show version and exit\n"\
           " -h                      show help and exit\n")

#define UDP_RAW_BUFSIZ 1472
#define UDP_ENC_BUFSIZ 1960
#define BUFSIZ_FOR_BEV 524288
#define WEBSOCKET_STATUS_LINE "HTTP/1.1 101 Switching Protocols"
#define SSL_CIPHERS "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305"

void *service(void *arg);

void tcp_newconn_cb(struct evconnlistener *listener, int sock, struct sockaddr *addr, int addrlen, void *arg);
void tcp_sendreq_cb(struct bufferevent *bev, short events, void *arg);
void tcp_recvres_cb(struct bufferevent *bev, void *arg);
void tcp_forward_cb(struct bufferevent *bev, void *arg);
void tcp_overbuf_cb(struct bufferevent *bev, void *arg);

void udp_events_cb(struct bufferevent *bev, short events, void *arg);
void udp_request_cb(int sock, short events, void *arg);
void udp_response_cb(struct bufferevent *bev, void *arg);

/* 线程共享的全局数据 */
static char               *servhost     = NULL;
static int                 servport     = 443;
static struct sockaddr_in  servaddr     = {0};
static char               *cafile       = NULL;
static char                servreq[256] = {0};
static struct sockaddr_in  tcpladdr     = {0};
static struct sockaddr_in  udpladdr     = {0};
static void               *udprbuff     = NULL;
static char               *udpebuff     = NULL;

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

char *loginf(char *str) { // sizeof(str) = 36
    time_t rawtime;
    time(&rawtime);

    struct tm curtm;
    localtime_r(&rawtime, &curtm);

    sprintf(str, "\e[1;32m%04d-%02d-%02d %02d:%02d:%02d INF:\e[0m",
            curtm.tm_year + 1900, curtm.tm_mon + 1, curtm.tm_mday,
            curtm.tm_hour,        curtm.tm_min,     curtm.tm_sec);

    return str;
}

char *logerr(char *str) { // sizeof(str) = 36
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

    optval = 30;
    if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &optval, sizeof(optval)) == -1) {
        printf("%s [tcp] setsockopt(TCP_KEEPIDLE) for %d: (%d) %s\n", logerr(ctime), sock, errno, strerror_r(errno, error, 64));
    }

    if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &optval, sizeof(optval)) == -1) {
        printf("%s [tcp] setsockopt(TCP_KEEPINTVL) for %d: (%d) %s\n", logerr(ctime), sock, errno, strerror_r(errno, error, 64));
    }

    optval = 3;
    if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &optval, sizeof(optval)) == -1) {
        printf("%s [tcp] setsockopt(TCP_KEEPCNT) for %d: (%d) %s\n", logerr(ctime), sock, errno, strerror_r(errno, error, 64));
    }
}

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);

    char *requri = NULL;
    char *reqext = NULL;
    char *listen = "127.0.0.1";
    int   tcport = 60080;
    int   udport = 60080;

    opterr = 0;
    char *optstr = "s:p:c:P:H:b:t:u:j:vh";
    int opt = -1;
    while ((opt = getopt(argc, argv, optstr)) != -1) {
        switch (opt) {
            case 'v':
                printf("tls-client v1.1\n");
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

    tcpladdr.sin_family = AF_INET;
    tcpladdr.sin_addr.s_addr = inet_addr(listen);
    tcpladdr.sin_port = htons(tcport);

    udpladdr.sin_family = AF_INET;
    udpladdr.sin_addr.s_addr = inet_addr(listen);
    udpladdr.sin_port = htons(udport);

    udprbuff = calloc(1, UDP_RAW_BUFSIZ);
    udpebuff = calloc(1, UDP_ENC_BUFSIZ);

    char ctime[36] = {0};
    printf("%s [srv] thread nums: %d\n",    loginf(ctime), thread_nums);
    printf("%s [srv] server host: %s\n",    loginf(ctime), servhost);
    printf("%s [srv] server addr: %s:%d\n", loginf(ctime), inet_ntoa(servaddr.sin_addr), servport);
    printf("%s [srv] tcp address: %s:%d\n", loginf(ctime), listen, tcport);
    printf("%s [srv] udp address: %s:%d\n", loginf(ctime), listen, udport);

    thread_datas = calloc(thread_nums, sizeof(THREAD_DATA));
    thread_datas[0].tid = pthread_self();
    for (int i = 1; i < thread_nums; ++i) {
        if (pthread_create(&thread_datas[i].tid, NULL, service, NULL) != 0) {
            printf("%s [srv] create thread: (%d) %s\n", logerr(ctime), errno, strerror(errno));
            return errno;
        }
    }
    service((void *)1); // mark: process udp proxy

    for (int i = 1; i < thread_nums; ++i) {
        pthread_join(thread_datas[i].tid, NULL);
    }

    free(udprbuff);
    free(udpebuff);
    free(thread_datas);

    ERR_free_strings();
    EVP_cleanup();

    return 0;
}

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

    struct evconnlistener *tcplistener = evconnlistener_new_bind(
            base, tcp_newconn_cb, NULL,
            LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE | LEV_OPT_REUSEABLE_PORT,
            SOMAXCONN, (struct sockaddr *)&tcpladdr, sizeof(struct sockaddr_in)
    );
    if (tcplistener == NULL) {
        printf("%s [tcp] listen socket: (%d) %s\n", logerr(ctime), errno, strerror_r(errno, error, 64));
        exit(errno);
    }
    int optval = 1;
    if (setsockopt(evconnlistener_get_fd(tcplistener), SOL_IP, IP_TRANSPARENT, &optval, sizeof(optval)) == -1) {
        printf("%s [tcp] setsockopt(IP_TRANSPARENT) for %d: (%d) %s\n", logerr(ctime), evconnlistener_get_fd(tcplistener), errno, strerror_r(errno, error, 64));
        exit(errno);
    }

    // main thread
    if (arg == (void *)1) {
        int udplsock = socket(AF_INET, SOCK_DGRAM, 0);
        evutil_make_socket_nonblocking(udplsock);
        if (setsockopt(udplsock, SOL_IP, IP_TRANSPARENT, &optval, sizeof(optval)) == -1) {
            printf("%s [udp] setsockopt(IP_TRANSPARENT) for %d: (%d) %s\n", logerr(ctime), udplsock, errno, strerror_r(errno, error, 64));
            exit(errno);
        }
        if (setsockopt(udplsock, IPPROTO_IP, IP_RECVORIGDSTADDR, &optval, sizeof(optval)) == -1) {
            printf("%s [udp] setsockopt(IP_RECVORIGDSTADDR) for %d: (%d) %s\n", logerr(ctime), udplsock, errno, strerror_r(errno, error, 64));
            exit(errno);
        }
        if (setsockopt(udplsock, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)) == -1) {
            printf("%s [udp] setsockopt(SO_REUSEPORT) for %d: (%d) %s\n", logerr(ctime), udplsock, errno, strerror_r(errno, error, 64));
            exit(errno);
        }
        // TODO
    }

    return NULL;
}
