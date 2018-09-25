#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/thread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <linux/netfilter_ipv4.h>
#include "libbase64.h"

#define REDIR_ADDR "0.0.0.0"
#define REDIR_PORT 60080

#define TPROXY_ADDR "0.0.0.0"
#define TPROXY_PORT 60080

#define TUNNEL_ADDR "0.0.0.0"
#define TUNNEL_PORT 60053

#define TUNNEL_DEST_ADDR "8.8.8.8"
#define TUNNEL_DEST_PORT 53

#define WEBSOCKET_STATUS_LINE "HTTP/1.1 101 Switching Protocols"

#define PRINT_COMMAND_HELP printf("usage: tls-client OPTIONS [-v] [-h]. OPTIONS are as follows:\n"\
                                  " -s <server_host>        server host. can't use IP address\n"\
                                  " -p <server_port>        server port. the default port is 443\n"\
                                  " -c <cafile_path>        CA file location. eg: /etc/ssl/ca.crt\n"\
                                  " -P <request_uri>        websocket request line uri. eg: /tls-proxy\n"\
                                  " -H <request_header>     websocket request headers. allow multi lines\n"\
                                  " -t <tcp_listen_addr>    tcp listen addr. format: [addr:]port. default: 60080\n"\
                                  "                         if not specify listen addr, 0.0.0.0 is used by default\n"\
                                  " -u <udp_listen_addr>    udp listen addr. format: [addr:]port. default: 60080\n"\
                                  "                         if not specify listen addr, 0.0.0.0 is used by default\n"\
                                  " -d <dns_listen_addr>    dns listen addr. format: [addr:]port. default: 60053\n"\
                                  "                         if not specify listen addr, 0.0.0.0 is used by default\n"\
                                  " -D <dns_remote_addr>    remote dns server address. default addr is 8.8.8.8:53\n"\
                                  "                         if not specify dns server port, 53 is used by default\n"\
                                  " -j <number_of_worker>   number of worker threads. default: 0 (number of CPUs)\n"\
                                  " -v                      show version and exit\n"\
                                  " -h                      show this help and exit\n")

struct tcp_cb_arg {
    int connsock;
    char destaddr[16];
    unsigned short destport;
};

struct tcp_cb_arg2 {
    char destaddr[16];
    unsigned short destport;
    struct bufferevent *bev;
};

static SSL_CTX *ctx = NULL;
static int   servport = 443;
static char *servhost = NULL;
static struct sockaddr_in servaddr;

#define UDP_RAW_BUFSIZ 1472
#define UDP_ENC_BUFSIZ 2048
static int dnslsock = -1;
static void *udprbuff = NULL;

static char *req_sub = NULL;
static int num_of_worker = 0;
static size_t num_of_accept = -1;
static struct event_base *base_master = NULL;
static struct event_base **base_workers = NULL;

void *worker_thread_func(void *arg) {
    struct event_base *base = (struct event_base *)arg;
    event_base_loop(base, EVLOOP_NO_EXIT_ON_EMPTY);
    event_base_free(base);
    return NULL;
}

// sizeof(output) >= 20
char *current_time(char *output) {
    time_t rawtime;
    time(&rawtime);

    struct tm *result = (struct tm *)malloc(sizeof(struct tm));
    localtime_r(&rawtime, result);

    sprintf(output, "%04d-%02d-%02d %02d:%02d:%02d",
            result->tm_year + 1900, result->tm_mon + 1, result->tm_mday,
            result->tm_hour,        result->tm_min,     result->tm_sec);

    free(result);
    return output;
}

/* tcp 相关回调 */
void tcp_new_cb(struct evconnlistener *listener, evutil_socket_t sock, struct sockaddr *addr, int addrlen, void *arg);
void tcp_err_cb(struct evconnlistener *listener, void *arg);
void tcp_conn_cb(struct bufferevent *bev, short events, void *arg);
void tcp_estab_cb(struct bufferevent *bev, void *arg);
void tcp_read_cb(struct bufferevent *bev, void *arg);
void tcp_event_cb(struct bufferevent *bev, short events, void *arg);

/* udp 相关回调 */
void udp_new_cb(evutil_socket_t sock, short events, void *arg);
void udp_conn_cb(struct bufferevent *bev, short events, void *arg);
void udp_read_cb(struct bufferevent *bev, void *arg);

/* dns 相关回调 */
void dns_new_cb(evutil_socket_t sock, short events, void *arg);
void dns_conn_cb(struct bufferevent *bev, short events, void *arg);
void dns_read_cb(struct bufferevent *bev, void *arg);

int main(int argc, char *argv[]) {
    /* 选项默认值 */
    char *cafile = NULL;
    char *requri = NULL;
    char *reqext = NULL;

    char  tcpaddr[16] = REDIR_ADDR;
    int   tcpport     = REDIR_PORT;

    char  udpaddr[16] = TPROXY_ADDR;
    int   udpport     = TPROXY_PORT;

    char  dnsaddr[16] = TUNNEL_ADDR;
    int   dnsport     = TUNNEL_PORT;

    char  rdnsaddr[16] = TUNNEL_DEST_ADDR;
    int   rdnsport     = TUNNEL_DEST_PORT;

    num_of_worker = get_nprocs();

    /* 解析命令行 */
    opterr = 0;
    char *optstr = "s:p:c:P:H:t:u:d:D:j:vh";
    int opt;
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
                    fprintf(stderr, "invalid number of server port: %d\n", servport);
                    PRINT_COMMAND_HELP;
                    return 1;
                }
                break;
            case 'c':
                cafile = optarg;
                if (access(cafile, F_OK) == -1) {
                    fprintf(stderr, "tls CA file does not exist: %s\n", cafile);
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
            case 't': {
                char *ptr = strchr(optarg, ':');
                if (ptr == NULL) {
                    tcpport = strtol(optarg, NULL, 10);
                    if (tcpport <= 0 || tcpport > 65535) {
                        fprintf(stderr, "invalid number of tcp listen port: %d\n", tcpport);
                        PRINT_COMMAND_HELP;
                        return 1;
                    }
                    break;
                }
                strncpy(tcpaddr, optarg, ptr - optarg);
                char _tcpport[6] = {0};
                strncpy(_tcpport, ptr + 1, optarg + strlen(optarg) - ptr);
                tcpport = strtol(_tcpport, NULL, 10);
                if (tcpport <= 0 || tcpport > 65535) {
                    fprintf(stderr, "invalid number of tcp listen port: %d\n", tcpport);
                    PRINT_COMMAND_HELP;
                    return 1;
                }
                break;
            }
            case 'u': {
                char *ptr = strchr(optarg, ':');
                if (ptr == NULL) {
                    udpport = strtol(optarg, NULL, 10);
                    if (udpport <= 0 || udpport > 65535) {
                        fprintf(stderr, "invalid number of udp listen port: %d\n", udpport);
                        PRINT_COMMAND_HELP;
                        return 1;
                    }
                    break;
                }
                strncpy(udpaddr, optarg, ptr - optarg);
                char _udpport[6] = {0};
                strncpy(_udpport, ptr + 1, optarg + strlen(optarg) - ptr);
                udpport = strtol(_udpport, NULL, 10);
                if (udpport <= 0 || udpport > 65535) {
                    fprintf(stderr, "invalid number of udp listen port: %d\n", udpport);
                    PRINT_COMMAND_HELP;
                    return 1;
                }
                break;
            }
            case 'd': {
                char *ptr = strchr(optarg, ':');
                if (ptr == NULL) {
                    dnsport = strtol(optarg, NULL, 10);
                    if (dnsport <= 0 || dnsport > 65535) {
                        fprintf(stderr, "invalid number of dns listen port: %d\n", dnsport);
                        PRINT_COMMAND_HELP;
                        return 1;
                    }
                    break;
                }
                strncpy(dnsaddr, optarg, ptr - optarg);
                char _dnsport[6] = {0};
                strncpy(_dnsport, ptr + 1, optarg + strlen(optarg) - ptr);
                dnsport = strtol(_dnsport, NULL, 10);
                if (dnsport <= 0 || dnsport > 65535) {
                    fprintf(stderr, "invalid number of dns listen port: %d\n", dnsport);
                    PRINT_COMMAND_HELP;
                    return 1;
                }
                break;
            }
            case 'D': {
                char *ptr = strchr(optarg, ':');
                if (ptr == NULL) {
                    strncpy(rdnsaddr, optarg, strlen(optarg));
                    break;
                }
                strncpy(rdnsaddr, optarg, ptr - optarg);
                char _rdnsport[6] = {0};
                strncpy(_rdnsport, ptr + 1, optarg + strlen(optarg) - ptr);
                rdnsport = strtol(_rdnsport, NULL, 10);
                if (rdnsport <= 0 || rdnsport > 65535) {
                    fprintf(stderr, "invalid number of rdns server port: %d\n", rdnsport);
                    PRINT_COMMAND_HELP;
                    return 1;
                }
                break;
            }
            case 'j':
                num_of_worker = strtol(optarg, NULL, 10);
                if (num_of_worker < 0) {
                    fprintf(stderr, "invalid number of worker threads: %d\n", num_of_worker);
                    PRINT_COMMAND_HELP;
                    return 1;
                }
                if (num_of_worker == 0) num_of_worker = get_nprocs();
                break;
            case '?':
                if (strchr(optstr, optopt) == NULL) {
                    fprintf(stderr, "unknown option '-%c'\n", optopt);
                    PRINT_COMMAND_HELP;
                    return 1;
                } else {
                    fprintf(stderr, "missing optval '-%c'\n", optopt);
                    PRINT_COMMAND_HELP;
                    return 1;
                }
        }
    }

    /* 检查相关参数 */
    if (servhost == NULL) {
        fprintf(stderr, "missing option '-s'\n");
        PRINT_COMMAND_HELP;
        return 1;
    }
    if (cafile == NULL) {
        fprintf(stderr, "missing option '-c'\n");
        PRINT_COMMAND_HELP;
        return 1;
    }
    if (requri == NULL) {
        fprintf(stderr, "missing option '-P'\n");
        PRINT_COMMAND_HELP;
        return 1;
    }

    /* websocket 请求头 */
    req_sub = (char *)malloc(256);
    memset(req_sub, 0, 256);
    strcpy(req_sub + strlen(req_sub), "GET ");
    strcpy(req_sub + strlen(req_sub), requri);
    strcpy(req_sub + strlen(req_sub), " HTTP/1.1\r\n");
    strcpy(req_sub + strlen(req_sub), "Host: ");
    strcpy(req_sub + strlen(req_sub), servhost);
    strcpy(req_sub + strlen(req_sub), "\r\n");
    strcpy(req_sub + strlen(req_sub), "Upgrade: websocket\r\n");
    strcpy(req_sub + strlen(req_sub), "Connection: Upgrade\r\n");
    strcpy(req_sub + strlen(req_sub), reqext); // must end with '\r\n'

    /* 运行 worker 线程 */
    base_master = event_base_new();

    evthread_use_pthreads(); // 告诉 libevent 库以下的 event_base 需要线程安全
    base_workers = (struct event_base **)malloc(sizeof(void *) * num_of_worker);
    pthread_t *tids = (pthread_t *)malloc(sizeof(pthread_t) * num_of_worker);

    char curtime[20] = {0};

    for (int i = 0; i < num_of_worker; ++i) {
        base_workers[i] = event_base_new();
        if (pthread_create(tids + i, NULL, worker_thread_func, base_workers[i]) != 0) {
            fprintf(stderr, "[%s] [ERR] can't create worker thread: (%d) %s\n", current_time(curtime), errno, strerror(errno));
            return errno;
        }
    }

    /* tcp proxy 监听器 */
    struct sockaddr_in tcpladdr;
    memset(&tcpladdr, 0, sizeof(tcpladdr));
    tcpladdr.sin_family = AF_INET;
    tcpladdr.sin_addr.s_addr = inet_addr(tcpaddr);
    tcpladdr.sin_port = htons(tcpport);

    struct evconnlistener *listener = evconnlistener_new_bind(
            base_master, tcp_new_cb, NULL,
            LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
            -1, (struct sockaddr *)&tcpladdr, sizeof(tcpladdr)
    );
    if (listener == NULL) {
        fprintf(stderr, "[%s] [ERR] can't listen tcp socket %s:%d: (%d) %s\n", current_time(curtime), tcpaddr, tcpport, errno, strerror(errno));
        return errno;
    }
    evconnlistener_set_error_cb(listener, tcp_err_cb);

    /* enable tcp keepalive */
    int on = 1;
    if (setsockopt(evconnlistener_get_fd(listener), SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) == -1) {
        fprintf(stderr, "[%s] [WRN] setsockopt(SO_KEEPALIVE) for %s:%d: (%d) %s\n",
                current_time(curtime), tcpaddr, tcpport, errno, strerror(errno));
    }

    int idle = 30;
    if (setsockopt(evconnlistener_get_fd(listener), IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle)) == -1) {
        fprintf(stderr, "[%s] [WRN] setsockopt(TCP_KEEPIDLE) for %s:%d: (%d) %s\n",
                current_time(curtime), tcpaddr, tcpport, errno, strerror(errno));
    }

    int intvl = 30;
    if (setsockopt(evconnlistener_get_fd(listener), IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl)) == -1) {
        fprintf(stderr, "[%s] [WRN] setsockopt(TCP_KEEPINTVL) for %s:%d: (%d) %s\n",
                current_time(curtime), tcpaddr, tcpport, errno, strerror(errno));
    }

    int cnt = 2;
    if (setsockopt(evconnlistener_get_fd(listener), IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt)) == -1) {
        fprintf(stderr, "[%s] [WRN] setsockopt(TCP_KEEPCNT) for %s:%d: (%d) %s\n",
                current_time(curtime), tcpaddr, tcpport, errno, strerror(errno));
    }

    /* enable tcp nodelay */
    if (setsockopt(evconnlistener_get_fd(listener), IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) == -1) {
        fprintf(stderr, "[%s] [WRN] setsockopt(TCP_NODELAY) for %s:%d: (%d) %s\n",
                current_time(curtime), tcpaddr, tcpport, errno, strerror(errno));
    }

    /* enable reuseaddr */
    if (setsockopt(evconnlistener_get_fd(listener), SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) {
        fprintf(stderr, "[%s] [WRN] setsockopt(SO_REUSEADDR) for %s:%d: (%d) %s\n",
                current_time(curtime), tcpaddr, tcpport, errno, strerror(errno));
    }

    /* udp proxy 监听器 */
    struct sockaddr_in udpladdr;
    memset(&udpladdr, 0, sizeof(udpladdr));
    udpladdr.sin_family = AF_INET;
    udpladdr.sin_addr.s_addr = inet_addr(udpaddr);
    udpladdr.sin_port = htons(udpport);

    evutil_socket_t udplsock = socket(AF_INET, SOCK_DGRAM, 0);
    evutil_make_socket_nonblocking(udplsock);

    if (setsockopt(udplsock, SOL_IP, IP_TRANSPARENT, &on, sizeof(on)) == -1) {
        fprintf(stderr, "[%s] [WRN] setsockopt(IP_TRANSPARENT) for %s:%d: (%d) %s\n",
                current_time(curtime), udpaddr, udpport, errno, strerror(errno));
    }

    if (setsockopt(udplsock, IPPROTO_IP, IP_RECVORIGDSTADDR, &on, sizeof(on)) == -1) {
        fprintf(stderr, "[%s] [WRN] setsockopt(IP_RECVORIGDSTADDR) for %s:%d: (%d) %s\n",
                current_time(curtime), udpaddr, udpport, errno, strerror(errno));
    }

    if (bind(udplsock, (struct sockaddr *)&udpladdr, sizeof(udpladdr)) == -1) {
        fprintf(stderr, "[%s] [ERR] can't listen udp socket %s:%d: (%d) %s\n", current_time(curtime), udpaddr, udpport, errno, strerror(errno));
        return errno;
    }

    udprbuff = malloc(UDP_RAW_BUFSIZ);
    struct event *ev1 = event_new(base_master, udplsock, EV_READ | EV_PERSIST, udp_new_cb, NULL);
    event_add(ev1, NULL);

    /* dns proxy 监听器 */
    struct sockaddr_in dnsladdr;
    memset(&dnsladdr, 0, sizeof(dnsladdr));
    dnsladdr.sin_family = AF_INET;
    dnsladdr.sin_addr.s_addr = inet_addr(dnsaddr);
    dnsladdr.sin_port = htons(dnsport);

    dnslsock = socket(AF_INET, SOCK_DGRAM, 0);
    evutil_make_socket_nonblocking(dnslsock);

    if (bind(dnslsock, (struct sockaddr *)&dnsladdr, sizeof(dnsladdr)) == -1) {
        fprintf(stderr, "[%s] [ERR] can't listen dns socket %s:%d: (%d) %s\n", current_time(curtime), dnsaddr, dnsport, errno, strerror(errno));
        return errno;
    }

    struct event *ev2 = event_new(base_master, dnslsock, EV_READ | EV_PERSIST, dns_new_cb, NULL);
    event_add(ev2, NULL);

    /* ssl ctx init */
    SSL_library_init();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_client_method());

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
    SSL_CTX_load_verify_locations(ctx, cafile, NULL);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305");

    /* 解析 servhost */
    struct hostent *ent = gethostbyname(servhost);
    if (ent == NULL) {
        fprintf(stderr, "[%s] [ERR] can't resolve hostname: %s. (%d) %s\n", current_time(curtime), servhost, errno, strerror(errno));
        return errno;
    }
    servaddr.sin_family = AF_INET;
    memcpy(&servaddr.sin_addr, ent->h_addr_list[0], ent->h_length);
    servaddr.sin_port = htons(servport);

    /* start event loop */
    printf("[%s] [INF] number of worker threads: %d\n",    current_time(curtime), num_of_worker);
    printf("[%s] [INF] remote https server host: %s\n",    current_time(curtime), servhost);
    printf("[%s] [INF] remote https server addr: %s:%d\n", current_time(curtime), inet_ntoa(servaddr.sin_addr), ntohs(servaddr.sin_port));
    printf("[%s] [INF] listen tcp proxy address: %s:%d\n", current_time(curtime), tcpaddr, tcpport);
    printf("[%s] [INF] listen udp proxy address: %s:%d\n", current_time(curtime), udpaddr, udpport);
    printf("[%s] [INF] listen dns proxy address: %s:%d\n", current_time(curtime), dnsaddr, dnsport);
    printf("[%s] [INF] remote dns resolver addr: %s:%d\n", current_time(curtime), rdnsaddr, rdnsport);
    event_base_dispatch(base_master);

    /* 清理相应的资源 */
    for (int i = 0; i < num_of_worker; ++i) {
        event_base_loopexit(base_workers[i], NULL);
        pthread_join(tids[i], NULL);
    }
    free(tids);
    free(base_workers);

    event_del(ev1);
    event_del(ev2);
    event_free(ev1);
    event_free(ev2);
    close(udplsock);
    close(dnslsock);
    free(udprbuff);
    free(req_sub);

    evconnlistener_free(listener);
    event_base_free(base_master);

    SSL_CTX_free(ctx);
    ERR_free_strings();
    EVP_cleanup();

    return 0;
}

void tcp_err_cb(struct evconnlistener *listener, void *arg) {
    (void)listener;
    (void)arg;
    char curtime[20] = {0};
    char *error_string = evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR());
    fprintf(stderr, "[%s] [ERR] error occurred when accepting: %s\n", current_time(curtime), error_string);
    event_base_loopexit(base_master, NULL);
}

void tcp_new_cb(struct evconnlistener *listener, evutil_socket_t sock, struct sockaddr *addr, int addrlen, void *arg) {
    (void)listener;
    (void)sock;
    (void)addr;
    (void)addrlen;
    (void)arg;

    char curtime[20] = {0};
    ++num_of_accept; // 0, 1, 2, 3 ...

    struct sockaddr_in *connaddr = (struct sockaddr_in *)addr;
    printf("[%s] [INF] accepted new connection: %s:%d\n", current_time(curtime), inet_ntoa(connaddr->sin_addr), ntohs(connaddr->sin_port));

    struct sockaddr_in destaddr;
    getsockopt(sock, SOL_IP, SO_ORIGINAL_DST, &destaddr, (socklen_t *)&addrlen);
    printf("[%s] [INF] get destination address: %s:%d\n", current_time(curtime), inet_ntoa(destaddr.sin_addr), ntohs(destaddr.sin_port));

    /* 平均分配新连接到每个工作线程 */
    struct event_base *base = NULL;
    for (int i = 0; i < num_of_worker; ++i) {
        if (num_of_accept % num_of_worker == (size_t)i) {
            base = base_workers[i];
            break;
        }
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, servhost);
    X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), servhost, 0);

    struct tcp_cb_arg *tcparg = (struct tcp_cb_arg *)malloc(sizeof(struct tcp_cb_arg));
    memset(tcparg, 0, sizeof(struct tcp_cb_arg));
    tcparg -> connsock = sock;
    tcparg -> destport = ntohs(destaddr.sin_port);
    strcpy(tcparg -> destaddr, inet_ntoa(destaddr.sin_addr));

    struct bufferevent *bev = bufferevent_openssl_socket_new(base, -1, ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(bev, NULL, NULL, tcp_conn_cb, tcparg);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
    printf("[%s] [INF] connecting to https server: %s:%d\n", current_time(curtime), servhost, servport);
    bufferevent_socket_connect(bev, (struct sockaddr *)&servaddr, addrlen);

    /* enable tcp keepalive */
    int on = 1;
    if (setsockopt(bufferevent_getfd(bev), SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) == -1) {
        fprintf(stderr, "[%s] [WRN] setsockopt(SO_KEEPALIVE) for %s:%d: (%d) %s\n",
                current_time(curtime), servhost, servport, errno, strerror(errno));
    }

    int idle = 30;
    if (setsockopt(bufferevent_getfd(bev), IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle)) == -1) {
        fprintf(stderr, "[%s] [WRN] setsockopt(TCP_KEEPIDLE) for %s:%d: (%d) %s\n",
                current_time(curtime), servhost, servport, errno, strerror(errno));
    }

    int intvl = 30;
    if (setsockopt(bufferevent_getfd(bev), IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl)) == -1) {
        fprintf(stderr, "[%s] [WRN] setsockopt(TCP_KEEPINTVL) for %s:%d: (%d) %s\n",
                current_time(curtime), servhost, servport, errno, strerror(errno));
    }

    int cnt = 2;
    if (setsockopt(bufferevent_getfd(bev), IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt)) == -1) {
        fprintf(stderr, "[%s] [WRN] setsockopt(TCP_KEEPCNT) for %s:%d: (%d) %s\n",
                current_time(curtime), servhost, servport, errno, strerror(errno));
    }

    /* enable tcp nodelay */
    if (setsockopt(bufferevent_getfd(bev), IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) == -1) {
        fprintf(stderr, "[%s] [WRN] setsockopt(TCP_NODELAY) for %s:%d: (%d) %s\n",
                current_time(curtime), servhost, servport, errno, strerror(errno));
    }

    /* enable reuseaddr */
    if (setsockopt(bufferevent_getfd(bev), SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) {
        fprintf(stderr, "[%s] [WRN] setsockopt(SO_REUSEADDR) for %s:%d: (%d) %s\n",
                current_time(curtime), servhost, servport, errno, strerror(errno));
    }
}

void tcp_conn_cb(struct bufferevent *bev, short events, void *arg) {
    (void)bev;
    (void)events;
    (void)arg;

    char curtime[20] = {0};
    struct tcp_cb_arg *tcparg = (struct tcp_cb_arg *)arg;

    if (events & BEV_EVENT_CONNECTED) {
        printf("[%s] [INF] connected to https server: %s:%d\n", current_time(curtime), servhost, servport);
        printf("[%s] [INF] connecting to destination: %s:%d\n", current_time(curtime), tcparg->destaddr, tcparg->destport);

        bufferevent_write(bev, req_sub, strlen(req_sub));
        bufferevent_write(bev, "ConnectionType: tcp; addr=", strlen("ConnectionType: tcp; addr="));
        bufferevent_write(bev, tcparg->destaddr, strlen(tcparg->destaddr));
        bufferevent_write(bev, "; port=", strlen("; port="));
        char portstr[6] = {0};
        sprintf(portstr, "%d", tcparg->destport);
        bufferevent_write(bev, portstr, strlen(portstr));
        bufferevent_write(bev, "\r\n\r\n", 4);

        bufferevent_setcb(bev, tcp_estab_cb, NULL, tcp_conn_cb, arg);
        return;
    }

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        if (events & BEV_EVENT_ERROR) {
            unsigned long sslerror = bufferevent_get_openssl_error(bev);
            if (sslerror != 0) {
                fprintf(stderr, "[%s] [ERR] https server tls/ssl error: %s\n", current_time(curtime), ERR_reason_error_string(sslerror));
            } else {
                fprintf(stderr, "[%s] [ERR] error occurred when request: (%d) %s\n", current_time(curtime), errno, strerror(errno));
            }
        }
        struct sockaddr_in connaddr;
        socklen_t addrlen = sizeof(connaddr);
        getpeername(tcparg->connsock, (struct sockaddr *)&connaddr, &addrlen);
        printf("[%s] [INF] closed server connection: %s:%d\n", current_time(curtime), servhost, servport);
        printf("[%s] [INF] closed client connection: %s:%d\n", current_time(curtime), inet_ntoa(connaddr.sin_addr), ntohs(connaddr.sin_port));
        SSL *ssl = bufferevent_openssl_get_ssl(bev);
        SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
        SSL_shutdown(ssl);
        bufferevent_free(bev);
        close(tcparg->connsock);
        free(tcparg);
    }
}

void tcp_estab_cb(struct bufferevent *bev, void *arg) {
    (void)bev;
    (void)arg;

    char curtime[20] = {0};
    struct tcp_cb_arg *tcparg = (struct tcp_cb_arg *)arg;

    struct evbuffer *input = bufferevent_get_input(bev);
    char *statusline = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF);
    evbuffer_drain(input, evbuffer_get_length(input));

    if (strcmp(statusline, WEBSOCKET_STATUS_LINE) == 0) {
        printf("[%s] [INF] connected to destination: %s:%d\n", current_time(curtime), tcparg->destaddr, tcparg->destport);

        struct tcp_cb_arg2 *connarg = (struct tcp_cb_arg2 *)malloc(sizeof(struct tcp_cb_arg2));
        memset(connarg, 0, sizeof(struct tcp_cb_arg2));
        connarg->bev = bev;
        connarg->destport = tcparg->destport;
        strcpy(connarg->destaddr, tcparg->destaddr);
        struct bufferevent *connbev = bufferevent_socket_new(bufferevent_get_base(bev), tcparg->connsock, BEV_OPT_CLOSE_ON_FREE);
        bufferevent_setcb(connbev, tcp_read_cb, NULL, tcp_event_cb, connarg);
        bufferevent_enable(connbev, EV_READ | EV_WRITE);
        free(tcparg);

        struct tcp_cb_arg2 *destarg = (struct tcp_cb_arg2 *)malloc(sizeof(struct tcp_cb_arg2));
        memset(destarg, 0, sizeof(struct tcp_cb_arg2));
        destarg->bev = connbev;
        destarg->destport = connarg->destport;
        strcpy(destarg->destaddr, connarg->destaddr);
        bufferevent_setcb(bev, tcp_read_cb, NULL, tcp_event_cb, destarg);

        struct sockaddr_in connaddr;
        socklen_t addrlen = sizeof(connaddr);
        getpeername(bufferevent_getfd(connbev), (struct sockaddr *)&connaddr, &addrlen);
        char *clitaddr = inet_ntoa(connaddr.sin_addr);
        int   clitport = ntohs(connaddr.sin_port);

        /* enable tcp keepalive */
        int on = 1;
        if (setsockopt(bufferevent_getfd(connbev), SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) == -1) {
            fprintf(stderr, "[%s] [WRN] setsockopt(SO_KEEPALIVE) for %s:%d: (%d) %s\n",
                    current_time(curtime), clitaddr, clitport, errno, strerror(errno));
        }

        int idle = 30;
        if (setsockopt(bufferevent_getfd(connbev), IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle)) == -1) {
            fprintf(stderr, "[%s] [WRN] setsockopt(TCP_KEEPIDLE) for %s:%d: (%d) %s\n",
                    current_time(curtime), clitaddr, clitport, errno, strerror(errno));
        }

        int intvl = 30;
        if (setsockopt(bufferevent_getfd(connbev), IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl)) == -1) {
            fprintf(stderr, "[%s] [WRN] setsockopt(TCP_KEEPINTVL) for %s:%d: (%d) %s\n",
                    current_time(curtime), clitaddr, clitport, errno, strerror(errno));
        }

        int cnt = 2;
        if (setsockopt(bufferevent_getfd(connbev), IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt)) == -1) {
            fprintf(stderr, "[%s] [WRN] setsockopt(TCP_KEEPCNT) for %s:%d: (%d) %s\n",
                    current_time(curtime), clitaddr, clitport, errno, strerror(errno));
        }

        /* enable tcp nodelay */
        if (setsockopt(bufferevent_getfd(connbev), IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) == -1) {
            fprintf(stderr, "[%s] [WRN] setsockopt(TCP_NODELAY) for %s:%d: (%d) %s\n",
                    current_time(curtime), clitaddr, clitport, errno, strerror(errno));
        }

        /* enable reuseaddr */
        if (setsockopt(bufferevent_getfd(connbev), SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) {
            fprintf(stderr, "[%s] [WRN] setsockopt(SO_REUSEADDR) for %s:%d: (%d) %s\n",
                    current_time(curtime), clitaddr, clitport, errno, strerror(errno));
        }
    } else {
        struct sockaddr_in connaddr;
        socklen_t addrlen = sizeof(connaddr);
        getpeername(tcparg->connsock, (struct sockaddr *)&connaddr, &addrlen);
        fprintf(stderr, "[%s] [ERR] server's response status-line is incorrect\n", current_time(curtime));
        printf("[%s] [INF] closed server connection: %s:%d\n", current_time(curtime), servhost, servport);
        printf("[%s] [INF] closed client connection: %s:%d\n", current_time(curtime), inet_ntoa(connaddr.sin_addr), ntohs(connaddr.sin_port));
        SSL *ssl = bufferevent_openssl_get_ssl(bev);
        SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
        SSL_shutdown(ssl);
        bufferevent_free(bev);
        close(tcparg->connsock);
        free(tcparg);
    }

    free(statusline);
}

void tcp_read_cb(struct bufferevent *bev, void *arg) {
    (void)bev;
    (void)arg;
    evbuffer_add_buffer(bufferevent_get_output(((struct tcp_cb_arg2 *)arg)->bev), bufferevent_get_input(bev));
}

void tcp_event_cb(struct bufferevent *bev, short events, void *arg) {
    (void)bev;
    (void)events;
    (void)arg;

    char curtime[20] = {0};
    struct tcp_cb_arg2 *tcparg = (struct tcp_cb_arg2 *)arg;

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        if (events & BEV_EVENT_ERROR) {
            unsigned long sslerror = bufferevent_get_openssl_error(bev);
            if (sslerror != 0) {
                fprintf(stderr, "[%s] [ERR] https server tls/ssl error: %s\n", current_time(curtime), ERR_reason_error_string(sslerror));
            } else {
                fprintf(stderr, "[%s] [ERR] error occurred when forward: (%d) %s\n", current_time(curtime), errno, strerror(errno));
            }
        }

        struct sockaddr_in thisaddr;
        socklen_t addrlen = sizeof(thisaddr);
        getpeername(bufferevent_getfd(bev), (struct sockaddr *)&thisaddr, &addrlen);

        if (memcmp(&thisaddr, &servaddr, sizeof(servaddr)) == 0) {
            getpeername(bufferevent_getfd(tcparg->bev), (struct sockaddr *)&thisaddr, &addrlen);
            printf("[%s] [INF] closed server connection: %s:%d\n", current_time(curtime), servhost, servport);
            printf("[%s] [INF] closed client connection: %s:%d\n", current_time(curtime), inet_ntoa(thisaddr.sin_addr), ntohs(thisaddr.sin_port));

            SSL *ssl = bufferevent_openssl_get_ssl(bev);
            SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
            SSL_shutdown(ssl);

            struct tcp_cb_arg2 *cliarg = NULL;
            bufferevent_getcb(tcparg->bev, NULL, NULL, NULL, (void **)&cliarg);

            bufferevent_free(bev);
            bufferevent_free(tcparg->bev);

            free(tcparg);
            free(cliarg);
        } else {
            printf("[%s] [INF] closed server connection: %s:%d\n", current_time(curtime), servhost, servport);
            printf("[%s] [INF] closed client connection: %s:%d\n", current_time(curtime), inet_ntoa(thisaddr.sin_addr), ntohs(thisaddr.sin_port));

            SSL *ssl = bufferevent_openssl_get_ssl(tcparg->bev);
            SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
            SSL_shutdown(ssl);

            struct tcp_cb_arg2 *dstarg = NULL;
            bufferevent_getcb(tcparg->bev, NULL, NULL, NULL, (void **)&dstarg);

            bufferevent_free(bev);
            bufferevent_free(tcparg->bev);

            free(tcparg);
            free(dstarg);
        }
    }
}

/* udp 相关回调 */
void udp_new_cb(evutil_socket_t sock, short events, void *arg) {
    (void)sock;
    (void)events;
    (void)arg;
}

/* dns 相关回调 */
void dns_new_cb(evutil_socket_t sock, short events, void *arg) {
    (void)sock;
    (void)events;
    (void)arg;
}
