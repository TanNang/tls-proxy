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
#include "libbase64.h"
#define gettid() syscall(__NR_gettid)

#define REDIR_ADDR "0.0.0.0"
#define REDIR_PORT 60080

#define TPROXY_ADDR "0.0.0.0"
#define TPROXY_PORT 60080

#define TUNNEL_ADDR "0.0.0.0"
#define TUNNEL_PORT 60053
#define TUNNEL_DEST_ADDR "8.8.8.8"
#define TUNNEL_DEST_PORT 53

#define WEBSOCKET_STATUS_LINE "HTTP/1.1 101 Switching Protocols\r\n"
#define WEBSOCKET_SUB_REQUEST "Upgrade: websocket\r\nConnection: Upgrade\r\n"

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

static int dns_sock = 0;
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
void tcp_read_cb(struct bufferevent *bev, void *arg);
void tcp_estab_cb(struct bufferevent *bev, void *arg);
void tcp_event_cb(struct bufferevent *bev, short events, void *arg);

/* udp 相关回调 */
void udp_new_cb(evutil_socket_t sock, short events, void *arg);
void udp_read_cb(struct bufferevent *bev, void *arg);
void udp_event_cb(struct bufferevent *bev, short events, void *arg);

/* dns 相关回调 */
void dns_new_cb(evutil_socket_t sock, short events, void *arg);
void dns_read_cb(struct bufferevent *bev, void *arg);
void dns_event_cb(struct bufferevent *bev, short events, void *arg);

int main(int argc, char *argv[]) {
    /* 选项默认值 */
    char *servhost = NULL;
    int   servport = 443;

    char *cafile = NULL;
    char *requri = NULL;
    char *reqext = NULL;

    char *tcpaddr = REDIR_ADDR;
    int   tcpport = REDIR_PORT;

    char *udpaddr = TPROXY_ADDR;
    int   udpport = TPROXY_PORT;

    char *dnsaddr = TUNNEL_ADDR;
    int   dnsport = TUNNEL_PORT;
    char *rdnsaddr = TUNNEL_DEST_ADDR;
    int   rdnsport = TUNNEL_DEST_PORT;

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
                char _tcpaddr[16] = {0};
                strncpy(_tcpaddr, optarg, ptr - optarg);
                tcpaddr = _tcpaddr;
                char _tcpport[6] = {0};
                strncpy(_tcpport, optarg, optarg + strlen(optarg) - ptr - 1);
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
                char _udpaddr[16] = {0};
                strncpy(_udpaddr, optarg, ptr - optarg);
                udpaddr = _udpaddr;
                char _udpport[6] = {0};
                strncpy(_udpport, optarg, optarg + strlen(optarg) - ptr - 1);
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
                char _dnsaddr[16] = {0};
                strncpy(_dnsaddr, optarg, ptr - optarg);
                dnsaddr = _dnsaddr;
                char _dnsport[6] = {0};
                strncpy(_dnsport, optarg, optarg + strlen(optarg) - ptr - 1);
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
                    rdnsaddr = optarg;
                    break;
                }
                char _rdnsaddr[16] = {0};
                strncpy(_rdnsaddr, optarg, ptr - optarg);
                rdnsaddr = _rdnsaddr;
                char _rdnsport[6] = {0};
                strncpy(_rdnsport, optarg, optarg + strlen(optarg) - ptr - 1);
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

    // TODO

    /* udp proxy 监听器 */
    struct sockaddr_in udpladdr;
    memset(&udpladdr, 0, sizeof(udpladdr));
    udpladdr.sin_family = AF_INET;
    udpladdr.sin_addr.s_addr = inet_addr(udpaddr);
    udpladdr.sin_port = htons(udpport);

    // TODO

    /* dns proxy 监听器 */

    return 0;
}
