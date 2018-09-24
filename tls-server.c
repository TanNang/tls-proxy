#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <sys/un.h>
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
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/thread.h>
#include "libbase64.h"
#define gettid() syscall(__NR_gettid)

#define DEFAULT_SOCK_PATH "/run/tls-server.sock"
#define WEBSOCKET_RESPONSE "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"

#define PRINT_COMMAND_HELP printf("usage: tls-server [-b sock_path] [-j worker_num] [-v] [-h]\n"\
                                  " -b <sock_path>         unix domain socket path. default: "DEFAULT_SOCK_PATH"\n"\
                                  " -j <worker_num>        number of worker threads. default: 0 (number of CPUs)\n"\
                                  " -v                     show version and exit.\n"\
                                  " -h                     show this help and exit.\n")

#define UDP_PACKET_BUFSIZE 1472
#define UDP_BASE64_BUFSIZE 2048

#define TCP_ARG_TYPE_INET 0
#define TCP_ARG_TYPE_UNIX 1
struct tcp_cb_arg {
    char type; // INET|UNIX
    struct bufferevent *bev;
};

static int num_of_worker = 0;
static char *sock_path = NULL;
static size_t num_of_accept = -1;
static struct event_base *base_master = NULL;
static struct event_base **base_workers = NULL; // 指针数组

void signal_handler(int signum) {
    (void)signum;
    unlink(sock_path);
    exit(0);
}

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

/* 处理新连接相关的回调 */
void accept_conn_cb(struct evconnlistener *listener, evutil_socket_t sock, struct sockaddr *addr, int addrlen, void *arg);
void accept_error_cb(struct evconnlistener *listener, void *arg);

// 处理 websocket 请求的 read 回调
void read_cb_for_req(struct bufferevent *bev, void *arg);
// 处理 websocket 请求的 event 回调
void event_cb_for_req(struct bufferevent *bev, short events, void *arg);

// 处理 type='tcp' 请求的 read 回调
void read_cb_for_tcp(struct bufferevent *bev, void *arg);
// 处理 type='tcp' 请求的 event 回调
void event_cb_for_tcp(struct bufferevent *bev, short events, void *arg);

// 处理 type='udp' 请求的 read 回调
void read_cb_for_udp(evutil_socket_t sock, short events, void *arg);

int main(int argc, char *argv[]) {
    /* 选项默认值 */
    sock_path = DEFAULT_SOCK_PATH;
    num_of_worker = get_nprocs(); // CPU 个数

    /* 解析命令行 */
    opterr = 0; // 自定义错误信息
    char *optstr = "b:j:vh";
    int opt;
    while ((opt = getopt(argc, argv, optstr)) != -1) {
        switch (opt) {
            case 'v':
                printf("tls-server v1.0\n");
                return 0;
            case 'h':
                PRINT_COMMAND_HELP;
                return 0;
            case 'b':
                sock_path = optarg;
                break;
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

    signal(SIGHUP,  signal_handler);
    signal(SIGINT,  signal_handler);
    signal(SIGQUIT, signal_handler);
    signal(SIGTERM, signal_handler);

    struct sockaddr_un servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sun_family = AF_UNIX;
    strcpy(servaddr.sun_path, sock_path);

    unlink(sock_path); // 如果文件已存在则先删除
    struct evconnlistener *listener = evconnlistener_new_bind(
            base_master, accept_conn_cb, NULL,
            LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
            -1, (struct sockaddr *)&servaddr, sizeof(servaddr)
    );
    if (listener == NULL) {
        fprintf(stderr, "[%s] [ERR] can't listen socket %s: (%d) %s\n", current_time(curtime), sock_path, errno, strerror(errno));
        return errno;
    }
    evconnlistener_set_error_cb(listener, accept_error_cb);
    chmod(sock_path, 00600); // 设置文件权限 rw- --- ---

    printf("[%s] [INF] listen socket: %s. number of workers: %d\n", current_time(curtime), sock_path, num_of_worker);
    event_base_dispatch(base_master);

    for (int i = 0; i < num_of_worker; ++i) {
        event_base_loopexit(base_workers[i], NULL);
        pthread_join(tids[i], NULL);
    }
    free(tids);
    free(base_workers);

    evconnlistener_free(listener);
    event_base_free(base_master);
    unlink(sock_path);

    return 0;
}

void accept_conn_cb(struct evconnlistener *listener, evutil_socket_t sock, struct sockaddr *addr, int addrlen, void *arg) {
    (void)listener;
    (void)addr;
    (void)addrlen;
    (void)arg;

    ++num_of_accept; // 0, 1, 2, 3 ...
    char curtime[20] = {0};
    printf("[%s] [INF] accepted new connection: %s@%d\n", current_time(curtime), sock_path, sock);

    /* 平均分配新连接到每个工作线程 */
    struct event_base *base = NULL;
    for (int i = 0; i < num_of_worker; ++i) {
        if (num_of_accept % num_of_worker == (size_t)i) {
            base = base_workers[i];
            break;
        }
    }

    struct bufferevent *bev = bufferevent_socket_new(base, sock, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(bev, read_cb_for_req, NULL, event_cb_for_req, NULL);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
}

void accept_error_cb(struct evconnlistener *listener, void *arg) {
    (void)listener;
    (void)arg;
    char curtime[20] = {0};
    char *error_string = evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR());
    fprintf(stderr, "[%s] [ERR] error occurred when accepting: %s\n", current_time(curtime), error_string);
    event_base_loopexit(base_master, NULL);
}

void event_cb_for_req(struct bufferevent *bev, short events, void *arg) {
    (void)arg;
    char curtime[20] = {0};
    if (events & BEV_EVENT_ERROR) {
        fprintf(stderr, "[%s] [ERR] error occurred when processing: fd=%d (%d) %s\n",
                current_time(curtime), bufferevent_getfd(bev), errno, strerror(errno));
    }
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        printf("[%s] [INF] closed client connection: %s@%d\n", current_time(curtime), sock_path, bufferevent_getfd(bev));
        bufferevent_free(bev);
    }
}

void read_cb_for_req(struct bufferevent *bev, void *arg) {
    (void)arg;

    struct evbuffer *input = bufferevent_get_input(bev);
    int len = evbuffer_get_length(input);
    char *buf = (char *)malloc(len + 1);
    bufferevent_read(bev, buf, len);
    buf[len] = 0; // string end with \0 character

    char curtime[20] = {0};

    /* websocket 请求头部格式 [tcp] */
    // value_min_len(25): ConnectionType: tcp; addr=1.2.3.4; port=1
    // value_max_len(37): ConnectionType: tcp; addr=111.111.111.111; port=55555

    /* websocket 请求头部格式 [udp] */
    // value_min_len(25): ConnectionType: udp; addr=1.2.3.4; port=1
    // value_max_len(37): ConnectionType: udp; addr=111.111.111.111; port=55555
    //                    ConnectionData: <base64_encoded_string>

    // 查找 Type 头部
    char *header_type = strstr(buf, "\r\nConnectionType: ");
    // 查找 Data 头部
    char *header_data = strstr(buf, "\r\nConnectionData: ");

    // UDP 代理
    if (header_type != NULL && header_data != NULL) {
        header_type += strlen("\r\nConnectionType: ");       // beg_ptr
        header_data += strlen("\r\nConnectionData: ");       // beg_ptr
        char *header_type_end = strstr(header_type, "\r\n"); // end_ptr
        char *header_data_end = strstr(header_data, "\r\n"); // end_ptr

        // 如果没有找到 \r\n 结束字符 (通常不会)
        if (header_type_end == NULL || header_data_end == NULL) {
            fprintf(stderr, "[%s] [ERR] TYPE header or DATA header not end with '\\r\\n'. fd=%d\n", current_time(curtime), bufferevent_getfd(bev));
            printf("[%s] [INF] closed client connection: %s@%d\n", current_time(curtime), sock_path, bufferevent_getfd(bev));
            bufferevent_free(bev);
            free(buf);
            return;
        }

        // 在 end_ptr 处写入 '\0' 结束字符
        *header_type_end = 0;
        *header_data_end = 0;

        // 如果字符串长度不符合预设情况
        if (strlen(header_type) < 25 || strlen(header_type) > 37 || strlen(header_data) < 1) {
            fprintf(stderr, "[%s] [ERR] TYPE header or DATA header length is incorrect. fd=%d\n", current_time(curtime), bufferevent_getfd(bev));
            printf("[%s] [INF] closed client connection: %s@%d\n", current_time(curtime), sock_path, bufferevent_getfd(bev));
            bufferevent_free(bev);
            free(buf);
            return;
        }

        // 存储 'tcp' or 'udp' 的数组
        char type[4] = {0};
        strncpy(type, header_type, 3);

        // 如果 type != 'udp'
        if (strcmp(type, "udp") != 0) {
            fprintf(stderr, "[%s] [ERR] TYPE header format error ('type' not equals 'udp'). fd=%d\n", current_time(curtime), bufferevent_getfd(bev));
            printf("[%s] [INF] closed client connection: %s@%d\n", current_time(curtime), sock_path, bufferevent_getfd(bev));
            bufferevent_free(bev);
            free(buf);
            return;
        }

        // 查找 'addr=' 子字符串
        char *addr_str = strstr(header_type, "udp; addr=");

        // 如果没有找到 'addr=' 子串
        if (addr_str != header_type) {
            fprintf(stderr, "[%s] [ERR] TYPE header format error (param 'addr' not found). fd=%d\n", current_time(curtime), bufferevent_getfd(bev));
            printf("[%s] [INF] closed client connection: %s@%d\n", current_time(curtime), sock_path, bufferevent_getfd(bev));
            bufferevent_free(bev);
            free(buf);
            return;
        }

        // 找到后将 addr_str 移至 IP 地址开头处
        addr_str += strlen("udp; addr=");

        // 查找 'port=' 子字符串
        char *port_str = strstr(addr_str, "; port=");

        // 如果没有找到 'port=' 子串
        if (port_str == NULL) {
            fprintf(stderr, "[%s] [ERR] TYPE header format error (param 'port' not found). fd=%d\n", current_time(curtime), bufferevent_getfd(bev));
            printf("[%s] [INF] closed client connection: %s@%d\n", current_time(curtime), sock_path, bufferevent_getfd(bev));
            bufferevent_free(bev);
            free(buf);
            return;
        }

        // 找到后在 port_str 处写入 \0 字符
        *port_str = 0;
        // 然后将 port_str 移至 Port 开头处
        port_str += strlen("; port=");

        // 尝试解析 IP 地址
        unsigned long addr = inet_addr(addr_str);
        if (addr == INADDR_NONE) {
            fprintf(stderr, "[%s] [ERR] TYPE header format error (param 'addr' format error). fd=%d\n", current_time(curtime), bufferevent_getfd(bev));
            printf("[%s] [INF] closed client connection: %s@%d\n", current_time(curtime), sock_path, bufferevent_getfd(bev));
            bufferevent_free(bev);
            free(buf);
            return;
        }

        // 尝试解析 Port 端口
        unsigned short port = htons((int)strtol(port_str, NULL, 10));
        if (port == 0) {
            fprintf(stderr, "[%s] [ERR] TYPE header format error (param 'port' format error). fd=%d\n", current_time(curtime), bufferevent_getfd(bev));
            printf("[%s] [INF] closed client connection: %s@%d\n", current_time(curtime), sock_path, bufferevent_getfd(bev));
            bufferevent_free(bev);
            free(buf);
            return;
        }

        // 尝试解码 base64 数据
        int datalen = 0;
        void *udpdata = malloc(strlen(header_data));
        if (base64_decode(header_data, strlen(header_data), udpdata, (size_t *)&datalen, 0) != 1) {
            fprintf(stderr, "[%s] [ERR] DATA header format error (decode base64 str failed). fd=%d\n", current_time(curtime), bufferevent_getfd(bev));
            printf("[%s] [INF] closed client connection: %s@%d\n", current_time(curtime), sock_path, bufferevent_getfd(bev));
            bufferevent_free(bev);
            free(udpdata);
            free(buf);
            return;
        }
        printf("[%s] [INF] recv %d bytes udp data from %s@%d\n", current_time(curtime), datalen, sock_path, bufferevent_getfd(bev));

        // 目的主机的套接字地址
        struct sockaddr_in destaddr;
        memset(&destaddr, 0, sizeof(destaddr));
        destaddr.sin_family = AF_INET;
        destaddr.sin_addr.s_addr = addr;
        destaddr.sin_port = port;

        // 创建收发数据的套接字
        evutil_socket_t destsock = socket(AF_INET, SOCK_DGRAM, 0);
        evutil_make_socket_nonblocking(destsock); // 必须设为非阻塞

        // 发送解码出来的原数据
        if (sendto(destsock, udpdata, datalen, 0, (struct sockaddr *)&destaddr, sizeof(destaddr)) == -1) {
            fprintf(stderr, "[%s] [ERR] send udp data to %s:%d failed (cfd=%d): (%d) %s\n", current_time(curtime),
                    inet_ntoa(destaddr.sin_addr), ntohs(destaddr.sin_port), bufferevent_getfd(bev), errno, strerror(errno));
            printf("[%s] [INF] closed client connection: %s@%d\n", current_time(curtime), sock_path, bufferevent_getfd(bev));
            bufferevent_free(bev);
            close(destsock);
            free(udpdata);
            free(buf);
            return;
        }
        printf("[%s] [INF] send %d bytes udp data to %s:%d. fd: %s@%d\n", current_time(curtime), datalen,
                inet_ntoa(destaddr.sin_addr), ntohs(destaddr.sin_port), sock_path, bufferevent_getfd(bev));

        // 将当前 BEV 的回调取消
        bufferevent_setcb(bev, NULL, NULL, NULL, NULL);

        // 创建 event 来接收数据
        struct event *ev = event_new(bufferevent_get_base(bev), destsock, EV_READ | EV_TIMEOUT, read_cb_for_udp, bev);
        struct timeval tv = {5, 0};
        event_add(ev, &tv);

        free(udpdata);
        free(buf);
        return;
    }

    // TCP 代理
    if (header_type != NULL) {
        header_type += strlen("\r\nConnectionType: ");       // beg_ptr
        char *header_type_end = strstr(header_type, "\r\n"); // end_ptr

        // 如果没有找到 \r\n 结束字符 (通常不会)
        if (header_type_end == NULL) {
            fprintf(stderr, "[%s] [ERR] (tcp proxy) TYPE header not end with '\\r\\n'. fd=%d\n", current_time(curtime), bufferevent_getfd(bev));
            printf("[%s] [INF] closed client connection: %s@%d\n", current_time(curtime), sock_path, bufferevent_getfd(bev));
            bufferevent_free(bev);
            free(buf);
            return;
        }

        // 在 end_ptr 处写入 \0 字符
        *header_type_end = 0;

        // 如果字符串长度不符合预设情况
        if (strlen(header_type) < 25 || strlen(header_type) > 37) {
            fprintf(stderr, "[%s] [ERR] (tcp proxy) TYPE header length is incorrect. fd=%d\n", current_time(curtime), bufferevent_getfd(bev));
            printf("[%s] [INF] closed client connection: %s@%d\n", current_time(curtime), sock_path, bufferevent_getfd(bev));
            bufferevent_free(bev);
            free(buf);
            return;
        }

        // 存储 'tcp' or 'udp' 的数组
        char type[4] = {0};
        strncpy(type, header_type, 3);

        // 如果 type != 'tcp'
        if (strcmp(type, "tcp") != 0) {
            fprintf(stderr, "[%s] [ERR] TYPE header format error ('type' not equals 'tcp'). fd=%d\n", current_time(curtime), bufferevent_getfd(bev));
            printf("[%s] [INF] closed client connection: %s@%d\n", current_time(curtime), sock_path, bufferevent_getfd(bev));
            bufferevent_free(bev);
            free(buf);
            return;
        }

        // 查找 'addr=' 子字符串
        char *addr_str = strstr(header_type, "tcp; addr=");

        // 如果没有找到 'addr=' 子串
        if (addr_str != header_type) {
            fprintf(stderr, "[%s] [ERR] TYPE header format error (param 'addr' not found). fd=%d\n", current_time(curtime), bufferevent_getfd(bev));
            printf("[%s] [INF] closed client connection: %s@%d\n", current_time(curtime), sock_path, bufferevent_getfd(bev));
            bufferevent_free(bev);
            free(buf);
            return;
        }

        // 找到后将 addr_str 移至 IP 地址开头处
        addr_str += strlen("tcp; addr=");

        // 查找 'port=' 子字符串
        char *port_str = strstr(addr_str, "; port=");

        // 如果没有找到 'port=' 子串
        if (port_str == NULL) {
            fprintf(stderr, "[%s] [ERR] TYPE header format error (param 'port' not found). fd=%d\n", current_time(curtime), bufferevent_getfd(bev));
            printf("[%s] [INF] closed client connection: %s@%d\n", current_time(curtime), sock_path, bufferevent_getfd(bev));
            bufferevent_free(bev);
            free(buf);
            return;
        }

        // 找到后在 port_str 处写入 \0 字符
        *port_str = 0;
        // 然后将 port_str 移至 Port 开头处
        port_str += strlen("; port=");

        // 尝试解析 IP 地址
        unsigned long addr = inet_addr(addr_str);
        if (addr == INADDR_NONE) {
            fprintf(stderr, "[%s] [ERR] TYPE header format error (param 'addr' format error). fd=%d\n", current_time(curtime), bufferevent_getfd(bev));
            printf("[%s] [INF] closed client connection: %s@%d\n", current_time(curtime), sock_path, bufferevent_getfd(bev));
            bufferevent_free(bev);
            free(buf);
            return;
        }

        // 尝试解析 Port 端口
        unsigned short port = htons((int)strtol(port_str, NULL, 10));
        if (port == 0) {
            fprintf(stderr, "[%s] [ERR] TYPE header format error (param 'port' format error). fd=%d\n", current_time(curtime), bufferevent_getfd(bev));
            printf("[%s] [INF] closed client connection: %s@%d\n", current_time(curtime), sock_path, bufferevent_getfd(bev));
            bufferevent_free(bev);
            free(buf);
            return;
        }

        // 目的主机的套接字地址
        struct sockaddr_in destaddr;
        memset(&destaddr, 0, sizeof(destaddr));
        destaddr.sin_family = AF_INET;
        destaddr.sin_addr.s_addr = addr;
        destaddr.sin_port = port;

        // 与目的主机建立 TCP 连接
        struct tcp_cb_arg *destarg = (struct tcp_cb_arg *)malloc(sizeof(struct tcp_cb_arg));
        destarg -> type = TCP_ARG_TYPE_INET; destarg -> bev = bev;
        struct bufferevent *destbev = bufferevent_socket_new(bufferevent_get_base(bev), -1, BEV_OPT_CLOSE_ON_FREE);
        bufferevent_setcb(destbev, NULL, NULL, event_cb_for_tcp, destarg);
        bufferevent_enable(destbev, EV_READ | EV_WRITE);
        bufferevent_socket_connect(destbev, (struct sockaddr *)&destaddr, sizeof(destaddr));

        // 设置当前 BEV 的相关回调
        struct tcp_cb_arg *clitarg = (struct tcp_cb_arg *)malloc(sizeof(struct tcp_cb_arg));
        clitarg -> type = TCP_ARG_TYPE_UNIX; clitarg -> bev = destbev;
        bufferevent_setcb(bev, NULL, NULL, event_cb_for_tcp, clitarg);

        free(buf);
        return;
    }

    // 错误请求
    fprintf(stderr, "[%s] [ERR] TYPE header or DATA header are not found. fd=%d\n", current_time(curtime), bufferevent_getfd(bev));
    printf("[%s] [INF] closed client connection: %s@%d\n", current_time(curtime), sock_path, bufferevent_getfd(bev));
    bufferevent_free(bev);
    free(buf);
}

void read_cb_for_udp(evutil_socket_t sock, short events, void *arg) {
    char curtime[20] = {0};
    struct bufferevent *bev = (struct bufferevent *)arg;

    struct sockaddr_in peeraddr;
    socklen_t addrlen = sizeof(peeraddr);

    void *rawdata = malloc(UDP_PACKET_BUFSIZE);
    int rawlen = recvfrom(sock, rawdata, UDP_PACKET_BUFSIZE, 0, (struct sockaddr *)&peeraddr, &addrlen);

    if (rawlen == -1) {
        if (events & EV_READ) {
            fprintf(stderr, "[%s] [ERR] recv udp data from %s:%d failed. cfd=%d. (%d) %s\n", current_time(curtime),
                    inet_ntoa(peeraddr.sin_addr), ntohs(peeraddr.sin_port), bufferevent_getfd(bev), errno, strerror(errno));
        } else { // 发生超时
            fprintf(stderr, "[%s] [ERR] recv udp data failed (udp server timeout). cfd=%d. (%d) %s\n",
                    current_time(curtime), bufferevent_getfd(bev), errno, strerror(errno));
        }
        printf("[%s] [INF] closed client connection: %s@%d\n", current_time(curtime), sock_path, bufferevent_getfd(bev));
        bufferevent_free(bev);
        free(rawdata);
        close(sock);
        return;
    }
    printf("[%s] [INF] recv %d bytes udp data from %s:%d. cfd: %s@%d\n", current_time(curtime), rawlen,
            inet_ntoa(peeraddr.sin_addr), ntohs(peeraddr.sin_port), sock_path, bufferevent_getfd(bev));

    int enclen = 0;
    int rl_dup = rawlen;
    char *encdata = (char *)malloc(UDP_BASE64_BUFSIZE);
    base64_encode(rawdata, rawlen, encdata, (size_t *)&enclen, 0);

    bufferevent_write(bev, WEBSOCKET_RESPONSE, strlen(WEBSOCKET_RESPONSE) - 2);
    bufferevent_write(bev, "ConnectionData: ", strlen("ConnectionData: "));
    bufferevent_write(bev, encdata, enclen);
    bufferevent_write(bev, "\r\n\r\n", 4);
    printf("[%s] [INF] send %d bytes udp data to %s@%d. from: %s:%d\n", current_time(curtime), rl_dup,
            sock_path, bufferevent_getfd(bev), inet_ntoa(peeraddr.sin_addr), ntohs(peeraddr.sin_port));

    close(sock);
    free(rawdata);
    free(encdata);

    bufferevent_setcb(bev, NULL, NULL, event_cb_for_req, NULL);
}

void read_cb_for_tcp(struct bufferevent *bev, void *arg) {
    evbuffer_add_buffer(bufferevent_get_output(((struct tcp_cb_arg *)arg)->bev), bufferevent_get_input(bev));
}

void event_cb_for_tcp(struct bufferevent *bev, short events, void *arg) {
    char curtime[20] = {0};
    struct tcp_cb_arg *tcparg = (struct tcp_cb_arg *)arg;

    if ((events & BEV_EVENT_CONNECTED) && tcparg->type == TCP_ARG_TYPE_INET) {
        struct sockaddr_in destaddr; socklen_t addrlen = sizeof(struct sockaddr_in);
        getpeername(bufferevent_getfd(bev), (struct sockaddr *)&destaddr, &addrlen);

        printf("[%s] [INF] connected to target host %s:%d (client fd=%d)\n", current_time(curtime),
               inet_ntoa(destaddr.sin_addr), ntohs(destaddr.sin_port), bufferevent_getfd(tcparg->bev));
        bufferevent_write(tcparg->bev, WEBSOCKET_RESPONSE, strlen(WEBSOCKET_RESPONSE));

        /* enable tcp keepalive */
        int on = 1;
        if (setsockopt(bufferevent_getfd(bev), SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) == -1) {
            fprintf(stderr, "[%s] [WRN] setsockopt(SO_KEEPALIVE) for %s:%d: (%d) %s\n",
                    current_time(curtime), inet_ntoa(destaddr.sin_addr), ntohs(destaddr.sin_port), errno, strerror(errno));
        }

        int idle = 30;
        if (setsockopt(bufferevent_getfd(bev), IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle)) == -1) {
            fprintf(stderr, "[%s] [WRN] setsockopt(TCP_KEEPIDLE) for %s:%d: (%d) %s\n",
                    current_time(curtime), inet_ntoa(destaddr.sin_addr), ntohs(destaddr.sin_port), errno, strerror(errno));
        }

        int intvl = 30;
        if (setsockopt(bufferevent_getfd(bev), IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl)) == -1) {
            fprintf(stderr, "[%s] [WRN] setsockopt(TCP_KEEPINTVL) for %s:%d: (%d) %s\n",
                    current_time(curtime), inet_ntoa(destaddr.sin_addr), ntohs(destaddr.sin_port), errno, strerror(errno));
        }

        int cnt = 2;
        if (setsockopt(bufferevent_getfd(bev), IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt)) == -1) {
            fprintf(stderr, "[%s] [WRN] setsockopt(TCP_KEEPCNT) for %s:%d: (%d) %s\n",
                    current_time(curtime), inet_ntoa(destaddr.sin_addr), ntohs(destaddr.sin_port), errno, strerror(errno));
        }

        bufferevent_setcb(bev, read_cb_for_tcp, NULL, event_cb_for_tcp, arg);

        struct tcp_cb_arg *cliarg = NULL;
        bufferevent_getcb(tcparg->bev, NULL, NULL, NULL, (void **)&cliarg);
        bufferevent_setcb(tcparg->bev, read_cb_for_tcp, NULL, event_cb_for_tcp, cliarg);
        return;
    }

    if (events & BEV_EVENT_ERROR) {
        if (tcparg->type == TCP_ARG_TYPE_INET) {
            struct sockaddr_in destaddr; socklen_t addrlen = sizeof(struct sockaddr_in);
            getpeername(bufferevent_getfd(bev), (struct sockaddr *)&destaddr, &addrlen);
            fprintf(stderr, "[%s] [ERR] error occurred when processing: %s:%d (%d) %s\n",
                    current_time(curtime), inet_ntoa(destaddr.sin_addr), ntohs(destaddr.sin_port), errno, strerror(errno));
        } else {
            fprintf(stderr, "[%s] [ERR] error occurred when processing: %s@%d (%d) %s\n",
                    current_time(curtime), sock_path, bufferevent_getfd(bev), errno, strerror(errno));
        }
    }

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        evutil_socket_t sock;
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);

        if (tcparg->type == TCP_ARG_TYPE_INET) {
            sock = bufferevent_getfd(tcparg->bev);
            getpeername(bufferevent_getfd(bev), (struct sockaddr *)&addr, &addrlen);
        } else {
            sock = bufferevent_getfd(bev);
            getpeername(bufferevent_getfd(tcparg->bev), (struct sockaddr *)&addr, &addrlen);
        }

        struct tcp_cb_arg *peerarg = NULL;
        bufferevent_getcb(tcparg->bev, NULL, NULL, NULL, (void **)&peerarg);

        printf("[%s] [INF] closed client connection: %s@%d\n", current_time(curtime), sock_path, sock);
        printf("[%s] [INF] closed server connection: %s:%d\n", current_time(curtime), inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        bufferevent_free(bev);
        bufferevent_free(tcparg->bev);

        free(arg);
        free(peerarg);
    }
}
