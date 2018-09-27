#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include "libbase64.h"

#define PRINT_COMMAND_HELP \
    printf("usage: tls-server <OPTIONS>. OPTIONS have these:\n"\
           " -b <listen_addr>       listen addr. default: 127.0.0.1\n"\
           " -l <listen_port>       listen port. default: 60080\n"\
           " -j <thread_nums>       thread nums. default: num of CPU\n"\
           " -v                     show current version and exit\n"\
           " -h                     show current message and exit\n")

#define WEBSOCKET_RESPONSE "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"

#define UDP_RAW_BUFSIZ 1472
#define UDP_ENC_BUFSIZ 1960
struct udp_arg {
    struct event *ev;
    struct bufferevent *bev;
};

// server listen addr
static struct sockaddr_in servaddr;

// worker thread func
void *service(void *arg);

// [new connect] accept callback
void new_accept_cb(struct evconnlistener *listener, int sock, struct sockaddr *addr, int addrlen, void *arg);
// [new connect] 1streq callback
void new_1streq_cb(struct bufferevent *bev, void *arg);
// [new connect] events callback
void new_events_cb(struct bufferevent *bev, short events, void *arg);

// [tcp request] datfwd callback
void tcp_datfwd_cb(struct bufferevent *bev, void *arg);
// [tcp request] events callback
void tcp_events_cb(struct bufferevent *bev, short events, void *arg);

// [udp request] rcvres callback
void udp_rcvres_cb(int sock, short events, void *arg);
// [udp request] events callback
void udp_events_cb(struct bufferevent *bev, short events, void *arg);

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

int main(int argc, char *argv[]) {
    // options default value
    char *listen_addr = "127.0.0.1";
    int   listen_port = 60080;
    int   thread_nums = get_nprocs();

    // parse command arguments
    opterr = 0;
    char *optstr = "b:l:j:vh";
    int opt = -1;
    while ((opt = getopt(argc, argv, optstr)) != -1) {
        switch (opt) {
            case 'v':
                printf("tls-server v1.0\n");
                return 0;
            case 'h':
                PRINT_COMMAND_HELP;
                return 0;
            case 'b':
                listen_addr = optarg;
                break;
            case 'l':
                listen_port = strtol(optarg, NULL, 10);
                if (listen_port <= 0 || listen_port > 65535) {
                    printf("invalid listen port: %d\n", listen_port);
                    PRINT_COMMAND_HELP;
                    return 1;
                }
                break;
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

    servaddr.sin_family = AF_INET;
    inet_aton(listen_addr, &servaddr.sin_addr);
    servaddr.sin_port = htons(listen_port);

    char ctime[20] = {0};
    printf("[%s] [INF] thread numbers: %d\n", curtime(ctime), thread_nums);
    printf("[%s] [INF] listen address: %s:%d\n", curtime(ctime), listen_addr, listen_port);

    char error[64] = {0};
    pthread_t tids[--thread_nums];
    for (int i = 0; i < thread_nums; ++i) {
        if (pthread_create(tids + i, NULL, service, NULL) != 0) {
            printf("[%s] [ERR] create thread: (%d) (%s)\n", curtime(ctime), errno, strerror_r(errno, error, 64));
            return 1;
        }
    }
    service(NULL);

    for (int i = 0; i < thread_nums; ++i) {
        pthread_join(tids[i], NULL);
    }

    return 0;
}

void *service(void *arg) {
    (void) arg;
    char ctime[20] = {0};
    char error[64] = {0};

    struct event_config *cfg = event_config_new();
    event_config_set_flag(cfg, EVENT_BASE_FLAG_NOLOCK | EVENT_BASE_FLAG_IGNORE_ENV);
    struct event_base *base = event_base_new_with_config(cfg);
    event_config_free(cfg);

    struct evconnlistener *listener = evconnlistener_new_bind(
            base, new_accept_cb, NULL,
            LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE | LEV_OPT_REUSEABLE_PORT,
            SOMAXCONN, (struct sockaddr *)&servaddr, sizeof(struct sockaddr_in)
    );
    if (listener == NULL) {
        printf("[%s] [ERR] listen socket: (%d) %s\n", curtime(ctime), errno, strerror_r(errno, error, 64));
        exit(1);
    }
    event_base_dispatch(base);

    evconnlistener_free(listener);
    event_base_free(base);
    libevent_global_shutdown();

    return NULL;
}

void new_accept_cb(struct evconnlistener *listener, int sock, struct sockaddr *addr, int addrlen, void *arg) {
    (void) listener;
    (void) sock;
    (void) addr;
    (void) addrlen;
    (void) arg;

    char ctime[20] = {0};
    set_tcp_sockopt(sock);
    struct sockaddr_in *clntaddr = (struct sockaddr_in *)addr;
    printf("[%s] [INF] new connect: %s:%d\n", curtime(ctime), inet_ntoa(clntaddr->sin_addr), ntohs(clntaddr->sin_port));

    struct bufferevent *clntbev = bufferevent_socket_new(evconnlistener_get_base(listener), sock, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(clntbev, new_1streq_cb, NULL, new_events_cb, NULL);
    bufferevent_enable(clntbev, EV_READ | EV_WRITE);
}

void new_events_cb(struct bufferevent *bev, short events, void *arg) {
    (void) bev;
    (void) events;
    (void) arg;
    char ctime[20] = {0};
    char error[64] = {0};

    struct sockaddr_in clntaddr;
    socklen_t addrlen = sizeof(clntaddr);
    getpeername(bufferevent_getfd(bev), (struct sockaddr *)&clntaddr, &addrlen);

    if (events & BEV_EVENT_ERROR) {
        printf("[%s] [ERR] error of %s:%d: (%d) %s\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port), errno, strerror_r(errno, error, 64));
    }

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
        bufferevent_free(bev);
    }
}

void new_1streq_cb(struct bufferevent *bev, void *arg) {
    (void) bev;
    (void) arg;
    char ctime[20] = {0};

    struct sockaddr_in clntaddr;
    socklen_t addrlen = sizeof(clntaddr);
    getpeername(bufferevent_getfd(bev), (struct sockaddr *)&clntaddr, &addrlen);

    struct evbuffer *input = bufferevent_get_input(bev);
    char *reqline = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF);

    if (reqline == NULL) {
        printf("[%s] [ERR] bad request of %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
        printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
        bufferevent_free(bev);
        return;
    }

    while ((reqline = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF)) != NULL) {
        char *type_header = strstr(reqline, "ConnectionType: ");
        if (type_header != NULL && type_header == reqline) {
            type_header += strlen("ConnectionType: "); // move to value's pos

            // 长度不对
            if (strlen(type_header) < 25) {
                printf("[%s] [ERR] bad request of %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                bufferevent_free(bev);
                free(reqline);
                return;
            }

            char type[4] = {0};
            strncpy(type, type_header, 3);

            // TCP 类型
            if (strcmp(type, "tcp") == 0) {
                char *addrptr = strstr(type_header, "tcp; addr=");

                // 格式不对
                if (addrptr != type_header) {
                    printf("[%s] [ERR] bad request of %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    bufferevent_free(bev);
                    free(reqline);
                    return;
                }

                addrptr += strlen("tcp; addr=");
                char *portptr = strstr(addrptr, "; port=");

                // 格式不对
                if (portptr == NULL || portptr == addrptr) {
                    printf("[%s] [ERR] bad request of %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    bufferevent_free(bev);
                    free(reqline);
                    return;
                }

                *portptr = 0;
                portptr += strlen("; port=");

                // 格式不对
                if (strlen(portptr) == 0) {
                    printf("[%s] [ERR] bad request of %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    bufferevent_free(bev);
                    free(reqline);
                    return;
                }

                // 解析 IP
                uint32_t addr = inet_addr(addrptr);
                if (addr == INADDR_NONE) {
                    printf("[%s] [ERR] bad request of %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    bufferevent_free(bev);
                    free(reqline);
                    return;
                }

                // 解析端口
                uint16_t port = htons(strtol(portptr, NULL, 10));
                if (port == 0) {
                    printf("[%s] [ERR] bad request of %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    bufferevent_free(bev);
                    free(reqline);
                    return;
                }

                // 创建地址
                struct sockaddr_in destaddr;
                memset(&destaddr, 0, sizeof(destaddr));
                destaddr.sin_family = AF_INET;
                destaddr.sin_addr.s_addr = addr;
                destaddr.sin_port = port;

                // 创建连接
                struct bufferevent *destbev = bufferevent_socket_new(bufferevent_get_base(bev), -1, BEV_OPT_CLOSE_ON_FREE);
                bufferevent_setcb(destbev, NULL, NULL, tcp_events_cb, bev);
                bufferevent_enable(destbev, EV_READ | EV_WRITE);
                bufferevent_socket_connect(destbev, (struct sockaddr *)&destaddr, sizeof(destaddr));
                set_tcp_sockopt(bufferevent_getfd(destbev));
                printf("[%s] [INF] connecting to %s:%s\n", curtime(ctime), addrptr, portptr);

                // 设置 BEV
                bufferevent_setcb(bev, NULL, NULL, tcp_events_cb, destbev);

                free(reqline);
                return;
            }

            // UDP 类型
            if (strcmp(type, "udp") == 0) {
                char *addrptr = strstr(type_header, "udp; addr=");

                // 格式不对
                if (addrptr != type_header) {
                    printf("[%s] [ERR] bad request of %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    bufferevent_free(bev);
                    free(reqline);
                    return;
                }

                addrptr += strlen("udp; addr=");
                char *portptr = strstr(addrptr, "; port=");

                // 格式不对
                if (portptr == NULL || portptr == addrptr) {
                    printf("[%s] [ERR] bad request of %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    bufferevent_free(bev);
                    free(reqline);
                    return;
                }

                *portptr = 0;
                portptr += strlen("; port=");

                // 格式不对
                if (strlen(portptr) == 0) {
                    printf("[%s] [ERR] bad request of %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    bufferevent_free(bev);
                    free(reqline);
                    return;
                }

                // 格式不对
                char *dataptr = strstr(portptr, "; data=");
                if (dataptr == NULL || dataptr == portptr) {
                    printf("[%s] [ERR] bad request of %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    bufferevent_free(bev);
                    free(reqline);
                    return;
                }

                *dataptr = 0;
                dataptr += strlen("; data=");

                // 格式不对
                if (strlen(dataptr) == 0) {
                    printf("[%s] [ERR] bad request of %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    bufferevent_free(bev);
                    free(reqline);
                    return;
                }

                // 解析 IP
                uint32_t addr = inet_addr(addrptr);
                if (addr == INADDR_NONE) {
                    printf("[%s] [ERR] bad request of %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    bufferevent_free(bev);
                    free(reqline);
                    return;
                }

                // 解析端口
                uint16_t port = htons(strtol(portptr, NULL, 10));
                if (port == 0) {
                    printf("[%s] [ERR] bad request of %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    bufferevent_free(bev);
                    free(reqline);
                    return;
                }

                // 解析数据
                void *rawdata = malloc(strlen(dataptr));
                size_t datalen = 0;
                if (base64_decode(dataptr, strlen(dataptr), rawdata, &datalen, 0) != 1) {
                    printf("[%s] [ERR] bad request of %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    bufferevent_free(bev);
                    free(reqline);
                    free(rawdata);
                    return;
                }

                // 创建地址
                struct sockaddr_in destaddr;
                memset(&destaddr, 0, sizeof(destaddr));
                destaddr.sin_family = AF_INET;
                destaddr.sin_addr.s_addr = addr;
                destaddr.sin_port = port;

                // 发送数据
                char error[64] = {0};
                int destsock = socket(AF_INET, SOCK_DGRAM, 0);
                evutil_make_socket_nonblocking(destsock);
                if (sendto(destsock, rawdata, datalen, 0, (struct sockaddr *)&destaddr, sizeof(destaddr)) == -1) {
                    printf("[%s] [ERR] sendto %s:%d: (%d) %s\n", curtime(ctime), inet_ntoa(destaddr.sin_addr), ntohs(destaddr.sin_port), errno, strerror_r(errno, error, 64));
                    printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    bufferevent_free(bev);
                    close(destsock);
                    free(reqline);
                    free(rawdata);
                    return;
                }
                printf("[%s] [INF] send %ld bytes data to %s:%d\n", curtime(ctime), datalen, inet_ntoa(destaddr.sin_addr), ntohs(destaddr.sin_port));
                free(rawdata);

                // 注册事件
                struct udp_arg *udparg = malloc(sizeof(struct udp_arg));
                struct event *ev = event_new(bufferevent_get_base(bev), destsock, EV_READ, udp_rcvres_cb, udparg);
                udparg->ev = ev;
                udparg->bev = bev;
                struct timeval tv = {10, 0}; // UDP read timeout
                event_add(ev, &tv);

                // 设置 BEV
                bufferevent_setcb(bev, NULL, NULL, udp_events_cb, udparg);

                free(reqline);
                return;
            }

            // 错误类型
            printf("[%s] [ERR] bad request of %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
            printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
            bufferevent_free(bev);
            free(reqline);
            return;
        }

        free(reqline);
    }

    // 离开了循环还没找到对应的头部说明是错误请求
    printf("[%s] [ERR] bad request of %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
    printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
    bufferevent_free(bev);
    free(reqline);
    return;
}

void tcp_datfwd_cb(struct bufferevent *bev, void *arg) {
    bufferevent_write_buffer(arg, bufferevent_get_input(bev));
}

void tcp_events_cb(struct bufferevent *bev, short events, void *arg) {
    char ctime[20] = {0};

    struct sockaddr_in thisaddr;
    socklen_t addrlen = sizeof(thisaddr);
    getpeername(bufferevent_getfd(bev), (struct sockaddr *)&thisaddr, &addrlen);

    if (events & BEV_EVENT_CONNECTED) {
        printf("[%s] [INF] connected to %s:%d\n", curtime(ctime), inet_ntoa(thisaddr.sin_addr), ntohs(thisaddr.sin_port));
        bufferevent_write(arg, WEBSOCKET_RESPONSE, strlen(WEBSOCKET_RESPONSE));
        bufferevent_setcb(bev, tcp_datfwd_cb, NULL, tcp_events_cb, arg);
        bufferevent_setcb(arg, tcp_datfwd_cb, NULL, tcp_events_cb, bev);
        return;
    }

    if (events & BEV_EVENT_ERROR) {
        char error[64] = {0};
        printf("[%s] [ERR] error of %s:%d: (%d) %s\n", curtime(ctime), inet_ntoa(thisaddr.sin_addr), ntohs(thisaddr.sin_port), errno, strerror_r(errno, error, 64));
    }

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        struct sockaddr_in othraddr;
        getpeername(bufferevent_getfd(arg), (struct sockaddr *)&othraddr, &addrlen);
        printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(thisaddr.sin_addr), ntohs(thisaddr.sin_port));
        printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(othraddr.sin_addr), ntohs(othraddr.sin_port));
        bufferevent_free(bev);
        bufferevent_free(arg);
    }
}

void udp_rcvres_cb(int sock, short events, void *arg) {
    char ctime[20] = {0};
    char error[64] = {0};
    struct udp_arg *udparg = arg;

    struct sockaddr_in destaddr;
    socklen_t addrlen = sizeof(destaddr);
    getpeername(sock, (struct sockaddr *)&destaddr, &addrlen);

    if (events & EV_TIMEOUT) {
        printf("[%s] [ERR] recv udp data timeout of %s:%d\n", curtime(ctime), inet_ntoa(destaddr.sin_addr), ntohs(destaddr.sin_port));
        bufferevent_free(udparg->bev);
        event_free(udparg->ev);
        free(udparg);
        close(sock);
        return;
    }

    void *rawbuf = malloc(UDP_RAW_BUFSIZ);
    int rawlen = recvfrom(sock, rawbuf, UDP_RAW_BUFSIZ, 0, NULL, NULL);

    if (rawlen == -1) {
        printf("[%s] [ERR] recv data from %s:%d: (%d) %s\n", curtime(ctime), inet_ntoa(destaddr.sin_addr), ntohs(destaddr.sin_port), errno, strerror_r(errno, error, 64));
        bufferevent_free(udparg->bev);
        event_free(udparg->ev);
        free(udparg);
        free(rawbuf);
        close(sock);
        return;
    }

    char *encbuf = malloc(UDP_ENC_BUFSIZ);
    size_t enclen = 0;
    base64_encode(rawbuf, rawlen, encbuf, &enclen, 0);
    free(rawbuf);

    bufferevent_write(udparg->bev, WEBSOCKET_RESPONSE, strlen(WEBSOCKET_RESPONSE) - 2);
    bufferevent_write(udparg->bev, "ConnectionType: ", strlen("ConnectionType: "));
    bufferevent_write(udparg->bev, encbuf, enclen);
    bufferevent_write(udparg->bev, "\r\n\r\n", 4);
    free(encbuf);

    struct sockaddr_in clntaddr;
    getpeername(bufferevent_getfd(udparg->bev), (struct sockaddr *)&clntaddr, &addrlen);
    printf("[%s] [INF] send %d bytes to %s:%d\n", curtime(ctime), rawlen, inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));

    close(sock);
    event_free(udparg->ev);
    udparg->ev = NULL; // 告诉 clntbev 不用 free event 了
}

void udp_events_cb(struct bufferevent *bev, short events, void *arg) {
    char ctime[20] = {0};

    struct sockaddr_in clntaddr;
    socklen_t addrlen = sizeof(clntaddr);
    getpeername(bufferevent_getfd(bev), (struct sockaddr *)&clntaddr, &addrlen);

    if (events & BEV_EVENT_ERROR) {
        char error[64] = {0};
        printf("[%s] [ERR] error of %s:%d: (%d) %s\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port), errno, strerror_r(errno, error, 64));
    }

    printf("[%s] [INF] closed connect: %s:%d\n", curtime(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));

    struct udp_arg *udparg = arg;
    if (udparg->ev != NULL) {
        event_free(udparg->ev);
        close(event_get_fd(udparg->ev));
    }
    bufferevent_free(bev);
    free(udparg);
}
