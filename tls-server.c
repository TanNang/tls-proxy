#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include "libbase64.h"
#include "uthash.h"

#define PRINT_COMMAND_HELP \
    printf("usage: tls-server <OPTIONS>. OPTIONS have these:\n"\
           " -b <listen_addr>       listen addr. default: 127.0.0.1\n"\
           " -l <listen_port>       listen port. default: 60080\n"\
           " -j <thread_nums>       thread nums. default: 1\n"\
           " -v                     show version and exit\n"\
           " -h                     show help and exit\n")

#define WEBSOCKET_RESPONSE "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
#define BUFSIZ_FOR_BEV 65536
#define UDP_RAW_BUFSIZ 1472
#define UDP_ENC_BUFSIZ 1960
#define UDP_HASH_LEN 500
#define UDP_HASH_PRE 10

static struct sockaddr_in servaddr;
void *service(void *arg);

void new_accept_cb(struct evconnlistener *listener, int sock, struct sockaddr *addr, int addrlen, void *arg);
void new_fstreq_cb(struct bufferevent *bev, void *arg);
void new_events_cb(struct bufferevent *bev, short events, void *arg);

void tcp_read_cb(struct bufferevent *bev, void *arg);
void tcp_write_cb(struct bufferevent *bev, void *arg);
void tcp_events_cb(struct bufferevent *bev, short events, void *arg);
void tcp_timeout_cb(int sock, short events, void *arg);

void udp_events_cb(struct bufferevent *bev, short events, void *arg);
void udp_request_cb(struct bufferevent *bev, void *arg);
void udp_response_cb(int sock, short events, void *arg);

typedef struct {
    struct event       *ev;
    struct bufferevent *bev;
} EVArg;

typedef struct {
    int            port;
    struct event  *ev;
    UT_hash_handle hh;
} UDPNode;

typedef struct {
    char                addr[16];
    char                port[6];
    UDPNode            *hash;
    struct bufferevent *bev;
} UDPArg;

UDPNode *udpnode_init() {
    UDPNode *hash = NULL;
    UDPNode *node = calloc(1, sizeof(UDPNode));
    HASH_ADD_INT(hash, port, node);
    return hash;
}

void udpnode_put(UDPNode *hash, int port, struct event *ev) {
    if (port == 0) return;
    UDPNode *node = NULL;
    HASH_FIND_INT(hash, &port, node);
    if (node == NULL) {
        node = calloc(1, sizeof(UDPNode));
        node->port = port;
        node->ev = ev;
        HASH_ADD_INT(hash, port, node);
        if (HASH_COUNT(hash) > UDP_HASH_LEN) {
            int cnt = 0;
            UDPNode *head = hash->hh.next;
            UDPNode *node = NULL, *temp = NULL;
            HASH_ITER(hh, head, node, temp) {
                HASH_DEL(hash, node);
                free(event_get_callback_arg(node->ev));
                close(event_get_fd(node->ev));
                event_free(node->ev);
                free(node);
                if (++cnt == UDP_HASH_PRE) return;
            }
        }
    } else {
        free(event_get_callback_arg(node->ev));
        close(event_get_fd(node->ev));
        event_free(node->ev);
        node->ev = ev;
        HASH_DEL(hash, node);
        HASH_ADD_INT(hash, port, node);
    }
}

UDPNode *udpnode_get(UDPNode *hash, int port) {
    if (port == 0) return NULL;
    UDPNode *node = NULL;
    HASH_FIND_INT(hash, &port, node);
    if (node == NULL) return NULL;
    HASH_DEL(hash, node);
    HASH_ADD_INT(hash, port, node);
    return node;
}

struct event *udpnode_getev(UDPNode *hash, int port) {
    if (port == 0) return NULL;
    UDPNode *node = udpnode_get(hash, port);
    return (node == NULL) ? NULL : (node->ev);
}

void udpnode_del(UDPNode *hash, int port) {
    if (port == 0) return;
    UDPNode *node = NULL;
    HASH_FIND_INT(hash, &port, node);
    if (node == NULL) return;
    HASH_DEL(hash, node);
    free(event_get_callback_arg(node->ev));
    close(event_get_fd(node->ev));
    event_free(node->ev);
    free(node);
}

void udpnode_clear(UDPNode *hash) {
    UDPNode *node = NULL, *temp = NULL;
    HASH_ITER(hh, hash, node, temp) {
        HASH_DEL(hash, node);
        if (node->port != 0) {
            free(event_get_callback_arg(node->ev));
            close(event_get_fd(node->ev));
            event_free(node->ev);
        }
        free(node);
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

    char *listen_addr = "127.0.0.1";
    int   listen_port = 60080;
    int   thread_nums = 1;

    opterr = 0;
    char *optstr = "b:l:j:vh";
    int opt = -1;
    while ((opt = getopt(argc, argv, optstr)) != -1) {
        switch (opt) {
            case 'v':
                printf("tls-server v1.1\n");
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

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(listen_addr);
    servaddr.sin_port = htons(listen_port);

    char ctime[36] = {0};
    printf("%s [srv] thread numbers: %d\n", loginf(ctime), thread_nums);
    printf("%s [srv] listen address: %s:%d\n", loginf(ctime), listen_addr, listen_port);

    pthread_t tids[--thread_nums];
    for (int i = 0; i < thread_nums; ++i) {
        if (pthread_create(tids + i, NULL, service, NULL) != 0) {
            printf("%s [srv] create thread: (%d) %s\n", logerr(ctime), errno, strerror(errno));
            return errno;
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
        char ctime[36] = {0};
        char error[64] = {0};
        printf("%s [srv] listen socket: %s:%d: (%d) %s\n", logerr(ctime), inet_ntoa(servaddr.sin_addr), ntohs(servaddr.sin_port), errno, strerror_r(errno, error, 64));
        exit(errno);
    }
    event_base_dispatch(base);

    evconnlistener_free(listener);
    event_base_free(base);
    libevent_global_shutdown();

    return NULL;
}

void new_accept_cb(struct evconnlistener *listener, int sock, struct sockaddr *addr, int addrlen, void *arg) {
    (void) listener; (void) sock; (void) addr; (void) addrlen; (void) arg;

    char ctime[36] = {0};
    setsockopt_tcp(sock);
    struct sockaddr_in *clntaddr = (struct sockaddr_in *)addr;
    printf("%s [srv] new connect: %s:%d\n", loginf(ctime), inet_ntoa(clntaddr->sin_addr), htons(clntaddr->sin_port));

    struct bufferevent *bev = bufferevent_socket_new(evconnlistener_get_base(listener), sock, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(bev, new_fstreq_cb, NULL, new_events_cb, NULL);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
    bufferevent_setwatermark(bev, EV_READ, 0, BUFSIZ_FOR_BEV);
}

void new_events_cb(struct bufferevent *bev, short events, void *arg) {
    (void) bev; (void) events; (void) arg;

    char ctime[36] = {0};
    struct sockaddr_in clntaddr = {0};
    socklen_t addrlen = sizeof(clntaddr);
    getpeername(bufferevent_getfd(bev), (struct sockaddr *)&clntaddr, &addrlen);

    if (events & BEV_EVENT_ERROR && errno != 0) {
        char error[64] = {0};
        printf("%s [srv] error on %s:%d: (%d) %s\n", logerr(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port), errno, strerror_r(errno, error, 64));
    }

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        printf("%s [srv] closed connect: %s:%d\n", loginf(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
        bufferevent_free(bev);
    }
}

void new_fstreq_cb(struct bufferevent *bev, void *arg) {
    (void) bev; (void) arg;

    char ctime[36] = {0};
    struct sockaddr_in clntaddr = {0};
    socklen_t addrlen = sizeof(clntaddr);
    getpeername(bufferevent_getfd(bev), (struct sockaddr *)&clntaddr, &addrlen);

    char *reqline = NULL;
    struct evbuffer *input = bufferevent_get_input(bev);
    while ((reqline = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF)) != NULL) {
        char *header = strstr(reqline, "ConnectionType: ");

        if (header == reqline) {
            header += strlen("ConnectionType: ");
            evbuffer_drain(input, evbuffer_get_length(input));

            if (strlen(header) < 3) {
                printf("%s [srv] bad request: %s:%d\n", logerr(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                printf("%s [srv] closed connect: %s:%d\n", loginf(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                bufferevent_free(bev);
                free(reqline);
                return;
            }

            char type[4] = {0};
            strncpy(type, header, 3);

            if (strcmp(type, "udp") == 0) {
                printf("%s [udp] new connect: %s:%d\n", loginf(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                bufferevent_write(bev, WEBSOCKET_RESPONSE, strlen(WEBSOCKET_RESPONSE));
                bufferevent_setcb(bev, udp_request_cb, NULL, udp_events_cb, udpnode_init());
                free(reqline);
                return;
            }

            if (strcmp(type, "tcp") == 0) {
                char *addrptr = strstr(header, "tcp; addr=");

                if (addrptr != header) {
                    printf("%s [tcp] bad request: %s:%d\n", logerr(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    printf("%s [tcp] closed connect: %s:%d\n", loginf(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    bufferevent_free(bev);
                    free(reqline);
                    return;
                }

                addrptr += strlen("tcp; addr=");
                char *portptr = strstr(addrptr, "; port=");

                if (portptr == addrptr || portptr == NULL) {
                    printf("%s [tcp] bad request: %s:%d\n", logerr(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    printf("%s [tcp] closed connect: %s:%d\n", loginf(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    bufferevent_free(bev);
                    free(reqline);
                    return;
                }

                *portptr = 0;
                portptr += strlen("; port=");

                if (strlen(portptr) == 0 || strlen(portptr) > 5) {
                    printf("%s [tcp] bad request: %s:%d\n", logerr(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    printf("%s [tcp] closed connect: %s:%d\n", loginf(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    bufferevent_free(bev);
                    free(reqline);
                    return;
                }

                uint32_t addr = inet_addr(addrptr);
                if (addr == INADDR_NONE) {
                    printf("%s [tcp] bad request: %s:%d\n", logerr(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    printf("%s [tcp] closed connect: %s:%d\n", loginf(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    bufferevent_free(bev);
                    free(reqline);
                    return;
                }

                uint16_t port = htons(strtol(portptr, NULL, 10));
                if (port == 0) {
                    printf("%s [tcp] bad request: %s:%d\n", logerr(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    printf("%s [tcp] closed connect: %s:%d\n", loginf(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
                    bufferevent_free(bev);
                    free(reqline);
                    return;
                }

                struct sockaddr_in destaddr = {0};
                destaddr.sin_family = AF_INET;
                destaddr.sin_addr.s_addr = addr;
                destaddr.sin_port = port;

                struct bufferevent *destbev = bufferevent_socket_new(bufferevent_get_base(bev), -1, BEV_OPT_CLOSE_ON_FREE);
                bufferevent_setcb(destbev, NULL, NULL, tcp_events_cb, bev);
                bufferevent_enable(destbev, EV_READ | EV_WRITE);
                bufferevent_setwatermark(destbev, EV_READ, 0, BUFSIZ_FOR_BEV);
                printf("%s [tcp] connecting to %s:%s\n", loginf(ctime), addrptr, portptr);
                bufferevent_socket_connect(destbev, (struct sockaddr *)&destaddr, sizeof(destaddr));
                setsockopt_tcp(bufferevent_getfd(destbev));

                bufferevent_setcb(bev, NULL, NULL, tcp_events_cb, destbev);
                bufferevent_disable(bev, EV_READ);
                free(reqline);
                return;
            }

            printf("%s [srv] bad request: %s:%d\n", logerr(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
            printf("%s [srv] closed connect: %s:%d\n", loginf(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
            bufferevent_free(bev);
            free(reqline);
            return;
        }

        free(reqline);
    }

    printf("%s [srv] bad request: %s:%d\n", logerr(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
    printf("%s [srv] closed connect: %s:%d\n", loginf(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
    bufferevent_free(bev);
}

void tcp_read_cb(struct bufferevent *bev, void *arg) {
    struct evbuffer *input = bufferevent_get_input(bev);
    struct evbuffer *output = bufferevent_get_output(arg);
    evbuffer_add_buffer(output, input);
    if (evbuffer_get_length(output) >= BUFSIZ_FOR_BEV) {
        bufferevent_disable(bev, EV_READ);
        bufferevent_setwatermark(arg, EV_WRITE, BUFSIZ_FOR_BEV / 2, 0);
        bufferevent_setcb(arg, tcp_read_cb, tcp_write_cb, tcp_events_cb, bev);
    }
}

void tcp_write_cb(struct bufferevent *bev, void *arg) {
    bufferevent_enable(arg, EV_READ);
    bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
    bufferevent_setcb(bev, tcp_read_cb, NULL, tcp_events_cb, arg);
}

void tcp_events_cb(struct bufferevent *bev, short events, void *arg) {
    char ctime[36] = {0};
    struct sockaddr_in thisaddr = {0};
    socklen_t addrlen = sizeof(thisaddr);
    getpeername(bufferevent_getfd(bev), (struct sockaddr *)&thisaddr, &addrlen);

    if (events & BEV_EVENT_CONNECTED) {
        printf("%s [tcp] connected to %s:%d\n", loginf(ctime), inet_ntoa(thisaddr.sin_addr), ntohs(thisaddr.sin_port));
        bufferevent_write(arg, WEBSOCKET_RESPONSE, strlen(WEBSOCKET_RESPONSE));
        bufferevent_setcb(bev, tcp_read_cb, NULL, tcp_events_cb, arg);
        bufferevent_setcb(arg, tcp_read_cb, NULL, tcp_events_cb, bev);
        bufferevent_enable(arg, EV_READ);
        return;
    }

    if (events & BEV_EVENT_ERROR && errno != 0) {
        char error[64] = {0};
        printf("%s [tcp] error on %s:%d: (%d) %s\n", logerr(ctime), inet_ntoa(thisaddr.sin_addr), ntohs(thisaddr.sin_port), errno, strerror_r(errno, error, 64));
    }

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        struct sockaddr_in othraddr = {0};
        getpeername(bufferevent_getfd(arg), (struct sockaddr *)&othraddr, &addrlen);
        printf("%s [tcp] closed connect: %s:%d\n", loginf(ctime), inet_ntoa(thisaddr.sin_addr), ntohs(thisaddr.sin_port));
        printf("%s [tcp] closed connect: %s:%d\n", loginf(ctime), inet_ntoa(othraddr.sin_addr), ntohs(othraddr.sin_port));
        bufferevent_free(bev);
        bufferevent_setcb(arg, NULL, NULL, NULL, NULL);

        EVArg *evarg = calloc(1, sizeof(EVArg));
        struct event *ev = event_new(bufferevent_get_base(arg), -1, EV_TIMEOUT, tcp_timeout_cb, evarg);
        evarg->ev = ev; evarg->bev = arg;
        struct timeval tv = {3, 0};
        event_add(ev, &tv);
    }
}

void tcp_timeout_cb(int sock, short events, void *arg) {
    (void) sock; (void) events;
    EVArg *evarg = arg;
    bufferevent_free(evarg->bev);
    event_free(evarg->ev);
    free(evarg);
}

void udp_events_cb(struct bufferevent *bev, short events, void *arg) {
    char ctime[36] = {0};
    struct sockaddr_in clntaddr = {0};
    socklen_t addrlen = sizeof(clntaddr);
    getpeername(bufferevent_getfd(bev), (struct sockaddr *)&clntaddr, &addrlen);

    if (events & BEV_EVENT_ERROR && errno != 0) {
        char error[64] = {0};
        printf("%s [udp] error on %s:%d: (%d) %s\n", logerr(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port), errno, strerror_r(errno, error, 64));
    }

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        printf("%s [udp] closed connect: %s:%d\n", loginf(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
        bufferevent_free(bev);
        udpnode_clear(arg);
    }
}

void udp_request_cb(struct bufferevent *bev, void *arg) {
    char ctime[36] = {0};
    struct sockaddr_in clntaddr = {0};
    socklen_t addrlen = sizeof(clntaddr);
    getpeername(bufferevent_getfd(bev), (struct sockaddr *)&clntaddr, &addrlen);

    char *request = NULL;
    struct evbuffer *input = bufferevent_get_input(bev);
    while ((request = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF)) != NULL) {
        int colon_cnt = 0;
        for (int i = 0, l = strlen(request); i < l; ++i) {
            if (request[i] == ':') ++colon_cnt;
        }

        if (colon_cnt != 5 || strlen(request) < 23) {
            printf("%s [udp] bad request: %s:%d\n", logerr(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
            free(request);
            continue;
        }

        char *iaddrptr = request;
        char *iportptr = strchr(iaddrptr, ':'); *iportptr = 0; ++iportptr;
        char *raddrptr = strchr(iportptr, ':'); *raddrptr = 0; ++raddrptr;
        char *rportptr = strchr(raddrptr, ':'); *rportptr = 0; ++rportptr;
        char *eportptr = strchr(rportptr, ':'); *eportptr = 0; ++eportptr;
        char *edataptr = strchr(eportptr, ':'); *edataptr = 0; ++edataptr;

        if (strlen(iaddrptr) < 7 || strlen(iaddrptr) > 15) {
            printf("%s [udp] bad request: %s:%d\n", logerr(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
            free(request);
            continue;
        }

        if (strlen(iportptr) < 1 || strlen(iportptr) > 5) {
            printf("%s [udp] bad request: %s:%d\n", logerr(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
            free(request);
            continue;
        }

        if (strlen(raddrptr) < 7 || strlen(raddrptr) > 15) {
            printf("%s [udp] bad request: %s:%d\n", logerr(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
            free(request);
            continue;
        }

        if (strlen(rportptr) < 1 || strlen(rportptr) > 5) {
            printf("%s [udp] bad request: %s:%d\n", logerr(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
            free(request);
            continue;
        }

        if (strlen(eportptr) < 1 || strlen(eportptr) > 5) {
            printf("%s [udp] bad request: %s:%d\n", logerr(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
            free(request);
            continue;
        }

        if (strlen(edataptr) < 1) {
            printf("%s [udp] bad request: %s:%d\n", logerr(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
            free(request);
            continue;
        }

        uint32_t raddr = inet_addr(raddrptr);
        if (raddr == INADDR_NONE) {
            printf("%s [udp] bad request: %s:%d\n", logerr(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
            free(request);
            continue;
        }

        uint16_t rport = htons(strtol(rportptr, NULL, 10));
        if (rport == 0) {
            printf("%s [udp] bad request: %s:%d\n", logerr(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
            free(request);
            continue;
        }

        int eport = strtol(eportptr, NULL, 10);
        if (eport < 0 || eport > 65535) {
            printf("%s [udp] bad request: %s:%d\n", logerr(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
            free(request);
            continue;
        }

        size_t rawlen = 0;
        void *rawbuf = malloc(strlen(edataptr));
        if (base64_decode(edataptr, strlen(edataptr), rawbuf, &rawlen, 0) != 1) {
            printf("%s [udp] bad request: %s:%d\n", logerr(ctime), inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));
            free(request);
            free(rawbuf);
            continue;
        }
        printf("%s [udp] recv %ld bytes data from %s:%d\n", loginf(ctime), rawlen, inet_ntoa(clntaddr.sin_addr), ntohs(clntaddr.sin_port));

        int esock = -1;
        if (eport != 0) {
            struct event *ev = udpnode_getev(arg, eport);
            if (ev != NULL) esock = event_get_fd(ev);
        }

        if (esock == -1) {
            esock = socket(AF_INET, SOCK_DGRAM, 0);
            evutil_make_socket_nonblocking(esock);

            struct sockaddr_in esrcaddr = {0};
            esrcaddr.sin_family = AF_INET;
            esrcaddr.sin_addr.s_addr = 0;
            esrcaddr.sin_port = 0;

            if (bind(esock, (struct sockaddr *)&esrcaddr, sizeof(esrcaddr)) == -1) {
                char error[64] = {0};
                printf("%s [udp] bind socket (any port): (%d) %s\n", logerr(ctime), errno, strerror_r(errno, error, 64));
                free(request);
                free(rawbuf);
                close(esock);
                continue;
            }

            memset(&esrcaddr, 0, addrlen);
            getsockname(esock, (struct sockaddr *)&esrcaddr, &addrlen);
            eport = ntohs(esrcaddr.sin_port);

            UDPArg *udparg = calloc(1, sizeof(UDPArg));
            strcpy(udparg->addr, iaddrptr);
            strcpy(udparg->port, iportptr);
            udparg->hash = arg;
            udparg->bev = bev;

            struct event *ev = event_new(bufferevent_get_base(bev), esock, EV_READ | EV_TIMEOUT | EV_PERSIST, udp_response_cb, udparg);
            struct timeval tv = {180, 0};
            event_add(ev, &tv);

            udpnode_put(arg, eport, ev);
        }

        struct sockaddr_in destaddr = {0};
        destaddr.sin_family = AF_INET;
        destaddr.sin_addr.s_addr = raddr;
        destaddr.sin_port = rport;

        if (sendto(esock, rawbuf, rawlen, 0, (struct sockaddr *)&destaddr, addrlen) == -1) {
            char error[64] = {0};
            printf("%s [udp] sendto %s:%s: (%d) %s\n", logerr(ctime), raddrptr, rportptr, errno, strerror_r(errno, error, 64));
            free(request);
            free(rawbuf);
            continue;
        }
        printf("%s [udp] send %ld bytes data to %s:%s\n", loginf(ctime), rawlen, raddrptr, rportptr);
        free(rawbuf);
        free(request);
    }
}

void udp_response_cb(int sock, short events, void *arg) {
    char ctime[36] = {0};
    UDPArg *udparg = arg;
    struct sockaddr_in esrcaddr = {0};
    socklen_t addrlen = sizeof(esrcaddr);
    getsockname(sock, (struct sockaddr *)&esrcaddr, &addrlen);

    if (events & EV_TIMEOUT) {
        printf("%s [udp] socket timeout: %s:%d\n", loginf(ctime), inet_ntoa(esrcaddr.sin_addr), ntohs(esrcaddr.sin_port));
        udpnode_del(udparg->hash, ntohs(esrcaddr.sin_port));
        return;
    }

    struct sockaddr_in destaddr = {0};
    void *rawbuf = malloc(UDP_RAW_BUFSIZ);
    int rawlen = recvfrom(sock, rawbuf, UDP_RAW_BUFSIZ, 0, (struct sockaddr *)&destaddr, &addrlen);
    if (rawlen == -1) {
        char error[64] = {0};
        printf("%s [udp] recv udp data: (%d) %s\n", logerr(ctime), errno, strerror_r(errno, error, 64));
        free(rawbuf);
        return;
    }
    printf("%s [udp] recv %d bytes data from %s:%d\n", loginf(ctime), rawlen, inet_ntoa(destaddr.sin_addr), ntohs(destaddr.sin_port));

    size_t enclen = 0;
    char *encbuf = malloc(UDP_ENC_BUFSIZ);
    base64_encode(rawbuf, rawlen, encbuf, &enclen, 0);
    encbuf[enclen] = 0;
    free(rawbuf);

    char raddr[16] = {0};
    char rport[6] = {0};
    char eport[6] = {0};
    strcpy(raddr, inet_ntoa(destaddr.sin_addr));
    sprintf(rport, "%d", ntohs(destaddr.sin_port));
    sprintf(eport, "%d", ntohs(esrcaddr.sin_port));

    bufferevent_write(udparg->bev, udparg->addr, strlen(udparg->addr));
    bufferevent_write(udparg->bev, ":", 1);
    bufferevent_write(udparg->bev, udparg->port, strlen(udparg->port));
    bufferevent_write(udparg->bev, ":", 1);
    bufferevent_write(udparg->bev, raddr, strlen(raddr));
    bufferevent_write(udparg->bev, ":", 1);
    bufferevent_write(udparg->bev, rport, strlen(rport));
    bufferevent_write(udparg->bev, ":", 1);
    bufferevent_write(udparg->bev, eport, strlen(eport));
    bufferevent_write(udparg->bev, ":", 1);
    bufferevent_write(udparg->bev, encbuf, strlen(encbuf));
    bufferevent_write(udparg->bev, "\r\n", 2);
    free(encbuf);

    memset(&destaddr, 0, addrlen);
    getpeername(bufferevent_getfd(udparg->bev), (struct sockaddr *)&destaddr, &addrlen);
    printf("%s [udp] send %d bytes data to %s:%d\n", loginf(ctime), rawlen, inet_ntoa(destaddr.sin_addr), ntohs(destaddr.sin_port));
}
