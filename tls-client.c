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
    printf("usage: tls-client OPTIONS [-v] [-h]. OPTIONS are as follows:\n"\
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

#define WEBSOCKET_STATUS_LINE "HTTP/1.1 101 Switching Protocols"
