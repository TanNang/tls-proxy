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

#define WEBSOCKET_STATUS_LINE "HTTP/1.1 101 Switching Protocols"
