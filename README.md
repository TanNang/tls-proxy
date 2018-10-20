# TLS-Proxy
**本软件仅供内部学习交流，严禁用于任何商业用途，严禁违反国家相关法律法规，请于测试后 24 小时内删除，谢谢！**

## 简单介绍
`tls-proxy` 可以看作为 V2Ray 的 `WebSocket + TLS + Web` 方案的 C 语言极简实现版，使用 `libevent2` 轻量级事件通知库编写。在硬件资源有限的环境中（如树莓派 3B，这也是我写 tls-proxy 的根本原因），tls-proxy 的资源占用更少，且代理速度比同等条件下的 v2ray 快的多（速度基本与 ss/ssr-libev 持平），同时又不降低安全性。

`tls-proxy` 支持 TCP 和 UDP 协议的代理（与 v2ray 一样，UDP 流量使用 TCP 传输，尽可能减少特征），通信过程：<br>
**`source-socket <-> tls-client <-> web-server(eg: nginx) <-> tls-server <-> destination-socket`**<br>
`tls-client` 与 `web-server` 之间使用 HTTPS 协议（TLS1.2），`web-server` 与 `tls-server` 之间使用 websocket 协议。

## 版本历史
**tls-proxy v1.0**<br>
初始版本，TCP 和 UDP 都有问题（TCP 套接字处理不当，导致尾部数据丢失；UDP 实现过于简单粗暴，不支持 QUIC 协议），基本无法正常使用，所以此版本仅供娱乐。

**tls-proxy v1.1**<br>
当前版本，在 v1.0 的基础上修复了 TCP 缓冲区数据残留问题，修正了 UDP 的代理逻辑，支持 QUIC 等"有状态"的 UDP 上层协议（LRU Cache），暂未发现日常使用问题。

## 相关依赖
**`tls-server`**：
 - [uthash](https://github.com/troydhanson/uthash)
 - [base64](https://github.com/aklomp/base64)
 - [libevent](https://github.com/libevent/libevent)

**`tls-client`**：
 - [uthash](https://github.com/troydhanson/uthash)
 - [base64](https://github.com/aklomp/base64)
 - [openssl](https://github.com/openssl/openssl)
 - [libevent](https://github.com/libevent/libevent)

## 编译方法
> 本地编译，以 linux x86_64 为例

```bash
# uthash
cd /tmp
git clone https://github.com/troydhanson/uthash

# base64
cd /tmp
git clone https://github.com/aklomp/base64
cd base64
make

# openssl
cd /tmp
wget https://www.openssl.org/source/openssl-1.1.0i.tar.gz
tar xvf openssl-1.1.0i.tar.gz
cd openssl-1.1.0i
./Configure linux-x86_64 --prefix=/tmp/openssl --openssldir=/tmp/openssl no-shared # for linux x86_64
make -j`nproc` && make install -j`nproc`

# libevent
cd /tmp
git clone https://github.com/libevent/libevent libevent-sources
cd libevent-sources
./autogen.sh
./configure --prefix=/tmp/libevent --enable-shared=no --enable-static=yes --disable-samples --disable-debug-mode --disable-malloc-replacement CPPFLAGS='-I/tmp/openssl/include' LDFLAGS='-L/tmp/openssl/lib' LIBS='-lssl -lcrypto -ldl'
make && make install

# tls-proxy
cd /tmp
git clone https://github.com/zfl9/tls-proxy
cd tls-proxy
gcc -I/tmp/uthash/include -I/tmp/base64/include -I/tmp/libevent/include -std=c11 -Wall -Wextra -Wno-format-overflow -O3 -s -pthread -o tls-server tls-server.c /tmp/base64/lib/libbase64.o /tmp/libevent/lib/libevent.a
gcc -I/tmp/uthash/include -I/tmp/base64/include -I/tmp/libevent/include -I/tmp/openssl/include -std=c11 -Wall -Wextra -Wno-format-overflow -O3 -s -pthread -o tls-client tls-client.c /tmp/base64/lib/libbase64.o /tmp/libevent/lib/libevent.a /tmp/libevent/lib/libevent_openssl.a /tmp/openssl/lib/libssl.a /tmp/openssl/lib/libcrypto.a -ldl
cp -af tls-client tls-server /usr/local/bin

# delete files
cd /
rm -fr /tmp/uthash
rm -fr /tmp/base64
rm -fr /tmp/openssl*
rm -fr /tmp/libevent*
rm -fr /tmp/tls-proxy
```

> 交叉编译，在 linux x86_64 上编译 linux aarch64 上用的 tls-proxy（RPi3B）

```bash
# 交叉编译工具链的前缀
ARCH='aarch64-linux-gnu'

# uthash
cd /tmp
git clone https://github.com/troydhanson/uthash

# base64
cd /tmp
git clone https://github.com/aklomp/base64
cd base64
make CC=$ARCH-gcc LD=$ARCH-ld OBJCOPY=$ARCH-objcopy

# openssl
cd /tmp
wget https://www.openssl.org/source/openssl-1.1.0i.tar.gz
tar xvf openssl-1.1.0i.tar.gz
cd openssl-1.1.0i
./Configure linux-aarch64 --prefix=/tmp/openssl --openssldir=/tmp/openssl no-shared
make CC=$ARCH-gcc RANLIB=$ARCH-ranlib -j`nproc` && make install -j`nproc`

# libevent
cd /tmp
git clone https://github.com/libevent/libevent libevent-sources
cd libevent-sources
./autogen.sh
./configure --host=$ARCH --prefix=/tmp/libevent --enable-shared=no --enable-static=yes --disable-samples --disable-debug-mode --disable-malloc-replacement CPPFLAGS='-I/tmp/openssl/include' LDFLAGS='-L/tmp/openssl/lib' LIBS='-lssl -lcrypto -ldl'
make && make install

# tls-proxy
cd /tmp
git clone https://github.com/zfl9/tls-proxy
cd tls-proxy
$ARCH-gcc -I/tmp/uthash/include -I/tmp/base64/include -I/tmp/libevent/include -std=c11 -Wall -Wextra -Wno-format-overflow -O3 -s -pthread -o tls-server tls-server.c /tmp/base64/lib/libbase64.o /tmp/libevent/lib/libevent.a
$ARCH-gcc -I/tmp/uthash/include -I/tmp/base64/include -I/tmp/libevent/include -I/tmp/openssl/include -std=c11 -Wall -Wextra -Wno-format-overflow -O3 -s -pthread -o tls-client tls-client.c /tmp/base64/lib/libbase64.o /tmp/libevent/lib/libevent.a /tmp/libevent/lib/libevent_openssl.a /tmp/openssl/lib/libssl.a /tmp/openssl/lib/libcrypto.a -ldl
```

> 交叉编译，在 linux x86_64 上编译 Android 8.1.0 (aarch64) 上用的 tls-proxy

```bash
# 交叉编译工具链的前缀
ARCH='aarch64-linux-android'

# uthash
cd /tmp
git clone https://github.com/troydhanson/uthash

# base64
cd /tmp
git clone https://github.com/aklomp/base64
cd base64
make CC=$ARCH-gcc LD=$ARCH-ld OBJCOPY=$ARCH-objcopy

# openssl
cd /tmp
wget https://www.openssl.org/source/openssl-1.1.0i.tar.gz
tar xvf openssl-1.1.0i.tar.gz
cd openssl-1.1.0i
./Configure linux-aarch64 --prefix=/tmp/openssl --openssldir=/tmp/openssl no-shared
make CC=$ARCH-gcc RANLIB=$ARCH-ranlib -j`nproc` && make install -j`nproc`

# libevent
cd /tmp
git clone https://github.com/libevent/libevent libevent-sources
cd libevent-sources
./autogen.sh
./configure --host=$ARCH --prefix=/tmp/libevent --enable-shared=no --enable-static=yes --disable-samples --disable-debug-mode --disable-malloc-replacement CPPFLAGS='-I/tmp/openssl/include' LDFLAGS='-L/tmp/openssl/lib' LIBS='-lssl -lcrypto -ldl'
make && make install

# tls-proxy
cd /tmp
git clone https://github.com/zfl9/tls-proxy
cd tls-proxy
$ARCH-gcc -I/tmp/uthash/include -I/tmp/base64/include -I/tmp/libevent/include -std=c11 -Wall -Wextra -Wno-format-overflow -O3 -s -pie -fPIE -pthread -o tls-server tls-server.c /tmp/base64/lib/libbase64.o /tmp/libevent/lib/libevent.a
$ARCH-gcc -I/tmp/uthash/include -I/tmp/base64/include -I/tmp/libevent/include -I/tmp/openssl/include -std=c11 -Wall -Wextra -Wno-format-overflow -O3 -s -pie -fPIE -pthread -o tls-client tls-client.c /tmp/base64/lib/libbase64.o /tmp/libevent/lib/libevent.a /tmp/libevent/lib/libevent_openssl.a /tmp/openssl/lib/libssl.a /tmp/openssl/lib/libcrypto.a -ldl
```

## 使用方法
> 如果你会使用 v2ray 的 websocket + tls + web 模式，那么 tls-proxy 对你来说很容易上手，因为使用方法基本一致。

**前提条件**
- 一个域名
- 一个 SSL 证书
- 一个 Web 服务器

SSL 证书免费的有很多，如果你没有 SSL 证书，请先申请一张（不建议使用自签发的 SSL 证书，因为不会被 tls-client 所信任，除非你将自签发的根证书添加到 tls-client 主机的 CA 文件中）；为什么需要一个域名？因为 tls-client 强制校验 SSL 证书对应的域名，如果 SSL 证书上的域名与指定的域名不一致，则会断开与 Web 服务器的连接；Web 服务器需要配置 HTTPS，以下的 Web 服务器均以 Nginx 为例，其它服务器请自行斟酌。

**配置 Nginx**

1、修改 `/etc/nginx/nginx.conf`，在 `http` 配置段中添加如下配置（根据情况自行修改）：
```nginx
http {
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;    # 禁用 SSLv2、SSLv3
    ssl_dhparam /etc/nginx/ssl/dhparam.pem; # 指定 DH-param 文件
    ssl_session_cache shared:SSL:50m;       # 启用 SSL 会话缓存，50 MB
    ssl_session_timeout 60m;                # 设置 SSL 会话缓存超时时间，60 min
    ssl_session_tickets on;                 # 启用 SSL Session Ticket 会话恢复功能
    resolver 8.8.8.8;                       # 设置 DNS 域名解析服务器
    ssl_stapling on;                        # 启用 OCSP Stapling，优化 TLS 握手
    ssl_stapling_verify on;                 # 启用对 OCSP responses 响应结果的校验
    ssl_prefer_server_ciphers on;           # 进行 TLS 握手时，优先选择服务器的加密套件
    ssl_ciphers "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA";
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
}
```

2、使用 openssl 生成 dhparam.pem 文件（`/etc/nginx/ssl/dhparam.pem`）
```bash
# 需要执行很长时间，请不要中断它
mkdir -p /etc/nginx/ssl
cd /etc/nginx/ssl
openssl dhparam -out dhparam.pem 4096
```

3、配置与 tls-server 相关的 vhost，根据实际情况修改
```nginx
server {
    listen      80 reuseport fastopen=3 default_server;
    server_name www.example.com;
    return 301 https://www.example.com$request_uri;
}

server {
    listen      443 ssl reuseport fastopen=3 default_server;
    server_name www.example.com;

    root    /srv/http/www.example.com;
    index   index.html;

    ssl                 on;
    ssl_certificate     "/etc/nginx/ssl/www.example.com.crt";
    ssl_certificate_key "/etc/nginx/ssl/www.example.com.key";

    location ~* \.(jpg|jpeg|png|gif|ico|(css|js)(\?v=.*)?)$ {
       expires 60d;
    }

    ## tls-proxy
    location /tls-proxy {
        if ($http_some_header != 'some_header_value') {
            return 404;
        }
        proxy_http_version 1.1;
        proxy_read_timeout 3650d;
        proxy_send_timeout 3650d;
        proxy_connect_timeout 3s;
        proxy_pass http://127.0.0.1:60080;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Upgrade $http_upgrade;
    }
}
```
`/tls-proxy` 可以改为你喜欢的任意 URI；`tls-server` 默认监听地址为 `127.0.0.1:60080/tcp`；说明一下 `$http_some_header` 语句的作用：即使别人知道你的 URI，如果它没有设置正确的 HTTP 头部（在这里就是 `Some-Header` 咯，去掉开头的 `http_`，下划线换成连字符，大小写不敏感），并且对应的头部的值不是 `some_header_value`（这就相当于你的密码了，请任意发挥），那么还是白搭，Nginx 会返回 404 Not Found 给它（这种情况也适合于 GFW 的主动探测）。

在上面的配置中，我们的自定义头部（为叙述方便，以下将自定义头部称为 **认证头部**、**密码头部**）只有一个 value（可以理解为只有一个密码），实际上我们可以为密码头部设置多个密码（即多个 value），假设我们的密码头部仍然为 `Some-Header`，现在我们需要为 tls-proxy 设置两个访问密码，一个是 `some_header_value_a`、一个是 `some_header_value_b`，则将上面的 `location /tls-proxy` 配置块改为：

```nginx
location /tls-proxy {
    set $verified 0;
    if ($http_some_header = 'some_header_value_a') {
        set $verified 1;
    }
    if ($http_some_header = 'some_header_value_b') {
        set $verified 1;
    }
    if ($verified != 1) {
        return 404;
    }
    proxy_http_version 1.1;
    proxy_read_timeout 3650d;
    proxy_send_timeout 3650d;
    proxy_connect_timeout 3s;
    proxy_pass http://127.0.0.1:60080;
    proxy_set_header Connection "Upgrade";
    proxy_set_header Upgrade $http_upgrade;
}
```

依此类推，如果想要设置三个访问密码，再添加一个类似的 `if ($http_some_header = 'some_header_value_c')` 语句即可。

4、使用 `nginx -t` 检查配置文件是否有语法错误，然后 `systemctl reload nginx.service` 使其生效。

**配置 tls-server**

将 `tls-proxy` 目录下的 `tls-server.service` systemd 服务文件拷贝到 `/etc/systemd/system/` 目录下，然后执行 `systemctl daemon-reload` 使其生效。`tls-server` 默认只启用一个工作线程（`-j` 参数），而在 `tls-server.service` 服务文件中，默认设置的是 `-j2`，也就是两个工作线程，一般推荐使用 `1 ~ 4` 个工作线程，再多也没啥用，浪费资源。如果需要修改线程数，请编辑 `/etc/systemd/system/tls-server.service` 服务文件，将 `-j2` 改为 `-jN`（N 为你想设置的线程数），注意，修改 service 文件之后需要执行 `systemctl daemon-reload` 生效。最后，执行 `systemctl start tls-server.service` 来启动 tls-server。

**配置 tls-client**

将 `tls-proxy` 目录下的 `tls-client.service` systemd 服务文件拷贝到 `/etc/systemd/system/` 目录下，然后使用文本编辑器打开 `/etc/systemd/system/tls-client.service` 文件，主要需要修改 tls-client 的命令行参数，目前 tls-client 的命令行参数有：
```bash
$ tls-client -h
usage: tls-client <OPTIONS>. OPTIONS have these:
 -s <server_host>        server host. can't use IP address
 -p <server_port>        server port. the default port is 443
 -c <cafile_path>        CA file location. eg: /etc/ssl/cert.pem
 -P <request_uri>        websocket request line uri. eg: /tls-proxy
 -H <request_header>     websocket request headers. allow multi line
 -b <listen_address>     tcp & udp listen address. default: 127.0.0.1
 -t <tcp_proxy_port>     tcp port (iptables xt_tproxy). default: 60080
 -u <udp_proxy_port>     udp port (iptables xt_tproxy). default: 60080
 -j <thread_numbers>     number of worker thread (for tcp). default: 1
 -T                      disable tcp transparent proxy
 -U                      disable udp transparent proxy
 -v                      show version and exit
 -h                      show help and exit
```
其中必须要指定的参数有：`-s` 指定服务器的域名、`-c` 指定本机 CA 文件路径、`-P` 指定请求的 URI。因为我们在 Nginx 中配置了自定义头部 `Some-Header: some_header_value\r\n`，所以还需要指定一个 `-H` 参数，注意，此参数指定的 HTTP 头部必须以 `\r\n` 结尾，且必须放在 `$''` 里面（否则不会进行转义），即 `-H $'Some-Header: some_header_value\r\n'`，`-H` 参数中允许设置多个自定义头部（HTTP 协议使用 `\r\n` 作为行结束符）。如果头部设置不正确，则 `tls-client` 会因为收到 `404 Not Found` 响应而提示 `bad response`。tls-client 和 tls-server 一样，默认都是启用一个工作线程，所以如果你需要启用多个线程，请指定 `-j` 参数（不要奇怪 tls-client 的 UDP 监听线程为什么只有一个，因为我需要在内部保持 UDP 的状态，所以必须只能有一个 UDP 套接字，也就是说，tls-client 的 -j 参数只针对 TCP 代理套接字）。

关于 tls-client 的 `-c <cafile_path>` 参数：前面说了，tls-client 会对 SSL 证书进行校验，确认 SSL 证书是否可信，所以 tls-client 需要知道本机的 CA 文件路径（每个发行版的 CA file 文件路径都不太相同，ArchLinux 中是 `/etc/ssl/cert.pem`）。为什么不取消证书验证这个步骤？原因不用我说吧，一切都是为了安全啊。如果你不知道当前系统的 CA 文件路径，请在 Bash 中执行 `curl -v https://www.baidu.com |& awk '/CAfile:/ {print $3}'` 命令，输出的字符串即为本机的 CA 文件路径（别跟我说 curl command not found，要么装 curl，要么自己找 CA file 去）。

最后，执行 `systemctl daemon-reload` 重载服务文件，然后执行 `systemctl start tls-client.service` 启动 tls-client。

**配置 iptables 规则**

`tls-client` 默认监听地址：`127.0.0.1:60080/tcp`、`127.0.0.1:60080/udp`；TCP 和 UDP 的透明代理都必须使用 iptables-TPROXY 方式（注意不是 iptables-REDIRECT）；这里给个简单的 bash 脚本，示例如何使用 iptables-TPROXY 来透明代理本机以及内网的 TCP 和 UDP 流量（没错，tls-client 一般用在 Linux 网关上，提供全局透明代理，当然也可以在普通 Linux 主机上使用，代理本机的 TCP 和 UDP）。注意，此脚本只是作为一个例子，实际上我们还需要配置分流规则（如 gfwlist、chnroute），如果你需要分流的话，请使用 [ss-tproxy](https://github.com/zfl9/ss-tproxy) 代理脚本。

```bash
#!/bin/bash

server='www.example.com' # 服务器的域名
intranet_nic='lan0'      # 本机内网网卡
extranet_nic='wan0'      # 本机外网网卡

function start {
    systemctl start tls-client.service

    iptables -t mangle -N SETMARK
    iptables -t mangle -A SETMARK -d 0/8        -j RETURN
    iptables -t mangle -A SETMARK -d 10/8       -j RETURN
    iptables -t mangle -A SETMARK -d 127/8      -j RETURN
    iptables -t mangle -A SETMARK -d 169.254/16 -j RETURN
    iptables -t mangle -A SETMARK -d 172.16/12  -j RETURN
    iptables -t mangle -A SETMARK -d 192.168/16 -j RETURN
    iptables -t mangle -A SETMARK -d 224/4      -j RETURN
    iptables -t mangle -A SETMARK -d 240/4      -j RETURN
    iptables -t mangle -A SETMARK -d $server    -j RETURN
    iptables -t mangle -A SETMARK -j MARK --set-mark 0x2333

    iptables -t mangle -A OUTPUT -o $extranet_nic -p tcp -j SETMARK
    iptables -t mangle -A OUTPUT -o $extranet_nic -p udp -j SETMARK

    iptables -t mangle -A PREROUTING -i $intranet_nic -p tcp -j SETMARK
    iptables -t mangle -A PREROUTING -i $intranet_nic -p udp -j SETMARK

    iptables -t mangle -A PREROUTING -m mark --mark 0x2333 -p tcp -j TPROXY --on-ip 127.0.0.1 --on-port 60080
    iptables -t mangle -A PREROUTING -m mark --mark 0x2333 -p udp -j TPROXY --on-ip 127.0.0.1 --on-port 60080

    ip route add local 0/0 dev lo table 100
    ip rule add fwmark 0x2333 table 100
}

function stop {
    ip rule del table 100 &>/dev/null
    ip route flush table 100 &>/dev/null

    iptables -t mangle -F
    iptables -t mangle -X

    systemctl stop tls-client.service
}

case $1 in
    start) start;;
    stop)  stop;;
    *) echo "usage: $(basename $0) start|stop"; exit 1;;
esac
```

本机的 DNS 需要修改为 `8.8.8.8`、`8.8.4.4` 等国外 DNS 服务器（`/etc/resolv.conf`），然后 `curl ip.cn` 测试吧。

**查看 tls-proxy 的日志**
- `tls-client`：执行命令 `journalctl -afu tls-client.service`
- `tls-server`：执行命令 `journalctl -afu tls-server.service`
