# TLS-Proxy
**本软件仅供内部学习交流，严禁用于任何商业用途，严禁违反国家相关法律法规，请于测试后 24 小时内删除，谢谢！**

## 简单介绍
`tls-proxy` 可以看作为 V2Ray 的 `WebSocket + TLS + Web` 方案的 C 语言极简实现版，使用 `libevent2` 轻量级事件通知库编写。在硬件资源有限的环境中（如树莓派 3B，这也是我写 tls-proxy 的根本原因），tls-proxy 可以比 v2ray 占用更少的 CPU 以及内存资源，并且提供更快的响应速度和代理速度（但不降低安全性，我已尽量取其精华去其糟粕）。

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
> 以 linux x86_64 为例，其他平台请酌情修改

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
./Configure linux-x86_64 --prefix=/tmp/openssl --openssldir=/tmp/openssl no-ssl3 no-shared # for linux x86_64
make && make install

# libevent
cd /tmp
wget https://github.com/libevent/libevent/releases/download/release-2.1.8-stable/libevent-2.1.8-stable.tar.gz 
tar xvf libevent-2.1.8-stable.tar.gz
cd libevent-2.1.8-stable
./configure --prefix=/tmp/libevent --enable-static=yes --enable-shared=no CPPFLAGS='-I/tmp/openssl/include' LDFLAGS='-L/tmp/openssl/lib' LIBS='-ldl -lssl -lcrypto'
make && make install # 检查是否存在 /tmp/libevent/lib/libevent_openssl.a，如果没有，请先安装 openssl 依赖库 (openssl-devel)

# tls-proxy
cd /tmp
git clone https://github.com/zfl9/tls-proxy
cd tls-proxy
gcc -I/tmp/uthash/include -I/tmp/base64/include -I/tmp/libevent/include -std=c11 -Wall -Wextra -Wno-format-overflow -O3 -s -lpthread -o tls-server tls-server.c /tmp/base64/lib/libbase64.o /tmp/libevent/lib/libevent.a
gcc -I/tmp/uthash/include -I/tmp/base64/include -I/tmp/libevent/include -I/tmp/openssl/include -std=c11 -Wall -Wextra -Wno-format-overflow -O3 -s -ldl -lpthread -o tls-client tls-client.c /tmp/base64/lib/libbase64.o /tmp/libevent/lib/libevent.a /tmp/libevent/lib/libevent_openssl.a /tmp/openssl/lib/libssl.a /tmp/openssl/lib/libcrypto.a
cp -af tls-client tls-server /usr/local/bin

# delete files
cd /
rm -fr /tmp/uthash
rm -fr /tmp/base64
rm -fr /tmp/openssl*
rm -fr /tmp/libevent*
rm -fr /tmp/tls-proxy
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
        proxy_read_timeout 30d;
        proxy_http_version 1.1;
        proxy_pass http://127.0.0.1:60080;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Upgrade $http_upgrade;
    }
}
```
`/tls-proxy` 可以改为你喜欢的任意 URI；`tls-server` 默认监听地址为 `127.0.0.1:60080/tcp`；说明一下 `$http_some_header` 语句的作用：即使别人知道你的 URI，如果它没有设置正确的 HTTP 头部（在这里就是 `Some-Header` 咯，去掉开头的 `http_`，下划线换成连字符，大小写不敏感），并且对应的头部的值不是 `some_header_value`（这就相当于你的密码了，请任意发挥），那么还是白搭，Nginx 会返回 404 Not Found 给它（这种情况也适合于 GFW 的主动探测）。

4、使用 `nginx -t` 检查配置文件是否有语法错误，然后 `systemctl reload nginx.service` 使其生效。

**配置 tls-server**

将 `tls-proxy` 目录下的 `tls-server.service` systemd 服务文件拷贝到 `/etc/systemd/system/` 目录下，然后执行 `systemctl daemon-reload` 使其生效。`tls-server` 默认只启用一个工作线程（`-j` 参数），而在 `tls-server.service` 服务文件中，默认设置的是 `-j2`，也就是两个工作线程，一般推荐使用 `1 ~ 4` 个工作线程，再多也没啥用，浪费资源。如果需要修改线程数，请编辑 `/etc/systemd/system/tls-server.service` 文件，将 `-j2` 改为 `-jN`（N 为你想设置的线程数），注意，修改 service 文件之后需要执行 `systemctl daemon-reload` 生效。最后，执行 `systemctl start tls-server.service` 来启动 tls-server。

// TODO
