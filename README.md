# TLS-Proxy
## 简单介绍
`tls-proxy` 可以看作为 V2Ray 的 `WebSocket + TLS + Web` 方案的 C 语言极简实现版，使用 `libevent2` 轻量级事件通知库编写。在硬件资源有限的环境中（如树莓派 3B，这也是我写 tls-proxy 的根本原因），tls-proxy 可以比 v2ray 占用更少的 CPU 以及内存资源，并且提供更快的响应速度和代理速度（但不降低安全性，我已尽量取其精华去其糟粕）。

## 相关依赖
**`tls-server`**：
 - [base64](https://github.com/aklomp/base64)
 - [libevent](https://github.com/libevent/libevent)

**`tls-client`**：
 - [base64](https://github.com/aklomp/base64)
 - [openssl](https://github.com/openssl/openssl)
 - [libevent](https://github.com/libevent/libevent)

## 如何编译
> 这里以 linux x86_64 为例，其他平台请酌情修改（貌似需要安装 `openssl-dev`、`openssl-devel`？）。

```bash
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
./Configure linux-x86_64 --prefix=/tmp/openssl --openssldir=/tmp/openssl no-ssl3 no-shared
make && make install

# libevent
cd /tmp
wget https://github.com/libevent/libevent/releases/download/release-2.1.8-stable/libevent-2.1.8-stable.tar.gz 
tar xvf libevent-2.1.8-stable.tar.gz
cd libevent-2.1.8-stable
./configure --prefix=/tmp/libevent --enable-static=yes --enable-shared=no CPPFLAGS='-I/tmp/openssl/include' LDFLAGS='-L/tmp/openssl/lib' LIBS='-ldl -lssl -lcrypto'
make && make install

# tls-proxy
cd /tmp
git clone https://github.com/zfl9/tls-proxy
cd tls-proxy
gcc -I/tmp/base64/include -I/tmp/libevent/include -std=c11 -Wall -Wextra -Os -s -lpthread -o tls-server tls-server.c /tmp/base64/lib/libbase64.o /tmp/libevent/lib/libevent.a
gcc -I/tmp/base64/include -I/tmp/libevent/include -I/tmp/openssl/include -std=c11 -Wall -Wextra -Os -s -ldl -lpthread -o tls-client tls-client.c /tmp/base64/lib/libbase64.o /tmp/libevent/lib/libevent.a /tmp/libevent/lib/libevent_openssl.a /tmp/openssl/lib/libssl.a /tmp/openssl/lib/libcrypto.a
cp -af tls-client tls-server /usr/local/bin

# delete files
cd /
rm -fr /tmp/base64
rm -fr /tmp/openssl*
rm -fr /tmp/libevent*
rm -fr /tmp/tls-proxy
```

### 已知问题
- 目前的 UDP 实现仅适用于 `request-response` 类型的协议，如 DNS，QUIC 暂时不支持。
- 程序使用了 `inet_ntoa()` 非线程安全函数，虽然这只会影响程序输出，但是还是有点不爽。
- 代码很简陋，毕竟我也是刚接触 C 语言不久；另外最近没啥时间，上述问题暂时没有时间修。
