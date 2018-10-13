# TLS-Proxy
**本软件仅供内部学习交流，严禁用于任何商业用途，严禁违反国家相关法律法规，请于测试后 24 小时内删除，谢谢！**

## 简单介绍
`tls-proxy` 可以看作为 V2Ray 的 `WebSocket + TLS + Web` 方案的 C 语言极简实现版，使用 `libevent2` 轻量级事件通知库编写。在硬件资源有限的环境中（如树莓派 3B，这也是我写 tls-proxy 的根本原因），tls-proxy 可以比 v2ray 占用更少的 CPU 以及内存资源，并且提供更快的响应速度和代理速度（但不降低安全性，我已尽量取其精华去其糟粕）。

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
如果你会使用 v2ray 的 websocket + tls + web 模式，那么 tls-proxy 对你来说很容易上手，因为使用方法基本一致。// TODO
