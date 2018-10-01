# TLS-Proxy
## 简要介绍
`tls-proxy` 可以看作为 V2Ray 的 `WebSocket + TLS + Web` 方案的 C 语言极简实现版，使用 `libevent2` 轻量事件通知库编写，与 V2Ray 相比，tls-proxy 可以在硬件资源有限的环境中（如树莓派 3B，没错，这也是我写 tls-proxy 的根本目的）占用更少的 CPU 和内存资源，并且提供更快的代理速度以及响应速度。

## 如何编译
```bash
## base64-library
make

## openssl-1.1.0i
./Configure linux-x86_64 --prefix=/root/temp/openssl --openssldir=/root/temp/openssl no-ssl2 no-ssl3 no-shared
make && make install

## libevent-2.1.8
./configure --prefix=/root/temp/libevent --enable-static=yes --enable-shared=no CPPFLAGS='-I/root/temp/openssl/include' LDFLAGS='-L/root/temp/openssl/lib' LIBS='-ldl -lssl -lcrypto'
make && make install

## tls-client
gcc -I../base64/include -I../libevent/include -I../openssl/include -Os -s -ldl -lpthread -o tls-client tls-client.c ../base64/lib/libbase64.o ../libevent/lib/libevent.a ../libevent/lib/libevent_openssl.a ../openssl/lib/libssl.a ../openssl/lib/libcrypto.a

## tls-server
gcc -I../base64/include -I../libevent/include -Os -s -lpthread -o tls-server tls-server.c ../base64/lib/libbase64.o ../libevent/lib/libevent.a
```
