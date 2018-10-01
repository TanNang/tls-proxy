# TLS-Proxy
## 简要介绍
`tls-proxy` 可以看作为 V2Ray 的 `WebSocket + TLS + Web` 方案的 C 语言极简实现版，使用 `libevent2` 事件通知库编写，在硬件资源有限的环境中（如树莓派 3B），可以比 v2ray 工作的更好，速度更快，内存占用更少。

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
