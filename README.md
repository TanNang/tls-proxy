# TLS-Proxy
## 简要介绍
`tls-proxy` 可以看作为 V2Ray 的 `WebSocket + TLS + Web` 方案的 C 语言极简实现版，使用 `libevent2` 轻量级事件通知库编写。在硬件资源有限的环境中（如树莓派 3B，这也是我写 tls-proxy 的根本目的），tls-proxy 可以在比 v2ray 占用更少的 CPU 以及内存资源的情况下，提供更快的响应速度和代理速度。

同时，tls-proxy 也是专门为 [ss-tproxy](https://github.com/zfl9/ss-tproxy) 编写的，因为我只写了 linux 平台的 client 以及 server。`tls-client` 只提供 3 个代理端口：`redir`（代理 TCP）、`tproxy`（代理 UDP）、`tunnel`（代理 DNS）。这么做的目的很简单：安全高效的全局透明代理。

## 相关依赖
**`tls-server`**：
 - [base64](https://github.com/aklomp/base64)
 - [libevent](https://github.com/libevent/libevent)

**`tls-client`**：
 - [base64](https://github.com/aklomp/base64)
 - [openssl](https://github.com/openssl/openssl)
 - [libevent](https://github.com/libevent/libevent)

## 如何编译
```bash
// TODO
```
