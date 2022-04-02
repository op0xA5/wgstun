# WireGuard 打洞原理

得益于 WireGuard 以下几个特性，可以实现跨过 NAT 连接
- 使用 UDP 协议
- 使用同一个端口连接不同的 peer

打洞过程需要一台有固定 IP 的服务器 S，服务器上运行 WireGurad 及 wgstun 服务端。
需要打洞连接的两个端点 A、B，配置上服务器 S 的节点公钥，及对端的节点公钥，确保 A、B 到 S 的通信正常。
打洞开始时，A 或 B 各自通过 S 获取对端的公网 IP 及 NAT 后的端口号，更新对端的端点地址，在下次握手时，可完成打洞连接。

# 本工具实现的功能

- 服务端：监听端口，接收客户端查询请求，通过 WireGuard 接口获得端点的 IP
- 客户端：连接服务器，查询所需端点 IP，通过 WireGuard 接口更新本机 WireGuard 中对应端点的 IP

# TODO
- daemonize
- 配置文件
- windows 托盘工具
