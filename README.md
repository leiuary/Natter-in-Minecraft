# Natter-in-Minecraft

将 Minecraft 服务器通过 Natter 打洞开放至公网。

## Natter是什么

将 fullcone NAT (NAT 1) 后的端口，打洞暴露至互联网。

项目主页有详细说明[Natter](https://github.com/MikeWang000000/Natter?tab=readme-ov-file)

## 我可以使用吗

将光猫改成桥接模式并使用电脑拨号连接到互联网，运行 natter-check ，如果 TCP 与 UDP 都是 NAT 1 ，说明运营商没有限制，可以使用。

```
Checking TCP NAT...                  [   OK   ] ... NAT Type: 1
Checking UDP NAT...                  [   OK   ] ... NAT Type: 1
```

## 我要怎么使用

1. 光猫改桥接，路由器拨号上网。路由器开启 UPnP 或 DMZ 功能，再使用 natter-check 验证。某些路由器可能会限制 NAT 类型。
2. 将本仓库下载解压到服务器启动脚本同级文件夹，将`nat.sh`复制到Natter-in-Minecraft文件夹外并打开进行配置。
3. 使用 DDNS 工具（如DDNS-GO）设置 IP地址 解析。
4. 配置 SRV 解析脚本（默认使用 srv 文件夹下阿里云配置），使服务器获取正确的端口。
5. 运行`nat.sh`，它会同时启动服务端。
6. 测试是否成功。

## 细节

多个家庭宽带通常被分配给同一个公网 IPv4 地址（或共享运营商级 NAT 地址池），而家庭内多设备（手机、电脑等）使用私有 IP（如192.168.x.x）。NAT 将这些私有IP映射到公网IP的不同端口上，实现多设备共享单一公网 IP 。

```
tcp://192.168.1.2:25565 <--iptables--> tcp://192.168.1.2:43363 <--Natter--> tcp://203.0.113.10:2362
```

Natter 转发 Minecraft 端口到自己的端口，再打开了 NAT 映射公网 IP 上的端口。

----

用 DDNS 将网址解析到公网 IP （例如`ip.mc.example.com`设 A 解析，解析值为`203.0.113.10`），调用脚本设置 SRV 解析（例如 `_minecraft._tcp.mc.example.com`设 SRV 解析，解析值为`0 0 2363 ip.mc.example.com`）。

这样，当连接地址为`mc.example.com`的服务器时，Minecraft 会做的事情是：

1. **先查 SRV 记录**
    查询：

   ```
   _minecraft._tcp.mc.example.com
   ```

   类型：`SRV`

   - 如果查到 → 用 SRV 里的目标域名（Target）和端口来连接
   - 如果查不到 → 直接尝试 `mc.example.com:25565`

2. **查 SRV 里的目标域名的 IP**
    比如 SRV 结果是：

   ```
   0 0 2363 ip.mc.example.com
   ```

   那它会去查：

   ```
   ip.mc.example.com → A/AAAA 记录
   ```

   获取实际 IP 地址。

3. **连接服务器**
    按 SRV 返回的端口连接（本例是 2363）。

客户端先查询 `_minecraft._mc.example.com`是Minecraft 协议在 DNS 查询时写死的规则（所有 Java 版客户端都是这样做的），客户端只要收到一个域名，就会自动在前面加 `_minecraft._tcp.` 去查 SRV。

----

DMZ 和 UPnP 都是内网主机暴露到外网的方式，但原理和风险差别很大。

- DMZ：在路由器上，把一个内网设备（例如 192.168.0.2）的所有端口都映射到公网 IP，相当于这个设备直接“裸连”公网，防火墙不做端口限制，缺点是安全风险大，整个设备直接暴露在公网，所有服务都对外开放（SSH、RDP、数据库等都能被扫描）。

- UPnP：一种自动端口映射协议，允许内网的应用程序告诉路由器：“帮我把某个端口映射到外网”。应用只会映射自己需要的端口（例如 Minecraft 服务器映射 25565）。如果有两个内网设备都需要映射，UPnP 能满足这个要求。 

----

宽带运营商会隔一段时间改变你对应的公网 IP ，一般在 24-48 小时。可以通过网站查询自己在公网上的 IP ,也可以持续运行 Natter，观察 IP 改变的时间。SRV 记录改变影响较小，10秒钟左右就能得到正确的端口。A 记录改变影响较大，可能需要十几分钟才能完全刷新 DNS 缓存，解析到新的 IP 。

因此，我们可以把 IP 更新安排在影响较小的时间，例如设置路由器每天凌晨4时重启或重新拨号。

----

