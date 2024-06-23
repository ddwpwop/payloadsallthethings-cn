# DNS重绑定

> DNS重绑定将攻击者控制的机器名称的IP地址更改为目标应用程序的IP地址，绕过了同源策略，从而允许浏览器向目标应用程序发出任意请求并读取它们的响应。

## 摘要

- 工具
- 利用
- 保护绕过
- 参考资料

## 工具

- [起源奇点 - 是一个执行DNS重绑定攻击的工具。](https://github.com/nccgroup/singularity)
- [起源奇点Web客户端（管理器界面、端口扫描器和自动攻击）](http://rebind.it/singularity.html)

## 利用

首先，我们需要确保目标服务对DNS重绑定易受攻击。
可以通过一个简单的curl请求来完成：

```bash
curl --header 'Host: <任意主机名>' http://<易受攻击的服务>:8080
```

如果服务器返回预期的结果（例如常规网页），则该服务易受攻击。
如果服务器返回错误消息（例如404或类似），服务器很可能实施了防止DNS重绑定攻击的保护措施。

然后，如果服务易受攻击，我们可以通过以下步骤滥用DNS重绑定：

1. 注册一个域名。
2. 设置起源奇点。
3. 根据您的需求编辑自动攻击HTML页面。
4. 浏览到 "http://rebinder.your.domain:8080/autoattack.html"。
5. 等待攻击完成（可能需要几秒/分钟）。

## 保护绕过

> 大多数DNS保护以阻止包含不需要的IP地址的DNS响应在进入内部网络时实施在边界上。最常见的保护形式是阻止RFC 1918中定义的私有IP地址（即10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16）。一些工具还允许额外阻止本地主机（127.0.0.0/8）、本地（内部）网络或0.0.0.0/0网络范围。

在启用了DNS保护的情况下（通常默认为禁用），NCC集团记录了多种DNS保护绕过方法，可以采用。

### 0.0.0.0

我们可以使用IP地址0.0.0.0访问本地主机（127.0.0.1），以绕过阻止包含127.0.0.1或127.0.0.0/8的DNS响应的过滤器。

### CNAME

我们可以使用DNS CNAME记录来绕过阻止所有内部IP地址的DNS保护解决方案。
由于我们的响应只返回内部服务器的CNAME，
因此不会应用过滤内部IP地址的规则。
然后，本地内部DNS服务器将解析CNAME。

```bash
$ dig cname.example.com +noall +answer
; <<>> DiG 9.11.3-1ubuntu1.15-Ubuntu <<>> example.com +noall +answer
;; 全局选项: +cmd
cname.example.com.            381     IN      CNAME   target.local.
```

### localhost

我们可以使用"localhost"作为DNS CNAME记录，以绕过阻止包含127.0.0.1的DNS响应的过滤器。

```bash
$ dig www.example.com +noall +answer
; <<>> DiG 9.11.3-1ubuntu1.15-Ubuntu <<>> example.com +noall +answer
;; 全局选项: +cmd
localhost.example.com.            381     IN      CNAME   localhost.
```

## 参考资料

- DNS重绑定攻击是如何工作的？- nccgroup, 2019
