# Google Web Toolkit

> Google Web Toolkit（GWT），也称为GWT Web Toolkit，是一套开源工具集，允许Web开发人员使用Java创建和维护JavaScript前端应用程序。它最初由Google开发，并于2006年5月16日发布。

## 概述

- 工具
- 枚举
- 参考资料

## 工具

- [FSecureLABS/GWTMap](FSecureLABS/GWTMap)
- [GDSSecurity/GWT-Penetration-Testing-Toolset](GDSSecurity/GWT-Penetration-Testing-Toolset)

## 枚举

- 通过远程应用程序的引导文件枚举方法，并创建代码的本地备份（随机选择排列）：

  ```ps1
  ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --backup
  ```

- 通过特定的代码排列枚举远程应用程序的方法

  ```ps1
  ./gwtmap.py -u http://10.10.10.10/olympian/C39AB19B83398A76A21E0CD04EC9B14C.cache.js
  ```

- 在通过HTTP代理路由流量时枚举方法：

  ```ps1
  ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --backup -p http://127.0.0.1:8080
  ```

- 枚举本地副本（文件）的任何给定排列的方法：

  ```ps1
  ./gwtmap.py -F test_data/olympian/C39AB19B83398A76A21E0CD04EC9B14C.cache.js
  ```

- 过滤输出到特定服务或方法：

  ```ps1
  ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter AuthenticationService.login
  ```

- 为过滤服务的所有方法生成RPC有效负载，并带有彩色输出

  ```ps1
  ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter AuthenticationService --rpc --color
  ```

- 自动测试（探测）过滤服务方法的生成RPC请求

  ```ps1
  ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter AuthenticationService.login --rpc --probe
  ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter TestService.testDetails --rpc --probe
  ```

## 参考资料

- [从序列化到Shell :: 利用EL注入攻击Google Web Toolkit - 2017年5月22日](https://srcincite.io/blog/2017/05/22/from-serialized-to-shell-auditing-google-web-toolkit-with-el-injection.html)
- [黑客攻击Google Web Toolkit应用程序 - 2021年4月22日 - thehackerish](https://thehackerish.com/hacking-a-google-web-toolkit-application/)