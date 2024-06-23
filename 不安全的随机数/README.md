# 不安全的随机性

## 摘要

* [GUID / UUID](#guid--uuid)
  * [GUID 版本](#guid-versions)
  * [工具](#tools)
* [Mongo ObjectId](#mongo-objectid)
  * [工具](#tools)
* [参考资料](#references)

## GUID / UUID

### GUID 版本

版本识别：`xxxxxxxx-xxxx-Mxxx-Nxxx-xxxxxxxxxxxx`
四位 M 和 1 到 3 位 N 字段编码了 UUID 本身的格式。

| 版本 | 备注                                      |
| ---- | ----------------------------------------- |
| 0    | 仅 `00000000-0000-0000-0000-000000000000` |
| 1    | 基于时间或时钟序列                        |
| 2    | 在 RFC 4122 中保留，但在许多实现中省略    |
| 3    | 基于 MD5 哈希                             |
| 4    | 随机生成                                  |
| 5    | 基于 SHA1 哈希                            |

### 工具

* [intruder-io/guidtool](https://github.com/intruder-io/guidtool) - 一个用于检查和攻击版本 1 GUID 的工具

  ```ps1
  $ guidtool -i 95f6e264-bb00-11ec-8833-00155d01ef00
  UUID 版本：1
  UUID 时间：2022-04-13 08:06:13.202186
  UUID 时间戳：138691299732021860
  UUID 节点：91754721024
  UUID MAC 地址：00:15:5d:01:ef:00
  UUID 时钟序列：2099
  
  $ guidtool 1b2d78d0-47cf-11ec-8d62-0ff591f2a37c -t '2021-11-17 18:03:17' -p 10000
  ```

## Mongo ObjectId

Mongo ObjectIds 以可预测的方式生成，12 字节 ObjectId 值包括：

* **时间戳**（4 字节）：表示 ObjectId 的创建时间，以自 Unix 纪元（1970 年 1 月 1 日）以来的秒数衡量。
* **机器标识符**（3 字节）：标识生成 ObjectId 的机器。通常从机器的主机名或 IP 地址派生，因此对于在同一台机器上创建的文档来说是可预测的。
* **进程 ID**（2 字节）：标识生成 ObjectId 的进程。通常是 MongoDB 服务器进程的进程 ID，因此对于由同一进程创建的文档来说是可预测的。
* **计数器**（3 字节）：为每个新生成的 ObjectId 递增的唯一计数值。在进程启动时初始化为一个随机值，但后续值是可预测的，因为它们是按顺序生成的。

### 工具

* [andresriancho/mongo-objectid-predict](https://github.com/andresriancho/mongo-objectid-predict) - 预测 Mongo ObjectIds

  ```ps1
  ./mongo-objectid-predict 5ae9b90a2c144b9def01ec37
  5ae9bac82c144b9def01ec39
  5ae9bacf2c144b9def01ec3a
  5ae9bada2c144b9def01ec3b
  ```

### 参考资料

* [In GUID We Trust - Daniel Thatcher - October 11, 2022](https://www.intruder.io/research/in-guid-we-trust)
* [通过 MongoDB ObjectIDs 预测进行 IDOR - Amey Anekar - August 25, 2020](https://techkranti.com/idor-through-mongodb-object-ids-prediction/)