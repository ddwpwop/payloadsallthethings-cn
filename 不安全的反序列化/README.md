# 不安全反序列化

> 序列化是将某些对象转换为以后可以恢复的数据格式的过程。人们经常序列化对象以便将其保存到存储中，或作为通信的一部分发送。反序列化是该过程的逆向过程——从某种格式结构化的数据中重建它成为对象 - OWASP

请查看以下位于其他文件中的小节：

* [Java反序列化：ysoserial等](Java.md)
* [PHP（对象注入）：phpggc等](PHP.md)
* [Ruby：通用RCE小部件等](Ruby.md)
* [Python：pickle等](Python.md)
* [YAML：PyYAML等](YAML.md)
* [.NET：ysoserial.net等](DotNET.md)

| 对象类型       | 头部（十六进制） | 头部（Base64） |
| -------------- | ---------------- | -------------- |
| Java序列化     | AC ED            | rO             |
| .NET ViewState | FF 01            | /w             |
| Python Pickle  | 80 04 95         | gASV           |
| PHP序列化      | 4F 3A            | Tz             |

## POP Gadgets

> POP（面向属性编程）小部件是应用程序类实现的一段代码，可以在反序列化过程中调用。

POP小部件的特点：

* 可序列化
* 具有公共/可访问属性
* 实现特定的易受攻击的方法
* 可以访问其他“可调用的”类

## 实验室

* [Portswigger - 不安全反序列化](https://portswigger.net/web-security/all-labs#insecure-deserialization)
* [NickstaDB/DeserLab - Java反序列化利用实验室](https://github.com/NickstaDB/DeserLab)

## 参考资料

* [Github - frohoff/ysoserial](https://github.com/frohoff/ysoserial)
* [Github - pwntester/ysoserial.net](https://github.com/pwntester/ysoserial.net)