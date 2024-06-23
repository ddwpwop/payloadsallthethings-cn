# HTTP隐藏参数

> Web应用程序通常具有在用户界面中未公开的隐藏或未记录的参数。模糊测试可以帮助发现这些参数，这些参数可能容易受到各种攻击。

## 摘要

* [工具](#工具)
* [利用](#利用)
  * [暴力破解参数](#暴力破解参数)
  * [旧参数](#旧参数)
* [参考资料](#参考资料)


## 工具

* [PortSwigger/param-miner](https://github.com/PortSwigger/param-miner) - 用于识别隐藏的、未链接参数的Burp扩展。
* [s0md3v/Arjun](https://github.com/s0md3v/Arjun) - HTTP参数发现套件
* [Sh1Yo/x8](https://github.com/Sh1Yo/x8) - 隐藏参数发现套件
* [tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls) - 获取Wayback Machine所知的所有域名URL
* [devanshbatham/ParamSpider](https://github.com/devanshbatham/ParamSpider) - 从Web档案的黑暗角落挖掘URL以进行错误狩猎/模糊测试/进一步探测
* [gh0stkey/CaA](gh0stkey/CaA) - 收集HTTP协议报文中的参数、路径、文件、参数值等信息，并统计出现的频次


## 利用

### 暴力破解参数

* 使用常见参数的单词列表发送它们，寻找来自后端的意外行为。

  ```ps1
  x8 -u "https://example.com/" -w <wordlist>
  x8 -u "https://example.com/" -X POST -w <wordlist>
  ```

单词列表示例：

- [Arjun/large.txt](https://github.com/s0md3v/Arjun/blob/master/arjun/db/large.txt)
- [Arjun/medium.txt](https://github.com/s0md3v/Arjun/blob/master/arjun/db/medium.txt)
- [Arjun/small.txt](https://github.com/s0md3v/Arjun/blob/master/arjun/db/small.txt)
- [samlists/sam-cc-parameters-lowercase-all.txt](https://github.com/the-xentropy/samlists/blob/main/sam-cc-parameters-lowercase-all.txt)
- [samlists/sam-cc-parameters-mixedcase-all.txt](https://github.com/the-xentropy/samlists/blob/main/sam-cc-parameters-mixedcase-all.txt)

### CaA

插件装载: `Extender - Extensions - Add - Select File - Next`。

数据存储在SQLite数据库中，文件位于插件Jar包同级目录下的`/Data/CaA.db`。

#### Collector

CaA收集功能主要应用于HTTP请求和响应。收集的数据信息主要为参数、参数值、请求路径、请求文件。

| 类型     | 来源                                                         |
| -------- | ------------------------------------------------------------ |
| 参数     | 请求参数（常规、JSON）、响应主体（JSON、INPUT标签TYPE为HIDDEN属性的NAME值）、请求头（Cookie）。 |
| 参数值   | 同参数，不仅会收集参数名，也会收集参数值。                   |
| 请求路径 | 以`/`符号对请求路径进行分割，逐层收集路径信息。              |
| 请求文件 | 以`.`符号对请求路径进行处理，收集最终带有文件后缀名的请求文件。 |

CaA所收集到的数据可以在响应包的Tab标签页`CollectInfo`，便于查看当前请求及当前网站收集到的数据信息。

[![collectinfo.png](C:\Users\52915\Desktop\PayloadsAllTheThings-cn\payloads-all-the-things-tran\异常参数FUZZ\static\collectinfo.png)](https://github.com/gh0stkey/CaA/blob/master/images/panel/collectinfo.png)

同时你也可以在CaA独立界面中的`Databoard`进行数据的查询，可以查询所有数据以及单个Host的数据。

[![databoard](C:\Users\52915\Desktop\PayloadsAllTheThings-cn\payloads-all-the-things-tran\异常参数FUZZ\static\databoard.png)](https://github.com/gh0stkey/CaA/blob/master/images/panel/databoard.png)

#### Analyzer

CaA分析功能主要为Web Fuzzing形态，可以对参数、参数值、请求路径、请求文件分别进行模糊测试，支持自定义字典。

我们可以在`CollectInfo`或`Databoard`界面中选择数据，并右键单击`Send to Fuzzer`即可开始配置。

[![send_to_fuzzer](C:\Users\52915\Desktop\PayloadsAllTheThings-cn\payloads-all-the-things-tran\异常参数FUZZ\static\send_to_fuzzer.png)](https://github.com/gh0stkey/CaA/blob/master/images/panel/fuzzer/send_to_fuzzer.png)

如果你是基于`CollectInfo`到配置页面的，就不需要配置请求信息，如果不是则需要。接着你可以在添加、修改、删除、去重Payload，以及选择Fuzzer工作的模式：参数、路径、文件、参数值。当一切配置完成之后单击`Confirm`按钮，输入任务名称即可开始Fuzzing工作。

[![fuzzer_config](https://github.com/gh0stkey/CaA/raw/master/images/panel/fuzzer/fuzzer_config.png)](https://github.com/gh0stkey/CaA/blob/master/images/panel/fuzzer/fuzzer_config.png)

[![input_task_name](C:\Users\52915\Desktop\PayloadsAllTheThings-cn\payloads-all-the-things-tran\异常参数FUZZ\static\input_task_name.png)](https://github.com/gh0stkey/CaA/blob/master/images/panel/fuzzer/input_task_name.png)

当你想要查看Fuzzer任务信息，可以在CaA独立界面中的`Databoard`进行查询。输入你创建的任务名称，就会有对应的下拉选择框，选择对应的信息，回车即可查询。

[![taskboard](C:\Users\52915\Desktop\PayloadsAllTheThings-cn\payloads-all-the-things-tran\异常参数FUZZ\static\taskboard.png)](https://github.com/gh0stkey/CaA/blob/master/images/panel/taskboard.png)



### 旧参数

探索目标的所有URL以找到旧参数。

* 浏览[Wayback Machine](http://web.archive.org/)
* 仔细查看JS文件以发现未使用的参数


## 参考资料

* [黑客工具：Arjun – 参数发现工具 - 2021年5月17日 - Intigriti](https://blog.intigriti.com/2021/05/17/hacker-tools-arjun-the-parameter-discovery-tool/)
* [参数发现：快速入门指南 - 2022年4月20日 - YesWeHack](https://blog.yeswehack.com/yeswerhackers/parameter-discovery-quick-guide-to-start/)
* https://github.com/gh0stkey/CaA
