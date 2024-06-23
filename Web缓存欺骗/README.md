# Web缓存欺骗

> Web缓存欺骗（WCD）是一种安全漏洞，当Web服务器或缓存代理误解了客户端对Web资源的请求，并随后提供了不同的资源（通常更敏感或私密），在缓存后。

## 摘要

* [工具](#工具)
* [利用](#利用)
  * [方法论 - 缓存敏感数据](#方法论---缓存-敏感数据)
  * [方法论 - 缓存自定义JavaScript](#方法论---缓存自定义JavaScript)
* [CloudFlare缓存](#cloudflare-缓存)
* [实验室](#实验室)
* [参考资料](#参考资料)

## 工具

* [PortSwigger/param-miner](https://github.com/PortSwigger/param-miner)

  > 该扩展识别隐藏的、未链接的参数。它特别适用于发现Web缓存投毒漏洞。

## 利用

Web缓存欺骗示例：

想象一下，攻击者引诱已登录的受害者访问`http://www.example.com/home.php/non-existent.css`

1. 受害者的浏览器请求资源`http://www.example.com/home.php/non-existent.css`
2. 在缓存服务器中搜索请求的资源，但没有找到（资源不在缓存中）。
3. 请求随后转发到主服务器。
4. 主服务器返回`http://www.example.com/home.php`的内容，很可能带有HTTP缓存头，指示不要缓存此页面。
5. 响应通过缓存服务器。
6. 缓存服务器识别出文件有CSS扩展名。
7. 在缓存目录下，缓存服务器创建一个名为home.php的目录，并将冒充的“CSS”文件（non-existent.css）缓存在其中。
8. 当攻击者请求`http://www.example.com/home.php/non-existent.css`时，请求发送到缓存服务器，缓存服务器返回带有受害者敏感`home.php`数据的缓存文件。

### 方法论 - 缓存敏感数据

**示例1** - PayPal主页上的Web缓存欺骗

1. 正常浏览，访问主页：`https://www.example.com/myaccount/home/`
2. 打开恶意链接：`https://www.example.com/myaccount/home/malicious.css`
3. 页面显示为/home并且缓存保存页面
4. 使用之前的URL打开隐私标签：`https://www.example.com/myaccount/home/malicous.css`
5. 显示缓存内容

Omer Gil的攻击视频 - PayPal主页上的Web缓存欺骗攻击
[![演示](https://i.vimeocdn.com/video/674856618-f9bac811a4c7bcf635c4eff51f68a50e3d5532ca5cade3db784c6d178b94d09a-d)](https://vimeo.com/249130093)

**示例2** - OpenAI上的Web缓存欺骗

1. 攻击者制作`/api/auth/session`端点的专用.css路径。
2. 攻击者分发链接
3. 受害者访问合法链接。
4. 响应被缓存。
5. 攻击者收集JWT凭据。

### 方法论 - 缓存自定义JavaScript

1. 查找用于缓存投毒的无键输入

```js
值：User-Agent
值：Cookie
头：X-Forwarded-Host
头：X-Host
头：X-Forwarded-Server
头：X-Forwarded-Scheme（头部；也与X-Forwarded-Host组合使用）
头：X-Original-URL（Symfony）
头：X-Rewrite-URL（Symfony）
```

2. 缓存投毒攻击示例，针对`X-Forwarded-Host`无键输入（记住使用buster只缓存此网页而不是网站的主页）

```js
GET /test?buster=123 HTTP/1.1
Host: target.com
X-Forwarded-Host: test"><script>alert(1)</script>

HTTP/1.1 200 OK
Cache-Control: public, no-cache
[..]
<meta property="og:image" content="https://test"><script>alert(1)</script>">
```

## CloudFlare缓存

当`Cache-Control`头设置为`public`且`max-age`大于0时，CloudFlare会缓存资源。

- Cloudflare CDN默认不缓存HTML
- Cloudflare仅基于文件扩展名而非MIME类型进行缓存：[cloudflare/default-cache-behavior](https://developers.cloudflare.com/cache/about/default-cache-behavior/)

CloudFlare有一份默认扩展名列表，可以在其负载均衡器后面进行缓存。

|       |      |      |      |      |       |      |
| ----- | ---- | ---- | ---- | ---- | ----- | ---- |
| 7Z    | CSV  | GIF  | MIDI | PNG  | TIF   | ZIP  |
| AVI   | DOC  | GZ   | MKV  | PPT  | TIFF  | ZST  |
| AVIF  | DOCX | ICO  | MP3  | PPTX | TTF   | CSS  |
| APK   | DMG  | ISO  | MP4  | PS   | WEBM  | FLAC |
| BIN   | EJS  | JAR  | OGG  | RAR  | WEBP  | MID  |
| BMP   | EOT  | JPG  | OTF  | SVG  | WOFF  | PLS  |
| BZ2   | EPS  | JPEG | PDF  | SVGZ | WOFF2 | TAR  |
| CLASS | EXE  | JS   | PICT | SWF  | XLS   | XLSX |



## 实验室

* [PortSwigger实验室针对Web缓存欺骗](https://portswigger.net/web-security/all-labs#web-cache-poisoning)

## 参考资料

* [Web缓存欺骗攻击 - Omer Gil](http://omergil.blogspot.fr/2017/02/web-cache-deception-attack.html)
* [实用Web缓存投毒 - James Kettle @albinowax](https://portswigger.net/blog/practical-web-cache-poisoning)
* [Web缓存纠缠：通往投毒的新路径 - James Kettle @albinowax](https://portswigger.net/research/web-cache-entanglement)
* [Web缓存欺骗攻击导致用户信息泄露 - Kunal Pandey - 2月25日](https://medium.com/@kunal94/web-cache-deception-attack-leads-to-user-info-disclosure-805318f7bb29)
* [Web缓存投毒 - Web安全学院学习材料](https://portswigger.net/web-security/web-cache-poisoning)
  - [利用缓存设计缺陷](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws)
  - [利用缓存实现缺陷](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws)
* [OpenAI账户接管 - @naglinagli - 2023年3月24日](https://twitter.com/naglinagli/status/1639343866313601024)
* [Shockwave发现影响OpenAI的ChatGPT的Web缓存欺骗和账户接管漏洞 - Gal Nagli](https://www.shockwave.cloud/blog/shockwave-works-with-openai-to-fix-critical-chatgpt-vulnerability)