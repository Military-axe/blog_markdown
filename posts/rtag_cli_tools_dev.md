+++
title = "Rtag cli tools dev"
date = 2023-09-01T16:15:57+08:00

[taxonomies]
tags = ["tag", "mongodb", "rust"]
categories = ["Develop"]
+++

自己无聊，想开发开发。想着最近需要一个tag管理的系统，我用的是windows的，文件管理是层级管理，不是tag的，想着写一个也不难，就自己写了一下。开发语言用rust，数据库使用mongodb，手很生，写了好几天，累死✌了。

<!-- more -->

github地址: https://github.com/Military-axe/rtag

一个tag管理的系统，为了方便使用tag查找文件使用tag记录对应的值，找个值是文件路径/单纯的值.

使用mongodb数据库存储数据，rust编程

## 安装

编译项目

```
cargo build
```

在`target`目录下`debug`下可以找到`rtag_data.exe`

源码也可以在其他平台编译，没差的啦

## 数据库

### 集合tags

存在多个文档，一个文档代表一个tag，每个文档中的值如下

```json
{
  "_id": {
    "$oid": "64e714b28054de22d73432e0"
  },
  "tag": "test", // tag名称
  "value": [     // 包含此tag的值
    "text0",
    "text1"
  ]
}
```

### 集合values

以values为主的集合，一个values一个文档

```json
{
    "_id": {
    "$oid": "64e714b28054de22d73432e0"
  },
  "value": "test", // 值
  "tag": [         // tag
    "v1",
    "v2"
  ]
}
```


## 命令行参数

+ -v/--value: 目标value
+ -t/--tag: 目标tag

value + tag : 插入值到对应tag中
value: 所有包含字符串的值以及对应的tag
tag: 展示有一个tag或者多个tag的值

+ -i/--import: 导入json文件进入数据库中
+ -e/--export: 导出数据库内容进入json文件中

### 添加值和对应的tag

将`babyre`打上`rc4`,`base64`两个不同的tag。或者是更新这个值的tag。

```sh
rtag -t rc4 base64 -v babyre
```

![](https://raw.githubusercontent.com/Military-axe/imgtable/main/202309011626855.png)

### 查看tag下所有的值

查看有`rc4`,`base64`两个tag的值

```sh
rtag -t rc4 base64
```

![](https://raw.githubusercontent.com/Military-axe/imgtable/main/202309011627758.png)

### 模糊搜索值以及对应tag

搜索包含`re`两个字符的值以及对应的tag

```sh
rtag -v re
```

![](https://raw.githubusercontent.com/Military-axe/imgtable/main/202309011627679.png)

## 配置

配置数据库，后面考虑加入更多数据配置相关的，配置文件采用toml格式。

配置文件的路径通过`RTAG`环境变量来配置，值是路径，文件名是`rtag.toml`。

```sh
$RTAG="C:/Documents/config"
```

+ mongodb_url: mongodb_url地址
+ database_name: 数据库名，默认是rtag
+ tags_collect: tags的集合名，默认是tags
+ values_collect：values的集合名，默认是values

```toml
[database]

mongodb_url = "mongodb://localhost:27017"
database_name = "rtag"
tags_collect = "tags"
values_collect = "values"
```
