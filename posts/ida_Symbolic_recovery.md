+++
title = "Ida Symbolic Recovery"
date = 2023-07-03T21:51:06+08:00

[taxonomies]
tags = ["sig","ida", "reverse"]
# categories = ["Reverse", "Cheatsheets"]
+++

最近发现二进制文件中符号恢复的手段有不少，这里想记录一下几种符号恢复的工具使用与效果对比。

Finger，lscan，flair，bindiff

<!-- more -->

# 编译工具与其他环境

主要是win下的MinGw，VC++，的C和C++和Linux下的GUN/LLVM。主要是针对库函数去符号的一个恢复。



# Finger

阿里出品，很好用，方便。

github 地址：[aliyunav/Finger: A tool for recognizing function symbol (github.com)](https://github.com/aliyunav/Finger)

实际上是要联网访问阿里的库来识别函数，所以遇到大程序，识别所有函数会慢一点。安装可以看github链接，使用也很简单，ida的导航栏会多一个Finger，两个选项，恢复所有函数或者恢复当前函数。

<img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202307031931288.png" alt="image-20230703193129579" style="zoom:50%;" />

绿色的部分是还原的函数名

<img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202307031923588.png" alt="image-20230703192350452" style="zoom:50%;" />

这个使用简单，效果好，但是要联网。只是不知道对arm，mips这些其他架构的识别如何。虽然识别可能会有假阳性，但是很低，从易用性来说，这个首选。

# lscan

github地址：[maroueneboubakri/lscan: lscan is a library identification tool on statically linked/stripped binaries (github.com)](https://github.com/maroueneboubakri/lscan)

lscan是一个python项目，使用FLIRT（快速库识别和识别技术）签名来进行库识别。也就是通过扫描sig文件，找到与二进制文件最相似的库

> FLIRT 最初是由辛普森 (Peter Silberman) 开发的，后来被 IDA Pro (一种逆向工程工具) 所采用。FLIRT 通过使用一种称为“特征”的字符串来识别库和函数。这些特征是函数中的指令序列，或者是库中使用的函数的调用序列。FLIRT 使用这些特征来生成一个签名数据库，然后可以使用这个数据库来识别二进制文件中使用的库和函数。

**使用**

`python ./lscan.py -S .sig的目录 -f 要扫描的二进制文件`，例子如下

```shell
python lscan.py -S i386/sig -f i386/bin/bin-libc-2.23
python lscan.py -s i386/sig/libpthread-2.23.sig -f i386/bin/bin-libpthread-2.23 -v
python lscan.py -f i386/win32/bin/bin-libcmt.exe -s i386/win32/sig/msvcmrt.sig
```

项目自带了一些sig文件，github上也有专门收集的sig文件[push0ebp/sig-database: IDA FLIRT Signature Database (github.com)](https://github.com/push0ebp/sig-database)

使用这个是来批量识别你目标程序中和那个sig文件最吻合，选择到对应的后，可以再ida中加载对饮的sig文件

<img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202307032030931.png" alt="image-20230703203058226" style="zoom:50%;" />

加载sig文件的功能直接在ida中。首先如果ida中没有这个对应的sig文件，需要将sig文件放到`<IDA_INSTALL_PATH>/sig/<arch>`。

<img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202307032111710.png" alt="image-20230703211141485" style="zoom:50%;" />

+ view-"Open subview"-Signatures(快捷键shift+F5)打开已应用的签名窗口
+ 右键Apply new signatures，选择一个添加

<img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202307032112628.png" alt="image-20230703211216386" style="zoom:50%;" />

但是这种方法要求你有sig文件，并且能确定是那个sig文件。对于c++的可以通过字符串来判断。如果是一些开源库这种不存在sig的情况，可以制作sig文件，并导入文件中。[IDA使用技巧--导入头文件和导入函数签名 | Hexo (tomqunchao.github.io)](https://tomqunchao.github.io/2020/10/10/note/rev/rev-1/#:~:text=导入函数签名 1 使用pelf制作pat 1 .%2Fpelf libgmp.a gmp.pat 如果出现,collisions. ... 3 如果一切顺利，则会生成sig文件 4 把sig文件复制到IDA_INSTALL_PATH%2Fsig%2Fpc目录下，打开IDA 5 Shift%2BF5，打开函数签名页面，右键，选择你刚刚添加的签名)

# bindiff

bindiff是针对idb文件，可以bindiff两个idb文件，对比两个idb的函数与相似程度。具体可以参考[2023-GUDOCTF-L!S!(bindiff的使用)_二木先生啊的博客-CSDN博客](https://blog.csdn.net/qq_54894802/article/details/130211890)

除了对比相进版本文件，也可以对比开源库在文件中的函数

![在这里插入图片描述](https://raw.githubusercontent.com/Military-axe/imgtable/main/202307032147866.png)

第一列是相似度，1是最高。

# 参考

[aliyunav/Finger: A tool for recognizing function symbol (github.com)](https://github.com/aliyunav/Finger)

[maroueneboubakri/lscan: lscan is a library identification tool on statically linked/stripped binaries (github.com)](https://github.com/maroueneboubakri/lscan)

[push0ebp/sig-database: IDA FLIRT Signature Database (github.com)](https://github.com/push0ebp/sig-database)

[IDA中应用SIG文件_ida sig_Yuri800的博客-CSDN博客](https://blog.csdn.net/lixiangminghate/article/details/81352205)

[IDA使用技巧--导入头文件和导入函数签名 | Hexo (tomqunchao.github.io)](https://tomqunchao.github.io/2020/10/10/note/rev/rev-1/#:~:text=导入函数签名 1 使用pelf制作pat 1 .%2Fpelf libgmp.a gmp.pat 如果出现,collisions. ... 3 如果一切顺利，则会生成sig文件 4 把sig文件复制到IDA_INSTALL_PATH%2Fsig%2Fpc目录下，打开IDA 5 Shift%2BF5，打开函数签名页面，右键，选择你刚刚添加的签名)

[2023-GUDOCTF-L!S!(bindiff的使用)_二木先生啊的博客-CSDN博客](https://blog.csdn.net/qq_54894802/article/details/130211890)