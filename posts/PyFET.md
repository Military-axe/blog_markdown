+++
title = "PyFET: Forensically Equivalent Transformation for Python Binary Decompilation"
date = 2023-06-10T21:12:15+08:00

[taxonomies]
tags = ["decompile", "python"]
# categories = ["Reverse", "Paper"]
+++

2023 S&P论文，讲述的是python反编译的研究工作，总结了大量的反编译特征，针对恶意代码分析领域，提供一种新的解决方案。
从逆向和工程的角度来说，这项工作有很多值得学习的部分。

<!-- more -->

# 论文主旨

## 困难点

python代码编译成pyc或者可执行文件后，对于反编译会出现困难，尤其是刻意加了混淆指令的python程序。以往遇到反编译失败，只能通过人工分析的方法，成本非常高昂，因为python的反编译只有几个，没有其他折中的选择。

## 作者思路

从分析恶意脚本出发，以往的角度都是完全还原源代码，往精准的反编译上靠拢，本文提出

- 对于分析中很多不重要的部分，可以去除，或者替换指令，来降低反编译难度
- 反编译过程中遇到报错，通过FET模式匹配修复后继续反编译，使得能够自动反编译完成。

无论是分析python编译后结构中可替换部分结构，还是反编译报错解决都需要大量的特征收集，从工程上本文的关键是数据收集，从研究角度上本文最大的贡献是提出无需精确还原，采用替换部分结构，为恶意代码分析之类对代码恢复的精确性不是那么敏感的工作（其实就是背后有大量人工投入嘛~）添砖加瓦。

# 项目细节

**在逆向分析的时候并不一定追求精确还原代码（即保证反编译结果的语义正确性）**，所以我们完全可以**做一些妥协，把一些不好处理的地方简化掉或者修改掉**，使得decompiler能够工作下去。

## 去除部分关键字

在逆向时，如果没有这些关键字，我们还是理解语义

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306102048004.png" alt="image.png" style="zoom:50%;" /></center>

## 转换控制逻辑结构

去掉部分结构或者替换成一些简单的结构是可行的

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306102048198.png" alt="image.png" style="zoom:50%;" /></center>

## 添加空操作指令

python本身具有一个NOP操作指令，但是现有的反编译器无法识别和翻译这个指令。次项目实现了类似的空操作指令，是得反编译器能翻译和识别。
空操作指令的用处是

1. 替换一些不重要的指令
2. 对齐已经替换的指令

## PYFET结构

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306102048665.png" alt="image.png" style="zoom:80%;" /></center>

主要有两个组成部分，错误识别，迭代转换自动解决检测到的错误

### 定位错误

通过来自反编译器的错误信息来定位错误位置，如果没有错误信息但是又反编译失败了则不认为是显性错误，可以查看下面的隐性错误。报错信息的模式如下

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306102048325.png" alt="image.png" style="zoom: 80%;" /></center>

### 处理隐性错误

处理隐性错误的流程。
如果识别出一个与隐形错误匹配的代码片段，则对照隐性错误，得到两个值，一个是原本的可能为隐形错\\(S_{error}\\)一个是对照后可能的正确模式\\(S_{correct}\\).将这两个源码重新编译一遍（同一个编译器），得到\\(I_{error}, I_{correct}\\)。然后回到原二进制文件中对应的位置，看匹配\\(I_{error}, I_{correct}\\)中哪一个，从而发现隐性错误，继续反编译。

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306102048320.png" alt="image.png" style="zoom:50%;" /></center>

常见的隐形错误模式的修复前后对比，这里只显示6组。

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306102048664.png" alt="image.png" style="zoom:50%;" /></center>

### 迭代转换

- 首先获取cfg，并选择包含错误位置的目标块
- 对目标块中的指令进行转换
- 对转换后的结果，运行错误识别来检查转换后的是否解决最初的目标错误，如果没有成功会找当前块的邻近块来反复执行这个过程。
- 当没有目标块可以处理，也没有找到成功的转换的时候，就失败

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306102103958.png" alt="image.png" style="zoom:67%;" /></center>

上图的例子就是0块发生错误，但是无法通过转换来解决，这时候首先找到与0块直接相连的几个1块，通过尝试转换，1块任然不行再拓展到2块。已经解决过的块是不会再加入这个流程，直接解决问题或者没有其他块了。下面是基本块选择算法。

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306102103990.png" alt="image.png" style="zoom:67%;" /></center>

从工程角度看一下细节，其中对于指令的匹配和替换是使用正则表达式和定义了一些转换规则。
正则表达式是匹配指令链

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306102103030.png" alt="image.png" style="zoom:80%;" /></center>

上图表示匹配一个`POP_JUMP_IF_FALSE`,`POP_JUMP_IF_TRUE`指令链加一个跳转块，再RE-1这种情况下会直接第三列的结果，RE-2没有匹配成功就不改变，RE-3对应的情况和RE-1不同，考虑下面这种情况

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306102103826.png" alt="image.png" style="zoom:80%;" /></center>

这种if语句超过三个参数，不再只有两个块，所以使用RE-1是不行的，需要多个块都跳转。也就是通过正则匹配指令链和参数后，根据不同情况，每种指令链都有多个可能情况需要对应。

# 实验评估

## 反编译效果验证

收集了38351个不同的python恶意样本，选取了现有的5中反编译器Uncompyle6, Decompyle3, Uncompyle2, Unpyc37, and Decompyle++，确定17117个样本（45.6%）反编译失败

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306102104337.png" alt="image.png" style="zoom:80%;" /></center>

使用这17117个样本去验证本项目的有效性，PYFET成功解决了所有的反编译错误
下表显示了样本中隐性和显性错误的数量。

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306102104412.png" alt="image.png" style="zoom:80%;" /></center>

## 正确性验证

1. 选择了100个流行python程序的源码，和二进制文件，总计14949个python文件。然后对30个FET规则选择40个对应报错，总共1200个反编译错误的样本。
2. 对每个错误样本，将FET的结果手动应用在源码上，然后编译为样本，得到1200个源码转换后的样本。
3. 然后对1中1200二进制文件，直接用PYFET转化，得到1200个转化后的二进制文件

对比2中的二进制样本和3中的二进制样本，结果显示没有字节码上的差异，意味着pyfet所有的转换都是正确的。

> 采用这种验证方法是因为，直接FET反编译过来中间优化或者去除了部分逻辑，不能执行的，无法对比一个正确性，所以作者正对每一个转化规则，选取了40个不同的报错，每个报错根据FET规则，在源码上手动修改，再编译。和直接用PYFET修改后的二进制对比，说明PYFET直接转发二进制程序反编译后和源码上直接应用FET规则是一样的效果。
> 但是由于其中有人工的部分，这一部分实验数据存疑。

## 转换的影响

100%的反编译率+100%的正确性，给作者他也不敢开这个口，于是他加了一个实验。
将3中的结果反编译成源码，对比项目原本的源码，结果显示，在源码层面，pyfet影响平均不到3行源码。（这看起来稍微靠谱了一点

# 对抗PjOrion与opcode remap python技术

## opcode remap python

这是通过修改python源码，改变指令对应的opcode值，这样正常的反编译器是无法反编译成功的。文中以Dropbox的反编译为例子讲述如何使用PYFET反编译.
首先Dropbox是基于python3.8.12版本的python，所以作者先编译python 3.8.12标准库，和Dropbox的二进制文件对比，发现除了opcode，其他部分都是吻合的。
图b正常编译后其中字节码的样子，图a则是Dropbox反编译看到的字节码，可以看到是不正常的。
这里可以通过对比和统计找到所有对应的形式，如图e。

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306102104058.png" alt="image.png" style="zoom:80%;" /></center>

## PjOrion

这种混淆技术有四种方法

1. 添加无效结构
2. 添加异常块
3. 在参数字节中隐藏原始操作码
4. 添加随机跳转指令，重构整个文件

这种混淆其实主要就是隐藏真实的控制流，首先要提取控制流，用下面这条正则来提取控制流

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306102117207.png" alt="image.png" style="zoom:80%;" /></center>

得到的控制流程图大概如下

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306102104778.png" alt="image.png" style="zoom:80%;" /></center>

然后应用FET规则来还原整个程序

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306102117182.png" alt="image.png" style="zoom:80%;" /></center>

> 首先删除那些不可到达的跳转
> 然后用上图e的指令重新找到入口点
> 然后使用f指令删除跳转来达到去混淆的效果

完成整个流程后就对PjOrion实现了成功的去混淆。

# 思考

本文总结了很多python反编译的数据与经验，在针对恶意代码领域，不完全的或者不精准的转换部分代码达到成功反编译效果是可以接受的。本文实际上是利用大量的人工分析来总结各种特征与转化方法，在思路上并没有很多的突破，但是是非常大的一个工作量，同时在反编译python二进制文件这个领域中也是做出了很多贡献。从工程角度上这是一份可以很快应用于恶意代码分析领域的工作。

# 参考

[G.O.S.S.I.P 阅读推荐 2023-05-15 PyFET](https://mp.weixin.qq.com/s/ziy9mOFUV8_pyHWZ1-cJ2Q)

[pyfet-pyc/src (github.com)](https://github.com/pyfet-pyc/src/)

[2023 IEEE Symposium on Security and Privacy (SP)](https://www.computer.org/csdl/proceedings-article/sp/2023/933600a800/1Js0DmsXjQQ)