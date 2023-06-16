---
title: "KextFuzz Fuzzing macOS Kernel EXTensions on Apple Silicon via Exploiting Mitigations"
date: 2023-06-14T15:53:46+08:00
categories:
- Fuzz
- Paper
tags:
- macOS
- fuzz
math: true
---

来自清华vul337实验室与蚂蚁基础安全合作的一篇2023年USENIX Security的文章

讲述如何针对macOS内核部分的kext进行模糊测试，原本kext是闭源的部分，同时处于内核。这使得插桩难，容易崩溃，黑盒测试效果差。同时苹果本身一些特权代码被保护。文章针对这些问题提出三个机制来解决

通过替换arm的PA指令来插桩，做覆盖率统计；通过本地hook特权检查函数来绕过苹果的检查，进一步fuzz特权代码；设计一个污点分析模块，分析macOS内核接口格式，辅助fuzz

<!--more-->


# 背景与困难

macOS的内核中有很大一部分是KEXT(Kernel Extension)，可以直接当作Linux中的驱动。但是在mac中是闭源的。由于闭源，分析难度高，所以漏洞挖掘与测试不充分，这也使得kext成为主要的攻击面。
但是对kext fuzz有3方面的问题

1. 怎么采集代码覆盖率：Coverage 反馈是提升 fuzz 效率的基本手段。其采集方法通常有代码插桩（kcov）、硬件监听（Intel-PT）与虚拟层监听（AFL-qemu）几种方式。但是三种方法都不使用kext. 源码插桩无法适用闭源组件，binary rewriting的闭源插桩具有一定可行，但是内核中使用这种插桩很容易系统崩溃，不使用与内核；apple silicon不提供Intel-PT 相似的硬件监听功能；Apple Silicon macOS 系统虚拟化技术仍不成熟，虚拟化环境能够支持的 kext 十分有限。
2. 如何识别接口格式：能准确得到接口格式，对fuzz数据的生成有更好的帮助，但是闭源程序信息少，macOS驱动接口又复杂，大量不同种类与格式的输入。
3. 如何绕过权限检查：macOS 驱动广泛使用 Entitlement 检查限制能够调用驱动的用户态程序，而大部分 Entitlement 仅分配给苹果公司或部分特殊开发者（如大型公司），包括 Fuzzer 在内的普通第三方程序难以获取，这限制了 Fuzzer 能够触发的代码范围。然而，在实战中，攻击者仍然可以通过构造攻击链，利用受保护代码中的漏洞，使得受 Entitlement 保护的特权代码成为了一个缺少测试的独特攻击面。

# 统计代码覆盖率

kext在统计代码覆盖率上使用的还是binary rewriting实现代码覆盖率插桩。直接加入指令会造成原有指令便宜，很容易破坏原有程序（静态分析修复可以修复一部分，但是也难以全面），在内核环境下不适用。
kext中使用了ARM的一个PA（Pointer Authentication）机制，这个机制是插入一些指令来保证控制流完整，这些指令会提高漏洞利用的难度，但是对于fuzz来说这些指令是没有实际作用的，同时不对正常功能有影响。所以作者直接去除这些PA指令，用这些指令的位置来添加插桩的代码。
<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306141531075.png" style="zoom:80%;" /></center>
具体覆盖PA指令，并插桩的例子，替换掉PA指令，改成跳转到_COVPC的覆盖率收集函数。_COVPC函数收集当前调用基本块地址。
_COVPC指令记录lr寄存器信息，kextFuzz还会讲原始的lr寄存器记录在堆栈中，用于恢复。
<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306141533507.png" alt="image.png" style="zoom:80%;" /></center>

# 接口识别

kext用户态的调用很规范，所以可以通过静态污点分析来分析用户态调用kext接口片段代码，从而分析出接口参数格式。KextFuzz设计了一个多标签静态五点方法来分析kext用户空间包装器代码。
> macOS为内核服务提供了抽象层，其中的组件将复杂的kext调用封装成良好的服务，并以标准的方式与kext互动。但是这些包装器也是闭源的，所以还是得二进制文件静态污点分析来还原出来。

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306141531171.png" alt="image.png" style="zoom:80%;" /></center>

KextFuzz建立了调用kext接口(\\(I\\))的函数(\\(F\\))的控制流程图(CFG)。然后，KextFuzz提取了从\\(F\\)的函数入口开始到\\(I\\)结束的路径(\\(\lambda\\))作为分析目标，也就是上图
污点分析定义污点源

- kext接口的输出(\\(s1\\))：一些kext接口使用其他接口的输出作为输入，这些值要求很精确，很难通过突变产生，所以通过这个标签来识别
- 全局变量(\\(s2\\))
- 对象创建函数返回值(\\(s3\\)) ：有一些参数是一些特别的对象，这些对象很复杂，由特殊的API创建，所以识别这些函数，在函数的返回值上打上标记。
- 栈和堆的指针(\\(s4\\))：在堆栈寄存器（SP，arm64的x29）和内存分配函数的返回值上添加污点标签
- 调用者函数参数(\\(s5\\))：c++开发的二进制文件在导入外部函数时，函数名是经过命令粉碎（name mangling）机制的，此时外部函数的参数信息也会在命名上得到显示，如果\\(I\\)接口调用函数\\(F\\)的参数，那也可以用于识别，所以在\\(F\\)的参数上识别

# 权限过滤器

权限保护敏感功能不被普通用户调用，只有授权的公司和产品才能调用，这也增加了测试的难度，使得这些代码缺乏测试。KextFuzz自动像攻击者一样绕过这部分检查。
kexts调用检查函数来检查权限（这部分函数由 macOS XNU和AMFI kext实现）。需要被检查kexts（也就是外部驱动）需要调用外部的kexts检查函数。
KextFuzz通过二进制重写来hook检查器函数来劫持权限检查。

> 在57个有权限检查的kexts中，有8个与安全有关，9个与系统管理有关，使用权限过滤器成功绕郭权限检查，并使用kextFuzz发现了18个特权代码漏洞。

# KextFuzz 结构

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306141531104.png" alt="image.png" style="zoom:80%;" /></center>
KextFuzz实现了两个kexts（util-kext和control-kext），util导出覆盖率收集器函数和加的特权检查函数

## binary rewriting

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306141532025.png" alt="image.png" style="zoom:80%;" /></center>
将现有的一部分函数地址换成_COVPC函数（将_IOLOG这种与主要功能无关的函数替换，比如日志函数），然后再替换PA指令成bl offset, offset是调用地址到函数的偏移。
hook 权限检查函数也是类似的步骤，只需要第一步就好

## 模拟执行的污点

使用Triton作为污点分析引擎。由于只分析代码片段，所有有两个问题

- 如何初始化寄存器和内存
- 对于其他调用函数怎么分析？尤其是创建CoreFoundation对象的函数，这些函数提供了参数类型信息？

KextFuzz使用特殊的值来初始化程序状态。同时必须在分析开始前对函数参数和堆栈指针初始化，对应就是\\(s4,s5\\)
<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306141532605.png" alt="image.png" style="zoom:80%;" /></center>

### 初始化寄存器与内存

在初始化中使用的特殊值被编码，如图6所示。KextFuzz将寄存器和内存分为32位单元。在每个单元中，KextFuzz使用高位来记录污点来源和详细信息（例如，函数和参数索引）。
它还记录了嵌套级别以识别指针。嵌套级别指的是访问该值所需的解除引用次数。指针使用零级。它们所指向的内存块使用第一级，进一步说，第二级和第三级。
在执行之前，KextFuzz初始化了寄存器和内存，如图6所示。参数以及它们所指向的内存都是用\\(s5\\)标签初始化的。因此，污点标签不会在指针解除引用时丢失。
macOS中的封装二进制文件主要是用C++开发的，所以KextFuzz认为存储在X0中的F的第一个参数是一个THIS变量指针，它可以被看作是一个全局变量，需要使用标签\\(s2\\)。

### 分析创建CoreFoundation对象的函数

KextFuzz为这些函数创建了一个通用抽象函数\\(M\\)，共同模式是输入为值和大小，输出为指向一段内存的指针，在返回的指针和内存块上会被我们添加\\(s3\\)的标签

# 实验数据

实验数据来解答以下几个问题：

- 覆盖率采集器可以采集多少基本块？开销如何，能帮助KextFuzz找到更多bug吗?
- kexts生成的接口规范与SyzGen生成的接口规范相比如何？
- KextFuzz能在kexts中发现多少个bug？

## 实验一

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306141533339.png" alt="image.png" style="zoom:80%;" /></center>
为了评估有效性，计算了基本块被检测的比例，与黑盒模糊测试做对比。数据如上图，对34.71%插入指令，对39.42%的基本块可以起到覆盖作用。
从bug发现上来看，KextFuzz运行24小时，在插入指令，统计覆盖率的情况下发现6个不同的crash，在不统计覆盖率也就是近似黑盒的测试中，只发现一个crash。
效率上的对比，统计的是1小时的fuzz，记录了吞吐量（fuzz期间执行的测试案例），平均开销是2.3倍

## 实验二

分析接口识别模块的效果与作用，与SyzGen对比，SyzGen是目前最先进的macOS接口识别工具。
> SyzGen是intel芯片下的，kextFuzz是arm芯片下的。所以选取了一个有两种版本的mac系统macOS 11.5.2，然后去除两个不同服务的部分。只保留在两个系统中都存在的服务，接口等。

结果显示KextFuzz发现70个有效的服务和97个客户端。SyzGen发现了43个服务和43个客户端

## 实验三

对KextFuzz使用不同的配置来测试

- KF-K: 只用kext二进制文件中提取的接口信息来Fuzz。（接口信息包括服务名称，客户端类型，函数名，参数）
- KF-En-K: 二进制文件提取信息+权限过滤，与KF-K相比，可以多测试有权限检查器保护的特权代码
- KF-En-K&U：在KF-En-K上加上使用接口分析器
- KF-En-SyzGen: 使用SyzGen分析接口信息

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306141533747.png" alt="image.png" style="zoom:80%;" /></center>

# 参考

[G.O.S.S.I.P 阅读推荐 2023-04-26 KextFuzz](https://mp.weixin.qq.com/s?__biz=Mzg5ODUxMzg0Ng==&mid=2247495000&idx=1&sn=c52f5395e5fcec0196733e83e7d3c212&chksm=c063c381f7144a979d712e9467e82f8e2a22f87417f17af1960d13591f3f07dc2ddb65d0e444&scene=178&cur_album_id=2324026554710114306#rd)

[Triton 污点分析引擎 github](https://github.com/JonathanSalwan/Triton)

[usenix security](https://www.usenix.org/conference/usenixsecurity23/presentation/yin#:~:text=KextFuzz%20exploits%20these%20mitigation%20schemes%20to%20instrument%20the,48%20unique%20kernel%20bugs%20in%20the%20macOS%20kexts)
