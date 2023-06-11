---
title: "2023 ciscn ezbytes Write Up"
date: 2023-06-11T15:40:13+08:00
categories:
- Reverse
tags:
- reverse
- dwarf
---

这题使用了DWARF字节码，需要了解DWARF相关知识，实际上是c++异常处理中的相关知识。这题利用异常处理的栈回溯，执行了一段设计好的DWARF字节码，单纯的跟踪是跟踪不到的

这题怪我没有心去做这题，不然早就出了，最近想改变一下心态，既然不能摆脱，那就走到底。

<!--more-->

# c++异常处理

根据 c++ 的标准，异常抛出后如果在当前函数内没有被捕捉(catch)，它就要沿着函数的调用链继续往上抛，直到走完整个调用链，或者在某个函数中找到相应的 catch。
程序中的 catch 那部分代码有一个专门的名字叫作：Landing pad（不十分准确），从抛异常开始到执行 landing pad 里的代码这中间的整个过程叫作 stack unwind（栈展开），这个过程包含了两个阶段：

- 从抛异常的函数开始，对调用链上的函数逐个往前查找 landing pad。
- 如果没有找到 landing pad 则把程序 abort，如果找到则记下 landing pad 的位置，再重新回到抛异常的函数那里开始，一帧一帧地清理调用链上各个函数内部的局部变量，直到 landing pad 所在的函数为止。

简而言之，正常情况下，stack unwind 所要做的事情就是从抛出异常的函数开始，沿着调用链向上找 catch 所在的函数，然后从抛异常的地方开始，清理调用链上各栈帧内已经创建了的局部变量。

```c
void func1()
{
    cs a; // stack unwind时被析构。
    throw 3;
}

void func2()
{
    cs b;
    func1();
}

void func3()
{
    cs c;
    try 
    {
        func2();
    }
    catch (int)
    {
        //进入这里之前， func1, func2已经被unwind.
    }
}
```

这里可以看到unwind的调用过程是函数调用的逆过程，实际实现的过程由专门的 stack unwind 库来进行。

由于是异常处理，还涉及到恢复调用现场，很大一部分上下文是可以从堆栈上恢复回来的,如 ebp, esp, 返回地址等。编译器为了让 unwinder 可以从栈上获取这些信息，它在编译代码的时候，建立了很多表项用于记录每个可以抛异常的函数的相关信息，这些信息在重建上下文时将会指导程序怎么去搜索栈上的东西。
这个表项中记录了很多关键的东西，这个表就是`.eh_frame`

## .eh_frame

.eh_frame 的格式与 .debug_frame 是很相似的，属于 [DWARF](http://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-Core-generic/LSB-Core-generic/normativerefs.html#STD.DWARF3) 标准中的一部分。所有由 GCC 编译生成的需要支持异常处理的程序都包含了 DWARF 格式的数据与字节码，这些数据与字节码的主要作用有两个：

- 描述函数调用栈的结构（layout）
- 异常发生后，指导 unwinder 怎么进行 unwind。

DWARF 字节码功能很强大，它是图灵完备的，这意味着仅仅通过 DWARF 就可以做几乎任何事情(therotically)，这题也是利用DWARF来执行真实的逻辑。
本质上来说，eh_frame 像是一张表，它用于描述怎样根据程序中某一条指令来设置相应的寄存器，从而返回到当前函数的调用函数中去，它的作用可以用如下表格来形象地描述。

> 本来DWARF是用来恢复栈结构，做一些异常捕获过程中的辅助操作。这题直接将数据等藏在DWARF，然后直接用DWARF中的代码处理寄存器执行，这样调试是无法跟踪的。


查看程序的`.eh_frame`段数据

```c
readelf -Wwf <file name>
// 或者使用
readelf –debug-dump=frames <file name>
```

得到的结果大概如下

```c
The section .eh_frame contains:

00000000 0000001c 00000000 CIE
  Version:               1
  Augmentation:          "zPL"
  Code alignment factor: 1
  Data alignment factor: -8
  Return address column: 16
  Augmentation data:     00 d8 09 40 00 00 00 00 00 00

  DW_CFA_def_cfa: r7 ofs 8   ##以下为字节码
  DW_CFA_offset: r16 at cfa-8

00000020 0000002c 00000024 FDE cie=00000000 pc=00400ac8..00400bd8
  Augmentation data:     00 00 00 00 00 00 00 00
  #以下为字节码
  DW_CFA_advance_loc: 1 to 00400ac9
  DW_CFA_def_cfa_offset: 16
  DW_CFA_offset: r6 at cfa-16
  DW_CFA_advance_loc: 3 to 00400acc
  DW_CFA_def_cfa_reg: r6
  DW_CFA_nop
  DW_CFA_nop
  DW_CFA_nop
```

整个eh_frame结构一般是一个CIE块加多个FDE块，连续存放。一般来说，一个CIE代表一个文件，一个FDE代表一个函数。
下图是使用`readelf **-wF**`查看的文件信息，其实和上一条命令大差不差的。

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306111542999.webp" style="zoom:80%;" /></center>

# 解题过程

ida64打开后，定位start，然后进入main函数也就是sub_404d25

```c
__int64 __fastcall sub_404D25(__int64 a1, __int64 a2, __int64 a3, __int64 a4, int a5, int a6)
{
  __int64 v6; // rax
  __int64 result; // rax
  __int64 v8[2]; // [rsp+10h] [rbp-420h] BYREF
  char v9[1008]; // [rsp+20h] [rbp-410h] BYREF
  unsigned __int64 v10; // [rsp+418h] [rbp-18h]

  v10 = __readfsqword(0x28u);
  v8[0] = 0LL;
  v8[1] = 0LL;
  memset(v9, 0, sizeof(v9));
  scanf((unsigned int)"%100s", (unsigned int)v8, (unsigned int)v9, 0, a5, a6);
  v6 = sub_46F4F0(&unk_5D5520, v8);
  sub_46E060(v6, sub_46EE20);
  sub_404C21(v8);
  result = 0LL;
  if ( __readfsqword(0x28u) != v10 )
    sub_535290();
  return result;
}
```

分析之后发现关键逻辑应该是在sub_404C21中，直接进入sub_404C21

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306111542361.png" alt="image.png" style="zoom:50%;" /></center>

进入之后发现调试无法跟踪下去，怀疑使用DWARF来隐藏逻辑

```c
readelf -Wwf ezbyte_patch > output.txt
```

查看DWARF代码，通过搜索函数地址`sub_404BF5`的地址定位到

<center><img src="https://raw.githubusercontent.com/Military-axe/imgtable/main/202306111542673.png" alt="image.png" style="zoom:67%;" /></center>

全部展开，发现隐藏了一段逻辑

```c
00000040 0000000000000094 00000044 FDE cie=00000000 pc=0000000000404bf5..0000000000404c21
  DW_CFA_advance_loc: 5 to 0000000000404bfa
  DW_CFA_def_cfa_offset: 16
  DW_CFA_offset: r6 (rbp) at cfa-16
  DW_CFA_advance_loc: 3 to 0000000000404bfd
  DW_CFA_def_cfa_register: r6 (rbp)
  DW_CFA_val_expression: r12 (r12) (
    DW_OP_constu: 2616514329260088143; 
    DW_OP_constu: 1237891274917891239; 
    DW_OP_constu: 1892739; 
    DW_OP_breg12 (r12): 0; 
    DW_OP_plus; 
    DW_OP_xor; 
    DW_OP_xor; 
    DW_OP_constu: 8502251781212277489; 
    DW_OP_constu: 1209847170981118947; 
    DW_OP_constu: 8971237; 
    DW_OP_breg13 (r13): 0; 
    DW_OP_plus; 
    DW_OP_xor; 
    DW_OP_xor; 
    DW_OP_or; 
    DW_OP_constu: 2451795628338718684; 
    DW_OP_constu: 1098791727398412397; 
    DW_OP_constu: 1512312; 
    DW_OP_breg14 (r14): 0; 
    DW_OP_plus; 
    DW_OP_xor; 
    DW_OP_xor; 
    DW_OP_or; 
    DW_OP_constu: 8722213363631027234; 
    DW_OP_constu: 1890878197237214971; 
    DW_OP_constu: 9123704; 
    DW_OP_breg15 (r15): 0; 
    DW_OP_plus; 
    DW_OP_xor; 
    DW_OP_xor; 
    DW_OP_or
  )
  DW_CFA_nop
  DW_CFA_nop
  DW_CFA_nop
```

通过查询DWARF指令，理解这段逻辑。这段逻辑实际是
分析发现，读取r12~r15，做异或和加法，判断最终值是否为0。再加上sub_404C21中的部分flag字符写出解密脚本。

```python
r12=(2616514329260088143^1237891274917891239)-1892739
r13=(8502251781212277489^1209847170981118947)-8971237
r14=(2451795628338718684^1098791727398412397)-1512312
r15=(8722213363631027234^1890878197237214971)-9123704

print(b'flag{'+r12.to_bytes(8,'little')+r13.to_bytes(8,'little')+r14.to_bytes(8,'little')+r15.to_bytes(8,'little')+b'3861}')

```

得到flag是`flag{e609efb5-e70e-4e94-ac69-ac31d96c3861}`

# 参考

[c++ 异常处理（1）](https://www.cnblogs.com/catch/p/3604516.html)

[c++ 异常处理（2）](https://www.cnblogs.com/catch/p/3619379.html)

[DWARF Debugging Standard Wiki](https://wiki.dwarfstd.org/CFI_with_Abbrevs.md#:~:text=The%20virtual%20unwind%20information%20is%20encoded%20in%20two,are%20specialized%20Debugging%20Information%20Entries%20with%20tag%20DW_TAG_frame_info.)

[DWARF  指令列表](https://dwarfstd.org/doc/DWARF5.pdf)

[linux 栈回溯](https://zhuanlan.zhihu.com/p/302726082)