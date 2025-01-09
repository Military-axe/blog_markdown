---
title: "Frida learn && sctf 2023 checkFlow"
date: 2023-07-03T16:06:30+08:00
toc: true
categories:
- Reverse
tags:
- sctf
- frida
- reverse
---

没有打sctf，但是赛后看NU1L wp时，看到checkFlow这题，师傅用frida调用本身函数来爆破。虽然这种爆破要求本身函数状态不受运行的影响，但还是很好的做法。这种做法一直都有，只是我一直没去了解，这次看到这个，就学习一下

<!--more-->

# frida hook 函数

平时看frida hook函数都是在android中，这里主要还是在elf和pe上。

下面的脚本是frida attach到进程上，并捕获对应函数，函数给地址就可以，当函数指针一样。然后将值打印出来。

```python
import frida
import sys

session = frida.attach("hello")
script = session.create_script("""
Interceptor.attach(ptr("%s"), {
    onEnter(args) {
        send(args[0].toInt32());
    }
});
""" % int(sys.argv[1], 16))
def on_message(message, data):
    print(message)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

命令行传入需要hook的函数的地址。可以gdb attach进去看再detch出来。或者关掉pie自己算一下偏移。

捕获函数指针并调用可以这么写

```python
import frida
import sys

session = frida.attach("hello")
script = session.create_script("""
const f = new NativeFunction(ptr("%s"), 'void', ['int']);
f(1911);
f(1911);
f(1911);
""" % int(sys.argv[1], 16))
script.load()
```

用`new NativeFunction(ptr("%s"), 'void', ['int'])`来捕获，第一个参数是函数指针，第二个是返回值，第三个是函数的参数类型列表。

有意思的是，如果在逆向或者分析时不知道确定类型，只知道是指针，那我们可以直接说是指针类型（只要确定是要被引用的就可以用指针类型）。

```
new NativeFunction(ptr("%s"), 'void', ['pointer'])
```

比如字符串类型的参数，直接传指针就可以。

```python
import frida
import sys

session = frida.attach("hi")
script = session.create_script("""
const st = Memory.allocUtf8String("TESTMEPLZ!");
const f = new NativeFunction(ptr("%s"), 'int', ['pointer']);
    // In NativeFunction param 2 is the return value type,
    // and param 3 is an array of input types
f(st);
""" % int(sys.argv[1], 16))
def on_message(message, data):
    print(message)
script.on('message', on_message)
script.load()
```

对于调用PE中的一些api也可以这样，不同的是api一般我们需要“找到”，然后才能调用，（只出js代码）。

这时候需要用到`Module`模块，同时对于我们自己生成的一些数据可能要用Memory模块

> Module模块主要是对一些库操作，比如查找库机制，查找库中函数地址等。对frida api的具体学习可以查看官方文档或参考FRIDA-API使用篇

```js
var pMessageBoxW = Module.findExportByName("user32.dll", 'MessageBoxA')
var lpText = Memory.allocAnsiString("I'm New MessageBox");
var funMsgBox = new NativeFunction(pMessageBoxW, 'uint32',['uint32','pointer','pointer','uint32']);

// 调用
funMsgBox(0,ptr(lpText),ptr(lpText),0);
```



# checkFlow

这题分析两个write up的做法，一个是NU1L的，一个是官方WP，因为NU1L使用的做法就是frida注入来爆破。官方wp说这是一个算法，也能学到一些东西。先按照NU1L的来分析。

题目地址：[ctf/2023/checkflow at master · Military-axe/ctf · GitHub](https://github.com/Military-axe/ctf/tree/master/2023/checkflow)

## frida from NU1L WP

打开程序分析后，发现是c++静态编译+去符号的程序。我个人直接使用Finger恢复符号。官方WP说可以用bindiff或者flair来恢复符号，这个flair可以研究一下。因为Finger恢复符号是存在一定的假阳性的，而且我直接恢复程序所有的函数，还用了挺长时间（十几分钟？）

```c++
__int64 sub_4062C5()
{
  __int64 v0; // rax
  int v1; // eax
  bool v2; // bl
  __int64 v3; // rax
  unsigned int v4; // eax
  bool v5; // bl
  __int64 v6; // rbx
  __int64 v7; // rax
  unsigned int v8; // eax
  bool v9; // bl
  __int64 v10; // rax
  __int64 v11; // rax
  unsigned __int64 v12; // rbx
  __int64 v13; // rax
  char v15; // [rsp+Eh] [rbp-162h] BYREF
  char v16; // [rsp+Fh] [rbp-161h] BYREF
  int i; // [rsp+10h] [rbp-160h]
  int v18; // [rsp+14h] [rbp-15Ch]
  unsigned int j; // [rsp+18h] [rbp-158h]
  unsigned int v20; // [rsp+1Ch] [rbp-154h]
  char *v21; // [rsp+20h] [rbp-150h]
  char *v22; // [rsp+28h] [rbp-148h]
  char *v23; // [rsp+30h] [rbp-140h]
  char *v24; // [rsp+38h] [rbp-138h]
  char *v25; // [rsp+40h] [rbp-130h]
  char *v26; // [rsp+48h] [rbp-128h]
  char v27[32]; // [rsp+50h] [rbp-120h] BYREF
  char v28[32]; // [rsp+70h] [rbp-100h] BYREF
  char v29[32]; // [rsp+90h] [rbp-E0h] BYREF
  char v30[32]; // [rsp+B0h] [rbp-C0h] BYREF
  char v31[32]; // [rsp+D0h] [rbp-A0h] BYREF
  char v32[32]; // [rsp+F0h] [rbp-80h] BYREF
  char v33[32]; // [rsp+110h] [rbp-60h] BYREF
  char v34[40]; // [rsp+130h] [rbp-40h] BYREF
  unsigned __int64 v35; // [rsp+158h] [rbp-18h]

  v35 = __readfsqword(0x28u);
  sub_406AE5();
  std::__cxx11::basic_string_char_std::char_traits_char__std::allocator_char__::basic_string_std::allocator_char__const__(v30);
  sub_481E90(&unk_5E32E0, "Input the flow:\n");
  sub_40E100(&unk_5E3400, v30);
  v22 = v28;
  v21 = &v16;
  std::vector_int__2__2__std::allocator_int__2__2___::vector_ulong_std::allocator_int__2__2___const__(v29, 12LL, &v16);
  std::vector_std::vector_Solution::SiteSnap_std::allocator_Solution::SiteSnap___std::allocator_std::vector_Solution::SiteSnap_std::allocator_Solution::SiteSnap____::vector_ulong_std::vector_Solution::SiteSnap_std::allocator_Solution::SiteSnap___const__std::allocator_std::vector_Solution::SiteSnap_std::allocator_Solution::SiteSnap____const__(
    v27,
    1LL,
    v29,
    v28);
  sub_407658(v29);
  _gnu_cxx::new_allocator_std::__cxx11::basic_string_char_std::char_traits_char__std::allocator_char___::_new_allocator___0(&v16);
  _gnu_cxx::new_allocator_std::__cxx11::basic_string_char_std::char_traits_char__std::allocator_char___::_new_allocator___1(v28);
  v24 = &v16;
  v23 = &v15;
  std::vector_int__2__2__std::allocator_int__2__2___::vector_ulong_std::allocator_int__2__2___const__(v29, 6LL, &v15);
  std::vector_std::vector_Solution::SiteSnap_std::allocator_Solution::SiteSnap___std::allocator_std::vector_Solution::SiteSnap_std::allocator_Solution::SiteSnap____::vector_ulong_std::vector_Solution::SiteSnap_std::allocator_Solution::SiteSnap___const__std::allocator_std::vector_Solution::SiteSnap_std::allocator_Solution::SiteSnap____const__(
    v28,
    1LL,
    v29,
    &v16);
  sub_407658(v29);
  _gnu_cxx::new_allocator_std::__cxx11::basic_string_char_std::char_traits_char__std::allocator_char___::_new_allocator___0(&v15);
  _gnu_cxx::new_allocator_std::__cxx11::basic_string_char_std::char_traits_char__std::allocator_char___::_new_allocator___1(&v16);
  v25 = v29;
  sub_407782(v31, "000000000000", v29);
  _gnu_cxx::new_allocator_std::__cxx11::basic_string_char_std::char_traits_char__std::allocator_char___::_new_allocator__(v29);
  std::__cxx11::basic_string_char_std::char_traits_char__std::allocator_char__::basic_string_std::allocator_char__const__(v32);
  std::__cxx11::basic_string_char_std::char_traits_char__std::allocator_char__::basic_string_std::allocator_char__const__(v33);
  for ( i = 0; ; i += 12 )
  {
    v12 = i;
    if ( v12 >= sub_493F60(v30) )
      break;
    std::__cxx11::basic_string_char_std::char_traits_char__std::allocator_char__::substr_ulong_ulong_(v34, v30, i, 12LL);
    sub_493D80(v33, v34);
    llvm::SmallVector_uint_4u_::_SmallVector___3(v34);
    if ( sub_493F60(v33) != 12 )
    {
      v0 = sub_481E90(&unk_5E32E0, "Length error.");
      sub_480730(v0, std::endl_char_std::char_traits_char___std::basic_ostream_char_std::char_traits_char_____);
      exit(1LL);
    }
    if ( !(unsigned __int8)sub_407028(v33, v27, v28) )
    {
      v11 = sub_481E90(&unk_5E32E0, "Emmmmmm......Wrong.");
      sub_480730(v11, std::endl_char_std::char_traits_char___std::basic_ostream_char_std::char_traits_char_____);
      exit(1LL);
    }
    if ( i )
    {
      sub_496AA0(v34, v31);
      v18 = sub_407141(v34);
      llvm::SmallVector_uint_4u_::_SmallVector___3(v34);
    }
    else
    {
      v18 = -1;
    }
    sub_496AA0(v34, v33);
    v1 = sub_407141(v34);
    v2 = v18 < v1;
    llvm::SmallVector_uint_4u_::_SmallVector___3(v34);
    if ( !v2 )
    {
      v10 = sub_481E90(&unk_5E32E0, "Emmmmmm......Wrong.");
      sub_480730(v10, std::endl_char_std::char_traits_char___std::basic_ostream_char_std::char_traits_char_____);
      exit(1LL);
    }
    for ( j = v18 + 1; ; ++j )
    {
      sub_496AA0(v34, v33);
      v4 = sub_407141(v34);
      v5 = j < v4;
      llvm::SmallVector_uint_4u_::_SmallVector___3(v34);
      if ( !v5 )
        break;
      sub_4070E1(v34, j);
      sub_493D80(v32, v34);
      llvm::SmallVector_uint_4u_::_SmallVector___3(v34);
      if ( (unsigned __int8)sub_407028(v32, v27, v28) )
      {
        v3 = sub_481E90(&unk_5E32E0, "Emmmmmm......Wrong.");
        sub_480730(v3, std::endl_char_std::char_traits_char___std::basic_ostream_char_std::char_traits_char_____);
        exit(1LL);
      }
    }
    v6 = (unsigned int)(i + 12);
    if ( v6 == sub_493F60(v30) )
    {
      sub_496AA0(v34, v33);
      v20 = sub_407141(v34) + 1;
      llvm::SmallVector_uint_4u_::_SmallVector___3(v34);
      while ( 1 )
      {
        v26 = v29;
        sub_407782(v34, "111111111111", v29);
        v8 = sub_407141(v34);
        v9 = v8 >= v20;
        llvm::SmallVector_uint_4u_::_SmallVector___3(v34);
        _gnu_cxx::new_allocator_std::__cxx11::basic_string_char_std::char_traits_char__std::allocator_char___::_new_allocator__(v29);
        if ( !v9 )
          break;
        sub_4070E1(v34, v20);
        sub_493D80(v32, v34);
        llvm::SmallVector_uint_4u_::_SmallVector___3(v34);
        if ( (unsigned __int8)sub_407028(v32, v27, v28) )
        {
          v7 = sub_481E90(&unk_5E32E0, "Emmmmmm......Wrong.");
          sub_480730(v7, std::endl_char_std::char_traits_char___std::basic_ostream_char_std::char_traits_char_____);
          exit(1LL);
        }
        ++v20;
      }
    }
    ngx_http_lua_ffi_parse_http_time(v31, v33);
  }
  v13 = sub_481E90(&unk_5E32E0, "Get the flag to MD5, and package with sctf{}");
  sub_480730(v13, std::endl_char_std::char_traits_char___std::basic_ostream_char_std::char_traits_char_____);
  llvm::SmallVector_uint_4u_::_SmallVector___3(v33);
  llvm::SmallVector_uint_4u_::_SmallVector___3(v32);
  llvm::SmallVector_uint_4u_::_SmallVector___3(v31);
  sub_40772C(v28);
  sub_40772C(v27);
  llvm::SmallVector_uint_4u_::_SmallVector___3(v30);
  return 0LL;
}
```

可以看到`sub_407028`这个函数是一个关键的检查函数，通过调试发现，输入并不会改变docheck函数中的状态值，也就说我们可以不停构造输入去爆破，直到能过check。

上述程序两次调用`sub_407028`，实际上分段检查flag，每一段是12个字符。并且经过调试，字符只能是0或者1，那么12个bit就是小于4096是可以爆破的。

如果使用frida来爆破，那首先需要这个循环不停执行，所以需要patch出一个死循环，在`sub_407028`的位置。并且要保证vector这些初始化已经结束，因为3个参数，第一个是输入，其他两个是两个vector。所以尝试直接在函数调用时patch成死循环，再通过gdb attach的方法，attach进去查看参数地址，在frida脚本中可以直接以指针形式指向这两个参数地址。

patch前

```asm
.text:0000000000406531                               loc_406531:                             ; CODE XREF: sub_4062C5+235↑j
.text:0000000000406531 48 8D 95 00 FF FF FF          lea     rdx, [rbp+var_100]
.text:0000000000406538 48 8D 8D E0 FE FF FF          lea     rcx, [rbp+var_120]
.text:000000000040653F 48 8D 45 A0                   lea     rax, [rbp+var_60]
.text:0000000000406543 48 89 CE                      mov     rsi, rcx
.text:0000000000406546 48 89 C7                      mov     rdi, rax
.text:0000000000406549 E8 DA 0A 00 00                call    sub_407028
.text:0000000000406549
.text:000000000040654E 84 C0                         test    al, al
.text:0000000000406550 0F 84 09 03 00 00             jz      loc_40685F
```

patch后

```asm
.text:0000000000406531                               loc_406531:                             ; CODE XREF: sub_4062C5+235↑j
.text:0000000000406531                                                                       ; sub_4062C5+289↓j
.text:0000000000406531 48 8D 95 00 FF FF FF          lea     rdx, [rbp+var_100]
.text:0000000000406538 48 8D 8D E0 FE FF FF          lea     rcx, [rbp+var_120]
.text:000000000040653F 48 8D 45 A0                   lea     rax, [rbp+var_60]
.text:0000000000406543 48 89 CE                      mov     rsi, rcx
.text:0000000000406546 48 89 C7                      mov     rdi, rax
.text:0000000000406549 E8 DA 0A 00 00                call    sub_407028
.text:0000000000406549
.text:000000000040654E EB E1                         jmp     short loc_406531                ; Keypatch modified this from:
.text:000000000040654E                                                                       ;   test al, al
```

patch成这样后，调用完`sub_4070208`后会继续调用原本的参数地址，再进入函数，形成一个死循环（保留原本参数是为了在frida脚本没hook之前能正常运行，不让程序崩溃）

启动patch后的程序，gdb attch上去后，断在sub_407028上，看一下两个vector的指针地址

![image-20230703132805333](https://raw.githubusercontent.com/Military-axe/imgtable/main/202307031328915.png)

然后写js脚本

```js
console.log("[+] load script")

var doCheck = new NativeFunction(new NativePointer(0x407028), 'bool', ['pointer', 'pointer', 'pointer'])
var string_init = new NativeFunction(new NativePointer(0x407782), 'pointer', ['pointer', 'pointer'])
var s = Memory.alloc(100)

function intTo12BitBinaryString(num) {
    num = num & 0xFFF;
    let binaryString = num.toString(2);
    while (binaryString.length < 12) {
        binaryString = '0' + binaryString;
    }
    return binaryString;
}

for (var i = 0; i < 4096; i++) {
    var ss = intTo12BitBinaryString(i)
    string_init(s, Memory.allocUtf8String(ss))
    if (doCheck(s, new NativePointer(0x00007ffff0c05b60), new NativePointer(0x00007ffff0c05b80))) {
        console.log(ss)
    }
}

console.log("[+] script end")
```

gdb detach后运行frida脚本。爆破出来的结果是能通过0x406549检查的输入，但是NU1L的脚本就到这了，与实际结果还是有差的，并且每次运行的结果会不同。考虑到可能是patch的方法不好，每次循环使用同样的vector可能会有问题。但是NU1L也没说怎么patch的。只是按上面这样调用是可以得到结果，只是不能用于解题。

## LDPC from Official WP

官方WP显示这是一个LDPC校验码

```
原码:
          |0 1 0|
生成矩阵:
          |1 0 0 0 1 1|
          |0 1 0 1 0 1|
          |0 0 1 1 1 0|
LDPC校验码生成, 就是矩阵乘法(元素乘法使用与运算代替, 加法使用异或代替):
          |1 0 0 0 1 1|
|0 1 0| * |0 1 0 1 0 1| = |0 1 0 1 0 1|
          |0 0 1 1 1 0|
经过矩阵乘法得到的1 * 6矩阵就是LDPC校验码. 其中: 前三位是原码, 后三位是校验码
```

可以看到，源码是前三位，校验码是后三位。也就是生成过程中，校验码只和生成矩阵的后三列有关。

根据后三列的不同，可以得到不同的源码与校验码的关系，如果是上面的矩阵，则源码(x1,x2,x3)与校验码(y1,y2,y3)的关系如下

$$ y_1 = x_2\oplus x_3 $$
$$ y_2 = x_1\oplus x_3 $$
$$ y_3 = x_1\oplus x_2 $$

同样的，根据上面的映射我们也能得到对应的矩阵。

然后程序一开始初始化了一个矩阵

```
|1 1 1 0 1 1 0 1 0 1 0 1|
|1 0 0 1 1 0 1 1 0 1 0 0|
|0 1 1 1 0 0 1 0 1 0 0 1|
|0 1 0 0 0 1 1 0 1 1 1 0|
|1 0 1 1 1 0 0 0 1 0 1 0|
|0 0 0 0 0 1 0 1 0 0 1 1|
```

然后程序的逻辑是

![image-20230703143655965](https://raw.githubusercontent.com/Military-axe/imgtable/main/202307031436901.png)

也就是找出这个生成矩阵，能验证的所有LDPC码，并按从小到大的顺序排列

```python
import numpy as np

N = 12
K = 6
H = np.array(
    [
        [1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1],
        [1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0],
        [0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1],
        [0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0],
        [1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0],
        [0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1],
    ]
)
# print(H)
b = []
for i in range(2**N):  # 2^10 = 1024
    a = format(i, "b")  # 列举出所有可能的校验码
    b.append("{:0>12s}".format(a))
v = np.zeros((2**N, N))  # 存储所有的校验码的元组
for i in range(2**N):  # 从⼩到⼤
    v[i] = b[i]
    for j in range(N):  # 存储校验码
        v[i][j] = b[i][j]  # v是0000000~1111111
w = np.zeros((1, N - K))
for i in range(2**N):
    if np.all(np.dot(v[i], H.T) % 2 == w):
        print(v[i])
```

# 参考

[Functions | Frida • A world-class dynamic instrumentation toolkit](https://frida.re/docs/functions/)

[Frida在windows上的玩法_frida hook windows_奋飞安全的博客-CSDN博客](https://blog.csdn.net/fenfei331/article/details/117755003)

[FRIDA-API使用篇：rpc、Process、Module、Memory使用方法及示例 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/101401252)

[SCTF 2023 WP By Nu1L Team (qq.com)](https://mp.weixin.qq.com/s/56nSyavj9ovMrzBN0BhEOA)

[LDPC码（一种前向纠错码）：基础 & 译码算法 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/514670102)