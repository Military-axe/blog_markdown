---
title: "2023 研究生国赛 Reverse"
date: 2023-09-27T23:08:11+08:00
categories:
- Reverse
tags:
- rc4
- 反调试
- 2023
- 研究生国赛
- base64
---

4道题做了3到，都不太方便纯静态，动调倒是都挺简单的. 最后一题unity的游戏没什么经验，不知道怎么下手，CE也没下就放弃了

更新：又看了一下其实unity还是很简单，只是忘记dnspy该展开那个类了，（我说怎么看不到代码呢

<!--more-->

## easy_xor

打开ida发现看不全代码

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  char v4; // [esp+0h] [ebp-1CCh]

  sub_401020("please input your flag:", v4);
  __asm { retn }
  return result;
}
```

汇编层面发现是利用`call $+5`，内联了一个没有用的函数，同时加了垃圾指令

```asm
.text:00401560 83 C4 04                      add     esp, 4
.text:00401563 55                            push    ebp
.text:00401564 E8 00 00 00 00                call    $+5
.text:00401564
.text:00401569
.text:00401569                               loc_401569:                             ; DATA XREF: _main+2B↓o
.text:00401569 5D                            pop     ebp
.text:0040156A 48                            dec     eax
.text:0040156B 83 C5 08                      add     ebp, (offset loc_401570+1 - offset loc_401569)
.text:0040156E 55                            push    ebp
.text:0040156F C3                            retn
.text:0040156F
.text:0040156F                               _main endp ; sp-analysis failed
.text:0040156F
.text:00401570                               ; ---------------------------------------------------------------------------
.text:00401570
.text:00401570                               loc_401570:                             ; DATA XREF: _main+2B↑o
.text:00401570 08 5D 8D                      or      [ebp-73h], bl
```

还有一些动态调试的api，我直接从0x401560 nop 到0x4015B8，把无关逻辑的混淆和动态都去掉了。得到的伪代码如下

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // ecx
  int v4; // ecx
  char v6; // [esp-8h] [ebp-1D4h]
  char v7; // [esp-4h] [ebp-1D0h]
  char v8; // [esp+0h] [ebp-1CCh]
  char flag[264]; // [esp+54h] [ebp-178h] BYREF
  __int128 v10[4]; // [esp+15Ch] [ebp-70h]
  int v11; // [esp+19Ch] [ebp-30h]
  int v12; // [esp+1A0h] [ebp-2Ch]
  int v13; // [esp+1A4h] [ebp-28h]
  int v14; // [esp+1A8h] [ebp-24h]
  int v15; // [esp+1ACh] [ebp-20h]
  int v16; // [esp+1B0h] [ebp-1Ch]
  int v17; // [esp+1B4h] [ebp-18h]
  int v18; // [esp+1B8h] [ebp-14h]
  int v19[3]; // [esp+1BCh] [ebp-10h] BYREF

  sub_401020("please input your flag:", v8);
  v11 = 50462976;
  v12 = 117835012;
  v13 = 185207048;
  v14 = 252579084;
  v15 = 319951120;
  v16 = 387323156;
  v17 = 454695192;
  v18 = 522067228;
  v19[0] = 0;
  v19[1] = 1241513984;
  v19[2] = 0;
  memset(flag, 0, 0xC8u);
  printf("%s", (char)flag);
  if ( strlen(flag) == 46 )
  {
    v10[0] = *(_OWORD *)flag;
    v10[1] = *(_OWORD *)&flag[16];
    v10[2] = *(_OWORD *)&flag[32];
    sub_401370(46);
    sub_401080(v19);
    for ( i = 0; i < 64; ++i )
    {
      if ( i >= 46 )
        break;
      *((_BYTE *)&v10[3] + i) = *((_BYTE *)v10 + i) ^ flag[i + 200];
    }
    v4 = 0;
    while ( *((_BYTE *)&v10[3] + v4) == byte_403114[v4] )
    {
      if ( ++v4 >= 46 )
      {
        sub_401020("you get your flag,the flag is your input!", v7);
        sub_401020("\n", v6);
        getchar();
        return 0;
      }
    }
    sub_401020("error\n", v7);
  }
  else
  {
    sub_401020("length error!", v7);
  }
  return 0;
}
```

发现奇怪的地方，`*((_BYTE *)&v10[3] + i) = *((_BYTE *)v10 + i) ^ flag[i + 200];`

`flag[i+200]`是个很怪的地方，问题只能出在`sub_401370`和`sub_401080`上

```c
void sub_401370()
{
  __asm { retn }
}
```

这是也是混淆，nop一下看看

```c
int __usercall sub_401370@<eax>(unsigned __int8 *a1@<edx>, _DWORD *a2@<ecx>, int a3, unsigned __int8 *a4)
{
  int v5; // ecx
  int v6; // esi
  int v7; // ecx
  int v8; // eax
  int v9; // ecx
  int v10; // eax
  int v11; // ecx
  int v12; // eax
  int v13; // ecx
  int v14; // eax
  int v15; // ecx
  int v16; // eax
  int v17; // ecx
  int v18; // eax
  int v19; // ecx
  int v20; // eax
  int v22; // ecx
  int v23; // eax
  int v24; // ecx
  int v25; // eax
  int v26; // ecx
  int result; // eax

  v5 = a1[7] << 8;
  v6 = *((unsigned __int16 *)a1 + 1);
  qmemcpy(a2, "expand 32-byte k", 16);
  v7 = a1[5] | ((a1[6] | v5) << 8);
  a2[4] = *a1 | ((a1[1] | (v6 << 8)) << 8);
  v8 = a1[10];
  a2[5] = a1[4] | (v7 << 8);
  v9 = a1[8] | ((a1[9] | ((v8 | (a1[11] << 8)) << 8)) << 8);
  v10 = a1[14];
  a2[6] = v9;
  v11 = a1[12] | ((a1[13] | ((v10 | (a1[15] << 8)) << 8)) << 8);
  v12 = a1[18];
  a2[7] = v11;
  v13 = a1[16] | ((a1[17] | ((v12 | (a1[19] << 8)) << 8)) << 8);
  v14 = a1[22];
  a2[8] = v13;
  v15 = a1[20] | ((a1[21] | ((v14 | (a1[23] << 8)) << 8)) << 8);
  v16 = a1[26];
  a2[9] = v15;
  v17 = a1[24] | ((a1[25] | ((v16 | (a1[27] << 8)) << 8)) << 8);
  v18 = a1[30];
  a2[10] = v17;
  v19 = a1[29] | ((v18 | (a1[31] << 8)) << 8);
  v20 = a1[28];
  a2[11] = v20 | (v19 << 8);
  v22 = *((unsigned __int16 *)a4 + 1);
  a2[12] = 1111;
  v23 = a4[6];
  a2[13] = *a4 | ((a4[1] | (v22 << 8)) << 8);
  v24 = a4[4] | ((a4[5] | ((v23 | (a4[7] << 8)) << 8)) << 8);
  v25 = a4[10];
  a2[14] = v24;
  v26 = a4[9] | ((v25 | (a4[11] << 8)) << 8);
  result = a4[8];
  a2[15] = result | (v26 << 8);
  return result;
}
```

很复杂的一个加密函数，但是从调用看和我们的输入无关，可以动调的情况下，这个函数可以不用看了

另一个函数也是很复杂的，但是去完上一个函数混淆后，回到main函数，重新f5，然后设置类型调整一下就可以看懂了

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // ecx
  int v4; // ecx
  char v6; // [esp-8h] [ebp-1D4h]
  char v7; // [esp-4h] [ebp-1D0h]
  char v8; // [esp+0h] [ebp-1CCh]
  __m128i v9[4]; // [esp+14h] [ebp-1B8h] BYREF
  char flag[200]; // [esp+54h] [ebp-178h] BYREF
  char xor_array[64]; // [esp+11Ch] [ebp-B0h] BYREF
  char flag2[64]; // [esp+15Ch] [ebp-70h]
  int v13[8]; // [esp+19Ch] [ebp-30h] BYREF
  int v14[3]; // [esp+1BCh] [ebp-10h] BYREF

  sub_401020("please input your flag:", v8);
  v13[0] = 50462976;
  v13[1] = 117835012;
  v13[2] = 185207048;
  v13[3] = 252579084;
  v13[4] = 319951120;
  v13[5] = 387323156;
  v13[6] = 454695192;
  v13[7] = 522067228;
  v14[0] = 0;
  v14[1] = 1241513984;
  v14[2] = 0;
  memset(flag, 0, sizeof(flag));
  printf("%s", (char)flag);
  if ( strlen(flag) == 46 )
  {
    *(_OWORD *)flag2 = *(_OWORD *)flag;
    *(_OWORD *)&flag2[16] = *(_OWORD *)&flag[16];
    *(_OWORD *)&flag2[32] = *(_OWORD *)&flag[32];
    init((unsigned __int8 *)v13, v9, 46, (unsigned __int8 *)v14);
    enc(v9, (int)xor_array);
    for ( i = 0; i < 64; ++i )
    {
      if ( i >= 46 )
        break;
      flag2[i + 48] = flag2[i] ^ xor_array[i];
    }
    v4 = 0;
    while ( flag2[v4 + 48] == cipher[v4] )
    {
      if ( ++v4 >= 46 )
      {
        sub_401020("you get your flag,the flag is your input!", v7);
        sub_401020("\n", v6);
        getchar();
        return 0;
      }
    }
    sub_401020("error\n", v7);
  }
  else
  {
    sub_401020("length error!", v7);
  }
  return 0;
}
```

这就可以看到，init函数和enc函数也就是上面分析的函数，主要是生成`xor_array`数组，也与输入无关，那么动调可以直接得到。

主要的加密也就是flag和xor_array异或，直接动调就可以

![image-20230927223323491](https://raw.githubusercontent.com/Military-axe/imgtable/main/202309272233529.png)

exp:

```python
xor_array = [0xFF, 0x24, 0x3F, 0xDA, 0xBE, 0xA9, 0xB6, 0xF7, 0x12, 0x8F, 0x29, 0xD0, 0x73, 0xF7, 0xF7, 0xA2, 0x83, 0xAD, 0x5F, 0xB0, 0x51, 0x90, 0x3F, 0x68, 0xF6, 0x8C, 0xC1, 0x0A, 0xB7, 0xB5, 0xBC,
             0x82, 0xCC, 0xFC, 0x67, 0xDE, 0xE9, 0xFF, 0x5B, 0xCB, 0xC9, 0x67, 0xEA, 0xF6, 0xA6, 0x1A, 0x39, 0x56, 0xCA, 0x23, 0x46, 0xE3, 0xC8, 0x71, 0x43, 0x53, 0xFF, 0x72, 0x2F, 0xC3, 0x5C, 0x1C, 0x5B, 0x94]

cipher = [0x99, 0x48, 0x5E, 0xBD, 0xC5, 0x9B, 0x85, 0x96, 0x20, 0xFC, 0x18, 0xB2, 0x00, 0xC5, 0xDA, 0xC0, 0xB1, 0xC8, 0x6C, 0x81, 0x63, 0xBD,
          0x09, 0x50, 0xC2, 0xBB, 0xEC, 0x33, 0xD6, 0xD7, 0x8F, 0xAF, 0xAD, 0xCE, 0x14, 0xED, 0x8C, 0xCE, 0x6F, 0xA9, 0xA8, 0x02, 0x8C, 0x90, 0x94, 0x67]

for i in range(len(cipher)):
    cipher[i] ^= xor_array[i]

print(bytes(cipher))
```

flag: `flag{23a2s1bs2-b2e312-6847-9ab3-a2s3e14baeff2}`

## T4ee

ida打开后分析，发现是将真实的逻辑分割成6个部分

```c
int __cdecl main_0(int argc, const char **argv, const char **envp)
{
  __CheckForDebuggerJustMyCode(&unk_D8E0A7);
  val1[0] = ret_address((int)j_part_1);         // 将函数J_program_start地址传递到val1中
                                                // 读取flag
  j_add_address(val1[0], (int)part_2, val2);    // 添加part_2地址到val1+4位置
                                                // flag length
  j_add_address(val1[0], (int)j_part_3, val3);  // 添加part_3地址到val1+8位置
                                                // arr1 ^= arr2
  j_add_address(*(_DWORD *)(val1[0] + 4), (int)j_part_4, val2);// 添加part_4地址到val1+8的位置
                                                // arr1等于打乱后的flag
  j_add_address(*(_DWORD *)(val1[0] + 4), (int)j_part_5, val3);// 添加part_4地址到val1+12的位置
                                                // rc4 key=GoodLuck
  j_add_address(*(_DWORD *)(val1[0] + 8), (int)part_6, val2);// 添加part_4地址到val1+12的位置
                                                // strcmp(arr1, cipher)
  run(val1[0]);
  return 0;
}
```

将6个部分插入到二叉树中，最后run函数是前序遍历，实际上6个部分可以通过各下一个断点，然后运行来调试出执行顺序。但是顺序是val2和val3来控制，所以需要注意这两个变量，通过交叉引用可以查到到这两个变量果然有一个反调试

```c
void *__thiscall check_debug(void *this)
{
  __CheckForDebuggerJustMyCode(&unk_D8E0A7);
  if ( sub_D8110E() )                           // 判断是否调试
  {
    val2 = 1;
    val3 = 0;
  }
  return this;
}
```

虽然我不知道这个函数到底是哪里调用的，很怪，但是就是会偷偷改调用顺序

调试可以发现调用顺序是

```text
part1
part2
part4
part5
part3
part6
```

1，2是输入，检查输入长度，6是对比密文，关键就是4，5，3，具体的功能来分析一下

### part4

将flag打乱后放到arr1数组中

```c
int part_4()
{
  int result; // eax
  int i; // [esp+D0h] [ebp-A0h]
  int v2[37]; // [esp+DCh] [ebp-94h]

  result = __CheckForDebuggerJustMyCode(&unk_D8E0A7);
  v2[0] = 4;
  v2[1] = 19;
  v2[2] = 9;
  v2[3] = 35;
  v2[4] = 34;
  v2[5] = 1;
  v2[6] = 24;
  v2[7] = 14;
  v2[8] = 5;
  v2[9] = 0;
  v2[10] = 18;
  v2[11] = 31;
  v2[12] = 21;
  v2[13] = 16;
  v2[14] = 11;
  v2[15] = 29;
  v2[16] = 12;
  v2[17] = 2;
  v2[18] = 30;
  v2[19] = 13;
  v2[20] = 3;
  v2[21] = 15;
  v2[22] = 8;
  v2[23] = 7;
  v2[24] = 17;
  v2[25] = 32;
  v2[26] = 33;
  v2[27] = 6;
  v2[28] = 25;
  v2[29] = 20;
  v2[30] = 26;
  v2[31] = 10;
  v2[32] = 23;
  v2[33] = 22;
  v2[34] = 27;
  v2[35] = 28;
  for ( i = 0; i < 34; ++i )
  {
    *(&arr1 + i) = flag[v2[i]];
    result = i + 1;
  }
  return result;
}
```

### part5

代码如下

```c
int part_5()
{
  size_t v0; // eax
  char Str[128]; // [esp+190h] [ebp-29Ch] BYREF
  int v3; // [esp+210h] [ebp-21Ch]
  char v4[264]; // [esp+21Ch] [ebp-210h] BYREF
  int key_stream[65]; // [esp+324h] [ebp-108h] BYREF

  __CheckForDebuggerJustMyCode(&unk_D8E0A7);
  j_memset(key_stream, 0, 0x100u);
  j_memset(v4, 0, 0x100u);
  v3 = 36;
  j_memset(&Str[20], 0, 0x64u);
  strcpy(Str, "GoodLuck");
  v0 = j_strlen(Str);
  j_rc4_init(key_stream, v4, Str, v0);
  return rc4_crypt((int)key_stream, (int)&arr1, &arr1);
}
```

分析后可以知道是rc4加密，密钥是`GoodLuck`

### part3

```c
int part_3()
{
  int result; // eax
  int i; // [esp+D0h] [ebp-8h]

  result = __CheckForDebuggerJustMyCode(&unk_D8E0A7);
  for ( i = 0; i < 33; ++i )
  {
    *(&arr1 + i) ^= arr2[i];
    result = i + 1;
  }
  return result;
}
```

这里的arr2其实就是arr1的下一位

![image-20230927225546876](https://raw.githubusercontent.com/Military-axe/imgtable/main/202309272255835.png)

所以其实这个加密可以写成

```python
for i in range(len(arr1)-1):
    arr1[i] ^= arr1[i + 1]
```

所以解密就先解密3，再5，再4就可以

exp:

```python
from Crypto.Cipher import ARC4

c = [0x2C, 0x40, 0xCE, 0x88, 0xEA, 0xB3, 0xA7, 0xFA, 0xBE, 0xE3, 0x32, 0xD9, 0x8B, 0xE4, 0x1C, 0x77, 0xFC,
     0xD4, 0x76, 0xAB, 0x87, 0x41, 0xB0, 0xCE, 0xF5, 0x5E, 0x61, 0x86, 0xA8, 0xCF, 0x71, 0x99, 0x5C, 0xB1]

# part3
for i in range(len(c)-1, 0, -1):
    c[i-1] ^= c[i]

# part5
key = b'GoodLuck'
rc4 = ARC4.new(key=key)
c = rc4.decrypt(bytes(c))

# part4
box = [4, 19, 9, 1, 24, 14, 5, 0, 18, 31, 21, 16, 11, 29, 12, 2, 30,
       13, 3, 15, 8, 7, 17, 32, 33, 6, 25, 20, 26, 10, 23, 22, 27, 28]
flag = [0] * 34
for i in range(len(c)):
    flag[box[i]] = c[i]

print(bytes(flag))
```

flag: `flag{T4ee_Travel_M@kes_me_H@ppy!!}`

## lin

这是一道golang语言编程的题目

搜索字符串，发现base64字符表，然后在程序中查找base64相关函数，发现在main_thirdChall中有一个base64字符串

```c
.text:00000000003FFAE0 E8 FB 06 FE FF                call    encoding_base64___Encoding__EncodeToString
.text:00000000003FFAE0
.text:00000000003FFAE5 48 83 FB 28                   cmp     rbx, 28h ; '('
.text:00000000003FFAE9 75 19                         jnz     short loc_3FFB04
.text:00000000003FFAE9
.text:00000000003FFAEB 48 8D 1D 30 49 02 00          lea     rbx, aReftq1rge2hhc2            ; "REFTQ1RGe2hhc2FraS1wZHR6cHR6LXZ4bmZudX0"...
.text:00000000003FFAF2 B9 28 00 00 00                mov     ecx, 28h ; '('
.text:00000000003FFAF7 E8 44 2D F6 FF                call    runtime_memequal
.text:00000000003FFAF7
.text:00000000003FFAFC 0F 1F 40 00                   nop     dword ptr [rax+00h]
.text:00000000003FFB00 84 C0                         test    al, al
.text:00000000003FFB02 75 61                         jnz     short loc_3FFB65
```

直接解码上图base64的密文（`REFTQ1RGe2hhc2FraS1wZHR6cHR6LXZ4bmZudX0=`）得到一个flag`DASCTF{hasaki-pdtzptz-vxnfnu}`

但是这个flag不对，其实只有中间那部分不对。

这是main_thirdChall前面还有main_firstChall和main_secondChall

查看前面的代码，main_firstChall有检查长度的部分

```c
  if ( v0 != 6 )
  {
    fmt_Fprintln();
    main_menu();
    return 0LL;
  }
```

运行程序后，测试多次发现输入`DASCTF{hasaki-pdtzptz-vxnfnu}`中的第一个部分`hasaki`可以通过

实际上看汇编或者动态调试分析main_firstChall是输入6个字符，rot13后和密文对比

```c
  if ( v4 != 6 || *(_DWORD *)v3 != 'nfnu' || *(_WORD *)(v3 + 4) != 'vx' )// unfnxv 调试发现是rot13后的结果
  {
    fmt_Fprintln();
    main_menu();
    return v9;
  }
```

`unfnxv`rot13加密后得到的就是`hasaki`，所以第一关的输入就是`hasaki`

然后第二部分测试后发现输入`DASCTF{hasaki-pdtzptz-vxnfnu}`中的第三个部分`vxnfnu`可以通过。

一定要分析的话，下断点到对比密文的地方就可以了，因为不加密输入，而是加密其他数据，然后和输入对比，所以动调就可以得到正确的输入是`vxnfnu`

```c
  if ( v8 == a1 && (unsigned __int8)runtime_memequal() )// vxnfnu
    return runtime_slicerunetostring();
```

然后第三个部分要求输入是29个字符，然后处理输入后base64加密对比密文，可以想到输入就是类似`DASCTF{hasaki-pdtzptz-vxnfnu}`的形式，只是中间那一段被处理了，我们调试这一部分

然后下断点到base64加密前，然后开始调试

前两关就还是输入`hasaki`,`vxnfnu`，第三个直接输入错误的flag，通过调试看看差别在哪里

```sh
欢迎来到小林的世界
请选择您要进行的操作：
1. 自我介绍
2. 开始闯关
3. 关闭程序
请输入操作选项：2
有一天小林发现了一张古老地图，上面标记着一个传说中的宝藏。然而，为了找到宝藏，需要先找到一把铜钥匙。
:: hasaki
恭喜你找到了铜钥匙！
于是他开始沿着地图指示的路径进行探索。经过长时间的跋涉和寻找，他最终来到了一个神秘的洞穴。在洞穴中，他看到了一扇大门，门上有一个锁。他观察了一下锁孔，发现需要一把银钥匙才能打开。
:: vxnfnu
恭喜你找到了银钥匙！
于是他开始四处搜索，但是任何线索都没有找到金钥匙。这时候，他想起了地图上的一些细节，破解了一些谜题，得到了一些提示。这些提示指向了一个古老的祭坛，据说这里曾经有传说中的金钥匙。
:: DASCTF{hasaki-pdtzptz-vxnfnu}
```

然后查看内存，可以发现flag中间那段变了

```
000000C0000ABD20  07 00 00 00 00 00 00 00  44 41 53 43 54 46 7B 68  ........DASCTF{h
000000C0000ABD30  61 73 61 6B 69 2D 75 69  79 65 75 79 65 2D 76 78  asaki-uiyeuye-vx
000000C0000ABD40  6E 66 6E 75 7D 00 00 00  AE 81 01 00 C0 00 00 00  nfnu}...........
```

我们输入的是`pdtzptz`，变成了`uiyeuye`

像misc一样测试一下偏移，发现每个字符差5，就是凯撒密码，所以解一下cyberchef解一下凯撒可以得到flag

```
欢迎来到小林的世界
请选择您要进行的操作：
1. 自我介绍
2. 开始闯关
3. 关闭程序
请输入操作选项：2
有一天小林发现了一张古老地图，上面标记着一个传说中的宝藏。然而，为了找到宝藏，需要先找到一把铜钥匙。
:: hasaki
恭喜你找到了铜钥匙！
于是他开始沿着地图指示的路径进行探索。经过长时间的跋涉和寻找，他最终来到了一个神秘的洞穴。在洞穴中，他看到了一扇大门，门上有一个锁。他观察了一下锁孔，发现需要一把银钥匙才能打开。
:: vxnfnu
恭喜你找到了银钥匙！
于是他开始四处搜索，但是任何线索都没有找到金钥匙。这时候，他想起了地图上的一些细节，破解了一些谜题，得到了一些提示。这些提示指向了一个古老的祭坛，据说这里曾经有传说中的金钥匙。
:: DASCTF{hasaki-kyoukou-vxnfnu}
恭喜你获取到了金钥匙，这就是最终的宝藏！
```

flag: `DASCTF{hasaki-kyoukou-vxnfnu}`

## Robbie gave up

这是一道unity的游戏题目，根据经验（~~就是上网搜一下~~），来到`Robbie gave up/Robbie gave up_Data/Managed/Assembly-CSharp.dll`，使用dnspy打开Assembly-CSharp.dll就可以看到具体的逻辑代码了

这是一道游戏题目，应该是游戏通关后才会出现flag，所以定位到游戏结束附件，所在类是`WinZone`

一路观察代码，看下去发现在Robbie类中有一个win方法会被调用到

```c#
using System;
using System.Reflection;
using UnityEngine;

// Token: 0x02000014 RID: 20
public class Robbie : MonoBehaviour
{
	// Token: 0x0600005C RID: 92 RVA: 0x0001080C File Offset: 0x0000EA0C
	public static object Win()
	{
		for (int i = GameManager.instance.orbs.Count; i < Robbie.data1.Length; i++)
		{
			Robbie.data2[i] = (byte)(Robbie.data1[i] ^ i);
		}
		Type type = Assembly.Load(Robbie.data2).GetType("ClassLibrary1.Class1");
		object obj = type.GetConstructor(Type.EmptyTypes).Invoke(new object[0]);
		return type.GetMethod("Method").Invoke(obj, null).ToString();
	}

	// Token: 0x04000084 RID: 132
	private static int[] data1 = new int[]
	{
		77,
		91,
		146,
		3,
		7,
        ...
    };
```

这里调用了data1数据，解密后保存成`ClassLibrary1.Class1`类，然后调用其中的方法得到flag

我手动解密一下，保存出来，看到具体代码如下。

```c#
// ClassLibrary1.Class1
// Token: 0x06000001 RID: 1 RVA: 0x00002130 File Offset: 0x00000330
public static string Method()
{
	string x = "はりずめはばぐだすだちずそぬけびせやのぞはとらよはやこらのとほめせだむばのだのぢはやよぢせりにやのばぢ";
	return new Crypt().Decode(x);
}
```

```c#
using System;
using System.Collections.Generic;
using System.Text;

namespace Libraries
{
	// Token: 0x02000003 RID: 3
	public class Crypt
	{
		// Token: 0x06000003 RID: 3 RVA: 0x00002058 File Offset: 0x00000258
		public Crypt()
		{
			this.T = new List<char>();
			this.K = "あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほまみむめもやよらりるれろわをぐげござじずぞだぢづでばびぶべぱぴぷぺぽ";
		}

		// Token: 0x17000001 RID: 1
		// (get) Token: 0x06000004 RID: 4 RVA: 0x00002076 File Offset: 0x00000276
		// (set) Token: 0x06000005 RID: 5 RVA: 0x00002150 File Offset: 0x00000350
		public string Token
		{
			get
			{
				if (this.S != null)
				{
					return this.S;
				}
				return this.K;
			}
			set
			{
				this.T.Clear();
				this.S = value;
				if (this.S == null)
				{
					foreach (char item in this.K)
					{
						this.T.Add(item);
					}
					return;
				}
				if (this.S.Length < 64)
				{
					foreach (char item2 in this.S)
					{
						this.T.Add(item2);
					}
					for (int j = 0; j < 64 - this.S.Length; j++)
					{
						this.T.Add(this.K[j]);
					}
					return;
				}
				for (int k = 0; k < 64; k++)
				{
					this.T.Add(this.S[k]);
				}
			}
		}

		// Token: 0x06000006 RID: 6 RVA: 0x0000208D File Offset: 0x0000028D
		public string Encode(string x)
		{
			if (!string.IsNullOrEmpty(x))
			{
				return this.InternalEncode(Encoding.UTF8.GetBytes(x));
			}
			return x;
		}

		// Token: 0x06000007 RID: 7 RVA: 0x000020AA File Offset: 0x000002AA
		public string Decode(string x)
		{
			if (!string.IsNullOrEmpty(x))
			{
				return Encoding.UTF8.GetString(this.InternalDecode(x));
			}
			return x;
		}

		// Token: 0x06000008 RID: 8 RVA: 0x000020C7 File Offset: 0x000002C7
		public byte[] Encode(byte[] x)
		{
			if (x != null)
			{
				return Encoding.UTF8.GetBytes(this.InternalEncode(x));
			}
			return null;
		}

		// Token: 0x06000009 RID: 9 RVA: 0x000020DF File Offset: 0x000002DF
		public byte[] Decode(byte[] x)
		{
			if (x != null)
			{
				return this.InternalDecode(Encoding.UTF8.GetString(x));
			}
			return null;
		}

		// Token: 0x0600000A RID: 10 RVA: 0x000020F7 File Offset: 0x000002F7
		private void CheckToken()
		{
			if (this.T.Count != 64)
			{
				this.Token = this.K;
			}
		}

		// Token: 0x0600000B RID: 11 RVA: 0x00002240 File Offset: 0x00000440
		private byte[] InternalDecode(string x)
		{
			this.CheckToken();
			int num = 0;
			int num2 = x.Length / 4;
			int num3 = x.Length % 4;
			byte[] array;
			if (num3 == 0)
			{
				array = new byte[3 * num2];
			}
			else
			{
				array = new byte[3 * num2 + num3 - 1];
				string text = string.Empty;
				for (int i = num3; i > 0; i--)
				{
					text += this.ByteToBin((byte)this.T.IndexOf(x[x.Length - i])).Substring(2);
				}
				for (int j = 0; j < num3 - 1; j++)
				{
					array[3 * num2 + j] = this.BinToByte(text.Substring(8 * j, 8));
				}
			}
			for (int k = 0; k < num2; k++)
			{
				string text = string.Empty;
				for (int l = 0; l < 4; l++)
				{
					text += this.ByteToBin((byte)this.T.IndexOf(x[4 * k + l])).Substring(2);
				}
				for (int m = 0; m < text.Length / 8; m++)
				{
					array[num++] = this.BinToByte(text.Substring(8 * m, 8));
				}
			}
			return array;
		}

		// Token: 0x0600000C RID: 12 RVA: 0x00002378 File Offset: 0x00000578
		private string InternalEncode(byte[] x)
		{
			this.CheckToken();
			string text = string.Empty;
			int num = x.Length / 3;
			int num2 = x.Length % 3;
			for (int i = 0; i < num; i++)
			{
				string text2 = string.Empty;
				for (int j = 0; j < 3; j++)
				{
					text2 += this.ByteToBin(x[3 * i + j]);
				}
				text += this.cryptEncode(text2);
			}
			if (num2 == 1)
			{
				string text2 = this.ByteToBin(x[x.Length - 1]).PadRight(12, '0');
				text += this.cryptEncode(text2);
			}
			else if (num2 == 2)
			{
				string text2 = string.Empty;
				for (int k = num2; k > 0; k--)
				{
					text2 += this.ByteToBin(x[x.Length - k]);
				}
				text2 = text2.PadRight(18, '0');
				text += this.cryptEncode(text2);
			}
			return text;
		}

		// Token: 0x0600000D RID: 13 RVA: 0x0000245C File Offset: 0x0000065C
		private string cryptEncode(string x)
		{
			string text = string.Empty;
			for (int i = 0; i < x.Length / 6; i++)
			{
				text += this.T[(int)this.BinToByte(x.Substring(6 * i, 6))].ToString();
			}
			return text;
		}

		// Token: 0x0600000E RID: 14 RVA: 0x00002114 File Offset: 0x00000314
		private string ByteToBin(byte x)
		{
			return Convert.ToString(x, 2).PadLeft(8, '0');
		}

		// Token: 0x0600000F RID: 15 RVA: 0x00002125 File Offset: 0x00000325
		private byte BinToByte(string x)
		{
			return Convert.ToByte(x, 2);
		}

		// Token: 0x04000001 RID: 1
		private string S;

		// Token: 0x04000002 RID: 2
		private string K;

		// Token: 0x04000003 RID: 3
		private List<char> T;
	}
}

```

稍微看一下很复杂，仔细看一眼，就是**base64换表**，直接cyberchef秒了

表：`あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほまみむめもやよらりるれろわをぐげござじずぞだぢづでばびぶべぱぴぷぺぽ`

密文: `はりずめはばぐだすだちずそぬけびせやのぞはとらよはやこらのとほめせだむばのだのぢはやよぢせりにやのばぢ`

flag: `flag{33419b8662e9df2ea7a787c64f946ecc}`

## 附件

https://github.com/Military-axe/ctf/tree/master/2023/2023%E7%A0%94%E7%A9%B6%E7%94%9F%E5%9B%BD%E8%B5%9B%E5%88%9D%E8%B5%9B
