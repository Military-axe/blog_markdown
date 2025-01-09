---
title: "2023 Two Reverse CrackMe WriteUp"
date: 2023-06-30T17:05:32+08:00
toc: true
categories:
- Reverse
tags:
- movfuscator
- junk
- reverse
---

前几天打了一个应该是天融信的比赛，题目不难，简单记录一下。

一道是花指令+rc4，一道是mov混淆

<!--more-->

# junk

这题是简单的花指令+rc4

打开题目后看到

![image-20230630161552079](https://raw.githubusercontent.com/Military-axe/imgtable/main/202306301617162.png)

这是经典的`jz,jnz`的花指令。只需要将第一个跳转指令换成jmp就可以。这里选择用idapython写一个脚本来去花

```python
from ida_bytes import patch_bytes, get_bytes

address = 0x4010C7
length = 0x10000
ptr = address

while address+length >= ptr:
    if get_bytes(ptr,3) != b'\x0f\x84\x09' or get_bytes(ptr+6, 3) != b'\x0f\x85\x03':
        ptr += 1
        continue
    patch_bytes(ptr, b'\xeb\x0d\x90\x90\x90')
    ptr += 12
```

然后将所有代码取消定义再重新解析，然后选中main开头到结尾，定义函数。在F5就可以看到代码了

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [esp+0h] [ebp-160h]
  char v5[256]; // [esp+30h] [ebp-130h] BYREF
  char Buf1; // [esp+130h] [ebp-30h] BYREF
  _BYTE v7[3]; // [esp+131h] [ebp-2Fh] BYREF
  int v8[2]; // [esp+150h] [ebp-10h] BYREF
  char v9; // [esp+158h] [ebp-8h]

  memset(v5, 0, sizeof(v5));
  v8[0] = -272716322;
  v8[1] = 2018915346;
  v9 = 0;
  sub_401050("%29s", &Buf1);
  sub_401080(v5, v8, (char *)v8 + strlen((const char *)v8) + 1 - ((char *)v8 + 1));
  sub_4011F0(v5, &Buf1, &v7[strlen(&Buf1)] - v7);
  if ( !memcmp(&Buf1, &unk_404018, 0x1Du) )
    sub_401020("yes~~~~~~~~~~~~~~~~~\n", v4);
  else
    sub_401020("no!!!!!!!!!!!!!!!!!!!!!!!\n", v4);
  return 0;
}
```

去混淆后直接看到是rc4裸的，直接秒了

```python
from Crypto.Cipher import ARC4

c = [0x56, 0x05, 0x03, 0x86, 0x7D, 0xEC, 0xF9, 0xAB, 0x26, 0xAA, 0x2D, 0x10, 0xB1, 0xD9, 0xD5, 0x8D, 0x0F, 0xC6, 0x49, 0xA7, 0xFB, 0x9D, 0xB1, 0xA4, 0x4D, 0x2D, 0x85, 0x2F, 0x9A]

key = b'\xEF\xBE\xAD\xDE'[::-1]+b'xV4\x12'[::-1]

cipher = ARC4.new(key)
m = cipher.decrypt(bytes(c))
print(bytes(m))
```

flag: `flag{jUnkc0dE_C0oO00o0oo0ode}`

题目链接: [ctf/2023/junk at master · Military-axe/ctf · GitHub](https://github.com/Military-axe/ctf/tree/master/2023/junk)

# mov

这题是mov混淆，也就是所有指令都用mov来替换。先去混淆用demovfuscator

![image-20230630165707757](https://raw.githubusercontent.com/Military-axe/imgtable/main/202306301657350.png)

得到mov.patch。这时候打开ida，查看代码，虽然还是很难看，但是可以找到系统的函数调用了

然后看到有read和strlen的调用。直接在strlen后找到输入的内存。然后下硬件断点

![image-20230630165848973](https://raw.githubusercontent.com/Military-axe/imgtable/main/202306301658039.png)

断下来后，单步跟踪发现是讲输入每个先异或0x12再加上0x34

exp:

```python
c = [0xA8, 0xB2, 0xA7, 0xA9, 0x9D, 0xB3, 0x56, 0x98, 0xA8, 0x9B, 0x5B, 0xA5, 0x5A,
     0x9A, 0x56, 0x94, 0x81, 0x9E, 0xB1, 0x94, 0x94, 0x94, 0x94, 0x94, 0x94, 0xA3]

for i in range(len(c)):
    c[i] -= 0x34
    c[i] ^= 0x12

print(bytes(c))
```

flag: `flag{m0vfu5c4t0r_xorrrrrr}`

题目链接：[ctf/2023/move at master · Military-axe/ctf · GitHub](https://github.com/Military-axe/ctf/tree/master/2023/move)


# 参考

[xoreaxeaxeax/movfuscator: The single instruction C compiler (github.com)](https://github.com/xoreaxeaxeax/movfuscator)

[leetonidas/demovfuscator: A work-in-progress deobfuscator for movfuscated binaries (github.com)](https://github.com/leetonidas/demovfuscator)

