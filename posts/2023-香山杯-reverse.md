+++
title = "2023 香山杯 Reverse"
date = 2023-10-16T14:05:44+08:00

[taxonomies]
tags = ["2023", "香山杯", "vm", "android", "base64", "xor"]
# categories = ["Reverse"]
+++

香山杯初赛的3到逆向的WP，不是很难的题，但是有一些新的东西，chaquopy框架，这个框架完成了一套sdk，可以安卓调用python代码也可以python调用java代码。可惜的是python是源码存储，还有研究的空间

<!-- more -->

## URL从哪儿来

题目说明：小A收到一个样本，很轻松就完成了任务：找到样本外联C2。但小A非常好奇的是，他并不能直接在样本中搜到C2，C2是如何被解密的呢？

题目链接：https://github.com/Military-axe/ctf/tree/master/2023/2023%E9%A6%99%E5%B1%B1%E6%9D%AF%E5%88%9D%E8%B5%9B

分析，发现有一个程序会导出一个临时文件，临时文件`ou.exe`才是真正的逻辑所在

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  HMODULE ModuleHandleW; // eax
  HMODULE v4; // eax
  HMODULE v5; // eax
  _BYTE *v7; // [esp+4h] [ebp-28Ch]
  HGLOBAL hResData; // [esp+8h] [ebp-288h]
  HRSRC hResInfo; // [esp+Ch] [ebp-284h]
  _BYTE *lpAddress; // [esp+10h] [ebp-280h]
  FILE *Stream; // [esp+1Ch] [ebp-274h]
  DWORD dwSize; // [esp+20h] [ebp-270h]
  DWORD i; // [esp+28h] [ebp-268h]
  struct _PROCESS_INFORMATION ProcessInformation; // [esp+30h] [ebp-260h] BYREF
  struct _STARTUPINFOA StartupInfo; // [esp+40h] [ebp-250h] BYREF
  CHAR Buffer[260]; // [esp+84h] [ebp-20Ch] BYREF
  CHAR TempFileName[260]; // [esp+188h] [ebp-108h] BYREF

  ModuleHandleW = GetModuleHandleW(0);
  hResInfo = FindResourceW(ModuleHandleW, (LPCWSTR)0x65, L"e_ou");
  v4 = GetModuleHandleW(0);
  hResData = LoadResource(v4, hResInfo);
  v7 = LockResource(hResData);
  v5 = GetModuleHandleW(0);
  dwSize = SizeofResource(v5, hResInfo);
  lpAddress = VirtualAlloc(0, dwSize, 0x1000u, 4u);
  if ( !lpAddress )
    return 1;
  for ( i = 0; i < dwSize; ++i )
  {
    if ( v7[i] && v7[i] != 'x' )
      lpAddress[i] = v7[i] ^ 'x';
    else
      lpAddress[i] = v7[i];
  }
  if ( !GetTempPathA(0x104u, Buffer) )
    return 1;
  if ( !GetTempFileNameA(Buffer, "ou.exe", 0, TempFileName) )
    return 1;
  Stream = fopen(TempFileName, "wb");
  if ( !Stream )
    return 1;
  if ( fwrite(lpAddress, 1u, dwSize, Stream) == dwSize )
  {
    fclose(Stream);
    VirtualFree(lpAddress, 0, 0x8000u);
    memset(&StartupInfo, 0, sizeof(StartupInfo));
    memset(&ProcessInformation, 0, sizeof(ProcessInformation));
    StartupInfo.cb = 68;
    GetStartupInfoA(&StartupInfo);
    StartupInfo.wShowWindow = 0;
    CreateProcessA(TempFileName, 0, 0, 0, 1, 0, 0, 0, &StartupInfo, &ProcessInformation);
    CloseHandle(ProcessInformation.hProcess);
    CloseHandle(ProcessInformation.hThread);
    DeleteFileA(TempFileName);
    return 0;
  }
  else
  {
    fclose(Stream);
    return 1;
  }
}
```

`idapython`提取存储在里面的ou.exe

```python
import idc 
s = idc.get_bytes(0x1550000,0x1a800) 
f=open('D:/Desktop/1.exe', 'wb') 
f.write(s) 
f.close()
```

![img](https://raw.githubusercontent.com/Military-axe/imgtable/main/202310161345760.png)、

分析ou.exe中代码，main函数中这部分代码，得到block的值是一个base64

![img](https://raw.githubusercontent.com/Military-axe/imgtable/main/202310161346427.png)flag{6469616e-6369-626f-7169-746170617761}

## hello_py

题目地址：https://github.com/Military-axe/ctf/tree/master/2023/2023%E9%A6%99%E5%B1%B1%E6%9D%AF%E5%88%9D%E8%B5%9B

这是一个叫chaquopy框架的题目，框架可以在安卓中调用python和python中调用安卓代码两种方式

一开始以为这个框架会把python文件编译成so文件，实际上没有，还是把python文件存在APK文件中

![img](https://raw.githubusercontent.com/Military-axe/imgtable/main/202310161346581.png)只是改了一下后缀名，改成app.zip，解开来就是hello.py发现只是一个`xxtea`加密，改都没改，秒了

 exp:

```python
from ctypes import *
from Crypto.Util.number import *

def MX(z, y, total, key, p, e):
    temp1 = (z.value>>5 ^ y.value<<2) + (y.value>>3 ^ z.value<<4)
    temp2 = (total.value ^ y.value) + (key[(p&3) ^ e.value] ^ z.value)
    
    return c_uint32(temp1 ^ temp2)

def decrypt(n, v, key):
    delta = 0x9e3779b9
    rounds = 6 + 52//n 
    
    total = c_uint32(rounds * delta)
    y = c_uint32(v[0])
    e = c_uint32(0)

    while rounds > 0:
        e.value = (total.value >> 2) & 3
        for p in range(n-1, 0, -1):
            z = c_uint32(v[p-1])
            v[p] = c_uint32((v[p] - MX(z,y,total,key,p,e).value)).value
            y.value = v[p]
        z = c_uint32(v[n-1])  
        v[0] = c_uint32(v[0] - MX(z,y,total,key,0,e).value).value
        y.value = v[0]  
        total.value -= delta
        rounds -= 1

    return v 

cipher =[689085350 ,626885696 ,1894439255 ,1204672445 ,1869189675 ,475967424 ,1932042439 ,1280104741 ,2808893494 ]
key = [12345678 ,12398712 ,91283904 ,12378192 ]
n = 9
res = decrypt(n, cipher, key)
flag = b''
for i in res:
    flag+=long_to_bytes(i)[::-1]
print(flag)
```

flag{c1f8ace6-4b46-4931-b25b-a1010a89c592}

## nesting

题目提示：`flag{uuid}`

题目地址：https://github.com/Military-axe/ctf/tree/master/2023/2023%E9%A6%99%E5%B1%B1%E6%9D%AF%E5%88%9D%E8%B5%9B

这是一个vm题，vm写的很复杂，实际上用污点分析的思路，下几个内存断点，跟踪一下输入的变化，就会发现只是输入和一组值相异或

exp:

```python
xor = [0x54, 0xf6, 0xf2, 7, 0xfb, 4, 5, 0xe, 0x5d, 0x53, 0xc9, 0x4e, 0x46, 0xa, 0x13, 0x1, 0x3, 0x38, 0xa0, 0xbb, 0xc7, 0x44, 0xfa, 0xbc, 0x3, 0x44, 0x2c, 0x9a, 0x6d, 0x98, 0x35, 0x4f, 0x4a, 0x10, 0xc4, 0x17, 0x9, 0x61, 0x6, 0xe1, 0x8d, 0x75]
c = [50, 154, 147, 96, 128, 54, 102, 57, 62, 99, 240, 125, 36, 39, 117, 55, 55, 0, 141, 138, 246, 33, 158, 145, 98, 115, 29, 172, 64, 175, 5, 126, 43, 114, 252, 116, 104, 0, 103, 135, 232, 8]

for i in range(len(xor)):
    c[i] ^= xor[i]

print(bytes(c))
print(xor)
```
