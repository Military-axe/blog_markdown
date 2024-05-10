+++
title = "Obfuscate hide string && zer0pts"
date = 2023-07-17T15:43:19+08:00

[taxonomies]
tags = ["rsa", "obfuscate"]
categories = ["Reverse"]
+++

Obfuscate项目是用于隐藏字符串，增加分析的难度，但是Obfuscate只能对抗静态的分析。zer0pts比赛中的一题就是利用这个项目，但是它很巧妙，隐藏的是模块的函数名，主要逻辑是调用so文件的模块，它隐藏so中的函数名后，从静态分析是很难看出来调用的逻辑是什么，忽然感觉这个项目就有点用了。

<!-- more -->

# Obfuscate 项目使用

github地址：[adamyaxley/Obfuscate: Guaranteed compile-time string literal obfuscation header-only library for C++14 (github.com)](https://github.com/adamyaxley/Obfuscate)

这个项目是对字符串进行加密与解密的一个项目，使用非常简单。

1. 复制`obfuscate.h` 到项目中并include进去
2. 封装字符串`AY_OBFUSCATE("My String")`

源码

```c++
#include <iostream>
#include <string>
#include "obfuscate.h"

int main() 
{
	const std::string username(AY_OBFUSCATE("root"));
	const std::string password(AY_OBFUSCATE("password"));

	std::cout << "Obfuscate naive login example (bloat test)" << std::endl;

	std::string input_username;
	std::string input_password;

	while (true)
	{
		std::cout << "Username: ";
		std::cin >> input_username;

		std::cout << "Password: ";
		std::cin >> input_password;

		if (input_username == username && input_password == password)
		{
			std::cout << "Login success!" << std::endl;
			break;
		}
		else
		{
			std::cout << "Login failure: unrecognised username and password"
				"combination." << std::endl;
		}
	}

	return 0;
}
```

ida打开分析后，发现

```c++
	const std::string username(AY_OBFUSCATE("root"));
	const std::string password(AY_OBFUSCATE("password"));
```

中的两个字符串找不到了，他们无法被静态的找到了，但是动态运行起来后，还是可以在内存中找到这个字符串。所以这个项目只能防护静态分析字符串。

如果只是防护字符串，那还是挺鸡肋的。下面这题用这个隐藏需要调用的函数名，一次来做一个隐藏函数逻辑的方法有一点意思。

# zer0pts mimikyu

题目地址：[ctf/2023/mimikyu at master · Military-axe/ctf (github.com)](https://github.com/Military-axe/ctf/tree/master/2023/mimikyu)

程序很直白，打开main函数看到几乎所有代码

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v4; // rdx
  __int64 v5; // rdx
  unsigned __int64 i; // [rsp+18h] [rbp-78h]
  unsigned __int64 j; // [rsp+20h] [rbp-70h]
  unsigned __int64 k; // [rsp+28h] [rbp-68h]
  char *s; // [rsp+30h] [rbp-60h]
  void *LibraryA; // [rsp+40h] [rbp-50h]
  void *libgmp; // [rsp+48h] [rbp-48h]
  char v12[16]; // [rsp+50h] [rbp-40h] BYREF
  char v13[16]; // [rsp+60h] [rbp-30h] BYREF
  char v14[24]; // [rsp+70h] [rbp-20h] BYREF
  unsigned __int64 v15; // [rsp+88h] [rbp-8h]

  v15 = __readfsqword(0x28u);
  if ( argc > 1 )
  {
    s = (char *)argv[1];
    if ( strlen(s) == 40 )
    {
      LibraryA = (void *)LoadLibraryA("libc.so.6");
      if ( !LibraryA )
        __assert_fail("hLibc != NULL", "main.c", 0x4Au, "main");
      libgmp = (void *)LoadLibraryA("libgmp.so");
      if ( !libgmp )
        __assert_fail("hGMP != NULL", "main.c", 0x4Cu, "main");
      ResolveModuleFunction(libgmp, 1907704461, v12);
      ResolveModuleFunction(libgmp, 1907704461, v13);
      ResolveModuleFunction(libgmp, 1907704461, v14);
      ResolveModuleFunction(LibraryA, -58821864, *(unsigned int *)main);
      ResolveModuleFunction(LibraryA, -1810257824, _bss_start, 0LL);
      printf("Checking...");
      for ( i = 0LL; i < 0x28; ++i )
      {
        if ( !(unsigned int)ResolveModuleFunction(LibraryA, 1317667610, (unsigned int)s[i]) )
        {
LABEL_21:
          puts("\nWrong.");
          goto LABEL_22;
        }
      }
      for ( j = 0LL; j < 0x28; j += 4LL )
      {
        ResolveModuleFunction(libgmp, -249367710, v13, 1LL);
        for ( k = 0LL; k <= 2; ++k )
        {
          ResolveModuleFunction(LibraryA, 13994153, 46LL);
          v4 = (int)ResolveModuleFunction(LibraryA, 2070735453) % 0x10000;
          cap(LibraryA, libgmp, v4, v12);
          ResolveModuleFunction(libgmp, 880641627, v13, v13, v12);
        }
        ResolveModuleFunction(LibraryA, 13994153, 46LL);
        v5 = (int)ResolveModuleFunction(LibraryA, 2070735453) % 0x10000;
        cap(LibraryA, libgmp, v5, v14);
        ResolveModuleFunction(libgmp, -249367710, v12, *(unsigned int *)&s[j]);
        ResolveModuleFunction(libgmp, -1876728194, v12, v12, v14, v13);
        if ( (unsigned int)ResolveModuleFunction(libgmp, -1309138724, v12, encoded[j >> 2]) )
          goto LABEL_21;
      }
      puts("\nCorrect!");
LABEL_22:
      ResolveModuleFunction(libgmp, 835473311, v12);// gmpz_clean
      ResolveModuleFunction(libgmp, 835473311, v13);// gmpz_clean
      ResolveModuleFunction(libgmp, 835473311, v14);// gmpz_clean
      CloseHandle(LibraryA);
      CloseHandle(libgmp);
      return 0;
    }
    else
    {
      puts("Nowhere near close.");
      return 0;
    }
  }
  else
  {
    printf("Usage: %s FLAG\n", *argv);
    return 1;
  }
}
```

会发现`ResolveModuleFunction`函数调用两个so文件模块。其实也可以才出来，应该是调用模块中的函数做一个运算吗，但是用`ResolveModuleFunction`来隐藏具体调用的是哪个函数。

接下来打开`ResolveModuleFunction`函数，看看这个函数做了什么

```c
__int64 ResolveModuleFunction(void *a1, int a2, ...)
{
  __int64 v2; // rax
  __int64 *overflow_arg_area; // rax
  int v5; // [rsp+18h] [rbp-158h]
  int j; // [rsp+1Ch] [rbp-154h]
  int k; // [rsp+20h] [rbp-150h]
  int v8; // [rsp+24h] [rbp-14Ch]
  __int64 v9; // [rsp+28h] [rbp-148h] BYREF
  __int64 v10; // [rsp+30h] [rbp-140h]
  __int64 v11; // [rsp+38h] [rbp-138h]
  __int64 v12; // [rsp+40h] [rbp-130h]
  __int64 *i; // [rsp+48h] [rbp-128h]
  unsigned int *v14; // [rsp+50h] [rbp-120h]
  char *name; // [rsp+58h] [rbp-118h]
  __int64 (__fastcall *v16)(__int64, __int64, __int64, __int64, __int64, __int64); // [rsp+60h] [rbp-110h]
  gcc_va_list va; // [rsp+68h] [rbp-108h] BYREF
  __int64 v18[8]; // [rsp+80h] [rbp-F0h]

  va_start(va, a2);
  v18[7] = __readfsqword(0x28u);
  v9 = 0LL;
  v12 = 0LL;
  if ( !(unsigned int)GetModuleInformation(a1, &v9) )
    __assert_fail("GetModuleInformation(hModule, &lpmodinfo)", "obfuscate.h", 0x71u, "ResolveModuleFunction");
  for ( i = *(__int64 **)(v9 + 16); *i; i += 2 )
  {
    v2 = *i;
    if ( *i == 11 )
    {
      v5 = i[1];
    }
    else if ( v2 <= 11 )
    {
      if ( v2 == 5 )
      {
        v11 = i[1];
      }
      else if ( v2 == 6 )
      {
        v10 = i[1];
      }
    }
  }
  dlerror();
  v8 = v11 - v10;
  for ( j = 0; j < v8 / v5; ++j )
  {
    v14 = (unsigned int *)(24LL * j + v10);
    if ( (v14[1] & 0xF) == 2 )
    {
      name = (char *)(*v14 + v11);
      if ( a2 == (unsigned int)CryptGetHashParam(name) )
      {
        v16 = (__int64 (__fastcall *)(__int64, __int64, __int64, __int64, __int64, __int64))dlsym(a1, name);
        if ( dlerror() )
          BUG();
        for ( k = 0; k <= 5; ++k )
        {
          if ( va[0].gp_offset > 0x2F )
          {
            overflow_arg_area = (__int64 *)va[0].overflow_arg_area;
            va[0].overflow_arg_area = (char *)va[0].overflow_arg_area + 8;
          }
          else
          {
            overflow_arg_area = (__int64 *)((char *)va[0].reg_save_area + va[0].gp_offset);
            va[0].gp_offset += 8;
          }
          v18[k] = *overflow_arg_area;
        }
        return v16(v18[0], v18[1], v18[2], v18[3], v18[4], v18[5]);
      }
    }
  }
  return v12;
}
```

可以看到很关键的两句，一句是

```c
v16 = (__int64 (__fastcall *)(__int64, __int64, __int64, __int64, __int64, __int64))dlsym(a1, name);
```

一句是

```c
 return v16(v18[0], v18[1], v18[2], v18[3], v18[4], v18[5]);
```

可以知道，前面都是解密运算真正的函数名，然后调用`dlsym`就可以获取对应函数的指针，再调用函数指针来运行此函数，做到一个隐藏真正调用函数的过程。

既然知道了这个流程，也非常简单，查看每次调用`ResolveModuleFunction`时，在`dlsym(a1, name)`中的name参数，也就知道此时的`ResolveModuleFunction`等同于那个函数了。

![image-20230717122504520](https://raw.githubusercontent.com/Military-axe/imgtable/main/202307171225131.png)

还原全部的调用后如下

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v4; // rdx
  __int64 v5; // rdx
  unsigned __int64 i; // [rsp+18h] [rbp-78h]
  unsigned __int64 j; // [rsp+20h] [rbp-70h]
  unsigned __int64 k; // [rsp+28h] [rbp-68h]
  char *s; // [rsp+30h] [rbp-60h]
  void *LibraryA; // [rsp+40h] [rbp-50h]
  void *libgmp; // [rsp+48h] [rbp-48h]
  char v12[16]; // [rsp+50h] [rbp-40h] BYREF
  char v13[16]; // [rsp+60h] [rbp-30h] BYREF
  char v14[24]; // [rsp+70h] [rbp-20h] BYREF
  unsigned __int64 v15; // [rsp+88h] [rbp-8h]

  v15 = __readfsqword(0x28u);
  if ( argc > 1 )
  {
    s = (char *)argv[1];
    if ( strlen(s) == 40 )
    {
      LibraryA = (void *)LoadLibraryA("libc.so.6");
      if ( !LibraryA )
        __assert_fail("hLibc != NULL", "main.c", 0x4Au, "main");
      libgmp = (void *)LoadLibraryA("libgmp.so");
      if ( !libgmp )
        __assert_fail("hGMP != NULL", "main.c", 0x4Cu, "main");
      ResolveModuleFunction(libgmp, 1907704461, v12);// gmpz_init
      ResolveModuleFunction(libgmp, 1907704461, v13);// gmpz_init
      ResolveModuleFunction(libgmp, 1907704461, v14);// gmpz_init
      ResolveModuleFunction(LibraryA, -58821864, *(unsigned int *)main);// srand
      ResolveModuleFunction(LibraryA, -1810257824, _bss_start, 0LL);// setbuf
      printf("Checking...");
      for ( i = 0LL; i < 0x28; ++i )
      {
        if ( !(unsigned int)ResolveModuleFunction(LibraryA, 1317667610, (unsigned int)s[i]) )// isprint
        {
LABEL_21:
          puts("\nWrong.");
          goto LABEL_22;
        }
      }
      for ( j = 0LL; j < 0x28; j += 4LL )
      {
        ResolveModuleFunction(libgmp, -249367710, v13, 1LL);// gmpz_set_ui
        for ( k = 0LL; k <= 2; ++k )
        {
          ResolveModuleFunction(LibraryA, 13994153, '.');// putchar
          v4 = (int)ResolveModuleFunction(LibraryA, 2070735453) % 0x10000;// rand
          cap(LibraryA, libgmp, v4, (__int64)v12);
          ResolveModuleFunction(libgmp, 880641627, v13, v13, v12);// gmpz_mul
        }
        ResolveModuleFunction(LibraryA, 13994153, '.');
        v5 = (int)ResolveModuleFunction(LibraryA, 2070735453) % 0x10000;// rand
        cap(LibraryA, libgmp, v5, (__int64)v14);
        ResolveModuleFunction(libgmp, -249367710, v12, *(unsigned int *)&s[j]);// gmpz_set_ui
        ResolveModuleFunction(libgmp, -1876728194, v12, v12, v14, v13);// gmpz_pown
        if ( (unsigned int)ResolveModuleFunction(libgmp, -1309138724, v12, encoded[j >> 2]) )// gmpz_cmp_ui
          goto LABEL_21;
      }
      puts("\nCorrect!");
LABEL_22:
      ResolveModuleFunction(libgmp, 835473311, v12);// gmpz_clean
      ResolveModuleFunction(libgmp, 835473311, v13);// gmpz_clean
      ResolveModuleFunction(libgmp, 835473311, v14);// gmpz_clean
      CloseHandle(LibraryA);
      CloseHandle(libgmp);
      return 0;
    }
    else
    {
      puts("Nowhere near close.");
      return 0;
    }
  }
  else
  {
    printf("Usage: %s FLAG\n", *argv);
    return 1;
  }
}
```

最重要的是下面这两句

```c
ResolveModuleFunction(libgmp, -249367710, v12, *(unsigned int *)&s[j]);// gmpz_set_ui
ResolveModuleFunction(libgmp, -1876728194, v12, v12, v14, v13);// gmpz_pown
if ( (unsigned int)ResolveModuleFunction(libgmp, -1309138724, v12, encoded[j >> 2]) )// gmpz_cmp_ui
     goto LABEL_21;
```

首先是读输入4个字符当做一个32bit数据，然后放入gmpz_pown中加密。其实libgmp是一个大数运算库，可以查到函数调声明的。

`gmpz_pown`就和python中的pow函数类似，需要三个参数`pow(a, b, c)`计算的就是 \\(a^b\bmod c\\) 。

此时a是我们输入的值也就是flag，b，c可以通过动态调试获得。需要注意的值，调用的参数是一个结构体，所以通过查询文档，确定gmp库中调用参数类型结构体如下

```c
void
mpz_powm (mpz_ptr r, mpz_srcptr b, mpz_srcptr e, mpz_srcptr m)// 函数声明，结构体是mpz_t

typedef __mpz_struct *mpz_ptr;

typedef struct
{
  int _mp_alloc;		/* Number of *limbs* allocated and pointed
				   to by the _mp_d field.  */
  int _mp_size;			/* abs(_mp_size) is the number of limbs the
				   last field points to.  If _mp_size is
				   negative this is a negative number.  */
  mp_limb_t *_mp_d;		/* Pointer to the limbs.  */
} __mpz_struct;

typedef unsigned long mp_limb_t;
```

所以可以知道参数结构体中只有三个值，两个int类型，以及一个指针指向存储的内存。

在ida中定义结构体，然后修改三个参数的类型

```c
00000000 mpz_t struc ; (sizeof=0x10, mappedto_8) ; XREF: main/r
00000000                                         ; main/r ...
00000000 _mp_alloc dd ?
00000004 _mp_size dd ?
00000008 _mp_d dq ?
00000010 mpz_t ends
00000010

/// 修改类型

  mpz_t v12; // [rsp+50h] [rbp-40h] BYREF
  mpz_t v13; // [rsp+60h] [rbp-30h] BYREF
  mpz_t v14; // [rsp+70h] [rbp-20h] BYREF
```

再动调获取每次调用`gmpz_powm`的参数值，每次修改一下对比后的跳转，就可以继续调试获取值。获取的值如下

```c
powm_argu = [
    {
        "exp": [0xD3, 0xF0],
        "mod": [0xFF, 0x0D, 0x3A, 0xF2, 0x50, 0x23]
    },
    {
        "exp": [0x5F, 0x08],
        "mod": [0x33, 0x4D, 0x9D, 0x8E, 0xD1, 0x32]
    },
    {
        "exp": [0x63, 0x8E],
        "mod": [0x1B, 0x1F, 0xD7, 0x6C, 0x86, 0x03]
    },
    {
        "exp": [0x49, 0x82],
        "mod": [0x8F, 0xFC, 0xE3, 0x9B, 0xAE, 0x10]
    },
    {
        "exp": [0xA1, 0xC6],
        "mod": [0x7D, 0xF6, 0xEF, 0x42, 0xD9, 0x09]
    },
    {
        "exp": [0x6D, 0x0C],
        "mod": [0xB1, 0x8B, 0xAA, 0xE3, 0xE2, 0x1D]
    },
    {
        "exp": [0xF5, 0xAE],
        "mod": [0xF3, 0x41, 0x58, 0xC6, 0x3F, 0x10]
    },
    {
        "exp": [0xDF, 0xD5],
        "mod": [0xC9, 0xED, 0x70, 0x09, 0x1A, 0x01]
    },
    {
        "exp": [0x8D, 0xE6],
        "mod": [0x39, 0xDF, 0xBD, 0x20, 0x8D, 0x5F]
    },
    {
        "exp": [0xFB, 0xF3],
        "mod": [0xED, 0xE0, 0x11, 0x4E, 0xB1, 0x45]
    }
]
```

这是总过10次加密，每次不同的powm中的指数与模数。

调用gmpz_powm的加密很像rsa，那可以尝试按照rsa的解密方法来解密。先分解`mod`，通过代码中可以知道每个mod是3个因子相乘，每个小于0x10000，直接一路爆破过去，可以得到三个因子，然后就是欧拉函数与求逆了。变成了baby rsa的密码题了

exp:

```python
from Crypto.Util.number import *

powm_argu = [
    {
        "exp": [0xD3, 0xF0],
        "mod": [0xFF, 0x0D, 0x3A, 0xF2, 0x50, 0x23]
    },
    {
        "exp": [0x5F, 0x08],
        "mod": [0x33, 0x4D, 0x9D, 0x8E, 0xD1, 0x32]
    },
    {
        "exp": [0x63, 0x8E],
        "mod": [0x1B, 0x1F, 0xD7, 0x6C, 0x86, 0x03]
    },
    {
        "exp": [0x49, 0x82],
        "mod": [0x8F, 0xFC, 0xE3, 0x9B, 0xAE, 0x10]
    },
    {
        "exp": [0xA1, 0xC6],
        "mod": [0x7D, 0xF6, 0xEF, 0x42, 0xD9, 0x09]
    },
    {
        "exp": [0x6D, 0x0C],
        "mod": [0xB1, 0x8B, 0xAA, 0xE3, 0xE2, 0x1D]
    },
    {
        "exp": [0xF5, 0xAE],
        "mod": [0xF3, 0x41, 0x58, 0xC6, 0x3F, 0x10]
    },
    {
        "exp": [0xDF, 0xD5],
        "mod": [0xC9, 0xED, 0x70, 0x09, 0x1A, 0x01]
    },
    {
        "exp": [0x8D, 0xE6],
        "mod": [0x39, 0xDF, 0xBD, 0x20, 0x8D, 0x5F]
    },
    {
        "exp": [0xFB, 0xF3],
        "mod": [0xED, 0xE0, 0x11, 0x4E, 0xB1, 0x45]
    }
]

encodes = [0x00000FE4C025C5F4, 0x00001B792FF17E8A, 0x00000183B156AB40, 0x00000BEFFCF5E5DA, 0x00000297CF86E251, 0x00000EB3EDC1D4B4, 0x000000FA10CE3A08, 0x0000002BDD418672, 0x00005EBB5050EA46, 0x000005BF9B73CF86]

def factor(x: int) -> list[int]:
    r = []
    for j in range(2, 0x10000):
        if x%j==0:
            r.append(j)
    return r

def inv_x(exp: int, r: list[int]) -> int:
    l = (r[0]-1) * (r[1]-1) * (r[2]-1)
    return inverse(exp, l)

def dec(c: int, x_inv: int, N: int):
    m = pow(c, x_inv, N)
    return m

flag = b''

for i,k in enumerate(powm_argu):
    x = int.from_bytes(bytes(k['exp']),'little')
    N = int.from_bytes(bytes(k['mod']),'little')
    r = factor(N)
    x_inv = inv_x(x, r)
    m = dec(encodes[i], x_inv, N)
    flag += long_to_bytes(m)[::-1]

print(flag)    
```

flag: `zer0pts{L00k_th3_1nt3rn4l_0f_l1br4r13s!}`

```shell
$ ./mimikyu zer0pts{L00k_th3_1nt3rn4l_0f_l1br4r13s!}
Checking...........................................
Correct!
```

# 参考

[GMP-C/C++（大数库）使用方法 - 新望 - 博客园 (cnblogs.com)](https://www.cnblogs.com/xinwang-coding/p/12803237.html)

[adamyaxley/Obfuscate: Guaranteed compile-time string literal obfuscation header-only library for C++14 (github.com)](https://github.com/adamyaxley/Obfuscate)