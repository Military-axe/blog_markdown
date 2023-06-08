+++
title = "GotYouKey"
categories = [
    "Reverse",
]
date = "2023-06-07T13:37:53+08:00"
tags = [
    "reverse",
    "android",
]
+++

前些天没做出来的题目，后面再思考后发现了自己忽略so文件中调用java代码，赛后做了出来整理在此。

<!--more-->


## 分析过程

jadx反编译后看源码，前面都是开线程，开端口，都不关键，直接到`com.hack.gotyourkey.Oooo000`中看到关键函数
![image.png](https://raw.githubusercontent.com/Military-axe/imgtable/main/202306071519119.png)
只有这个`check`函数关键其他的都是加的，传入`check`函数中的就是输入的值。
进入之后是AES加密和base64换表
![image.png](https://raw.githubusercontent.com/Military-axe/imgtable/main/202306071519871.png)
接出来得到flag: `flag{345ghyuj!$}`

```shell
from Crypto.Cipher import AES
import base64

str1 = "UGCA3QBFjPnlAZ6-NbV2Ca^^"
string1 = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-+^"
string2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
key = b'1234567890abcdef'
c = base64.b64decode(str1.translate(str.maketrans(string1,string2)))

e = AES.new(key, AES.MODE_ECB)
m = e.decrypt(c)
print(m)
```

但是这个flag是假的，继续分析后发现，存在一个`libgotyoukey.so`
打开后在`JNI_OnLoad`函数存在很多逻辑
![image.png](https://raw.githubusercontent.com/Military-axe/imgtable/main/202306071519549.png)
进入`core`函数后，设置第一个参数为`JNIEnv *`
可以发现core中的函数是调用各种java中的函数，还原函数类型后，重命名后逻辑如下

```basic
v54 = FindClass(env, "android/app/ActivityThread");
v53 = GetStaticFieldID(env, v54, "sCurrentActivityThread", "Landroid/app/ActivityThread;");
v52 = GetFieldID(env, v54, "mInitialApplication", "Landroid/app/Application;");
v51 = GetStaticObjectField(env, v54, v53);
v50 = GetObjectField(env, v51, v52);
v49 = FindClass(env, "android/app/Application");
v48 = GetMethodID(env, v49, "getAssets", "()Landroid/content/res/AssetManager;");
v47 = CallObjectMethodV(env, v50, v48);
v46 = FindClass(env, "android/content/res/AssetManager");
v45 = GetMethodID(env, v46, "openFd", "(Ljava/lang/String;)Landroid/content/res/AssetFileDescriptor;");
v44 = NewStringUTF(env, "asset.bin");
v43 = CallObjectMethodV(env, v47, v45, v44);
v42 = FindClass(env, "android/content/res/AssetFileDescriptor");
v41 = GetMethodID(env, v42, "getLength", "()J");
length = CallLongMethodV(env, v43, v41);
v39 = GetMethodID(env, v46, "open", "(Ljava/lang/String;)Ljava/io/InputStream;");
v38 = CallObjectMethodV(env, v47, v39, v44);
new_array = NewByteArray(env, length);
v36 = FindClass(env, "java/io/InputStream");
v35 = GetMethodID(env, v36, "read", "([BII)I");
my_input = CallIntMethodV(env, v38, v35, new_array, 0LL, length);
v33 = malloc(length);
if ( my_input > 0 )
  GetByteArrayRegion(env, new_array, 0, length, v33);
  v32 = malloc(length);
  rc4("goodluck", v33, length, v32);
  SetByteArrayRegion(env, new_array, 0, length, v32);
  if ( v32 )
    free(v32);
    if ( v33 )
      free(v33);
      v31 = FindClass(env, "java/nio/ByteBuffer");
      v30 = GetStaticMethodID(env, v31, "allocate", "(I)Ljava/nio/ByteBuffer;");
      v29 = CallStaticObjectMethodV(env, v31, v30, length);
      v28 = GetMethodID(env, v31, "put", "([B)Ljava/nio/ByteBuffer;");
      v27 = GetMethodID(env, v31, "position", "(I)Ljava/nio/Buffer;");
      CallObjectMethodV(env, v29, v28, new_array);
      CallObjectMethodV(env, v29, v27, 0LL);
      v26 = FindClass(env, "com/hack/gotyourkey/MainActivity");
      v25 = FindClass(env, "java/lang/Class");
      v24 = GetMethodID(env, v25, "getClassLoader", "()Ljava/lang/ClassLoader;");
      v23 = CallObjectMethodV(env, v26, v24);
      v22 = FindClass(env, "dalvik/system/PathClassLoader");
      v21 = GetFieldID(env, v22, "pathList", "Ldalvik/system/DexPathList;");
      v20 = FindClass(env, "dalvik/system/DexPathList");
      v19 = GetFieldID(env, v20, "dexElements", "[Ldalvik/system/DexPathList$Element;");
      v18 = FindClass(env, "dalvik/system/InMemoryDexClassLoader");
      v17 = GetMethodID(env, v18, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
      v16 = NewObjectV(env, v18, v17, v29, v23);
      v15 = GetObjectField(env, v16, v21);
      v14 = GetObjectField(env, v15, v19);
      v13 = GetObjectField(env, v23, v21);
      v12 = GetObjectField(env, v13, v19);
      v11 = FindClass(env, "java/util/ArrayList");
      v10 = GetMethodID(env, v11, "add", "(Ljava/lang/Object;)Z");
      v9 = GetMethodID(env, v11, "toArray", "()[Ljava/lang/Object;");
      v8 = GetMethodID(env, v11, "<init>", "()V");
      v7 = NewObjectV(env, v11, v8);
      for ( i = 0; i < GetArrayLength(env, v14); ++i )
        {
        v5 = GetObjectArrayElement(env, v14, i);
        CallBooleanMethodV(env, v7, v10, v5);
        }
        for ( j = 0; j < GetArrayLength(env, v12); ++j )
          {
          v3 = GetObjectArrayElement(env, v12, j);
          CallBooleanMethodV(env, v7, v10, v3);
          }
          v1 = CallObjectMethodV(env, v7, v9);
          return SetObjectField(env, v13, v19, v1);
```

中间调用了一个rc4，key是`goodluck`
直接给chatgpt解释后知道，这里用rc4解密了asset.bin这个文件，然后加载进入apk，中间都是使用java的函数。所以还原了之后很好做
解密asset.bin代码

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void rc4_init(unsigned char* s, unsigned char* key,
              unsigned long len)   // s最开始是传入的长度为256的char型空数组，用来存放初始化后的s
    // key是密钥，内容可定义  //最后一个len是密钥的长度
{
    int           i      = 0;
    int           j      = 0;
    unsigned char k[256] = {0};
    unsigned char temp   = 0;
    for (i = 0; i < 256; i++) {
        s[i] = i;              // 0-255赋给s
        k[i] = key[i % len];   // 将k重新计算
    }
    for (i = 0; i < 256; i++) {
        j    = (j + s[i] + k[i]) % 256;   // 给j赋
        temp = s[i];
        s[i] = s[j];
        s[j] = temp;   // s[i]和s[j]交换
    }
}

void rc4_crypt(unsigned char* s, unsigned char* data,
               unsigned long len)   // s是上面初始化之后的，data是我们要加密的数据，len是data的长度
{
    int           i = 0, j = 0, t = 0;
    unsigned long k = 0;
    unsigned char temp;
    for (k = 0; k < len; k++) {
        i    = (i + 1) % 256;      // 固定方式生成的i
        j    = (j + s[i]) % 256;   // 固定方式生成的j
        temp = s[i];
        s[i] = s[j];
        s[j] = temp;                  // 交换
        t    = (s[i] + s[j]) % 256;   // 固定方式生成的t
        data[k] ^= s[t];              // 异或运算
    }
}

int main()
{
    unsigned char  s[256]   = {0};
    unsigned char  s2[256]  = {0};
    unsigned char  key[256] = {"goodluck"};
    unsigned char* data;
    unsigned long  len;
    FILE*          file1;
    FILE*          file2;

    file1 = fopen("./asset.bin", "rb");

    fseek(file1, 0, SEEK_END);
    len = ftell(file1);
    printf("file len: %ld \r\n", len);

    data = calloc(len + 1, sizeof(unsigned char));
    rewind(file1);
    fread(data, sizeof(unsigned char), len, file1);
    fclose(file1);

    rc4_init(s, (unsigned char*)key, strlen((const char*)key));
    rc4_crypt(s, (unsigned char*)data, len);

    file2 = fopen("./dec", "wb");
    fwrite(data, sizeof(unsigned char), len, file2);
    fclose(file2);
}
```

解密之后发现和原来的逻辑几乎一样，但是在最关节的check函数不同

![image.png](https://raw.githubusercontent.com/Military-axe/imgtable/main/202306071519480.png)

这里是base64换表和rc4加密，不是原来的base+aes
所以，直接base64换表后rc4解密

![image.png](https://raw.githubusercontent.com/Military-axe/imgtable/main/202306071519880.png)

但是得到这个flag: `flag{ikjnmkjh±$}`还是过不了原apk的check
通过调试发现，密文变了不是`SSro3CogRALMhCnQRBDyWa^^`变成了`SSro3CogRALMhCnQRG9yWa^^`

![fa686bcd2089778e03832656e34b71c.png](https://raw.githubusercontent.com/Military-axe/imgtable/main/202306071519811.png)

所以再用`SSro3CogRALMhCnQRG9yWa^^`解密一次，得到flag: `flag{ikjnmkjh@$}`，这就可以过check了

![7c41a84fd36fb8cf5da333553b0480e.jpg](https://raw.githubusercontent.com/Military-axe/imgtable/main/202306071519143.jpeg)