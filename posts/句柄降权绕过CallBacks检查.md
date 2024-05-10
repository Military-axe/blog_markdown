+++
title = "句柄降权绕过CallBacks检查"
date = 2024-04-29T22:01:29+08:00

[taxonomies]
tags = ["windows", "句柄降权", "x64"]
categories = ["Driver"]
+++

ObRegistyCallBacks保护指定进程，可以让攻击程序OpenProcess打开指定进程后获取的句柄权限是我们指定的权限范围, 比如不能读取进程内存, 不能终止进程。

如何绕过这种保护，可以使用句柄降权/提权的方法，就可以对提高已经获取到的句柄权限。

<!-- more -->

# 句柄降权

## 什么是句柄

当一个进程利用名称来创建或打开一个对象时，将获得一个句柄，该句柄指向所创建或打开的对象。以后，该进程无须使用名称来引用该对象，使用此句柄即可访问。这样做可以显著地提高引用对象的效率。句柄是一个在软件设计中被广泛使用的概念。例如，在C运行库中，文件操作使用句柄来表示，每当应用程序创建或打开一个文件时，只要此创建或打开操作成功，则C运行库返回一个句柄。以后应用程序对文件的读写操作都使用此句柄来标识该文件。而且，如果两个应用程序以共享方式打开了同一个文件，那么，它们将分别得到各自的句柄，且都可以通过句柄操作该文件。尽管两个应用程序得到的句柄的值并不相同，但是这两个句柄所指的文件却是同一个。因此，句柄只是一个对象引用，同一个对象在不同的环境下可能有不同的引用（句柄）值。

上文中的"对象"指的是内核对象，我们在R3中所使用的文件、进程、线程在内核中都有对应内核对象。应用层每次创建或打开进程、文件都会对相应的内核对象创建一个句柄。当多个进程同时打开一个文件时，该文件在内核中只会存在一个文件内核对象，但每个进程都有一个各自的文件句柄，每个句柄会增加内核对象的引用计数，只有当内核对象的引用计数为0时，内核对象才会释放。

## 私有句柄表

![image-20240427100234291](https://s2.loli.net/2024/04/29/XAuz3r5m7bEqVPv.png)

`eprocess`指向一个`ObjectTable`，`ObjectTbale`中存在`TableCode`，这个指向的是这个进程的私有句柄表。同时`ObjectTable`中还有一个`HandleTableList`，这个是一个链表，通过`HandleTableList` 成员遍历得到所有进程的`ObjectTable`地址

我们的目标是获取到`_object_header`结构体，这个结构体才是句柄的真正内容。但是不同版本系统下的取法不太一样，win7是直接指向句柄，win10则需要做一些偏移，这些偏移google没有资料，大多都是通过IDA静态分析函数才能得到。

win中有一些根据_handle_table_entry获取进程句柄的函数，我这里没有做过多分析，直接使用前辈分析后的经验。分析目标`ntoskrnl.exe`下的`ObpEnumFindHandleProcedure`函数，可以看到如下

```c
__int64 __fastcall ObpEnumFindHandleProcedure(
        _HANDLE_TABLE *handle_table,
        _HANDLE_TABLE_ENTRY *handle_table_entry,
        HANDLE a3,
        HANDLE *object_header)
{
  unsigned __int8 v5; // bl
  HANDLE v7; // rbx
  _DWORD *v8; // rcx
  __int64 v9; // r11
  int v10[10]; // [rsp+0h] [rbp-28h] BYREF

  if ( !*object_header || *object_header == (HANDLE)((handle_table_entry->LowValue >> 16) & 0xFFFFFFFFFFFFFFF0ui64) )
  {
    v7 = object_header[1];
    if ( !v7
      || v7 == (HANDLE)ObTypeIndexTable[(unsigned __int8)ObHeaderCookie ^ *(unsigned __int8 *)(((handle_table_entry->LowValue >> 16) & 0xFFFFFFFFFFFFFFF0ui64)
                                                                                             + 0x18) ^ (unsigned __int64)(unsigned __int8)((unsigned __int16)(WORD1(handle_table_entry->LowValue) & 0xFFF0) >> 8)] )
    {
      v8 = object_header[2];
      if ( !v8 )
        goto LABEL_11;
      v9 = (handle_table_entry->LowValue >> 17) & 7;
      if ( (*(_DWORD *)(&handle_table_entry->4 + 1) & 0x2000000) != 0 )
        LOBYTE(v9) = v9 | 8;
      if ( *v8 == (v9 & 7) && v8[1] == (*(_DWORD *)(&handle_table_entry->4 + 1) & 0x1FFFFFF) )
LABEL_11:
        v5 = 1;
      else
        v5 = 0;
    }
    else
    {
      v5 = 0;
    }
  }
  else
  {
    v5 = 0;
  }
  _InterlockedExchangeAdd64(&handle_table_entry->VolatileLowValue, 1ui64);
  _InterlockedOr(v10, 0);
  if ( handle_table->HandleContentionEvent.Value )
    ExfUnblockPushLock(&handle_table->HandleContentionEvent, 0i64);
  return v5;
}
```

可以在开头部分看到`(handle_table_entry->LowValue >> 16) & 0xFFFFFFFFFFFFFFF0ui64)`，这样才能获取到句柄内容，获取到`_object_header`.

但是我自己尝试的时候没有获取到，直到我注意到帖子里面最后得到的值开头都是`0xffff`，这说明右移前面不是补充0，而是补充1

所以地址计算实际是：`(handle_table_entry->LowValue >> 16) & 0xFFFFFFFFFFFFFFF0ui64) + 0xffff000000000000`

得到的就是`_OBJECT_HEADER`，这表示一个句柄头，句柄体在body的位置，我系统版本的偏移是0x30，进程句柄的话就是_`eprocess`结构体

```c
//0x38 bytes (sizeof)
struct _OBJECT_HEADER
{
    LONGLONG PointerCount;                                                  //0x0
    union
    {
        LONGLONG HandleCount;                                               //0x8
        VOID* NextToFree;                                                   //0x8
    };
    struct _EX_PUSH_LOCK Lock;                                              //0x10
    UCHAR TypeIndex;                                                        //0x18
    union
    {
        UCHAR TraceFlags;                                                   //0x19
        struct
        {
            UCHAR DbgRefTrace:1;                                            //0x19
            UCHAR DbgTracePermanent:1;                                      //0x19
        };
    };
    UCHAR InfoMask;                                                         //0x1a
    union
    {
        UCHAR Flags;                                                        //0x1b
        struct
        {
            UCHAR NewObject:1;                                              //0x1b
            UCHAR KernelObject:1;                                           //0x1b
            UCHAR KernelOnlyAccess:1;                                       //0x1b
            UCHAR ExclusiveObject:1;                                        //0x1b
            UCHAR PermanentObject:1;                                        //0x1b
            UCHAR DefaultSecurityQuota:1;                                   //0x1b
            UCHAR SingleHandleEntry:1;                                      //0x1b
            UCHAR DeletedInline:1;                                          //0x1b
        };
    };
    ULONG Reserved;                                                         //0x1c
    union
    {
        struct _OBJECT_CREATE_INFORMATION* ObjectCreateInfo;                //0x20
        VOID* QuotaBlockCharged;                                            //0x20
    };
    VOID* SecurityDescriptor;                                               //0x28
    struct _QUAD Body;                                                      //0x30
}; 
```

0x18位置的TypeIndex表示这个句柄对应的对象是一个什么类型的对象，比如文件、进程、线程等，0x30的Body就是便指向了该句柄对应的对象结构。若句柄对应的对象是一个进程对象那么0x30的位置存的就是对应进程对象的`_EPROCESS`的结构，可以从这个结构便获得进程名、进程ID等等信息。

所以在内核中有一个链表存放了每一个进程的私有句柄表。

## TableCode句柄表

句柄表是以页为单位，两层句柄表则是第一层存放第二层的指针，一般只有系统进程才会打开那么多的句柄，恶意进程通常只有一层。win10的机器上tablecode是存放了一页的handle_table_entry，每一个16字节，一页大小是4k，所以一页最多256个句柄。（32位系统的是一页512个句柄）

**怎么判断句柄表有几层？**

TableCode的最后2个bit表示层数（有的文章说是3个bit，我也不确定）,但是目前我看最多的也只有两层，下面分别是0层和1层的情况。

![image-20240427100430264](https://s2.loli.net/2024/04/29/dEIlA19MrjFNV5L.png)

可以看到tablecode句柄表的内容不是句柄，而是`_handle_table_entry`，这不是一个结构体，是一个union

![image-20240427100507003](https://s2.loli.net/2024/04/29/bIXg3JmWzkBpilU.png)

从handle_table_entry到句柄还需要一些额外的计算变化，同时一个进程句柄的权限就标注在每个句柄对应的这个结构体当中

## Windbg 调试

以手动的方式从一个eprocess内存看到他下面的句柄表

windbg以内核附加模式连接上虚拟机/真机后，首先我们需要一个EPROCESS结构体地址，使用`!process 0 0`查看所有进程的基本信息

```c
3: kd> !process 0 0
**** NT ACTIVE PROCESS DUMP ****
PROCESS ffffbf8eaa092040
    SessionId: none  Cid: 0004    Peb: 00000000  ParentCid: 0000
    DirBase: 001ad000  ObjectTable: ffffd00b12a10840  HandleCount: 1715.
    Image: System

PROCESS ffffbf8eab1ea080
    SessionId: 0  Cid: 01d8    Peb: bbe935c000  ParentCid: 01cc
    DirBase: 2364c9000  ObjectTable: ffffd00b145784c0  HandleCount: 462.
    Image: csrss.exe
```

PROCESS的值就是EPROCESS的地址值, 我这里选用csrss.exe的PROCESS值`ffffbf8eab1ea080`

定位`ObjectTable`的值

```c
3: kd> dt ffffbf8eab1ea080 nt!_EPROCESS -y object
   +0x570 ObjectTable : 0xffffd00b`145784c0 _HANDLE_TABLE
```

再进一步查看_HANDLE_TABLE结构体，定位TableCode的值

```c
3: kd> dt 0xffffd00b`145784c0 _HANDLE_TABLE
ntdll!_HANDLE_TABLE
   +0x000 NextHandleNeedingPool : 0x800
   +0x004 ExtraInfoPages   : 0n0
   +0x008 TableCode        : 0xffffd00b`16d58001
   +0x010 QuotaProcess     : 0xffffbf8e`ab1ea080 _EPROCESS
   +0x018 HandleTableList  : _LIST_ENTRY [ 0xffffd00b`167057d8 - 0xffffd00b`140fde18 ]
   +0x028 UniqueProcessId  : 0x1d8
   +0x02c Flags            : 0x12
   +0x02c StrictFIFO       : 0y0
   +0x02c EnableHandleExceptions : 0y1
   +0x02c Rundown          : 0y0
   +0x02c Duplicated       : 0y0
   +0x02c RaiseUMExceptionOnInvalidHandleClose : 0y1
   +0x030 HandleContentionEvent : _EX_PUSH_LOCK
   +0x038 HandleTableLock  : _EX_PUSH_LOCK
   +0x040 FreeLists        : [1] _HANDLE_TABLE_FREE_LIST
   +0x040 ActualEntry      : [32]  ""
   +0x060 DebugInfo        : (null) 
```

得到TableCode的值是0xffffd00b`16d58001，注意TableCode最后的一位是1，这表示有两层页表，第一层的值是指向的第二层的指针，所以先查看第一层句柄指针表

```c
2: kd> dq 0xffffd00b`16d58000 
ffffd00b`16d58000  ffffd00b`16667000 ffffd00b`16d59000
ffffd00b`16d58010  ffffd00b`19a4c000 00000000`00000000
ffffd00b`16d58020  00000000`00000000 00000000`00000000
ffffd00b`16d58030  00000000`00000000 00000000`00000000
ffffd00b`16d58040  00000000`00000000 00000000`00000000
ffffd00b`16d58050  00000000`00000000 00000000`00000000
ffffd00b`16d58060  00000000`00000000 00000000`00000000
ffffd00b`16d58070  00000000`00000000 00000000`00000000
```

看到有3个二层句柄表，我们选用第一张表

```c
2: kd> dq ffffd00b`16667000
ffffd00b`16667000  00000000`00000000 00000000`00000000
ffffd00b`16667010  bf8eaaee`9430ffff 00000000`001f0003
ffffd00b`16667020  bf8eaaee`ae30fffb 00000000`001f0003
ffffd00b`16667030  bf8eab18`25b0fffd 00000000`00000001
ffffd00b`16667040  bf8eaaec`6890ffc3 00000000`001f0003
ffffd00b`16667050  bf8eab1e`ba40ffc3 00000000`000f00ff
ffffd00b`16667060  bf8eab18`bb00ffff 00000000`00100002
ffffd00b`16667070  bf8eab18`1b20ffff 00000000`00000001
```

可以看到从ffffd00b`16667010开始每16字节表示一个_handle_table_entry union体

```c
2: kd> dt _handle_table_entry ffffd00b`16667010
nt!_HANDLE_TABLE_ENTRY
   +0x000 VolatileLowValue : 0n-4643586224107225089
   +0x000 LowValue         : 0n-4643586224107225089
   +0x000 InfoTable        : 0xbf8eaaee`9430ffff _HANDLE_TABLE_ENTRY_INFO
   +0x008 HighValue        : 0n2031619
   +0x008 NextFreeHandleEntry : 0x00000000`001f0003 _HANDLE_TABLE_ENTRY
   +0x008 LeafHandleValue  : _EXHANDLE
   +0x000 RefCountField    : 0n-4643586224107225089
   +0x000 Unlocked         : 0y1
   +0x000 RefCnt           : 0y0111111111111111 (0x7fff)
   +0x000 Attributes       : 0y000
   +0x000 ObjectPointerBits : 0y10111111100011101010101011101110100101000011 (0xbf8eaaee943)
   +0x008 GrantedAccessBits : 0y0000111110000000000000011 (0x1f0003)
   +0x008 NoRightsUpgrade  : 0y0
   +0x008 Spare1           : 0y000000 (0)
   +0x00c Spare2           : 0
```

`(handle_table_entry->LowValue >> 16) & 0xFFFFFFFFFFFFFFF0ui64)`获取_object_header结构体，记得前面填充的要是1，计算一下值

```python
In [2]: hex(((0xbf8eaaee9430ffff >> 0x10) & 0xFFFFF                               
   ...: FFFFFFFFFF0) | ((0xffff) << 48))                                          
Out[2]: '0xffffbf8eaaee9430'
```

`0xbf8eaaee9430ffff`是`ffffd00b16667010`的值，对应的就是`handle_table_entry->LowValue`，得到地址`0xffffbf8eaaee9430`也就是_object_header

```c
3: kd> dt _object_header 0xffffbf8eaaee9430
nt!_OBJECT_HEADER
   +0x000 PointerCount     : 0n32768
   +0x008 HandleCount      : 0n1
   +0x008 NextToFree       : 0x00000000`00000001 Void
   +0x010 Lock             : _EX_PUSH_LOCK
   +0x018 TypeIndex        : 0xaa ''
   +0x019 TraceFlags       : 0 ''
   +0x019 DbgRefTrace      : 0y0
   +0x019 DbgTracePermanent : 0y0
   +0x01a InfoMask         : 0x8 ''
   +0x01b Flags            : 0 ''
   +0x01b NewObject        : 0y0
   +0x01b KernelObject     : 0y0
   +0x01b KernelOnlyAccess : 0y0
   +0x01b ExclusiveObject  : 0y0
   +0x01b PermanentObject  : 0y0
   +0x01b DefaultSecurityQuota : 0y0
   +0x01b SingleHandleEntry : 0y0
   +0x01b DeletedInline    : 0y0
   +0x01c Reserved         : 0
   +0x020 ObjectCreateInfo : 0xfffff807`28e53780 _OBJECT_CREATE_INFORMATION
   +0x020 QuotaBlockCharged : 0xfffff807`28e53780 Void
   +0x028 SecurityDescriptor : (null) 
   +0x030 Body             : _QUAD
```

可以看到整个object_header的内容，这只是句柄的头部，句柄的内容还在0x30偏移的位置，由于我调试发现这一个进程句柄，所以直接用eprocess展示这个句柄内容。

```c
3: kd> dt _EPROCESS 0xffffbf8eaaee9430 + 0x30
nt!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x438 ProcessLock      : _EX_PUSH_LOCK
   +0x440 UniqueProcessId  : 0xffffbf8e`aaee9ba0 Void
   +0x448 ActiveProcessLinks : _LIST_ENTRY [ 0xffffbf8e`aaec6370 - 0xffffbf8e`ac4330e0 ]
   +0x458 RundownProtect   : _EX_RUNDOWN_REF
   +0x460 Flags2           : 0xcdb1a88a
   ...
```

这样就通过进程的私有句柄表获得了被打开句柄进程的信息。

## 判断句柄类型

怎么样从一个句柄头(_object_header)判断出这是一个进程句柄(process handle)，文件句柄(file handle)还是设备句柄(device handle)

这个不同版本的系统判断方法不一样，win7/8/8.1是一样的 win10则不同。网络上大多都是win7, win8的我在这篇[外网文章](https://medium.com/@ashabdalhalim/a-light-on-windows-10s-object-header-typeindex-value-e8f907e7073a)上才找到win10的判断方法

### win7/8/8.1

这几个版本的_object_header结构大致如下

```c
//0x38 bytes (sizeof)
struct _OBJECT_HEADER
{
    LONGLONG PointerCount;                                                  //0x0
    union
    {
        LONGLONG HandleCount;                                               //0x8
        VOID* NextToFree;                                                   //0x8
    };
    struct _EX_PUSH_LOCK Lock;                                              //0x10
    UCHAR TypeIndex;                                                        //0x18
    UCHAR TraceFlags;                                                       //0x19
    UCHAR InfoMask;                                                         //0x1a
    UCHAR Flags;                                                            //0x1b
    union
    {
        struct _OBJECT_CREATE_INFORMATION* ObjectCreateInfo;                //0x20
        VOID* QuotaBlockCharged;                                            //0x20
    };
    VOID* SecurityDescriptor;                                               //0x28
    struct _QUAD Body;                                                      //0x30
}; 
```

一般直接TypeIndex表示这个句柄的类型index。相同的类型这个值会相同，还可以进一步查看这个index在`nt!object_type`这个表中的具体信息

![image-20240427100941481](https://s2.loli.net/2024/04/29/t2pnKEHbC3QDIez.png)

上面就是`Typeindex = 7`对应的意义，是进程句柄

### win10

win10的`Typeindex`就不一样了，测试会发现，哪怕都是进程句柄这个`Typeindex`的值也会不同。

需要将3个单字节的值异或起来，`Typeindex ^ nt!ObHeaderCookie ^ 地址的第二个字节`

![image-20240427101048535](https://s2.loli.net/2024/04/29/97xnmAgJDQ5zLKy.png)

最后得到的才是真的Typeindex

## 句柄降权/提权

一个句柄的权限，表示句柄拥有者对这个句柄的操作权限，权限有以下几种

```c
#define PROCESS_TERMINATE                  (0x0001)  
#define PROCESS_CREATE_THREAD              (0x0002)  
#define PROCESS_SET_SESSIONID              (0x0004)  
#define PROCESS_VM_OPERATION               (0x0008)  
#define PROCESS_VM_READ                    (0x0010)  
#define PROCESS_VM_WRITE                   (0x0020)  
#define PROCESS_DUP_HANDLE                 (0x0040)  
#define PROCESS_CREATE_PROCESS             (0x0080)  
#define PROCESS_SET_QUOTA                  (0x0100)  
#define PROCESS_SET_INFORMATION            (0x0200)  
#define PROCESS_QUERY_INFORMATION          (0x0400)  
#define PROCESS_SUSPEND_RESUME             (0x0800)  
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)  
#define PROCESS_SET_LIMITED_INFORMATION    (0x2000)  
#if (NTDDI_VERSION >= NTDDI_VISTA)
#define PROCESS_ALL_ACCESS        (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \0xFFFF)
```

当我们通过`OpenProcess`以多种权限申请打开进程时便将多种权限或运算就得到了我们想要的权限值，我们的目的是为了降低句柄拥有者对我们要保护的进程的操作权限，那最简单暴力的方法便是把`handle_table_entry->GrantedAccessBits`的值修改成我们设定的值，直接让句柄拥有者对我们的进程操作权限被修改。

```c
//0x10 bytes (sizeof)
union _HANDLE_TABLE_ENTRY
{
    volatile LONGLONG VolatileLowValue;                                     //0x0
    LONGLONG LowValue;                                                      //0x0
    struct
    {
        struct _HANDLE_TABLE_ENTRY_INFO* volatile InfoTable;                //0x0
    LONGLONG HighValue;                                                     //0x8
    union _HANDLE_TABLE_ENTRY* NextFreeHandleEntry;                         //0x8
        struct _EXHANDLE LeafHandleValue;                                   //0x8
    };
    LONGLONG RefCountField;                                                 //0x0
    ULONGLONG Unlocked:1;                                                   //0x0
    ULONGLONG RefCnt:16;                                                    //0x0
    ULONGLONG Attributes:3;                                                 //0x0
    struct
    {
        ULONGLONG ObjectPointerBits:44;                                     //0x0
    ULONG GrantedAccessBits:25;                                             //0x8
    ULONG NoRightsUpgrade:1;                                                //0x8
        ULONG Spare1:6;                                                     //0x8
    };
    ULONG Spare2;                                                           //0xc
}; 
```

![image-20240427101135672](https://s2.loli.net/2024/04/29/gtmIaVLpNdEnZS1.png)

## 代码实现防止CE读取进程内存

现在假设一个场景，我们打开一个记事本(notepad.exe)，然后用CE去读取这个进程的内存。我们的目标是保护这个记事本进程，让降低CE中已经打开的记事本进程句柄权限，让CE无法再继续读取内存。

首先CE打开目标进程

![image-20240427101154597](https://s2.loli.net/2024/04/29/EjYorzmwSiIWy8U.png)

我这里直接写死进程号了，使用`PsLookupProcessByProcessId`获取指定PID的`eprocess`结构体

```c
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pRegPath)
{
    PEPROCESS eprocess = NULL;
    NTSTATUS  status   = PsLookupProcessByProcessId((HANDLE)0xab4, &eprocess);
    if (!NT_SUCCESS(status)) {
        kprintf("Open process  unsuccessfully!\r\n");
        return STATUS_UNSUCCESSFUL;
    }
    ObDereferenceObject(eprocess);
    ProtectProcessHandleByEprocess(eprocess);

    pDriver->DriverUnload = DriveUnload;

    return STATUS_SUCCESS;
}
```

然后开始写`ProtectProcessHandleByEprocess`函数，这个函数才是主要的逻辑，传入指定`eprocess`，然后遍历链表所有的句柄表，匹配是否相同，如果相同则修改权限。

我首先定义两个结构体，方便后面编程

```c
typedef struct HANDLE_TABLE_ENTRY
{
    UINT64 LowValue;
    UINT32 GrantedAccessBits;
    UINT32 Spare2;
} *PHANDLE_TABLE_ENTRY, HANDLE_TABLE_ENTRY;

/// @brief 存放每个进程的信息
typedef struct PROCESS_HANDLE_OBJECT
{
    PEPROCESS           eprocess;
    PHANDLE_TABLE_ENTRY table_code;
} *PPROCESS_HANDLE_OBJECT, PROCESS_HANDLE_OBJECT;
```

然后给这两个结构体定义了几个方法

-   `CheckHandleTableEntry`：检查HANDLE_TABLE_ENTRY的值是否合法
-   `NewProcessHandleObject`：新建一个PROCESS_HANDLE_OBJECT结构体
-   `FreeProcessHandleObject`：释放一个PROCESS_HANDLE_OBJECT结构体
-   `HandleEntryTable2ObjectHeader`: 计算单个handle_table_entry转化成object_header地址

```c
/// @brief
/// 检查一个PHANDLE_TABLE_ENTRY中的数值是否合法，LowValue是否为0，合法返回TRUE，否则返回FALSE
/// @param pHandleTableEntry PHANDLE_TABLE_ENTRY指针
/// @return 合法返回TRUE，否则返回FALSE
BOOLEAN CheckHandleTableEntry(PHANDLE_TABLE_ENTRY pHandleTableEntry)
{
    if (!pHandleTableEntry->LowValue) {
        return FALSE;
    }

    return TRUE;
}

/// @brief
/// 新建一个PROCESS_HANDLE_OBJECT结构体。传入eprocess地址或者handle_table地址，二者至少其一
/// 创建成功返回结构体指针，失败则返回NULL
/// @param pEprocess eprocess地址或者NULL
/// @param pHandleTable _handle_table地址或者NULL
/// @return 创建成功返回结构体指针，失败则返回NULL
PPROCESS_HANDLE_OBJECT NewProcessHandleObject(PEPROCESS pEprocess,
                                              PVOID64   pHandleTable)
{
    UINT64                 uTableCode;
    PPROCESS_HANDLE_OBJECT ptr;

    if (pEprocess == NULL && pHandleTable == NULL) {
        return NULL;
    }

    if (pEprocess == NULL) {
        pEprocess = *(PUINT64)((PUCHAR)pHandleTable +
                               WIN10_21H1_X64_QUOTOPROCESS_OFFSET);
    }

    if (pHandleTable == NULL) {
        pHandleTable =
            *(PUINT64)((PUCHAR)pEprocess + WIN10_21H1_X64_OBJECTTABLE_OFFSET);
    }

    uTableCode =
        *(PUINT64)((PUINT8)pHandleTable + WIN10_21H1_X64_TABLECODE_OFFSET);
    ptr = ExAllocatePool(NonPagedPool, sizeof(PROCESS_HANDLE_OBJECT));
    if (ptr == NULL) {
        kprintf("[!] Alloc struct PROCESS_HANDLE_OBJECT faild\r\n");
        return NULL;
    }

    ptr->eprocess   = pEprocess;
    ptr->table_code = uTableCode;
}

/// @brief 销毁PROCESS_HANDLE_OBJECT结构体，传入一个对应指针
/// @param pProcessHandlePbject PROCESS_HANDLE_OBJECT的指针
/// @return
VOID FreeProcessHandleObject(PPROCESS_HANDLE_OBJECT pProcessHandlePbject)
{
    pProcessHandlePbject->eprocess   = NULL;
    pProcessHandlePbject->table_code = 0;

    ExFreePool(pProcessHandlePbject);
}

/// @brief 传入一个HANDLE_TABLE_ENTRY结构体的地址，计算出ObjectHeader地址
/// @param addr HANDLE_TABLE_ENTRY结构体的地址
/// @return 返回ObjectHeader地址
ULONG64 HandleEntryTable2ObjectHeader(PHANDLE_TABLE_ENTRY addr)
{
    return ((addr->LowValue >> 0x10) & 0xFFFFFFFFFFFFFFF0) + 0xFFFF000000000000;
}
```

然后看一下ProtectProcessHandleByEprocess函数，传入eprocess地址后，首先计算出来_object_table地址，然后计算出来HandleTableList地址

```c
    pHandleTable =
        *(PUINT64)((PCHAR)pEprocess + WIN10_21H1_X64_OBJECTTABLE_OFFSET);
    pPriList = (PLIST_ENTRY64)((PUCHAR)pHandleTable +
                               WIN10_21H1_X64_HANDLETABLELIST_OFFSET);
```

然后遍历链表，我们把链表上每一个节点都创建一个PROCESS_HANDLE_OBJECT结构体，因为链表上每一个节点代表一个进程，每一个进程都有一张或者多张句柄表，我们先将链表上每一个节点的部分信息收集好后放在一个数组中，方便我们后续遍历操作

```c
/// @brief
/// 传入一个PLIST_ENTRY64，会遍历这个链表，每个链表节点会生成一个对应的PROCESS_HANDLE_OBJECT指针
/// 组成一个数组，存放指针，存放到ObjArr
/// @param pHandleList Handle_list链表
/// @param ObjArr PPROCESS_HANDLE_OBJECT* 指针
/// @return 返回一个指针数组，数组元素是PROCESS_HANDLE_OBJECT指针
NTSTATUS CreateProcessObjArrByHandleList(PLIST_ENTRY64            pHandleList,
                                         PPROCESS_HANDLE_OBJECT** ObjArr)
{
    PLIST_ENTRY64           pTmp;
    UINT64                  cout = 0;
    PPROCESS_HANDLE_OBJECT* pProcessObjArr;

    // 获取链表节点数量，用于申请内存块大小
    pTmp = pHandleList;
    do {
        pTmp = pTmp->Flink;
        cout += 1;
    } while (pTmp != pHandleList);
    pProcessObjArr = ExAllocatePoolZero(
        NonPagedPool, (cout + 1) * sizeof(PPROCESS_HANDLE_OBJECT), POOL_TAG);
    if (!pProcessObjArr) {
        kprintf("[!] Alloc process handle obj array failed\r\n");
        return STATUS_ALLOCATE_BUCKET;
    }

    // 遍历链表获取节点信息，并创建ProcessHandleObject结构体
    for (size_t i = 0; i < cout; i++) {
        pProcessObjArr[i] = NewProcessHandleObject(
            NULL, ((PUCHAR)pTmp - WIN10_21H1_X64_HANDLETABLELIST_OFFSET));
        pTmp = pTmp->Flink;
    }

    *ObjArr = pProcessObjArr;
    return STATUS_SUCCESS;
}
```

然后开始遍历这个数组，具体每一个进程都遍历它的句柄表再来对比，关键逻辑在如下的`FilterObjByEprocess`函数中

```c
/// @brief 传入需要保护的进程eprocess，保护程序句柄
/// @param pEprocess PEPROCESS地址
/// @return 
NTSTATUS ProtectProcessHandleByEprocess(PEPROCESS pEprocess)
{
    PVOID64                 pHandleTable;
    PLIST_ENTRY64           pPriList, pTmp;
    UINT64                  cout;
    PPROCESS_HANDLE_OBJECT* ObjArr;
    NTSTATUS                status;

    pHandleTable =
        *(PUINT64)((PCHAR)pEprocess + WIN10_21H1_X64_OBJECTTABLE_OFFSET);
    pPriList = (PLIST_ENTRY64)((PUCHAR)pHandleTable +
                               WIN10_21H1_X64_HANDLETABLELIST_OFFSET);

    kprintf("[+] EPROCESS: %p\r\n[+] handle object: %p\r\n[+] handle table "
            "list: %p\r\n",
            pEprocess,
            pHandleTable,
            pPriList);

    status = CreateProcessObjArrByHandleList(pPriList, &ObjArr);
    if (!NT_SUCCESS(status)) {
        kprintf("[!] CreateProcessObjArrByHandleList error");
        return STATUS_UNSUCCESSFUL;
    }

    for (size_t i = 0; ObjArr[i] != 0; i++) {
        // kprintf("[+] Obj[%d]: %llx\r\n", i, ObjArr[i]);
        // DisplayProcessHandleObj(ObjArr[i]);
        kprintf("[+] Use handle process imagename: %s; eprocess: %p\r\n",
                (PUCHAR)ObjArr[i]->eprocess + EPROCESS_IMAGE_OFFSET,
                ObjArr[i]->eprocess);
        FilterObjByEprocess(ObjArr[i], pEprocess);
    }

    FreeProcessObjArr(ObjArr);

    return STATUS_SUCCESS;
}
```

下面看我们怎么遍历一个进程节点的句柄表，也就是`FilterObjByEprocess`函数。

这里我只考虑一层和两次的句柄表，至于三层的不考虑。大部分恶意软件都只有一层句柄表，CE有两层。所以我们分两种来处理，一种是只有一层句柄表的，一种是两层句柄表的

-   `FilterOneTableByEprocess`
-   `FilterTWOTabelByEprocess`

```c
/// @brief 遍历一层/两层句柄表，判断其中是否有目标句柄进程pEprocess
/// 如果有则返回TRUE, 否则返回FALSE
/// @param pProcessHandleObj 需要遍历的pProcessHandleObj的结构体
/// @param pEprocess 目标进程句柄
/// @return
BOOLEAN FilterObjByEprocess(PPROCESS_HANDLE_OBJECT pProcessHandleObj,
                            PEPROCESS              pEprocess)
{
    UINT64              tablecode;
    PHANDLE_TABLE_ENTRY pHandleTableEntry;
    PVOID64             pObjHeader;

    tablecode = pProcessHandleObj->table_code;

    switch (tablecode & TABLE_LEVEL_MASK)
    {
    case TABLE_LEVEL_ZERO:
        return FilterOneTableByEprocess(pEprocess, tablecode);
        break;
    case TABLE_LEVEL_ONE:
        return FilterTWOTabelByEprocess(pEprocess, tablecode);
        break;
    default:
        break;
    }

    return FALSE;
}
```

`FilterOneTableByEprocess`需要传入两个参数，一个是需要保护的eprocess地址，一个是一层的句柄表tablecode，大致流程如下

检查传入的tablecode有没有异常，有异常的跳过

tablecode其实就是_handle_table_entry数组，所以把所有_handle_table_entry转换成对应的_object_header

然后提取每个_object_header的body对比是否等于我们的目标EPROCESS，如果等于表示找到了，就修改权限

```c
/// @brief 针对单张句柄表的情况，匹配目标eprocess，如果匹配到则修改句柄权限
/// @param pEprocess 目标eprocess结构体指针
/// @param tablecode 单张句柄表的tablecode
/// @return 
BOOLEAN FilterOneTableByEprocess(PEPROCESS pEprocess, UINT64 tablecode) {
    PHANDLE_TABLE_ENTRY pHandleTableEntry;
    PVOID64             pObjHeader;

    pHandleTableEntry = tablecode;
    for (size_t i = 0; i < PAGE_HANDLE_MAX; i++) {
        // 如果tablecode有异常则跳过这个
        if (!CheckHandleTableEntry(&pHandleTableEntry[i])) {
            continue;
        }

        // 通过_handle_table_entry计算_object_header地址
        pObjHeader = HandleEntryTable2ObjectHeader(&pHandleTableEntry[i]);

        // Option: Check this object is process?
        if (!IsProcess(pObjHeader)) {
            continue;
        }

        // Compare whether the two eprocess variables are the same
        if ((PVOID64)((PUCHAR)pObjHeader + HANDLE_BODY_OFFSET) == pEprocess) {
            kprintf("[+] Found tablecode: %llx; object_handle: %p; "
                    "handle_table_entry: %p;\r\n",
                    tablecode,
                    pObjHeader,
                    &pHandleTableEntry[i]);
            // 取消句柄的读写权限
            ModfiyGrantedAccessBits(&pHandleTableEntry[i]);
            return TRUE;
        }
    }

    return FALSE;
}
```

修改权限也很简单，直接去掉内存读和内存写的权限

```c
/// @brief 修改handle_entry_table的GrantedAccessBits权限，句柄的内存读写权限
/// @param pHandleTableEntry
/// @return
NTSTATUS ModfiyGrantedAccessBits(PHANDLE_TABLE_ENTRY pHandleTableEntry)
{
    pHandleTableEntry->GrantedAccessBits &=
        ~(PROCESS_VM_READ | PROCESS_VM_WRITE);
    return STATUS_SUCCESS;
}
```

上面就是一层句柄的修改了，这样改完CE还是能读取内存，因为CE是两层句柄表，所以要再处理一下

```c
/// @brief 遍历两层的句柄表，判断其中是否有目标句柄进程pEprocess
/// 如果有则返回TRUE, 否则返回FALSE
/// @param pProcessHandleObj 需要遍历的pProcessHandleObj的结构体
/// @param pEprocess 目标进程句柄
/// @return
BOOLEAN FilterTWOTabelByEprocess(PEPROCESS pEprocess, UINT64 tablecode) {
    PUINT64 tables;
    
    tables = tablecode & TABLE_CODE_MASK;

    for (size_t i = 0; tables[i] != 0; i++) {
        if (FilterOneTableByEprocess(pEprocess, tables[i])){
            return TRUE;
        }
    }

    return FALSE;
}
```

这样整个代码逻辑就完全了，下面放一下全部的代码，分两个文件，写的比较难看。

-   main.c
-   header.c

### main.c

```c
#include "header.h"

VOID DriveUnload(PDRIVER_OBJECT pDriver)
{
    kprintf("Unload");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pRegPath)
{
    PEPROCESS eprocess = NULL;
    NTSTATUS  status   = PsLookupProcessByProcessId((HANDLE)0xab4, &eprocess);
    if (!NT_SUCCESS(status)) {
        kprintf("Open process  unsuccessfully!\r\n");
        return STATUS_UNSUCCESSFUL;
    }
    ObDereferenceObject(eprocess);
    ProtectProcessHandleByEprocess(eprocess);

    pDriver->DriverUnload = DriveUnload;

    return STATUS_SUCCESS;
}
```

### header.c

```c
#pragma once
#include <ntifs.h>

#define WIN10_21H1_X64_OBJECTTABLE_OFFSET 0x570
#define WIN10_21H1_X64_HANDLETABLELIST_OFFSET 0x18
#define WIN10_21H1_X64_TABLECODE_OFFSET 0x8
#define WIN10_21H1_X64_QUOTOPROCESS_OFFSET 0x10
#define TABLE_LEVEL_MASK 3
#define TABLE_LEVEL_ZERO 0
#define TABLE_LEVEL_ONE 1
#define TABLE_LEVEL_TWO 2
#define PAGE_HANDLE_MAX 256
#define EPROCESS_IMAGE_OFFSET 0x5A8
#define HANDLE_BODY_OFFSET 0x30
#define TYPE_INDEX_OFFSET 0x18
#define TABLE_CODE_MASK 0xFFFFFFFFFFFFFFF8
#define POOL_TAG 'axe'

// GrantedAccessBits
#define PROCESS_VM_READ (0x0010)
#define PROCESS_VM_WRITE (0x0020)

/**
 * 下面两个值是通过调试系统得到的
 *  OB_HEADER_COOKIE可以使用`db nt!ObHeaderCookie l1`得到
 *  PROCESS_TYPE通过计算得到当前系统的PROCESS的type index值为7
 * */
#define OB_HEADER_COOKIE 0x21
#define PROCESS_TYPE 7

#define kprintf(...) \
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__))

typedef struct HANDLE_TABLE_ENTRY
{
    UINT64 LowValue;
    UINT32 GrantedAccessBits;
    UINT32 Spare2;
} *PHANDLE_TABLE_ENTRY, HANDLE_TABLE_ENTRY;

/// @brief 存放每个进程的信息
typedef struct PROCESS_HANDLE_OBJECT
{
    PEPROCESS           eprocess;
    PHANDLE_TABLE_ENTRY table_code;
} *PPROCESS_HANDLE_OBJECT, PROCESS_HANDLE_OBJECT;

VOID DisplayProcessHandleObj(PPROCESS_HANDLE_OBJECT pHandleObj)
{
    kprintf("[+] eprocess: %p; table_code: %p; image_name: %15s\r\n",
            pHandleObj->eprocess,
            pHandleObj->table_code,
            (PUCHAR)(pHandleObj->eprocess) + EPROCESS_IMAGE_OFFSET);
}

/// @brief
/// 检查一个PHANDLE_TABLE_ENTRY中的数值是否合法，LowValue是否为0，合法返回TRUE，否则返回FALSE
/// @param pHandleTableEntry PHANDLE_TABLE_ENTRY指针
/// @return 合法返回TRUE，否则返回FALSE
BOOLEAN CheckHandleTableEntry(PHANDLE_TABLE_ENTRY pHandleTableEntry)
{
    if (!pHandleTableEntry->LowValue) {
        return FALSE;
    }

    return TRUE;
}

/// @brief
/// 新建一个PROCESS_HANDLE_OBJECT结构体。传入eprocess地址或者handle_table地址，二者至少其一
/// 创建成功返回结构体指针，失败则返回NULL
/// @param pEprocess eprocess地址或者NULL
/// @param pHandleTable _handle_table地址或者NULL
/// @return 创建成功返回结构体指针，失败则返回NULL
PPROCESS_HANDLE_OBJECT NewProcessHandleObject(PEPROCESS pEprocess,
                                              PVOID64   pHandleTable)
{
    UINT64                 uTableCode;
    PPROCESS_HANDLE_OBJECT ptr;

    if (pEprocess == NULL && pHandleTable == NULL) {
        return NULL;
    }

    if (pEprocess == NULL) {
        pEprocess = *(PUINT64)((PUCHAR)pHandleTable +
                               WIN10_21H1_X64_QUOTOPROCESS_OFFSET);
    }

    if (pHandleTable == NULL) {
        pHandleTable =
            *(PUINT64)((PUCHAR)pEprocess + WIN10_21H1_X64_OBJECTTABLE_OFFSET);
    }

    uTableCode =
        *(PUINT64)((PUINT8)pHandleTable + WIN10_21H1_X64_TABLECODE_OFFSET);
    ptr = ExAllocatePool(NonPagedPool, sizeof(PROCESS_HANDLE_OBJECT));
    if (ptr == NULL) {
        kprintf("[!] Alloc struct PROCESS_HANDLE_OBJECT faild\r\n");
        return NULL;
    }

    ptr->eprocess   = pEprocess;
    ptr->table_code = uTableCode;
}

/// @brief 销毁PROCESS_HANDLE_OBJECT结构体，传入一个对应指针
/// @param pProcessHandlePbject PROCESS_HANDLE_OBJECT的指针
/// @return
VOID FreeProcessHandleObject(PPROCESS_HANDLE_OBJECT pProcessHandlePbject)
{
    pProcessHandlePbject->eprocess   = NULL;
    pProcessHandlePbject->table_code = 0;

    ExFreePool(pProcessHandlePbject);
}

/// @brief 传入一个HANDLE_TABLE_ENTRY结构体的地址，计算出ObjectHeader地址
/// @param addr HANDLE_TABLE_ENTRY结构体的地址
/// @return 返回ObjectHeader地址
ULONG64 HandleEntryTable2ObjectHeader(PHANDLE_TABLE_ENTRY addr)
{
    return ((addr->LowValue >> 0x10) & 0xFFFFFFFFFFFFFFF0) + 0xFFFF000000000000;
}

/// @brief 传入一个ObjectHeader地址，判断是否是进程对象，如果是则返回TRUE,
/// 不是则返回FALSE
/// @param Address 句柄头的地址，也就是_object_header结构体地址
/// @return 如果是则返回TRUE, 不是则返回FALSE
BOOLEAN IsProcess(PVOID64 Address)
{
    UINT8 uTypeIndex;
    UINT8 uByte;

    uByte      = ((ULONG64)Address >> 8) & 0xff;
    uTypeIndex = *(PCHAR)((PCHAR)Address + TYPE_INDEX_OFFSET);
    uTypeIndex = uTypeIndex ^ OB_HEADER_COOKIE ^ uByte;

    if (uTypeIndex == PROCESS_TYPE) {
        return TRUE;
    }

    return FALSE;
}

/// @brief 匹配进程的imageName,如果和指定的ImageName相同则返回
/// @param Address _object_header的地址
/// @param Name 需要匹配的程序名称
/// @return 如果这个是进程句柄且是目标进程则返回TRUE，否则返回FALSE
BOOLEAN IsProcessName(PVOID64 Address, PUCHAR Name)
{
    PVOID64 pEprocess;
    PUCHAR  ImageName;

    if (!IsProcess(Address)) {
        return FALSE;
    }

    pEprocess = ((PCHAR)Address + HANDLE_BODY_OFFSET);
    ImageName = (PUCHAR)pEprocess + EPROCESS_IMAGE_OFFSET;

    if (strstr(ImageName, Name) == NULL) {
        return FALSE;
    }

    return TRUE;
}

/// @brief
/// 传入一个PLIST_ENTRY64，会遍历这个链表，每个链表节点会生成一个对应的PROCESS_HANDLE_OBJECT指针
/// 组成一个数组，存放指针，存放到ObjArr
/// @param pHandleList Handle_list链表
/// @param ObjArr PPROCESS_HANDLE_OBJECT* 指针
/// @return 返回一个指针数组，数组元素是PROCESS_HANDLE_OBJECT指针
NTSTATUS CreateProcessObjArrByHandleList(PLIST_ENTRY64            pHandleList,
                                         PPROCESS_HANDLE_OBJECT** ObjArr)
{
    PLIST_ENTRY64           pTmp;
    UINT64                  cout = 0;
    PPROCESS_HANDLE_OBJECT* pProcessObjArr;

    // 获取链表节点数量，用于申请内存块大小
    pTmp = pHandleList;
    do {
        pTmp = pTmp->Flink;
        cout += 1;
    } while (pTmp != pHandleList);
    pProcessObjArr = ExAllocatePoolZero(
        NonPagedPool, (cout + 1) * sizeof(PPROCESS_HANDLE_OBJECT), POOL_TAG);
    if (!pProcessObjArr) {
        kprintf("[!] Alloc process handle obj array failed\r\n");
        return STATUS_ALLOCATE_BUCKET;
    }

    // 遍历链表获取节点信息，并创建ProcessHandleObject结构体
    for (size_t i = 0; i < cout; i++) {
        pProcessObjArr[i] = NewProcessHandleObject(
            NULL, ((PUCHAR)pTmp - WIN10_21H1_X64_HANDLETABLELIST_OFFSET));
        pTmp = pTmp->Flink;
    }

    *ObjArr = pProcessObjArr;
    return STATUS_SUCCESS;
}

/// @brief 释放ProcessObject指针数组的内容
/// @param ObjArr PPROCESS_HANDLE_OBJECT数组
/// @return
VOID FreeProcessObjArr(PPROCESS_HANDLE_OBJECT* ObjArr)
{
    for (size_t i = 0; ObjArr[i] != 0; i++) {
        FreeProcessHandleObject(ObjArr[i]);
        ObjArr[i] = NULL;
    }

    // ExFreePoolWithTag(&ObjArr, POOL_TAG);
}

/// @brief 传入一个_object_header指针打印body是_eprocess的ImageName字符内容
/// @param ObjectHeader
/// @return
VOID ShowImageNameByObjectHeader(PVOID64 ObjectHeader)
{
    PVOID64 pEprocess;
    PUCHAR  ImageName;

    pEprocess = ((PUCHAR)ObjectHeader + HANDLE_BODY_OFFSET);
    ImageName = (PUCHAR)pEprocess + EPROCESS_IMAGE_OFFSET;

    kprintf("[+] ImageName: %15s\r\n", ImageName);
}

/// @brief 修改handle_entry_table的GrantedAccessBits权限，句柄的内存读写权限
/// @param pHandleTableEntry
/// @return
NTSTATUS ModfiyGrantedAccessBits(PHANDLE_TABLE_ENTRY pHandleTableEntry)
{
    pHandleTableEntry->GrantedAccessBits &=
        ~(PROCESS_VM_READ | PROCESS_VM_WRITE);
    return STATUS_SUCCESS;
}

/// @brief 针对单张句柄表的情况，匹配目标eprocess，如果匹配到则修改句柄权限
/// @param pEprocess 目标eprocess结构体指针
/// @param tablecode 单张句柄表的tablecode
/// @return 
BOOLEAN FilterOneTableByEprocess(PEPROCESS pEprocess, UINT64 tablecode) {
    PHANDLE_TABLE_ENTRY pHandleTableEntry;
    PVOID64             pObjHeader;

    pHandleTableEntry = tablecode;
    for (size_t i = 0; i < PAGE_HANDLE_MAX; i++) {
        // 如果tablecode有异常则跳过这个
        if (!CheckHandleTableEntry(&pHandleTableEntry[i])) {
            continue;
        }

        // 通过_handle_table_entry计算_object_header地址
        pObjHeader = HandleEntryTable2ObjectHeader(&pHandleTableEntry[i]);

        // Option: Check this object is process?
        if (!IsProcess(pObjHeader)) {
            continue;
        }

        // Compare whether the two eprocess variables are the same
        if ((PVOID64)((PUCHAR)pObjHeader + HANDLE_BODY_OFFSET) == pEprocess) {
            kprintf("[+] Found tablecode: %llx; object_handle: %p; "
                    "handle_table_entry: %p;\r\n",
                    tablecode,
                    pObjHeader,
                    &pHandleTableEntry[i]);
            // 取消句柄的读写权限
            ModfiyGrantedAccessBits(&pHandleTableEntry[i]);
            return TRUE;
        }
    }

    return FALSE;
}

/// @brief 遍历两层的句柄表，判断其中是否有目标句柄进程pEprocess
/// 如果有则返回TRUE, 否则返回FALSE
/// @param pProcessHandleObj 需要遍历的pProcessHandleObj的结构体
/// @param pEprocess 目标进程句柄
/// @return
BOOLEAN FilterTWOTabelByEprocess(PEPROCESS pEprocess, UINT64 tablecode) {
    PUINT64 tables;
    
    tables = tablecode & TABLE_CODE_MASK;

    for (size_t i = 0; tables[i] != 0; i++) {
        if (FilterOneTableByEprocess(pEprocess, tables[i])){
            return TRUE;
        }
    }

    return FALSE;
}

/// @brief 遍历一层/两层句柄表，判断其中是否有目标句柄进程pEprocess
/// 如果有则返回TRUE, 否则返回FALSE
/// @param pProcessHandleObj 需要遍历的pProcessHandleObj的结构体
/// @param pEprocess 目标进程句柄
/// @return
BOOLEAN FilterObjByEprocess(PPROCESS_HANDLE_OBJECT pProcessHandleObj,
                            PEPROCESS              pEprocess)
{
    UINT64              tablecode;
    PHANDLE_TABLE_ENTRY pHandleTableEntry;
    PVOID64             pObjHeader;

    tablecode = pProcessHandleObj->table_code;

    switch (tablecode & TABLE_LEVEL_MASK)
    {
    case TABLE_LEVEL_ZERO:
        return FilterOneTableByEprocess(pEprocess, tablecode);
        break;
    case TABLE_LEVEL_ONE:
        return FilterTWOTabelByEprocess(pEprocess, tablecode);
        break;
    default:
        break;
    }

    return FALSE;
}

/// @brief 传入需要保护的进程eprocess，保护程序句柄
/// @param pEprocess PEPROCESS地址
/// @return 
NTSTATUS ProtectProcessHandleByEprocess(PEPROCESS pEprocess)
{
    PVOID64                 pHandleTable;
    PLIST_ENTRY64           pPriList, pTmp;
    UINT64                  cout;
    PPROCESS_HANDLE_OBJECT* ObjArr;
    NTSTATUS                status;

    pHandleTable =
        *(PUINT64)((PCHAR)pEprocess + WIN10_21H1_X64_OBJECTTABLE_OFFSET);
    pPriList = (PLIST_ENTRY64)((PUCHAR)pHandleTable +
                               WIN10_21H1_X64_HANDLETABLELIST_OFFSET);

    kprintf("[+] EPROCESS: %p\r\n[+] handle object: %p\r\n[+] handle table "
            "list: %p\r\n",
            pEprocess,
            pHandleTable,
            pPriList);

    status = CreateProcessObjArrByHandleList(pPriList, &ObjArr);
    if (!NT_SUCCESS(status)) {
        kprintf("[!] CreateProcessObjArrByHandleList error");
        return STATUS_UNSUCCESSFUL;
    }

    for (size_t i = 0; ObjArr[i] != 0; i++) {
        // kprintf("[+] Obj[%d]: %llx\r\n", i, ObjArr[i]);
        // DisplayProcessHandleObj(ObjArr[i]);
        kprintf("[+] Use handle process imagename: %s; eprocess: %p\r\n",
                (PUCHAR)ObjArr[i]->eprocess + EPROCESS_IMAGE_OFFSET,
                ObjArr[i]->eprocess);
        FilterObjByEprocess(ObjArr[i], pEprocess);
    }

    FreeProcessObjArr(ObjArr);

    return STATUS_SUCCESS;
}
```

### 结果

运行后，打印内容大致如下：

```
...
[+] Use handle process imagename: sppsvc.exe; eprocess: FFFFC40D2B969080
[+] Use handle process imagename: SppExtComObj.E; eprocess: FFFFC40D26F19080
[+] Use handle process imagename: svchost.exe; eprocess: FFFFC40D2BA1C080
[+] Use handle process imagename: slui.exe; eprocess: FFFFC40D2CBF4080
[+] Use handle process imagename: svchost.exe; eprocess: FFFFC40D24B43080
[+] Use handle process imagename: backgroundTask; eprocess: FFFFC40D2CCE2080
[+] Use handle process imagename: HxTsr.exe; eprocess: FFFFC40D2AD7E080
[+] Use handle process imagename: backgroundTask; eprocess: FFFFC40D295E5080
[+] Use handle process imagename: CompatTelRunne; eprocess: FFFFC40D2AD42080
[+] Use handle process imagename: RuntimeBroker.; eprocess: FFFFC40D2CA6F080
[+] Use handle process imagename: RuntimeBroker.; eprocess: FFFFC40D2CC3D080
[+] Use handle process imagename: svchost.exe; eprocess: FFFFC40D2B966080
[+] Use handle process imagename: \; eprocess: FFFFF8066AB8E038
[+] Found tablecode: ffff9981206e3000; object_handle: FFFFC40D2CBE4050; handle_table_entry: FFFF9981206E3430;
[+] Use handle process imagename: Registry; eprocess: FFFFC40D23D26080
[+] Use handle process imagename: smss.exe; eprocess: FFFFC40D24711040
[+] Use handle process imagename: csrss.exe; eprocess: FFFFC40D24599080
[+] Use handle process imagename: wininit.exe; eprocess: FFFFC40D2542E080
[+] Use handle process imagename: csrss.exe; eprocess: FFFFC40D25432140
[+] Found tablecode: ffff9981262f6000; object_handle: FFFFC40D2CBE4050; handle_table_entry: FFFF9981262F6110;
[+] Use handle process imagename: services.exe; eprocess: FFFFC40D254CB080
[+] Use handle process imagename: lsass.exe; eprocess: FFFFC40D254D70C0
[+] Use handle process imagename: winlogon.exe; eprocess: FFFFC40D255820C0
[+] Use handle process imagename: svchost.exe; eprocess: FFFFC40D25428080
[+] Use handle process imagename: fontdrvhost.ex; eprocess: FFFFC40D25D6E140
[+] Use handle process imagename: fontdrvhost.ex; eprocess: FFFFC40D25D9D140
[+] Use handle process imagename: svchost.exe; eprocess: FFFFC40D25DBB2C0
[+] Found tablecode: ffff9981206e8000; object_handle: FFFFC40D2CBE4050; handle_table_entry: FFFF9981206E8390;
...
```

然后此时CE已经不能查看内存了

![202404291009831.png](https://s2.loli.net/2024/04/29/Lf1nXzJh9AkSZqM.png)

但是这只是当前这个CE进程的，如果关掉这个CE进程，再打开新的CE并且Open记事本进程就又可以重新读取了。因为在新的CE进程中，还没有修改句柄表中记事本进程的权限，所以还需要对抗。

## 对抗句柄降权思路

### 反复修改权限

防护方是通过驱动来遍历私有句柄表，然后修改攻击者进程的私有句柄表中指向被保护进程的句柄属性。

那我们也可以写一个驱动来不停的修改我们自身进程的私有句柄权限，将句柄权限改成full control

### 断链

防护方是通过遍历私有句柄链表来查找攻击方的私有句柄表，那我们可以将私有句柄从链表上断掉，放置一个空/假的私有句柄表结构体或者直接让我们的进程私有句柄表从链表上断开。可以参考github项目[HideDriver](https://github.com/nbqofficial/HideDriver)

## ObRegisterCallbacks 保护

实际上上述的句柄降权/提权都是针对callbacks保护来做的，很多厂商是使用这个微软公开的API来保护自身进程句柄的权限.

ObRegisterCallbacks 例程为线程、进程和桌面句柄操作注册一系列回调例程。也就是我们可以给我们进程句柄设定一个回调函数，当我们的进程句柄被NtOpenProcess打开后，就会执行这个回调函数。如果我们在回调函数中修改这个句柄的权限，那么任何进程获取我们进程句柄将得到修改过后权限的句柄。

```c
NTSTATUS ObRegisterCallbacks(
  [in]  POB_CALLBACK_REGISTRATION CallbackRegistration,
  [out] PVOID                     *RegistrationHandle
);
```

```
[in] CallbackRegistration
```

指向 [OB_CALLBACK_REGISTRATION](https://learn.microsoft.com/zh-cn/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_callback_registration) 结构的指针，该结构指定回调例程和其他注册信息的列表。

```
[out] RegistrationHandle
```

指向变量的指针，该变量接收标识注册的回调例程集的值。 调用方将此值传递给 [ObUnRegisterCallbacks](https://learn.microsoft.com/zh-cn/windows-hardware/drivers/ddi/wdm/nf-wdm-obunregistercallbacks) 例程，以取消注册回调集。

我们看一下OB_CALLBACK_REGISTRATION结构体

```c
typedef struct _OB_CALLBACK_REGISTRATION {
  USHORT                    Version;
  USHORT                    OperationRegistrationCount;
  UNICODE_STRING            Altitude;
  PVOID                     RegistrationContext;
  OB_OPERATION_REGISTRATION *OperationRegistration;
} OB_CALLBACK_REGISTRATION, *POB_CALLBACK_REGISTRATION;
```

其中`OperationRegistration`参数是指向`OB_OPERATION_REGISTRATION`结构的数组的指针。 每个结构指定 [ObjectPreCallback](https://learn.microsoft.com/zh-cn/windows-hardware/drivers/ddi/wdm/nc-wdm-pob_pre_operation_callback) 和 [ObjectPostCallback](https://learn.microsoft.com/zh-cn/windows-hardware/drivers/ddi/wdm/nc-wdm-pob_post_operation_callback) 回调例程以及调用例程的操作类型。

ObjectPreCallback就是发生进程或线程句柄操作**时**，操作系统会调用 *ObjectPreCallback* 例程

ObjectPostCallback就是发生进程或线程句柄操作**后**，操作系统会调用 *ObjectPostCallback* 例程

所以我们的操作函数也就是放在这两个数组当中。

> [ObRegisterCallbacks](https://learn.microsoft.com/zh-cn/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks) 例程使用此结构。 此例程的 *CallBackRegistration* 参数是指向包含 [OB_CALLBACK_REGISTRATION](https://learn.microsoft.com/zh-cn/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_callback_registration) 结构的缓冲区的指针，该结构后跟一个或多个 **OB_OPERATION_REGISTRATION** 结构的数组。
>
> 在传递给 **ObRegisterCallback** 的每个**OB_OPERATION_REGISTRATION**结构中，调用方必须提供一个或两个回调例程。 如果此结构的 **PreOperation** 和 **PostOperation** 成员均为 **NULL**，则回调注册操作将失败。

为了保证注册成功，我们可以在不用的操作上注册一个空的函数。比如我要注册Pre的，我也写一个空的Post

>   具体代码可以参考驱动系统注册回调函数的三篇内容，我不写的主要原因是我64位win10 21h2我不知道怎么过驱动验证

# 参考

https://cloud.tencent.com/developer/article/2316143

https://www.52pojie.cn/thread-1546336-1-1.html

https://bbs.kanxue.com/thread-281120.htm

https://mp.weixin.qq.com/s/AXjVjguHaWd3rHqYQ4wfmw

https://www.52pojie.cn/thread-1771006-1-1.html

https://www.52pojie.cn/thread-1770541-1-1.html

[探索Windows内核系列——句柄，利用句柄进行进程保护_volatilelowvalue-CSDN博客](https://blog.csdn.net/sunjiaoya/article/details/135628674)

https://www.52pojie.cn/thread-806825-1-1.html

[句柄表篇——进程句柄表 - 寂静的羽夏 - 博客园](https://www.cnblogs.com/wingsummer/p/15823780.html)

https://medium.com/@ashabdalhalim/a-light-on-windows-10s-object-header-typeindex-value-e8f907e7073a

https://spikysabra.gitbook.io/kernelcactus/pocs/handle-elevation

[HideDriver ( Direct kernel object manipulation ) | github.com](https://github.com/nbqofficial/HideDriver)

>   驱动注册系统回调函数

https://bbs.kanxue.com/thread-248703.htm

https://xiaodaozhi.com/kernel/4.html

https://www.cnblogs.com/LyShark/p/16818453.html