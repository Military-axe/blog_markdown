+++
title = "利用PEB遍历模块链表"
date = 2024-03-19T11:36:56+08:00

[taxonomies]
tags = ["c++", "peb"]
categories = ["Reverse"]
+++

使用c++, rust实现遍历PEB获取模块信息的代码段. 主要练练rust

<!-- more -->

> 测试环境: win11 23h2 desktop
>
> 编译环境: 
>
> Microsoft Visual Studio Community 2022
> 版本 17.9.2
> VisualStudio.17.Release/17.9.2+34622.214
> Microsoft .NET Framework
> 版本 4.8.09032
>
> 已安装的版本: Community
>
> Visual C++ 2022   00482-90000-00000-AA003
> Microsoft Visual C++ 2022
>
> ASP.NET and Web Tools   17.9.197.37128
> ASP.NET and Web Tools
>
> Azure 应用服务工具 3.0.0 版   17.9.197.37128
> Azure 应用服务工具 3.0.0 版
>
> C# 工具   4.9.0-3.24121.1+a98c90d56455379836dd5c845b35fa932b00cfa3
> IDE 中使用的 C# 组件。可能使用其他版本的编译器，具体取决于你的项目类型和设置。
>
> Debugging Tools for Windows   10.0.22621.311
> Integrates the Windows Debugger functionality (http://go.microsoft.com/fwlink/?linkid=223405) in Visual Studio.
>
> Microsoft JVM Debugger   1.0
> Provides support for connecting the Visual Studio debugger to JDWP compatible Java Virtual Machines
>
> NuGet 包管理器   6.9.1
> Visual Studio 中的 NuGet 包管理器。有关 NuGet 的详细信息，请访问 https://docs.nuget.org/
>
> TypeScript Tools   17.0.30103.2001
> TypeScript Tools for Microsoft Visual Studio
>
> Visual Basic 工具   4.9.0-3.24121.1+a98c90d56455379836dd5c845b35fa932b00cfa3
> IDE 中使用的 Visual Basic 组件。可能使用其他版本的编译器，具体取决于你的项目类型和设置。
>
> Visual Studio IntelliCode   2.2
> Visual Studio 的 AI 协助开发。
>
> Windows Driver Kit   10.0.22621.311
> Headers, libraries, and tools needed to develop, debug, and test Windows drivers (msdn.microsoft.com/en-us/windows/hardware/gg487428.aspx)
>
> 用于 Boost.Test 的测试适配器   1.0
> 通过针对 Boost.Test 编写的单元测试启用 Visual Studio 测试工具。扩展安装目录中提供用户条款和第三方通知。
>
> 适用于 Google Test 的测试适配器   1.0
> 启用带有针对 Google Test 编写的单元测试的 Visual Studio 测试工具。扩展安装目录中提供了使用条款和第三方通知。

## 结构体关系

这是x86下的神图，x64相差无多

![img](https://raw.githubusercontent.com/Military-axe/imgtable/main/202403191145558.jpeg)

获取模块信息需要从PEB中来获取，PEB的Ldr属性指向的结构体中就存储着该进程所有模块数据的链表。

思路：通过TEB找到PEB，再遍历LDR里的链表得到所有模块信息

```mermaid
graph LR
	TEB --> PEB --PEB+0xc--> LDR --> 链表
	
```

+ x86 下，fs 寄存器指的是 TEB 结构体首地址，fs:[18h]存的是 TEB 地址，fs:[30h]存的是 PEB 地址

+ x64 下，PEB 的位置在 gs:[60h]的位置

下面以x86为例子

**PEB 结构体**

```c
//0x480 bytes (sizeof)
struct _PEB
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages:1;                                    //0x3
            UCHAR IsProtectedProcess:1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated:1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders:1;                           //0x3
            UCHAR IsPackagedProcess:1;                                      //0x3
            UCHAR IsAppContainer:1;                                         //0x3
            UCHAR IsProtectedProcessLight:1;                                //0x3
            UCHAR IsLongPathAwareProcess:1;                                 //0x3
        };
    };
    VOID* Mutant;                                                           //0x4
    VOID* ImageBaseAddress;                                                 //0x8
    struct _PEB_LDR_DATA* Ldr;                                              //0xc
    struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x10
    VOID* SubSystemData;                                                    //0x14
    VOID* ProcessHeap;                                                      //0x18
    struct _RTL_CRITICAL_SECTION* FastPebLock;                              //0x1c
    union _SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x20
    VOID* IFEOKey;                                                          //0x24
    union
    {
        ULONG CrossProcessFlags;                                            //0x28
        struct
        {
            ULONG ProcessInJob:1;                                           //0x28
            ULONG ProcessInitializing:1;                                    //0x28
            ULONG ProcessUsingVEH:1;                                        //0x28
            ULONG ProcessUsingVCH:1;                                        //0x28
            ULONG ProcessUsingFTH:1;                                        //0x28
            ULONG ProcessPreviouslyThrottled:1;                             //0x28
            ULONG ProcessCurrentlyThrottled:1;                              //0x28
            ULONG ProcessImagesHotPatched:1;                                //0x28
            ULONG ReservedBits0:24;                                         //0x28
        };
    };
    union
    {
        VOID* KernelCallbackTable;                                          //0x2c
        VOID* UserSharedInfoPtr;                                            //0x2c
    };
    ULONG SystemReserved;                                                   //0x30
    union _SLIST_HEADER* volatile AtlThunkSListPtr32;                       //0x34
    VOID* ApiSetMap;                                                        //0x38
    ULONG TlsExpansionCounter;                                              //0x3c
    VOID* TlsBitmap;                                                        //0x40
    ULONG TlsBitmapBits[2];                                                 //0x44
    VOID* ReadOnlySharedMemoryBase;                                         //0x4c
    VOID* SharedData;                                                       //0x50
    VOID** ReadOnlyStaticServerData;                                        //0x54
    VOID* AnsiCodePageData;                                                 //0x58
    VOID* OemCodePageData;                                                  //0x5c
    VOID* UnicodeCaseTableData;                                             //0x60
    ULONG NumberOfProcessors;                                               //0x64
    ULONG NtGlobalFlag;                                                     //0x68
    union _LARGE_INTEGER CriticalSectionTimeout;                            //0x70
    ULONG HeapSegmentReserve;                                               //0x78
    ULONG HeapSegmentCommit;                                                //0x7c
    ULONG HeapDeCommitTotalFreeThreshold;                                   //0x80
    ULONG HeapDeCommitFreeBlockThreshold;                                   //0x84
    ULONG NumberOfHeaps;                                                    //0x88
    ULONG MaximumNumberOfHeaps;                                             //0x8c
    VOID** ProcessHeaps;                                                    //0x90
    VOID* GdiSharedHandleTable;                                             //0x94
    VOID* ProcessStarterHelper;                                             //0x98
    ULONG GdiDCAttributeList;                                               //0x9c
    struct _RTL_CRITICAL_SECTION* LoaderLock;                               //0xa0
    ULONG OSMajorVersion;                                                   //0xa4
    ULONG OSMinorVersion;                                                   //0xa8
    USHORT OSBuildNumber;                                                   //0xac
    USHORT OSCSDVersion;                                                    //0xae
    ULONG OSPlatformId;                                                     //0xb0
    ULONG ImageSubsystem;                                                   //0xb4
    ULONG ImageSubsystemMajorVersion;                                       //0xb8
    ULONG ImageSubsystemMinorVersion;                                       //0xbc
    ULONG ActiveProcessAffinityMask;                                        //0xc0
    ULONG GdiHandleBuffer[34];                                              //0xc4
    VOID (*PostProcessInitRoutine)();                                       //0x14c
    VOID* TlsExpansionBitmap;                                               //0x150
    ULONG TlsExpansionBitmapBits[32];                                       //0x154
    ULONG SessionId;                                                        //0x1d4
    union _ULARGE_INTEGER AppCompatFlags;                                   //0x1d8
    union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x1e0
    VOID* pShimData;                                                        //0x1e8
    VOID* AppCompatInfo;                                                    //0x1ec
    struct _UNICODE_STRING CSDVersion;                                      //0x1f0
    struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x1f8
    struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x1fc
    struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x200
    struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x204
    ULONG MinimumStackCommit;                                               //0x208
    VOID* SparePointers[4];                                                 //0x20c
    ULONG SpareUlongs[5];                                                   //0x21c
    VOID* WerRegistrationData;                                              //0x230
    VOID* WerShipAssertPtr;                                                 //0x234
    VOID* pUnused;                                                          //0x238
    VOID* pImageHeaderHash;                                                 //0x23c
    union
    {
        ULONG TracingFlags;                                                 //0x240
        struct
        {
            ULONG HeapTracingEnabled:1;                                     //0x240
            ULONG CritSecTracingEnabled:1;                                  //0x240
            ULONG LibLoaderTracingEnabled:1;                                //0x240
            ULONG SpareTracingBits:29;                                      //0x240
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x248
    ULONG TppWorkerpListLock;                                               //0x250
    struct _LIST_ENTRY TppWorkerpList;                                      //0x254
    VOID* WaitOnAddressHashTable[128];                                      //0x25c
    VOID* TelemetryCoverageHeader;                                          //0x45c
    ULONG CloudFileFlags;                                                   //0x460
    ULONG CloudFileDiagFlags;                                               //0x464
    CHAR PlaceholderCompatibilityMode;                                      //0x468
    CHAR PlaceholderCompatibilityModeReserved[7];                           //0x469
    struct _LEAP_SECOND_DATA* LeapSecondData;                               //0x470
    union
    {
        ULONG LeapSecondFlags;                                              //0x474
        struct
        {
            ULONG SixtySecondEnabled:1;                                     //0x474
            ULONG Reserved:31;                                              //0x474
        };
    };
    ULONG NtGlobalFlag2;                                                    //0x478
}; 
```

偏移为0xc的地方就是Ldr了

**PPEB_LDR_DATA 结构体**

```c
//0x30 bytes (sizeof)
struct _PEB_LDR_DATA
{
    ULONG Length;                                                           //0x0
    UCHAR Initialized;                                                      //0x4
    VOID* SsHandle;                                                         //0x8
    struct _LIST_ENTRY InLoadOrderModuleList;                               //0xc
    struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x14
    struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x1c
    VOID* EntryInProgress;                                                  //0x24
    UCHAR ShutdownInProgress;                                               //0x28
    VOID* ShutdownThreadId;                                                 //0x2c
}; 
```

这里的 0xc 处存着模块链表。里面有3条链表，分别代表的意义是：

| 名称                              | 意义                       |
| --------------------------------- | -------------------------- |
| `InLoadOrderModuleList`           | 模块链表，以加载顺序排序   |
| `InMemoryOrderModuleList`         | 模块链表，以内存位置排序   |
| `InInitializationOrderModuleList` | 模块链表，以初始化顺序排序 |

每个链表的节点都一样，只是顺序不同。

**_LIST_ENTRY 结构体**

```c
//0x8 bytes (sizeof)
struct _LIST_ENTRY
{
    struct _LIST_ENTRY* Flink;                                              //0x0
    struct _LIST_ENTRY* Blink;                                              //0x4
}; 
```

可以看到这个结构有两个成员，第一个成员`Flink`指向下一个节点，`Blink`指向上一个节点。所以这是一个双向链表。接下来的概念很重要：

当我们从`_PEB_LDR_DATA`结构中取到`InInitializationOrderModuleList`结构或其他两个链表时，这个结构中的`Flink`指向真正的模块链表，这个真正的链表的每个成员都是一个`LDR_DATA_TABLE_ENTRY`结构。

之前的`_PEB_LDR_DATA`只是一个**入口**，这个结构只有一个，它不是链表节点，真正的链表节点结构如下

**_LDR_DATA_TABLE_ENTRY 结构**

```c
//0xa8 bytes (sizeof)
struct _LDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x8
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x10
    VOID* DllBase;                                                          //0x18
    VOID* EntryPoint;                                                       //0x1c
    ULONG SizeOfImage;                                                      //0x20
    struct _UNICODE_STRING FullDllName;                                     //0x24
    struct _UNICODE_STRING BaseDllName;                                     //0x2c
    union
    {
        UCHAR FlagGroup[4];                                                 //0x34
        ULONG Flags;                                                        //0x34
        struct
        {
            ULONG PackagedBinary:1;                                         //0x34
            ULONG MarkedForRemoval:1;                                       //0x34
            ULONG ImageDll:1;                                               //0x34
            ULONG LoadNotificationsSent:1;                                  //0x34
            ULONG TelemetryEntryProcessed:1;                                //0x34
            ULONG ProcessStaticImport:1;                                    //0x34
            ULONG InLegacyLists:1;                                          //0x34
            ULONG InIndexes:1;                                              //0x34
            ULONG ShimDll:1;                                                //0x34
            ULONG InExceptionTable:1;                                       //0x34
            ULONG ReservedFlags1:2;                                         //0x34
            ULONG LoadInProgress:1;                                         //0x34
            ULONG LoadConfigProcessed:1;                                    //0x34
            ULONG EntryProcessed:1;                                         //0x34
            ULONG ProtectDelayLoad:1;                                       //0x34
            ULONG ReservedFlags3:2;                                         //0x34
            ULONG DontCallForThreads:1;                                     //0x34
            ULONG ProcessAttachCalled:1;                                    //0x34
            ULONG ProcessAttachFailed:1;                                    //0x34
            ULONG CorDeferredValidate:1;                                    //0x34
            ULONG CorImage:1;                                               //0x34
            ULONG DontRelocate:1;                                           //0x34
            ULONG CorILOnly:1;                                              //0x34
            ULONG ChpeImage:1;                                              //0x34
            ULONG ReservedFlags5:2;                                         //0x34
            ULONG Redirected:1;                                             //0x34
            ULONG ReservedFlags6:2;                                         //0x34
            ULONG CompatDatabaseProcessed:1;                                //0x34
        };
    };
    USHORT ObsoleteLoadCount;                                               //0x38
    USHORT TlsIndex;                                                        //0x3a
    struct _LIST_ENTRY HashLinks;                                           //0x3c
    ULONG TimeDateStamp;                                                    //0x44
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x48
    VOID* Lock;                                                             //0x4c
    struct _LDR_DDAG_NODE* DdagNode;                                        //0x50
    struct _LIST_ENTRY NodeModuleLink;                                      //0x54
    struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0x5c
    VOID* ParentDllBase;                                                    //0x60
    VOID* SwitchBackContext;                                                //0x64
    struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0x68
    struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0x74
    ULONG OriginalBase;                                                     //0x80
    union _LARGE_INTEGER LoadTime;                                          //0x88
    ULONG BaseNameHashValue;                                                //0x90
    enum _LDR_DLL_LOAD_REASON LoadReason;                                   //0x94
    ULONG ImplicitPathOptions;                                              //0x98
    ULONG ReferenceCount;                                                   //0x9c
    ULONG DependentLoadFlags;                                               //0xa0
    UCHAR SigningLevel;                                                     //0xa4
}; 
```

所以PEB中链表的**Flink**指向**_LDR_DATA_TABLE_ENTRY**结构体，结构体中前3个值，才是真的链表

![](https://raw.githubusercontent.com/Military-axe/imgtable/main/202403181452479.png)

## 遍历模块

分为x64和x86两种，借鉴kn0sky的代码写的C++版本，修改成win11 23h2的代码，因为结构体有些许不同，其实不该也一样，因为引用到的偏移都是相同的，还没有使用到不同结构体的地方。不过有些低版本的可能就有差异，具体问题具体分析。

### header.h

```c
#pragma once
#include <stdio.h>
#include <Windows.h>
#include <iostream>
#include <process.h>

#if defined(_WIN64)
extern "C" PVOID64 _cdecl GetPebLdr(void);

//0x10 bytes (sizeof)
struct _UNICODE_STRING
{
    USHORT Length;                                                          //0x0
    USHORT MaximumLength;                                                   //0x2
    USHORT* Buffer;                                                         //0x8
};

//0x58 bytes (sizeof)
struct _PEB_LDR_DATA64
{
    ULONG Length;                                                           //0x0
    UCHAR Initialized;                                                      //0x4
    VOID* SsHandle;                                                         //0x8
    struct LIST_ENTRY64 InLoadOrderModuleList;                               //0x10
    struct LIST_ENTRY64 InMemoryOrderModuleList;                             //0x20
    struct LIST_ENTRY64 InInitializationOrderModuleList;                     //0x30
    VOID* EntryInProgress;                                                  //0x40
    UCHAR ShutdownInProgress;                                               //0x48
    VOID* ShutdownThreadId;                                                 //0x50
};

//0x138 bytes (sizeof)
struct _LDR_DATA_TABLE_ENTRY64
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    union
    {
        UCHAR FlagGroup[4];                                                 //0x68
        ULONG Flags;                                                        //0x68
        struct
        {
            ULONG PackagedBinary : 1;                                         //0x68
            ULONG MarkedForRemoval : 1;                                       //0x68
            ULONG ImageDll : 1;                                               //0x68
            ULONG LoadNotificationsSent : 1;                                  //0x68
            ULONG TelemetryEntryProcessed : 1;                                //0x68
            ULONG ProcessStaticImport : 1;                                    //0x68
            ULONG InLegacyLists : 1;                                          //0x68
            ULONG InIndexes : 1;                                              //0x68
            ULONG ShimDll : 1;                                                //0x68
            ULONG InExceptionTable : 1;                                       //0x68
            ULONG ReservedFlags1 : 2;                                         //0x68
            ULONG LoadInProgress : 1;                                         //0x68
            ULONG LoadConfigProcessed : 1;                                    //0x68
            ULONG EntryProcessed : 1;                                         //0x68
            ULONG ProtectDelayLoad : 1;                                       //0x68
            ULONG ReservedFlags3 : 2;                                         //0x68
            ULONG DontCallForThreads : 1;                                     //0x68
            ULONG ProcessAttachCalled : 1;                                    //0x68
            ULONG ProcessAttachFailed : 1;                                    //0x68
            ULONG CorDeferredValidate : 1;                                    //0x68
            ULONG CorImage : 1;                                               //0x68
            ULONG DontRelocate : 1;                                           //0x68
            ULONG CorILOnly : 1;                                              //0x68
            ULONG ChpeImage : 1;                                              //0x68
            ULONG ChpeEmulatorImage : 1;                                      //0x68
            ULONG ReservedFlags5 : 1;                                         //0x68
            ULONG Redirected : 1;                                             //0x68
            ULONG ReservedFlags6 : 2;                                         //0x68
            ULONG CompatDatabaseProcessed : 1;                                //0x68
        };
    };
    USHORT ObsoleteLoadCount;                                               //0x6c
    USHORT TlsIndex;                                                        //0x6e
    struct _LIST_ENTRY HashLinks;                                           //0x70
    ULONG TimeDateStamp;                                                    //0x80
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
    VOID* Lock;                                                             //0x90
    struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
    struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
    struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
    VOID* ParentDllBase;                                                    //0xb8
    VOID* SwitchBackContext;                                                //0xc0
    // struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
    // struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
    VOID* BaseAddressIndexNode;//0xc8
    VOID* MappingInfoIndexNode;//0xe0
    ULONGLONG OriginalBase;                                                 //0xf8
    union _LARGE_INTEGER LoadTime;                                          //0x100
    ULONG BaseNameHashValue;                                                //0x108
    enum _LDR_DLL_LOAD_REASON LoadReason;                                   //0x10c
    ULONG ImplicitPathOptions;                                              //0x110
    ULONG ReferenceCount;                                                   //0x114
    ULONG DependentLoadFlags;                                               //0x118
    UCHAR SigningLevel;                                                     //0x11c
    ULONG CheckSum;                                                         //0x120
    VOID* ActivePatchImageBase;                                             //0x128
    enum _LDR_HOT_PATCH_STATE HotPatchState;                                //0x130
};
#else
//0x8 bytes (sizeof)
struct _UNICODE_STRING
{
    USHORT Length;                                                          //0x0
    USHORT MaximumLength;                                                   //0x2
    USHORT* Buffer;                                                         //0x4
};

//0x30 bytes (sizeof)
struct _PEB_LDR_DATA
{
    ULONG Length;                                                           //0x0
    UCHAR Initialized;                                                      //0x4
    VOID* SsHandle;                                                         //0x8
    struct _LIST_ENTRY InLoadOrderModuleList;                               //0xc
    struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x14
    struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x1c
    VOID* EntryInProgress;                                                  //0x24
    UCHAR ShutdownInProgress;                                               //0x28
    VOID* ShutdownThreadId;                                                 //0x2c
};

//0x78 bytes (sizeof)
struct _LDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x8
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x10
    VOID* DllBase;                                                          //0x18
    VOID* EntryPoint;                                                       //0x1c
    ULONG SizeOfImage;                                                      //0x20
    struct _UNICODE_STRING FullDllName;                                     //0x24
    struct _UNICODE_STRING BaseDllName;                                     //0x2c
    ULONG Flags;                                                            //0x34
    USHORT LoadCount;                                                       //0x38
    USHORT TlsIndex;                                                        //0x3a
    union
    {
        struct _LIST_ENTRY HashLinks;                                       //0x3c
        struct
        {
            VOID* SectionPointer;                                           //0x3c
            ULONG CheckSum;                                                 //0x40
        };
    };
    union
    {
        ULONG TimeDateStamp;                                                //0x44
        VOID* LoadedImports;                                                //0x44
    };
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x48
    VOID* PatchInformation;                                                 //0x4c
    struct _LIST_ENTRY ForwarderLinks;                                      //0x50
    struct _LIST_ENTRY ServiceTagLinks;                                     //0x58
    struct _LIST_ENTRY StaticLinks;                                         //0x60
    VOID* ContextInformation;                                               //0x68
    ULONG OriginalBase;                                                     //0x6c
    union _LARGE_INTEGER LoadTime;                                          //0x70
};
#endif // defined(_WIN64)
```

### GetPebLdr.asm

x64不能直接内联汇编，需要设置一下vs，可以查看[vs2022编译x64加入汇编 | CSDN](https://blog.csdn.net/qq_29176323/article/details/129145326)

```asm
.CODE
GetPebLdr PROC
	mov rax, gs:[60h];
	add rax, 18h;
	mov rax, [rax];
	ret;
GetPebLdr ENDP
END
```

### main.cpp

```c
#include "header.h"
using namespace std;

void GetModuleInfo()
{
#if defined(_WIN64)
    _PEB_LDR_DATA64* pLdr = (_PEB_LDR_DATA64*)GetPebLdr();
    if (pLdr == NULL) {
        cout << "Get Peb Ldr failed" << endl;
        exit(0);
    }

    PLIST_ENTRY64 pList = (PLIST_ENTRY64) & (pLdr->InLoadOrderModuleList);
    _LDR_DATA_TABLE_ENTRY64* pListData = (_LDR_DATA_TABLE_ENTRY64*)pList->Flink;
    while ((int*)pList != (int*)pListData) {
        /* 获取模块信息 */
        printf("DllModuleName: %ws\r\n", pListData->FullDllName.Buffer);
        printf("DllBaseAddr: %#016x\r\n", pListData->DllBase);

        /* 链表操作 */
        pListData =
            (_LDR_DATA_TABLE_ENTRY64*)(pListData->InLoadOrderLinks.Flink);
    }

#else
    /* 获取LDR地址 */
    _PEB_LDR_DATA* pLdr = NULL;
    __asm {
        mov eax, dword ptr fs:[0x30];
        add eax, 0xc;
        mov eax, [eax];
        mov pLdr, eax;
    }

    if (pLdr == NULL)
    {
        cout << "Get Peb Ldr failed" << endl;
        exit(0);
    }

    _LIST_ENTRY* pList = (_LIST_ENTRY*)&(pLdr->InLoadOrderModuleList);
    _LDR_DATA_TABLE_ENTRY* pListData = (_LDR_DATA_TABLE_ENTRY*)pList->Flink;
    while ((int*)pList != (int*)pListData) {
        /* 获取模块信息 */
        printf("DllModuleName: %ws\r\n", pListData->FullDllName.Buffer);
        printf("DllBaseAddr: %#08x\r\n", pListData->DllBase);

        /* 链表操作 */
        pListData = (_LDR_DATA_TABLE_ENTRY*)pListData->InLoadOrderLinks.Flink;
    }
#endif
}

int main()
{
    GetModuleInfo();
    return 0;
}
```

这里我测试发现在我的系统上（还测试了win10虚拟机），如果遍历`InMemoryOrderModuleList`则只会显示一个节点信息，前后指针的值都为NULL，用其他两个链表则无事

![image-20240318170028590](https://raw.githubusercontent.com/Military-axe/imgtable/main/202403181700975.png)

## Rust实现

思路与c语言思路相同，获取Peb,找到ldr链表,循环遍历链表.下面是一个x64的实现，比较简陋，wchar类型的打印就只简单做了一个例子

```rust
use std::arch::asm;
use std::char;
use std::ffi::c_void;
use std::mem;
use std::slice;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct ListEntry64 {
    flink: *mut ListEntry64,
    blink: *mut ListEntry64,
}

#[derive(Debug, Clone)]
#[repr(C)]
struct PebLdrData64 {
    length: u32,
    initialized: u32,
    ss_handle: *mut c_void,
    in_load_order_module_list: ListEntry64,
    in_memory_order_module_list: ListEntry64,
    in_initialization_order_module_list: ListEntry64,
    entry_in_progress: *mut c_void,
    shutdown_in_progress: u64,
    shutdown_thread_id: *mut c_void,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct LdrDataTableEntry {
    in_load_order_links: ListEntry64,
    in_memory_order_links: ListEntry64,
    in_initialization_order_links: ListEntry64,
    dll_base: *mut c_void,
    entry_point: *mut c_void,
    size_of_image: u32,
    full_dll_name: UnicodeString,
    base_dll_name: UnicodeString,
    flags: [u8; 4],
    obsolete_load_count: u16,
    tls_index: u16,
    hash_links: ListEntry64,
    time_date_stamp: u32,
    entry_point_activation_context: u64,
    lock: *mut c_void,
    ddag_node: u64,
    node_module_link: ListEntry64,
    load_context: u64,
    parent_dll_base: *mut c_void,
    switch_back_context: *mut c_void,
    base_address_index_node: u64,
    mapping_info_index_node: u64,
    original_base: u64,
    load_time: u64,
    base_name_hash_value: u32,
    load_reason: u64,
    implicit_path_options: u32,
    reference_count: u32,
    dependent_load_flags: u32,
    signing_level: u8,
}

fn print_wchar_ptr(ptr: *const u16, length: usize) {
    // 创建一个 &[u16] 切片
    let wchar_slice = unsafe { slice::from_raw_parts(ptr, length) };

    // 解码 UTF-16 字符为 Rust 的 Unicode 字符串
    let unicode_string: String = char::decode_utf16(wchar_slice.iter().cloned())
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();

    // 打印 Unicode 字符串
    println!("{}", unicode_string);
}

fn main() {
    let mut peb_ldr_data64: u64 = 0;
    unsafe {
        asm!(
            "mov {0}, gs:[0x60]",
            "add {0}, 0x18",
            "mov {0}, [{0}]",
            inout(reg) peb_ldr_data64
        );
    }

    println!("PEB_LDR addr: {:#x}", peb_ldr_data64);
    let pldr = unsafe { mem::transmute::<u64, *const PebLdrData64>(peb_ldr_data64) };

    let p_list_entry64 = unsafe { &(*pldr).in_load_order_module_list as *const ListEntry64 };

    /* 获取下一个节点 */
    let mut p_ldr_data = unsafe { (*p_list_entry64).flink as *mut LdrDataTableEntry };

    while p_list_entry64 as u64 != p_ldr_data as u64 {
        /* 打印节点信息 */
        let addr = unsafe { (*p_ldr_data).dll_base as u64 };
        let buffer = unsafe { (*p_ldr_data).full_dll_name.buffer };
        let buffer_len = unsafe { (*p_ldr_data).full_dll_name.length };
        print_wchar_ptr(buffer, (buffer_len / 2) as usize);
        println!("module addr: {:#x}", addr);

        /* 遍历链表 */
        p_ldr_data = unsafe { (*p_ldr_data).in_load_order_links.flink as *mut LdrDataTableEntry }
    }
}
```

这个代码我测试发现和c语言一样有一个奇怪的问题，只有`in_load_order_module_list`这条链表能用，其他两条链表都有问题。

![](https://raw.githubusercontent.com/Military-axe/imgtable/main/202403191640027.png)

## 参考

[PEB结构：获取模块kernel32基址技术及原理分析 | 看雪](https://bbs.kanxue.com/thread-266678.htm)

[x86x64用户层基于PEB遍历模块信息 | kn0sky](https://www.kn0sky.com/?p=69)

[windows 结构体 | VERGILIUS](https://www.vergiliusproject.com/)

[vs2022编译x64加入汇编 | CSDN](https://blog.csdn.net/qq_29176323/article/details/129145326)