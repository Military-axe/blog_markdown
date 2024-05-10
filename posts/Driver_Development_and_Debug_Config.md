+++
title = "Driver Development and Debug Config"
date = 2023-06-08T13:58:36+08:00

[taxonomies]
tags = ["debug", "driver development"]
categories = ["Driver"]
+++

配置windows驱动开发环境与windbg preview调试技巧，还会记录一下遇到的问题

<!-- more -->

## 驱动开发

我选择的模式是物理机编译开发驱动，虚拟机调试

### 开发环境

开发环境：vs2019 + vscode

> 选择vs2019的原因是我用vs2022，配置wdk和sdk后，模板中没有minifilter，刚好又是我要用的，只能选择vs2019.
> 如果有师傅解决了这个问题麻烦mail我，感激不尽.

sdk version: `10.0.19041`
wdk version: `10.0.19041`, [WDK 版本和其他下载](https://learn.microsoft.com/zh-cn/windows-hardware/drivers/other-wdk-downloads)

> wdk和sdk版本务必一样，查看wdk是下载下来后，点击安装在安装界面的上边可以看到，我这里是已经安装了所以报错

![image-20230608142033119](https://raw.githubusercontent.com/Military-axe/imgtable/main/202306081420890.png)

### 项目设置

根据vs2019的配置与需求配置项目，配置都是在`project->properties`中设置，不一定按照这个配置，这个配置是为了开发时候方便调试，一切从简。从上线项目的角度来看，不建议开启下面的，但是我测试项目，上线再说。

1. `c++->General->Treat Warnings As Err`设置为 No
2. `c++->Code Generation->Spectre Mitigation`设置Disable
3. `Linker->General->Treat Warnings As Err`设置为No
4. `Driver->Settings->Target OS version`设置为`Windows 10 or higher`，因为我的虚拟机是win10
5. `Configuartion`选择Debug，没有证书别选release，否则安装不上

这些都是vs2019中用于编译的，我开发代码是用vscode，写完了再去vs2019点一下编译，直接用vscode打开项目会很多头文件缺失，补全也很简单，在项目目录下配置一下。

vscode control+shift+p打开控制面板，选择`C/C++ Edit Configuration(JSON)`，然后在vs2019右键引用在vscode中缺失的头文件，copy一下路径，配置在vscode的项目json中。实际上只用添加一个路径，我这是`"C:/Program Files (x86)/Windows Kits/10/Include/10.0.19041.0/km"`

```json
{
    "configurations": [
        {
            "name": "Win32",
            "includePath": [
                "${workspaceFolder}/**",
                "C:/Program Files (x86)/Windows Kits/10/Include/10.0.19041.0/km"
            ],
            "defines": [
                "_DEBUG",
                "UNICODE",
                "_UNICODE"
            ],
            "windowsSdkVersion": "10.0.22000.0",
            "compilerPath": "cl.exe",
            "cStandard": "c17",
            "cppStandard": "c++17",
            "intelliSenseMode": "windows-msvc-x64"
        }
    ],
    "version": 4
}
```

然后vscode就可以愉快的打代码了

### 虚拟机设置

这个很多文章都有很详细的配置，这里只记录简单的几个我用到的命令，详细的请找别的文章

虚拟机需要开启测试模式，一般的驱动无法直接安装上在win10 x64下，需要签名，开启测试模式则无需签名

> 如果安装驱动服务，启动时报签名损毁，577错误时，需要打开windows启动中的高级设置，强制关闭驱动签名验证。
>
> shift+单机重启 -> 高级选项->启动设置->重启，然后选择强制禁用驱动签名

**管理员 powershell**

```kotlin
bcdedit /set testsigning on
bcdedit /Debug on
bcdedit /dbgsettings serial baudrate:115200 debugport:2
```

最后一个开启后，还要再虚拟机上设置，开启一个端口才能在物理机上用windbg连上虚拟机

![](https://raw.githubusercontent.com/Military-axe/imgtable/main/202306081444764.png)



以下命令都是在管理员权限下执行

**启动服务**

```kotlin
net start <service_name>
```

**关闭服务**

```kotlin
net stop <service_anem>
```

**删除服务**

```kotlin
sc delete <service_name>
```

## 驱动调试

在物理机上调试虚拟机中的驱动

调试软件: `windbg preview`，设置截图

![](https://raw.githubusercontent.com/Military-axe/imgtable/main/202306081458667.png)

然后再setting中设置源码与符号目录

连接之后开始调试。

系统运行中间不能再键入命令，需要再设置什么值则可以点击左上角的Break，然后再键入命令

### 日志调试等级

开发中在源码中写入`KdPrintEx`，并在参数中设置调试等级。

```c
KdPrintEx(( DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[+] HoneyFile: FileNameInfo->Name.MaximumLength: %d >= 260\r\n",
            FileNameInfo->Name.MaximumLength));
```

`DPFLTR_WARNING_LEVEL`就是等级，对应的值是1

在windbg中运行起来后设置

```shell
kd> ed Kd_IHVDRIVER_Mask 3
```

这样，打印的时候进行的运算是`(1 << DPFLTR_WARNING_LEVEL) & Kd_IHVDRIVER_Mask = 2`只要值不是0就可以打印出来

`Kd_IHVDRIVER_Mask`的设置是根据源码中第一个参数设置成`Kd_XXXX_Mask`的，要是怕变量名重复可以改成

```
nt!Kd_IHVDRIVER_Mask
```

下面是调试日志等级对应的值

```c
#define DPFLTR_ERROR_LEVEL 0
#define DPFLTR_WARNING_LEVEL 1
#define DPFLTR_TRACE_LEVEL 2
#define DPFLTR_INFO_LEVEL 3
#define DPFLTR_MASK 0x80000000
```

