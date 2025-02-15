---
title: "llvm base development environment configuration"
date: 2025-01-25T15:28:53+08:00
toc: true
categories: C++
tags: [llvm, c++]
---

之前一直以为编译llvm的pass需要编译一整个llvm,然后llvm编译的内存要求要又很高（50G交换空间都不够！然后发现其实完全不需要，安装库就可以，编译参数也可以通过llvm-config来获取。 我这里使用arch,做一下简单的记录

<!--more-->

# 安装

## Ubuntu/Debain

如果是ubuntu/debain就很方便，llvm官方有[安装脚本](https://apt.llvm.org/llvm.sh)

可以通过这个脚本安装指定的包，指定的版本。

安装最新版本

```Bash
bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)"
```

安装指定版本

```Bash
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh <version number>
```

安装所有包

```Bash
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh <version number> all
# or
sudo ./llvm.sh all
```

## Arch

Arch就没有这么方便了，不过pacman/yay也可以指定安装llvm的包以及版本，这里以安装llvm18为例

```Bash
yay -Syu llvm18 llvm18-libs
```

llvm18-libs 是 LLVM 18 runtime库

## Other OS

如果想使用命令安装包，可以参考

```Bash
# LLVM
apt-get install libllvm-19-ocaml-dev libllvm19 llvm-19 llvm-19-dev llvm-19-doc llvm-19-examples llvm-19-runtime
# Clang and co
apt-get install clang-19 clang-tools-19 clang-19-doc libclang-common-19-dev libclang-19-dev libclang1-19 clang-format-19 python3-clang-19 clangd-19 clang-tidy-19
# compiler-rt
apt-get install libclang-rt-19-dev
# polly
apt-get install libpolly-19-dev
# libfuzzer
apt-get install libfuzzer-19-dev
# lldb
apt-get install lldb-19
# lld (linker)
apt-get install lld-19
# libc++
apt-get install libc++-19-dev libc++abi-19-dev
# OpenMP
apt-get install libomp-19-dev
# libclc
apt-get install libclc-19-dev
# libunwind
apt-get install libunwind-19-dev
# mlir
apt-get install libmlir-19-dev mlir-19-tools
# bolt
apt-get install libbolt-19-dev bolt-19
# flang
apt-get install flang-19
# wasm support
apt-get install libclang-rt-19-dev-wasm32 libclang-rt-19-dev-wasm64 libc++-19-dev-wasm32 libc++abi-19-dev-wasm32 libclang-rt-19-dev-wasm32 libclang-rt-19-dev-wasm64
# LLVM libc
apt-get install libllvmlibc-19-dev
```

## 手动

在github/llvm-project的[releases](https://github.com/llvm/llvm-project/releases)页面中，可以下载指定系统的llvm包，比如我要下载llvm19在Linux上x64的库，就选择[LLVM-19.1.7-Linux-X64.tar.xz](https://github.com/llvm/llvm-project/releases/download/llvmorg-19.1.7/LLVM-19.1.7-Linux-X64.tar.xz)

解压到指定位置后，给bin目录添加权限，并添加进入PATH中，也可以做到相似效果。

## Windows

Windows其实就是使用手动的方式，在[releases](https://github.com/llvm/llvm-project/releases)页面中下载[clang+llvm-19.1.7-x86_64-pc-windows-msvc.tar.xz](https://github.com/llvm/llvm-project/releases/download/llvmorg-19.1.7/clang+llvm-19.1.7-x86_64-pc-windows-msvc.tar.xz)

解压到指定位置后，添加bin目录到环境变量中即可

>   注意：不要使用[LLVM-19.1.7-win64.exe](https://github.com/llvm/llvm-project/releases/download/llvmorg-19.1.7/LLVM-19.1.7-win64.exe)这些图形化来安装，这个不会安装库，只安装了bin目录那些软件

# 编译Pass

pass的例子选择llvm/examples/Bye/Bye.cpp，这个例子有NewPassManager和LegacyPassManager版本，都在一个文件中

```C++
#include "llvm/IR/Function.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Pass.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

static cl::opt<bool> Wave("wave-goodbye", cl::init(false),
                          cl::desc("wave good bye"));

namespace {

bool runBye(Function &F) {
  if (Wave) {
    errs() << "Bye: ";
    errs().write_escaped(F.getName()) << '\n';
  }
  return false;
}

struct LegacyBye : public FunctionPass {
  static char ID;
  LegacyBye() : FunctionPass(ID) {}
  bool runOnFunction(Function &F) override { return runBye(F); }
};

struct Bye : PassInfoMixin<Bye> {
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
    if (!runBye(F))
      return PreservedAnalyses::all();
    return PreservedAnalyses::none();
  }
};

} // namespace

char LegacyBye::ID = 0;

static RegisterPass<LegacyBye> X("goodbye", "Good Bye World Pass",
                                 false /* Only looks at CFG */,
                                 false /* Analysis Pass */);

/* New PM Registration */
llvm::PassPluginLibraryInfo getByePluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "Bye", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerVectorizerStartEPCallback(
                [](llvm::FunctionPassManager &PM, OptimizationLevel Level) {
                  PM.addPass(Bye());
                });
            PB.registerPipelineParsingCallback(
                [](StringRef Name, llvm::FunctionPassManager &PM,
                   ArrayRef<llvm::PassBuilder::PipelineElement>) {
                  if (Name == "goodbye") {
                    PM.addPass(Bye());
                    return true;
                  }
                  return false;
                });
          }};
}

#ifndef LLVM_BYE_LINK_INTO_TOOLS
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getByePluginInfo();
}
#endif
```

## 命令行编译

在bash中，zsh和fish不太行，主要是没有``语法

```Bash
clang++ `llvm-config-18 --cxxflags` -fPIC -shared pass.cpp -o pass.so `llvm-c
onfig-18 --ldflags`
```

-   `llvm-config-18 --cxxflags` 输出的实际上是c++编译器标志，主要是llvm头文件的路径。
-   `llvm-config-18 --ldflags` 输入的实际上是连接库位置 下面是我环境的输入

```Bash
$ llvm-config-18 --cxxflags
-I/usr/lib/llvm18/include -std=c++17   -fno-exceptions -funwind-tables -D_GNU_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS

$ llvm-config-18 --ldflags
-L/usr/lib/llvm18/lib
```

所以上面的命令可以拼接起来，就是可以用于脚本

```Bash
clang++ -I/usr/lib/llvm18/include -std=c++17   -fno-exceptions -funwind-tables -D_GNU_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS -fPIC -shared pass.cpp -o pass.so -L/usr/lib/llvm18/lib
```

## CMake编译

其实就是上面的编译命令改成脚本

```CMake
cmake_minimum_required(VERSION 3.10)
project(MyPass)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-exceptions -funwind-tables -fPIC")

# Add preprocessor definitions
add_definitions(
    -D_GNU_SOURCE
    -D__STDC_CONSTANT_MACROS
    -D__STDC_FORMAT_MACROS
    -D__STDC_LIMIT_MACROS
)

# Include directories
include_directories(/usr/lib/llvm18/include)

# Link directories
link_directories(/usr/lib/llvm18/lib)

# Add the shared library target
add_library(pass SHARED pass.cpp)

# Set the output name for the shared library
set_target_properties(pass PROPERTIES OUTPUT_NAME "pass.o")
```

# 运行

有两种运行方式

-   一种是适合调试时使用的，使用opt加载pass,修改IR
-   一种是使用clang加载插件，直接编译成可执行文件

编译、修改并运行 IR

```Shell
clang -emit-llvm -S main.c -o main.ll
opt -S -load-pass-plugin=./pass.so -passes="dynamic-cc" main.ll -o new_main.ll -print-pipeline-passes
cat main.ll
lli ./new_main.ll
```

clang 方式

```Shell
clang -Xclang -fpass-plugin=./pass.so main.c -o main.exe
./main.exe
```

# Vscode cpp && clangd 配置

安装了库之后，直接引入头文件，虽然编译可以，但是没有语法提示。这是因为编译我指定了llvm头文件路径，但是语法提示没有指定。

vscode中c++语法提示一般就两个，一个微软官方出的C++，需要在.vscode中设置。一个是clangd，实际上是封装使用LSP协议的clangd，所以使用clangd的通用配置就可以。

可以通过llvm-config-18 --includedir获取头文件目录

```Bash
$ llvm-config-18 --includedir
/sur/lib/llvm18/include
```

## clangd

可以直接在项目更目录下添加`.clangd`文件

```Plain
CompileFlags:
  Add:
    - "-I/usr/lib/llvm18/include" # LLVM头文件路径
    - "-std=c++17"                # 使用C++17标准
    - "-DLLVM_ENABLE_ASSERTIONS"  # 如果需要启用断言
```

或者在vscode的setting中添加参数，这个就只适用vscode，毕竟每个IDE封装LSP肯定有差异

```JSON
{
    "clangd.fallbackFlags": [
        "-std=c++17",
        "-I/usr/lib/llvm18/include"
    ]
}
```

## 微软C++插件

在项目根目录下的`.vscode/c_cpp_properties.json`中添加库路径

```JSON
{
    "configurations": [
        {
            "name": "Linux",
            "includePath": [
                "${workspaceFolder}/**",
                "/usr/lib/llvm18/include/llvm/**",
                "/usr/lib/llvm18/include/llvm-c/**"
            ],
            "defines": [],
            "compilerPath": "/usr/bin/clang",
            "cStandard": "c17",
            "intelliSenseMode": "linux-clang-x64"
        }
    ],
    "version": 4
}
```

# 参考文档

[LLVM Debian/Ubuntu nightly packages](https://apt.llvm.org/)

[LLVM 从零开始实现LLVM PASS](https://www.less-bug.com/posts/llvm-implement-function-pass-from-scratch/)