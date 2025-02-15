---
title: "C++ static polymorphism && Curiously recurring template pattern"
date: 2025-01-10T00:40:23+08:00
toc: true
categories: C++
tags: [c++ ,polymorphism ,CRTP]
---

在看llvm新旧版pass manager的时候，看到其中一个设计是使用CRTP这种模式，对我来说还是很陌生的。或者说C++多态我都不太熟，于是简单学习一下这个部分（C++真tm难啊

<!--more-->

# 多态

多态（Polymorphism）是面向对象编程（Object - Oriented Programming，OOP）中的一个重要概念。它指的是同一个操作作用于不同的对象，可以有不同的解释，产生不同的执行结果。简单来说，多态允许使用统一的接口来处理多种不同类型的对象。

在C++中多态分为两种，静态多态和动态多态。

动态多态的优势是灵活性，能在运行时才确定具体类型。静态多态相对应的则是在性能上比动态多态更具备优势。动态多态是需要使用虚表来查找具体的函数实现，再通过函数指针间接调用函数，会造成性能的损失。

## 动态多态

### 实现机制

依赖于虚函数表（v-table）。当一个类包含虚函数时，编译器会为这个类创建一个虚函数表，虚函数表中存储了虚函数的地址。每个含有虚函数的类对象内部会有一个指针（v-pointer），这个指针指向所属类的虚函数表。在运行时，当通过基类指针或引用调用虚函数时，就会根据对象的 v-pointer 找到对应的虚函数表，然后根据虚函数在表中的位置调用正确的函数。这种机制有一定的运行时开销，因为需要通过额外的指针查找来确定函数调用。

### 灵活性和可维护性

提供了高度的灵活性，特别是在处理具有层次结构的对象集合时。可以方便地添加新的派生类，只要遵循基类的虚函数接口规范，就可以在不修改原有代码（通过基类指针或引用调用虚函数的代码）的基础上，实现新的功能。例如，在一个图形绘制系统中，有`Shape`基类和`Circle`、`Rectangle`等派生类。如果要添加一个新的图形类型（如`Triangle`），只需要从`Shape`类派生，并重写`draw`等虚函数，而不用修改绘制图形的主程序代码（只要主程序是通过`Shape*`或`Shape&`来调用`draw`函数的）。不过，动态多态的代码调试可能会稍微复杂一些，因为函数调用的实际路径是在运行时确定的。

### 性能

由于运行时需要查找虚函数表来确定函数调用，会有一定的性能开销。每次通过基类指针或引用调用虚函数时，都需要进行间接的内存访问来获取虚函数表指针，然后再查找函数地址。在对性能要求极高的场景下，这种开销可能需要考虑。不过，现代编译器和处理器在优化方面也做了很多工作，在一定程度上减轻了这种性能损失。

### 常见动态多态

常见的动态多态是通过虚函数来实现的

```C++
#include <iostream>
#include <ostream>
#include <string>
#include <vector>
constexpr double PI = 3.14159;

class Shape {
public:
  virtual double area() const = 0;
};

class Circle : public Shape {
private:
  double radius;

public:
  Circle(double r) : radius(r) {}
  double area() const override { return PI * radius * radius; }
};

class Bracket : public Shape {
private:
  double edge;

public:
  Bracket(double e) : edge(e) {}
  double area() const override { return edge * edge; }
};

double sum_all_shape(std::vector<Shape*> vec = {}) {
  double sum(0);
  for (auto s : vec) {
    sum += s->area();
  }

  return sum;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    return -1;
  }

  Circle circle(std::stod(argv[1]));
  Bracket bracket(std::stod(argv[2]));
  std::vector<Shape *> vec = {&circle, &bracket};
  std::cout << sum_all_shape(vec) << std::endl;
}
```

## 静态多态

### 实现机制

函数重载是基于编译器对函数签名（包括函数名、参数类型、参数个数、参数顺序等）的匹配。编译器在编译阶段扫描代码，根据函数调用的实参情况，在符号表中查找匹配的函数定义。对于模板，编译器会在编译时根据模板参数进行模板实例化。它根据模板的定义和调用时提供的模板实参，生成具体的函数或类代码。相比动态多态，静态多态在编译时就确定了调用关系，没有运行时查找虚函数表的开销。

### 灵活性和可维护性

函数重载的灵活性相对较低。当需要增加新的功能，可能需要修改函数的参数列表或者添加新的重载函数，这可能会导致代码的膨胀和维护成本的增加。但是，由于函数调用是在编译时确定的，所以调试相对容易，编译器能够在编译阶段发现一些错误，如参数类型不匹配等。模板的灵活性较高，它可以用于创建通用的代码结构，适用于多种数据类型。不过，模板代码的编译错误信息可能比较复杂，而且模板的实例化过程可能会导致代码膨胀（生成了多个针对不同类型的函数或类版本）

### 性能

因为函数调用是在编译时确定的，没有运行时查找虚函数表的开销，所以在性能上通常比动态多态要好。特别是对于一些对性能敏感的代码，如底层的数值计算库等，静态多态可以提供更好的性能。但是，模板的实例化可能会导致代码体积增大，这可能会对程序的加载时间和内存占用等方面产生一定的影响。

### 常见静态多态

```C++
int add(int a, int b) {
  return a + b;
}
double add(double a, double b) {
  return a + b;
}
int main() {
  int result1 = add(3, 4);
  double result2 = add(3.5, 4.5);
  return 0;
}
```

模板也是实现静态多态的一种方式。例如函数模板

```C++
template<typename T>T max(T a, T b) {
  return (a > b)? a : b;
}

int main() {
  int result1 = max(3, 4);
  double result2 = max(3.5, 4.5);
  return 0;
}
```

# Curiously recurring template pattern

Curiously Recurring Template Pattern（CRTP），即奇异递归模板模式，是一种 C++ 编程中的设计模式。它是一种基于模板的技术，用于在编译时实现静态多态性。这种模式的特点是将派生类作为模板参数传递给基类。

使用这种方式来实现常规动态多态的例子

```C++
#include <iostream>
#include <ostream>
#include <string>

constexpr double PI = 3.14159;

template <class T> class Shape {
public:
  double area() { return static_cast<T *>(this)->area_impl(); }
};

class Circle : public Shape<Circle> {
private:
  double radius;

public:
  Circle(double r) : radius(r) {}
  double area_impl() { return PI * radius * radius; }
};

class Bracket : public Shape<Bracket> {
private:
  double edge;

public:
  Bracket(double e) : edge(e) {}
  double area_impl() { return edge * edge; }
};

int main(int argc, char **argv) {
  if (argc < 3) {
    return -1;
  }

  Circle circle(std::stod(argv[1]));
  Bracket bracket(std::stod(argv[2]));

  double sum = circle.area() + bracket.area();
  std::cout << sum << std::endl;
}
```

## 实现机制与原理

- 编译时多态性：CRTP 主要利用了模板在编译时实例化的特性。当编译器遇到`Shape<T>`这种模板实例化的代码时，它会在编译时生成具体的代码。在`Shape`类的`area`函数中，通过`static_cast`强制转换`this`指针，编译器能够确定转换后的类型是`T*`，因为`T`类在继承`Shape`类时明确了自己作为模板参数。这种在编译时确定的函数调用关系体现了静态多态性。

- 代码生成与继承关系：由于`T`类继承自`Shape<T>`，`T`类中的成员函数（如`aera_impl`）可以访问`T`类中的成员（通过`static_cast`转换后的`this`指针）。编译器在生成代码时，会根据`T`类的实际定义来确定`aera_impl`函数的具体实现。例如，如果`T`类的`area_impl`函数有不同的实现逻辑，那么在不同的`T`类实例中，`Shape`类的`area`函数调用`aera_impl`函数时会产生不同的行为，这类似于多态性，但这种多态是在编译时确定的。

## 汇编对比

使用静态多态，在编译时就确定了调用的函数

```Assembly
lea     rcx, [rbp+40h+var_28]
call    j_?area@?$Shape@VCircle@@@@QEAANXZ ; Shape<Circle>::area(void)
movsd   [rbp+40h+var_A0], xmm0
lea     rcx, [rbp+40h+var_50]
```

对应的就是

```C++
v5 = Shape<Circle>::area();    
```

而动态多态则需要在查询虚表获取函数指针

```Assembly
mov     rax, [rax]
mov     [rbp+var_38], rax
mov     rcx, [rbp+var_38]
mov     rax, [rcx]
mov     rax, [rax]
loc_14000C0E4:                          ; DATA XREF: .rdata:000000014010E5C4↓o
try {
  call    rax  
} // starts at 14000C0E4
loc_14000C0E6:                          ; DATA XREF: .rdata:000000014010E5CC↓o
movsd   [rbp+var_48], xmm0
jmp     $+5
```

对应的c++代码是

```C++
v4 = (*v1)->area(*v1);
```

## 优势

除了静态多态的固有优势外，这种模拟多态绑定的模式，可以方便的实现代码复用。虽然无法做到运行时多态那么灵活，但是也可以在一些场景中方便的做代码复用

接下来介绍几种CRTP有优势场景

# 对象计数器

对象计数器的主要用途是检索给定类的对象创建和销毁统计数据，使用CRTP可以很简单的解决

```C++
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
template <typename T> struct counter {
  static inline int objects_created = 0;
  static inline int objects_alive = 0;

  counter() {
    ++objects_created;
    ++objects_alive;
  }

  counter(const counter &) {
    ++objects_created;
    ++objects_alive;
  }

protected:
  ~counter() // objects should never be removed through pointers of this type
  {
    --objects_alive;
  }
};

class X : public counter<X> {
private:
  uint32_t x;

public:
  X(uint32_t val) : x(val) {}
};

class Y : public counter<Y> {
private:
  uint32_t y;

public:
  Y(uint32_t val) : y(val) {}
};

int main(int argc, char **argv) {
  if (argc < 3) {
    return -1;
  }

  std::vector<std::unique_ptr<X>> x_arr;
  std::vector<std::unique_ptr<Y>> y_arr;
  for (auto i = 0; i < std::stoul(argv[1]); ++i) {
    x_arr.push_back(std::make_unique<X>(i));
  }

  for (auto i = 0; i < std::stoul(argv[2]); ++i) {
    y_arr.push_back(std::make_unique<Y>(i));
  }

  std::cout << "object x num: " << X::objects_alive << std::endl;
  std::cout << "object y num: " << Y::objects_alive << std::endl;
}
```

每次创建 X 类对象时，都会调用计数器<X>的构造函数，使创建计数和存活计数递增。 每次销毁 X 类对象时，存活计数都会递减。

需要注意的是，counter<X> 和 counter<Y> 是两个不同的类，这就是它们分别保存 X 和 Y 的计数的原因。 在 CRTP 的这个示例中，类的这种区别是模板参数（counter<T> 中的 T）的唯一用途，也是我们不能使用简单的非模板基类的原因。

# 多态链

方法链又称命名参数习语，是面向对象编程语言中调用多个方法的常用语法。 每个方法都会返回一个对象，这样就可以在一条语句中将这些调用串联起来，而无需使用变量来存储中间结果。

多态链就是使用多态来实现方法链。先来看一个失败的例子，在未使用多态的情况下，链条可能会中断，无法连续调用。

```C++
#include <iostream>
#include <ostream>

enum Color {
  Red,
  Blue,
  Green,
};

class Printer {
public:
  Printer(std::ostream &pstream) : m_stream(pstream) {}

  template <typename T> Printer &print(T &&t) {
    m_stream << t;
    return *this;
  }

  template <typename T> Printer &println(T &&t) {
    m_stream << t << std::endl;
    return *this;
  }

private:
  std::ostream &m_stream;
};

class CoutPrinter : public Printer {
public:
  CoutPrinter() : Printer(std::cout) {}

  CoutPrinter &SetConsoleColor(Color c) {
    // ...
    return *this;
  }
};
```

上面的两个类，可以使用如下的链来打印

```C++
Printer(myStream).println("hello").println(500);
```

但是如果使用父类的调用子类函数就会失败，哪怕链条最开始是由子类对象调用

```C++
//                           v----- we have a 'Printer' here, not a 'CoutPrinter'
CoutPrinter().print("Hello ").SetConsoleColor(Color.red).println("Printer!"); 
// compile error
```

编译报错是因为，`print` 函数返回的是`Printer &`类型，是基类，链后续调用的函数`SetConsoleColor`是子类函数，所以会报错。这里就需要用到多态，可以使用CRTP来避免这种问题

```C++
#include <iostream>
#include <ostream>

enum Color {
  Red,
  Blue,
  Green,
};

template <typename ConcretePrinter> class Printer {
public:
  Printer(std::ostream &pstream) : m_stream(pstream) {}

  template <typename T> Printer &print(T &&t) {
    m_stream << t;
    return *this;
  }

  template <typename T> Printer &println(T &&t) {
    m_stream << t << std::endl;
    return *this;
  }

private:
  std::ostream &m_stream;
};

// Derived class
class CoutPrinter : public Printer<CoutPrinter> {
public:
  CoutPrinter() : Printer(std::cout) {}

  CoutPrinter &SetConsoleColor(Color c) {
    // ...
    return *this;
  }
};

// usage
CoutPrinter().print("Hello ").SetConsoleColor(Color.red).println("Printer!");
```

# 多态克隆函数

在使用多态性时，有时需要通过基类指针创建对象副本。 一个常用的成语就是在每个派生类中定义一个虚拟克隆函数。 CRTP 可用于避免在每个派生类中复制该函数或其他类似函数。

```C++
// Base class has a pure virtual function for cloning
class AbstractShape {
public:
  virtual ~AbstractShape() = default;
  virtual std::unique_ptr<AbstractShape> clone() const = 0;
};

// This CRTP class implements clone() for Derived
template <typename Derived> class Shape : public AbstractShape {
public:
  std::unique_ptr<AbstractShape> clone() const override {
    return std::make_unique<Derived>(static_cast<Derived const &>(*this));
  }

protected:
  // We make clear Shape class needs to be inherited
  Shape() = default;
  Shape(const Shape &) = default;
  Shape(Shape &&) = default;
};

// Every derived class inherits from CRTP class instead of abstract class

class Square : public Shape<Square> {};

class Circle : public Shape<Circle> {};
```

静态多态性的一个问题是，如果不使用像上例中的 AbstractShape 这样的通用基类，派生类就无法同构存储，也就是说，无法将同一基类派生的不同类型放在同一容器中。 例如，定义为 std::vector<Shape*> 的容器是行不通的，因为 Shape 不是一个类，而是一个需要特殊化的模板。 定义为 std::vector<Shape<Circle>*> 的容器只能存储圆形，而不能存储正方形。 这是因为从 CRTP 基类 Shape 派生的每个类都是唯一的类型。 解决这一问题的常见方法是从具有虚拟析构函数的共享基类继承，如上面的 AbstractShape 示例，这样就可以创建一个 std::vector<AbstractShape*>。

# 参考文档

https://en.wikipedia.org/wiki/Curiously_recurring_template_pattern
