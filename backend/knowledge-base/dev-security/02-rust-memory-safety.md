# 02. Rust 内存安全模型：从根源消灭内存漏洞

> 领域：开发安全
> 关联：01-c-language-memory-safety.md（C 的内存安全问题——Rust 的解决方案）
> 学习路线：OS 内核 → 网络协议 → Web 安全 → C 内存安全 → **Rust 安全模型（当前）** → 代码审计

---

## 一、Rust 的核心理念

### 1.1 与 C 的根本区别

```
C:      手动内存管理 + 无边界检查 = 70% 安全漏洞为此而生
Rust:   编译时内存安全 + 零成本抽象 = 消灭内存漏洞（在 safe 代码中）

Golang: GC + 边界检查 = 安全但性能有开销
Java:   GC + JVM = 安全但有 GC 停顿

Rust 的特殊之处: 不用 GC 提供内存安全
                是唯一能安全替代 C 的后选
```

Rust 不是通过"运行时检查"或"垃圾回收"来保证安全的，而是通过**编译时的类型系统**——这意味着安全检查在编译期完成，运行时**零开销**。

### 1.2 三大核心原则

```
1. 所有权 (Ownership)     — 每个值只有一个所有者
2. 借用 (Borrowing)       — 引用不转移所有权
3. 生命周期 (Lifetimes)   — 引用有效期编译时检查

这三者共同消灭了:
  ✓ 缓冲区溢出       — 数组边界检查编译时/运行时
  ✓ Use-After-Free   — 所有者释放后，借用失效
  ✓ Double Free      — 只有一个所有者释放一次
  ✓ 空指针解引用     — Option<T> 强制处理 None
  ✓ 数据竞争         — 引用规则确保线程安全
  ✓ 野指针           — 生命周期确保引用有效
```

---

## 二、所有权 (Ownership)

### 2.1 三条规则

```
1. 每个值都有一个变量作为它的"所有者"
2. 同一时间只有一个所有者
3. 所有者离开作用域时，值被自动释放 (drop)
```

### 2.2 C vs Rust 的对比

```c
// C 语言：谁能释放这个内存？
void example() {
    int *arr = malloc(3 * sizeof(int));
    // arr 是唯一持有地址的变量
    // 但以后可以:
    int *p = arr;     // 复制指针 → 两个变量指向同一内存
    free(arr);        // arr 释放了
    // p 现在悬空！（Use-After-Free）
    free(p);          // 或者 double free！
}
```

```rust
// Rust：所有权强制执行
fn example() {
    let arr = Box::new([1, 2, 3]);  // arr 是所有者
    let p = arr;                    // 所有权转移到 p！
    // println!("{:?}", arr);       // ❌ 编译错误！arr 已无效
    // drop(arr);                   // ❌ 编译错误！p 是所有者
}   // 离开作用域，p.drop() 被自动调用 → 安全释放
```

**关键区别：** C 的 `int *p = arr` 复制了指针（导致两个所有者），Rust 的 `let p = arr` 转移了所有权（一个值永远只有一个所有者）。

### 2.3 Move 语义

```rust
// 基本类型 (实现了 Copy trait) → 复制
let a = 42;     // i32 是 Copy 类型
let b = a;      // 复制 a 的值到 b
println!("{}", a);  // ✅ a 仍然有效

// 堆分配类型 (未实现 Copy) → 移动
let s = String::from("hello");  // s 是所有者
let t = s;                      // 所有权从 s 移动到 t
// println!("{}", s);            // ❌ 编译错误！s 已失效
println!("{}", t);              // ✅ t 是新的所有者
```

**为什么有这种区别？**

```
i32 (4 字节) → 复制成本低，直接复制
String (指针+长度+容量) → 复制成本高，转移所有权

Stack-only 类型 (Copy):      i32, u64, f64, bool, char, [i32; 3]
Heap-alloc 类型 (Move):      String, Vec<T>, Box<T>, HashMap<K,V>
```

**安全含义：**
- C 中：所有赋值都是"浅复制"——指针复制后两个指针指向同一内存，自由使用
- Rust 中：要么深复制（需要显式 `.clone()`），要么移动（原变量失效）
- 防止了 C 中常见的"忘记哪个变量拥有内存"的 bug

### 2.4 所有权与 drop

```rust
// 自动释放
{
    let s = String::from("hello");
}   // 这里 s.out_of_scope() → drop(s) → 释放堆内存
    // 自动的，确定的，编译时安排的

// 等价于 C++ 的 RAII:
// std::string s("hello");
// } // 析构函数自动调用
```

**Rust 没有 GC 的原因：** GC 在运行时扫描内存，有停顿。Rust 的所有权在编译时确定释放点——零运行时开销。

---

## 三、借用 (Borrowing)

### 3.1 为什么需要借用

```
问题：如果每个值只有一个所有者，
      函数想读取字符串内容又不获取所有权怎么办？

C 的解法: 传指针（但可能被释放，可能被修改）
Rust 的解法: 借用（引用）— 临时访问，不转移所有权
```

### 3.2 引用类型

```rust
// 不可变引用（共享引用）— &T
fn print_len(s: &String) {          // 借用 String
    println!("length: {}", s.len());
}   // s 离开作用域 → 但它是引用，不释放 String

fn main() {
    let s = String::from("hello");
    print_len(&s);                  // 传引用
    println!("{}", s);              // ✅ s 仍然有效（所有权没变）
}

// 可变引用（独占引用）— &mut T
fn add_world(s: &mut String) {
    s.push_str(", world");
}

fn main() {
    let mut s = String::from("hello");
    add_world(&mut s);              // 传可变引用
    println!("{}", s);              // "hello, world"
}
```

### 3.3 借用规则（Rust 最严格的规则）

```
规则 1: 任意时刻，一个值只能有：
  - 多个不可变引用（&T）    → 多个读者
  - 或者一个可变引用（&mut T）→ 一个写者
  - 但不能同时存在

规则 2: 引用必须始终有效（不能比其指向的值活得久）
```

**为什么这条规则重要（从安全角度）：**

```rust
// 违反规则 1 — 数据竞争
let mut v = vec![1, 2, 3];
let r1 = &v;           // 不可变引用
let r2 = &mut v;       // ❌ 编译错误！已经存在不可变引用
// r1.push(4);          // r1 不能修改
// r2.push(4);          // r2 想要修改
// 如果允许：r1 可能在 r2 修改时读取 → 数据竞争

// C++ 中这完全合法（未定义行为）：
// vector<int> v{1,2,3};
// int *r1 = v.data();  // 指针
// v.push_back(4);      // 可能重新分配 → r1 悬空
// cout << *r1;         // Use-After-Free
```

### 3.4 借用与 C 指针的对比

```
C 指针:
  可以任意复制、修改、释放
  没有任何限制
  指向的内存可能在任意时刻被释放

Rust 引用:
  生命期由编译器验证
  引用不能比被引用者活得更久
  要么多个只读 / 要么一个读写
```

**这是 Rust 消灭数据竞争的核心机制：** 多个读操作不冲突，但读写操作不能同时发生。编译器在编译时强制这些规则。

---

## 四、生命周期 (Lifetimes)

### 4.1 生命周期的本质

```
生命周期是 Rust 的"指针有效期"标注系统

C:         void* p = malloc(...);  // 生命周期不明
           free(p);                 // 但编译器不知道 p 是否还在使用
           p->field = 42;          // 未定义行为！（UAF）

Rust:      let p: &'a T = ...;      // 'a 是生命周期参数
           编译器验证 'a 不会比它指向的值更长
```

### 4.2 生命周期标注

```rust
// 函数签名表示：
// "返回的引用和参数 x 有相同的生命周期"
fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() { x } else { y }
}

// 调用:
fn main() {
    let s1 = String::from("long");
    let result;
    {
        let s2 = String::from("short");
        result = longest(&s1, &s2);  // 'a = min(s1, s2 的生命周期)
    }   // s2 离开作用域
    // println!("{}", result);       // ❌ 编译错误！
    // result 引用的 s2 已被释放
}
```

**在 C 中：** 返回指向局部变量的指针是合法的（编译器只会警告），运行时就是 UAF。

**在 Rust 中：** 编译器拒绝编译这种代码。生命周期标注让"指针的有效期"成为类型系统的一部分。

### 4.3 生命周期省略规则

```
大多数情况下不需要写生命周期标注:
  fn first(s: &str) -> &str    // 自动推断
  fn get(&self) -> &T          // 自动
  fn bar(x: &i32) -> &i32     // 自动
```

编译器有三个隐含规则自动添加生命周期标注，只有在规则无法满足时才需要显式标注。

---

## 五、Safe Rust 消灭了哪些漏洞

| 漏洞类型 | 在 C 中 | 在 Safe Rust 中 |
|---------|---------|----------------|
| **缓冲区溢出** | 数组下标不检查 → 任意内存写 | 边界检查（越界 → panic 或编译拒绝） |
| **Use-After-Free** | 释放后使用指针 → 未定义行为 | **不可能**（所有者释放后引用失效）|
| **Double Free** | free 两次 → 堆损坏 | **不可能**（只有一个所有者释放一次）|
| **空指针解引用** | NULL 检查依赖程序员 | **不可能**（Option<T> 强制处理） |
| **数据竞争** | 多线程同时读写 → UB | **不可能**（或者只读/或者一个写）|
| **栈缓冲区溢出** | char buf[32]; gets(buf) | **不可能**（固定数组不能越界）|
| **野指针** | 指向未初始化或释放的内存 | **不可能**（未初始化变量不能使用）|
| **格式化字符串** | printf(user_input) | **不可能**（格式字符串必须在编译时确定）|

**这是安全语言和"安全代码实践"的区别：**

```
C 的安全: 依赖程序员的纪律
  → "记得做边界检查"
  → "记得释放后置 NULL"
  → "记得检查返回值"
  → 人总会犯错

Rust 的安全: 编译器强制执行
  → "不符合规则的代码无法编译"
  → 程序员犯错 → 编译失败（不是运行时崩溃）
```

---

## 六、Unsafe Rust（安全的边界）

Safe Rust 能做的事情有限制——无法直接操作硬件、无法调用外部 C 函数、无法实现底层数据结构。Unsafe Rust 允许这些操作，但**安全保证降级到程序员手中**。

### 6.1 Unsafe 允许的五种操作

```rust
unsafe {
    // 1. 解引用裸指针（*const T, *mut T）
    let ptr: *const i32 = &42;
    let val = *ptr;             // unsafe!

    // 2. 调用 unsafe 函数
    // FFI 调用 C 函数:
    // extern "C" { fn strlen(s: *const c_char) -> usize; }
    // strlen(...) 是 unsafe

    // 3. 访问/修改可变静态变量
    static mut COUNTER: u32 = 0;
    COUNTER += 1;               // unsafe!

    // 4. 实现 unsafe trait
    // unsafe trait Foo { ... }

    // 5. 访问 union 的字段
    // union U { i: i32, f: f32 }
    // u.i = 42;  // unsafe!
}
```

### 6.2 Unsafe ≠ 不安全

```
Unsafe Rust 的关键设计理念:
  "我向编译器保证这段代码在运行时是安全的"
  "编译器相信我，不再做安全检查"

Unsafe 不是关闭所有保护 → 只是关闭了特定几个检查
Safe Rust 的其他保护（所有权、借用规则）在 unsafe 块内仍有效
```

### 6.3 Unsafe 的正确使用模式

```rust
// 正确的 unsafe 封装模式:
// 用 safe API 包装 unsafe 代码

/// 安全地从缓冲区读取 N 个字节
fn read_n(buf: &[u8], n: usize) -> Option<&[u8]> {
    if n > buf.len() {
        return None;    // 边界检查在 safe 代码中完成
    }
    // unsafe 块只做"我确定这里安全"的操作
    unsafe {
        Some(&buf[..n])  // 编译器无法检查 `n <= len`
    }                     // 但程序员已经验证了
}
```

### 6.4 Unsafe Rust 从漏洞

```
即使在 Unsafe Rust 中，出现漏洞的概率比 C 低，原因:

1. unsafe 块范围小（通常几行代码）
2. safe 封装提供边界保护
3. 只在使用裸指针/FII 时才真正危险
```

**Rust 中一些真正的 CVE：**

| CVE | 问题 | 原因 |
|:---:|------|------|
| CVE-2018-1000657 | VecDeque::reserve 缓冲区溢出 | unsafe 内标错误 |
| CVE-2020-36323 | std::io::Read::read_to_end | 整数溢出 + 未检查 |
| CVE-2024-27308 | 内存分配器 | 特定平台的整行为 |

**但注意：** 这些问题在 Rust 中极其罕见，远少于 C/C++。而且发现后固定在代码/生态系统级别修复。

---

## 七、Rust 与 C 的内存安全对比（技术细节）

### 7.1 缓冲区溢出

```c
// C: 可以编译运行，但会溢出
void overflow() {
    int arr[5];
    for (int i = 0; i <= 100; i++) {
        arr[i] = i;    // 越界写入栈上的其他数据
    }
}
```

```rust
// Rust: 编译器拒绝或者运行时 panic
fn overflow() {
    let arr = [0i32; 5];
    for i in 0..=100 {
        arr[i] = i;    // ❌ 编译错误！arr 是不可变引用？
    }                   // 即使改成 mut，运行时 panic（边界检查）
}
```

**Rust 不是 coder 安全，而是检查：**
- 静态可确定的索引 → 编译时拒绝
- 动态索引 → 运行时边界检查（有开销，但确保了安全）
- LLVM 在 Release 模式下会优化掉很多边界检查

### 7.2 Use-After-Free

```c
// C: 经典 UAF
int* get_ptr() {
    int* p = malloc(sizeof(int));
    *p = 42;
    return p;
}
void use_after_free() {
    int* p = get_ptr();
    int val = *p;      // ✅ OK
    free(p);
    val = *p;          // ❌ UAF！但 C 编译器不报错
}
```

```rust
// Rust: 编译器拒绝
fn uaf() {
    let r: &i32;
    {
        let x = 42;
        r = &x;
    }   // x 在这里被释放
    // println!("{}", r); // ❌ 编译错误！r 引用已释放的 x
}
```

### 7.3 数据竞争

```c
// C: 多线程数据竞争（无锁，合法但 UB）
int counter = 0;
// 线程 1: counter++;
// 线程 2: counter++;
// → 结果不确定（读-修改-写非原子）
```

```rust
// Rust: 编译器拒绝
let mut counter = 0;
// std::thread::spawn(move || { counter += 1; });
// std::thread::spawn(move || { counter += 1; });
// ❌ 编译错误！不能同时有两个可变引用
// → 需要使用 Mutex<Rc<>> 或 Arc<Mutex<>>
```

**Rust 的 Send/Sync trait：**
```
Send:  类型可以安全地在线程间传递所有权
Sync:  类型可以安全地在线程间共享引用（&T）

编译器自动检查这些 trait — 写代码时不需要手动处理
大多数类型自动实现了 Send/Sync
但裸指针、Rc 等不是（因为它们不安全）
```

---

## 八、Rust 的 weaknesses（安全局限性）

### 8.1 逻辑漏洞

```
Rust 解决了内存安全，但没解决「逻辑漏洞」：

  认证绕过:
    if user.is_admin() { ... }
    → Rust 不会检查你的 is_admin() 函数是否正确

  密码学错误:
    let encrypted = xor(data, key);  // XOR 加密
    → Rust 不会阻止你使用弱加密算法

  业务漏洞:
    price = price * quantity;
    → Rust 不会检查你是否有"越权改价"漏洞
```

**Rust 消灭了攻击面最大的漏洞（~70%），但其余 30% 仍需人工检查。**

### 8.2 Unsafe 的使用在生态中常见

```
虽然 Rust 鼓励最小化 unsafe 使用
但实际 Rust 生态中 unsafe 的使用较常见:

  - std 库内部: ~2000 个 unsafe 块
  - 很多高性能 crate: unsafe 用于 SIMD、FFI、自托管结构
  - 嵌入式: core 库无分配器 → unsafe 更多
  
但关键区别: unsafe 被明确标记、范围小、更容易审计
```

### 8.3 FII 边界是最薄弱的环节

```
Rust + C/C++ 混合项目中:
  Rust 侧: 安全的
  C 侧:    不安全的
  FFI 边界: 需要大量 unsafe 代码
             需要处理类型转换、生命周期、内存所有权移交
             最容易出现问题

例如:
  1. C 分配内存，传递指针到 Rust
  2. Rust 侧安全代码用 unsafe 操作该指针
  3. C 侧释放内存 → Rust 的指针悬空
  4. → UAF（虽然 Rust 代码是安全的，但跨越 FFI 边界时出问题）
```

### 8.4 编译时安全检查的原则性限制

```
Rust 的借用检查器是"保守的"：
  它拒绝一些实际上安全的代码
    
  例如:
    let mut v = vec![1, 2, 3];
    let r = &v[0];
    v.push(4);
    // println!("{}", r);  // ❌ 编译错误
    // 实际上 v 在 push 后可能重新分配，r 会悬空
    // 但有时程序员"知道" push 不会重新分配（如果 capacity 足够）
    // 编译器仍然拒绝

  为了解决这种问题: 引入 unsafe 或使用 RefCell（运行时借用检查）
```

---

## 九、从原理推导攻击面

### 攻击面 1：Unsafe 的条件越界

```
Safe Rust 保证安全——但需要 unsafe 的地方（FFI、裸指针）
一旦 unsafe 代码有 bug，所有安全保证都被破坏

可推导攻击:
  检查 unsafe 块是否完成了安全验证
  任何 unsafe 块中的逻辑错误 → 可能的内存漏洞
```

### 攻击面 2：FFI 边界的内存所有权歧义

```
Rust-C FFI 中谁负责释放？
  C 分配 → Rust 使用 → 谁 free？
  Rust 分配 → C 使用 → 谁 drop？

如果约定不明确 → double free 或内存泄漏
```

### 攻击面 3：逻辑漏洞（内存安全之外的）

```
认证、授权、加密、业务逻辑
Rust 不提供这些领域的保护

更危险的是：Rust 让开发者产生"安全错觉"
  认为"我用 Rust = 我的程序安全"
  但认证绕过、SQL 注入仍然存在
```

### 攻击面 4：panic 导致的安全问题

```
Rust 的 panic 可能导致:
  - 代码执行中断（类似异常）
  - abort 模式下的服务终止（DoS）
  - unwind 模式下的资源清理错误
  - 在 unsafe 代码中 panic → 未定义行为
```

---

## 十、渗透测试中的 Rust 评估要点

### 10.1 识别 Rust 程序

```bash
# 检查可执行文件
file target
# → ELF 64-bit LSB executable, x86-64, Rust

# 查看符号表
nm target | grep rust
# → 包含 rust 相关的符号

# 查看字符串
strings target | grep "rust"
# → 可能包含 rust_panic, rust_oom 等
```

### 10.2 评估 Rust 程序的安全性

```rust
// 评估清单:
// 1. 是否包含 unsafe 块？
//    grep "unsafe" src/
//    如果 unsafe 多 → 攻击面大

// 2. FFI 边界
//    grep "extern" src/
//    如果 FFI 多 → 需要检查 C 侧的安全

// 3. 未使用 Option/Result
//    if x.is_null() { ... }  // 危险！应使用 Option
//    unwrap() 滥用 → 可能 panic

// 4. 关键依赖的版本
//    Cargo.toml 中依赖的版本
//    已知 CVE 的旧版本
```

### 10.3 如何绕过 Rust 的保护

```
理论上可能的方式:

1. 利用 unsafe 代码
   → 如果程序包含大量 unsafe → 传统内存攻击可能有效

2. 逻辑漏洞
   → Rust 不阻止逻辑错误 → 认证绕过、业务漏洞

3. DoS
   → Rust 的 panic 可能导致服务崩溃（如果使用 unwrap）

4. 侧信道
   → Rust 不阻止时序攻击、缓存侧信道

现实中:
  - 纯 safe Rust 程序几乎无法被内存攻击
  - 包含大量 unsafe + FFI 的程序 ≈ C 的攻击面
```

---

## 十一、总结

### Rust 安全的本质

```
Rust 不是"更安全的 C"——它是完全不同的安全模型。

C:    编译器信任程序员 → 不安全的行为被编译
Rust: 程序员必须赢得编译器的信任 → 编译器在编译时强制执行安全规则

结果:
  - Safe Rust 中的内存漏洞几乎不可能
  - Unsafe Rust 中的漏洞远少于 C（范围小、易审计）
  - 大量安全问题的传统攻击面被消除
```

### 核心矛盾

```
Rust 的权衡:

             安全性 ↑
     Rust (safe)
   Rust (unsafe)
        C

               控制权/灵活性 →

越安全的 → 控制权越少 → 越需要编译器判断
越灵活的 → 安全责任越大 → 越依赖程序员的判断

Rust 的优雅之处：选择了一个好的平衡点
  - 95% 的代码用 safe Rust（编译器保护）
  - 5% 用 unsafe（显式标记，范围小，易审计）
```

### 对渗透测试的启示

```
1. 纯 safe Rust 程序 → "几乎刀枪不入"
   攻击的重点从内存溢出 → 逻辑漏洞/业务漏洞

2. 含 unsafe 的 Rust 程序 → "防弹衣有缝隙"
   攻击的重点是 unsafe 块和 FFI 边界

3. Rust + C 混合程序 → "防弹衣只有一半"
   C 部分仍用传统攻击手法
   FFI 边界是新的攻击面

4. 工具链/生态 → "供应链攻击"
   Cargo 依赖 → 恶意包 → 供应链
```

### 最重要的结论

> **Rust 不是免于安全——它是把最危险的漏洞类别（内存安全）从运行时移到了编译时。**
> 
> 这是安全领域最有效的防护——不是"降低漏洞概率"（像安全编码规范那样），而是**让漏洞在编译阶段就无法存在**。
> 
> 对于渗透测试者：Rust 程序主要攻击方向从内存溢出 → 逻辑漏洞/侧信道/供应链。对于大量用 unsafe 的 Rust 程序，传统攻击手法仍可能有效。
