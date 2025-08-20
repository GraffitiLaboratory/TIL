https://bpsecblog.wordpress.com/2016/03/07/about_got_plt_1/

#PLT #GOT #GOT_Overwrite

### PLT와 GOT

PLT(Procedure Linkage Table) 와 GOT(Global Offset Table) 는 라이브러리에서 동적 링크된 심볼의 주소를 찾을 때 사용하는 테이블이다.

바이너리가 실행되면 ASLR에 의해 라이브러리가 임의의 주소에 매핑된다. 이 상태에서 라이브러리 함수를 호출하면, 함수의 이름을 바탕으로 라이브러리에서 심볼들을 탐색하고, 해당 함수의 정의를 발견하면 그 주소로 실행 흐름을 옮기게 된다.
이 모든 과정을 통틀어 runtime resolve 라고 한다.

그런데 만약 반복적으로 호출되는 함수의 정의를 매번 탐색해야 한다면, 비효율적일 것이다. 그래서 ELF 는 GOT 라는 테이블을 두고, resolve 된 함수의 주소를 해당 테이블에 저장한다. 그리고 나중에 다시 해당 함수를 호출하면 저장된 주소를 바로 꺼내서 사용한다.

``` c
// Name: got.c
// Compile: gcc -o got got.c -no-pie

#include <stdio.h>

int main() {
    puts("Resolving address of 'puts'.");
    puts("Get address from GOT");
}
```

### resolve 되기 전

먼저 got.c를 컴파일하고 실행한 직후에, GOT의 상태를 보여주는 명령어인 got를 사용해 본다.
puts의 GOT 엔트리인 0x404018 에는 아직 puts 의 주소를 찾기 전이므로, 함수 주소 대신 .plt 섹션 어딘가의 주소인 0x401030 이 적혀 있다.
```
$ gdb ./got
pwndbg> entry
pwndbg> got
GOT protection: Partial RELRO | GOT functions: 1
[0x404018] puts@GLIBC_2.2.5 -> 0x401030 ◂— endbr64

pwndbg> plt
Section .plt 0x401020-0x401040:
No symbols found in section .plt
pwndbg>
```

이제 main()에서 puts@plt 를 호출하는 지점에 중단점을 설정하고, 내부로 따라 들어가 본다.
PLT에서는 먼저 puts 의 GOT 엔트리에 쓰인 값인 0x401030 으로 실행 흐름을 옮긴다.
pwndbg 컨텍스트에서 DISASM 부분은 프로그램에서 명령어가 호출되는 순서인 제어 흐름을 보여주는데, 실행 흐름을 따라가면 \_dl_runtime_resolve_fxsave 가 호출될 것임을 알 수 있다.
```
pwndbg> b *main+18
pwndbg> c
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
   0x40113e <main+8>     lea    rax, [rip + 0xebf]
   0x401145 <main+15>    mov    rdi, rax
 ► 0x401148 <main+18>    call   puts@plt                      <puts@plt>
        s: 0x402004 ◂— "Resolving address of 'puts'."
...
pwndbg> si
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
 ► 0x401040       <puts@plt>                        endbr64
   0x401044       <puts@plt+4>                      bnd jmp qword ptr [rip + 0x2fcd]     <0x401030>
    ↓
   0x401030                                         endbr64
   0x401034                                         push   0
   0x401039                                         bnd jmp 0x401020                     <0x401020>
    ↓
   0x401020                                         push   qword ptr [rip + 0x2fe2]      <_GLOBAL_OFFSET_TABLE_+8>
   0x401026                                         bnd jmp qword ptr [rip + 0x2fe3]     <_dl_runtime_resolve_fxsave>
    ↓
   0x7ffff7fd8be0 <_dl_runtime_resolve_fxsave>      endbr64
   0x7ffff7fd8be4 <_dl_runtime_resolve_fxsave+4>    push   rbx
   0x7ffff7fd8be5 <_dl_runtime_resolve_fxsave+5>    mov    rbx, rsp
   0x7ffff7fd8be8 <_dl_runtime_resolve_fxsave+8>    and    rsp, 0xfffffffffffffff0
...
```

여기서 코드를 조금 더 실행시키면 \_dl_runtime_resolve_fxsave 라는 함수가 실행되는데, 이 함수에서 puts 의 주소가 구해지고, GOT 엔트리에 주소를 쓰게 된다.

실제 ni 명령어를 반복적으로 수행해서 \_dl_runtime_resolve_fxsave 안으로 진입한 후, finish 명려어로 함수를 빠져나오면,  puts 의 GOT 엔트리에 libc 영역 내 실제 puts 주소인 0x7ffff7e02ed0 가 쓰여 있는 모습을 확인 할 수 있다.
```
pwndbg> ni
...
pwndbg> ni
_dl_runtime_resolve_fxsave () at ../sysdeps/x86_64/dl-trampoline.h:67
67  ../sysdeps/x86_64/dl-trampoline.h: No such file or directory.
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
   0x401030                                          endbr64
   0x401034                                          push   0
   0x401039                                          bnd jmp 0x401020                     <0x401020>
    ↓
   0x401020                                          push   qword ptr [rip + 0x2fe2]      <_GLOBAL_OFFSET_TABLE_+8>
   0x401026                                          bnd jmp qword ptr [rip + 0x2fe3]     <_dl_runtime_resolve_fxsave>
    ↓
 ► 0x7ffff7fd8be0 <_dl_runtime_resolve_fxsave>       endbr64
   0x7ffff7fd8be4 <_dl_runtime_resolve_fxsave+4>     push   rbx
   0x7ffff7fd8be5 <_dl_runtime_resolve_fxsave+5>     mov    rbx, rsp
   0x7ffff7fd8be8 <_dl_runtime_resolve_fxsave+8>     and    rsp, 0xfffffffffffffff0
   0x7ffff7fd8bec <_dl_runtime_resolve_fxsave+12>    sub    rsp, 0x240
   0x7ffff7fd8bf3 <_dl_runtime_resolve_fxsave+19>    mov    qword ptr [rsp], rax
...
pwndbg> finish
Run till exit from #0  _dl_runtime_resolve_fxsave () at ../sysdeps/x86_64/dl-trampoline.h:67
Resolving address of 'puts'.
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
   0x401148 <main+18>    call   puts@plt                      <puts@plt>

 ► 0x40114d <main+23>    lea    rax, [rip + 0xecd]
   0x401154 <main+30>    mov    rdi, rax
   0x401157 <main+33>    call   puts@plt                      <puts@plt>

   0x40115c <main+38>    mov    eax, 0
   0x401161 <main+43>    pop    rbp
   0x401162 <main+44>    ret

   0x401163              add    bl, dh
...
pwndbg> got
GOT protection: Partial RELRO | GOT functions: 1
[0x404018] puts@GLIBC_2.2.5 -> 0x7ffff7e02ed0 (puts) ◂— endbr64
pwndbg> vmmap 0x7ffff7e02ed0
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x7ffff7daa000     0x7ffff7f3f000 r-xp   195000  28000 /usr/lib/x86_64-linux-gnu/libc.so.6 +0x58ed0
```

### resolve 된 후

puts@plt 를 두번째로 호출할 때는 puts의 GOT 엔트리에 실제 puts의 주소인 0x7ffff7e02ed0 가 쓰여 있어서 바로 puts 가 실행된다.
```
pwndbg> b *main+33
pwndbg> c
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
   0x401148 <main+18>    call   puts@plt                      <puts@plt>

   0x40114d <main+23>    lea    rax, [rip + 0xecd]
   0x401154 <main+30>    mov    rdi, rax
 ► 0x401157 <main+33>    call   puts@plt                      <puts@plt>
        s: 0x402021 ◂— 'Get address from GOT'
...
pwndbg> si
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
 ► 0x401040       <puts@plt>      endbr64
   0x401044       <puts@plt+4>    bnd jmp qword ptr [rip + 0x2fcd]     <puts>
    ↓
   0x7ffff7e02ed0 <puts>          endbr64
   0x7ffff7e02ed4 <puts+4>        push   r14
   0x7ffff7e02ed6 <puts+6>        push   r13
   0x7ffff7e02ed8 <puts+8>        push   r12
   0x7ffff7e02eda <puts+10>       mov    r12, rdi
   0x7ffff7e02edd <puts+13>       push   rbp
   0x7ffff7e02ede <puts+14>       push   rbx
   0x7ffff7e02edf <puts+15>       sub    rsp, 0x10
   0x7ffff7e02ee3 <puts+19>       call   *ABS*+0xa8720@plt                <*ABS*+0xa8720@plt>
...
```

### 시스템 해킹의 관점에서 본 PLT 와 GOT

시스템 해커의 관점에서 볼 때, PLT에서 GOT를 참조하여 실행 흐름을 옮길 때, GOT의 값을 검증하지 않는다는 보안상의 약점이 있다.

따라서 만약 앞의 예에서 puts의 GOT 엔트리에 저장된 값을 공격자가 임의로 변경할 수 있다면, puts 가 호출될 때 공격자가 원하는 코드가 실행되게 할 수 있다.

GOT의 엔트리에 저장된 값을 임의로 변조할 수 있는 수단이 있음을 가정하고, 이 공격 기법이 가능한지 gdb를 이용하여 간단하게 실험을 해볼 수 있다.
got 바이너리에서 main()  내 두번째 puts() 호출 직전에 puts의 GOT 엔트리를 "AAAAAAAA" 로 변경한 후 실행시키면 실제로 "AAAAAAAA"로 실행 흐름이 옮겨지는 것을 확인할 수 있다.

```
$ gdb -q ./got
pwndbg> b *main+33
pwndbg> r
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
 ► 0x401157 <main+33>    call   puts@plt                      <puts@plt>
        s: 0x402021 ◂— 'Get address from GOT'

   0x40115c <main+38>    mov    eax, 0
pwndbg> got
GOT protection: Partial RELRO | GOT functions: 1
[0x404018] puts@GLIBC_2.2.5 -> 0x7ffff7e02ed0 (puts) ◂— endbr64

pwndbg> set *(unsigned long long *)0x404018 = 0x4141414141414141

pwndbg> got
GOT protection: Partial RELRO | GOT functions: 1
[0x404018] puts@GLIBC_2.2.5 -> 0x4141414141414141 ('AAAAAAAA')
pwndbg> c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x0000000000401044 in puts@plt ()
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
 ► 0x401044 <puts@plt+4>    bnd jmp qword ptr [rip + 0x2fcd]     <0x4141414141414141>
```

set \*(unsigned long long \*)0x404018 = 0x4141414141414141
: set \*(타입 \*)주소 = 값
: GDB에서 변수나 메모리에 값을 저장할 때 사용
: 주어진 주소를 특정 타입 포인터로 캐스팅 한 뒤, 그 위치에 값을 씀
- `(unsigned long long *)0x404018`  
    → 주소 `0x404018`을 `unsigned long long` (8바이트 정수) 포인터로 간주.
- `*` : 그 포인터가 가리키는 **메모리 위치**를 참조.
- `= 0x4141414141414141`  
    → 그 위치에 16진수 `0x4141414141414141` 값을 저장.  
    → 아스키로 보면 `'A'` 문자(`0x41`)가 8번 반복된 값.