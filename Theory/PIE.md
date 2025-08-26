PIE(Position-Independent Executable)은 ASLR이 실행 파일이 매핑된 영역에도 적용되게 해 주는 기술.

ASLR이 적용된 상태에서 PIE가 적용되어 있지 않다면, 스택, 힙, 라이브러리 영역의 주소는 매 실행마다 무작위하게 바뀌지만 **실행파일이 매핑되는 영역은 바뀌지 않고 고정된 주소를 가진다.**

ASLR 과 PIE 가 둘 다 적용되어 있으면, 스택, 힙, 라이브러리 영역뿐 아니라 **실행파일이 매핑된 영역도 무작위하게 바뀐다.**

``` c
// Name: addr.c
// Compile: gcc addr.c -o addr_n -ldl -no-pie -fno-PIE (PIE 미적용)
// Compile: gcc addr.c -o addr_y -ldl -pie -fPIE (PIE 적용)

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    char buf_stack[0x10];                   // 스택 영역의 버퍼
    char *buf_heap = (char *)malloc(0x10);  // 힙 영역의 버퍼

    printf("buf_stack addr: %p\n", buf_stack);
    printf("buf_heap addr: %p\n", buf_heap);
    printf("libc_base addr: %p\n",
        *(void **)dlopen("libc.so.6", RTLD_LAZY));  // 라이브러리 영역 주소

    printf("printf addr: %p\n",
        dlsym(dlopen("libc.so.6", RTLD_LAZY),
        "printf"));  // 라이브러리 영역의 함수 주소
    printf("main addr: %p\n", main);  // 코드 영역의 함수 주소
}
```

다음과 같이 컴파일하면 PIE가 적용된 바이너리를 얻을 수 있다.
```
$ gcc -o pie addr.c -ldl
```

```
$ gcc -o pie addr.c -ldl
$ ./pie
buf_stack addr: 0x7ffc85ef37e0
buf_heap addr: 0x55617ffcb260
libc_base addr: 0x7f0989d06000
printf addr: 0x7f0989d6af00
main addr: 0x55617f1297ba
$ ./pie
buf_stack addr: 0x7ffe9088b1c0
buf_heap addr: 0x55e0a6116260
libc_base addr: 0x7f9172a7e000
printf addr: 0x7f9172ae2f00
main addr: 0x55e0a564a7ba
$ ./pie
buf_stack addr: 0x7ffec6da1fa0
buf_heap addr: 0x5590e4175260
libc_base addr: 0x7fdea61f2000
printf addr: 0x7fdea6256f00
main addr: 0x5590e1faf7ba
```



이처럼 ASLR 이 적용되어 있다하더라도 PIE 가 적용되어 있지 않으면 실행파일이 매핑된 영역의 주소는 고정이기 때문에, 이런 특징을 이용하여 공격자는 고정된 주소의 코드 가젯을 활용하여 ROP(Return-Oriented Programming) 공격을 수행할 수가 있다.

PIE는 ASLR이 코드 영역에서 적용되게 해 주는 기술이다.


PIE 는 무작위 주소에 매핑돼도 실행 가능한 실행파일을 뜻한다. 
ASLR 이 도입되기 전에는 실행파일이 무작위 주소에 매핑할 필요가 없었다. 그래서 리눅스의 실행파일 형식은 재배치를 고려하지 않고 설계되었다.
이후에 ASLR 이 도입되었을 때는 실행파일도 무작위 주소에 매핑될 수 있게 하고 싶었으나, 이미 널리 사용되는 실행 파일의 형식을 변경하면 호환성 문제가 발생할 것이 분명했다. 
그래서 개발자들은 원래 재배치가 가능했던 공유 오브젝트를 실행 파일로 사용하기로 했다.

실제로 리눅스이 기본 실행 파일 중 하나인 /bin/ls 의 헤더를 살펴보면, Type 이 공유 오브젝트(Shared Object) 를 나타내는 DYN(ET_DYN) 임을 알 수 있다.
```
$ readelf -h /bin/ls
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x6ab0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          136224 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         13
  Size of section headers:           64 (bytes)
  Number of section headers:         31
  Section header string table index: 30
```


