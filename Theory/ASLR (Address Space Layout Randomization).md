#ASLR

ASLR은 바이너리가 실행될 때마다 스택, 힙, 공유 라이브러리 등을 임의의 주소에 할당하는 보호 기법

```
$ ./r2s
Address of the buf: 0x7ffe8624a160
Distance between buf and $rbp: 96
[1] Leak the canary
Input: ^C
$ ./r2s
Address of the buf: 0x7ffd7dad3630
Distance between buf and $rbp: 96
[1] Leak the canary
Input: ^C
$ ./r2s
Address of the buf: 0x7ffdb20560d0
Distance between buf and $rbp: 96
[1] Leak the canary
Input: ^C
$ ./r2s
Address of the buf: 0x7ffdc0cae930
Distance between buf and $rbp: 96
[1] Leak the canary
Input: ^C
$ ./r2s
Address of the buf: 0x7ffcbc673720
Distance between buf and $rbp: 96
[1] Leak the canary
Input: ^C

```
리눅스 시스템에 ASLR이 적용되어 있기 때문에 실행마다 buf 라는 변수가 무작위한 주소에 위치하게 된다.

r2s 프로그램의 경우 buf 주소를 매 실행마다 출력해주기 때문에 buf를 공격에 활용하는 것이 어렵지 않았다.
그러나 일반적인 바이너리였다면 버퍼의 주소를 구하는 과정이 선행되어야 한다.

```
$ cat /proc/sys/kernel/randomize_va_space
2
```

- No ASLR(0): ASLR을 적용하지 않음
- Conservative Randomization(1): 스택, 라이브러리, vdso 등
- conservative Randomization + brk(2): (1)의 영역과 brk 로 할당된 영역

### ASLR 의 특징
``` c
// Name: addr.c
// Compile: gcc addr.c -o addr -ldl -no-pie -fno-PIE

/*
-ldl
: libdl.so (dynamic linking library)를 링크하라는 의미
: 동적 라이브러리 함수(dlopen, dlsym, dlclose 등)를 사용할 때 필요함
: 예. 런타임에 동적으로 공유 라이브러리를 열어서 심볼을 찾는 경우.

-no-pie
: PIE(Position Independent Executable) 비활성화
: 기본적으로 최신 gcc는 PIE를 켜서 실행 파일을 위치 독립적 코드(ASLR과 함께 랜덤하게 로드 가능)로 만듬.
: -no-pie를 주면 실행 파일의 코드 영역 주소가 고정된 위치에 로드 됨.
-> 익스플로잇에서 main 이나 함수 심볼 주소를 예측할 수 있게 해 줌.

-fno-PIE
: 컴파일러에게 PIE용 코드 생성하지 마라고 지시하는 옵션.
: -no-pie와 짝을 이루는 옵션인데.....
: -fno-PIE -> 컴파일 단계에서 PIE 비활성화
: -no-pie -> 링킹 단계에서 PIE 비활성화
*/

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
  char buf_stack[0x10];                   // 스택 버퍼
  char *buf_heap = (char *)malloc(0x10);  // 힙 버퍼

  printf("buf_stack addr: %p\n", buf_stack);
  printf("buf_heap addr: %p\n", buf_heap);
  printf("libc_base addr: %p\n",
         *(void **)dlopen("libc.so.6", RTLD_LAZY));  // 라이브러리 주소

  printf("printf addr: %p\n",
         dlsym(dlopen("libc.so.6", RTLD_LAZY),
               "printf"));  // 라이브러리 함수의 주소
  printf("main addr: %p\n", main);  // 코드 영역의 함수 주소
}
```

```
$ gcc addr.c -o addr -ldl -no-pie -fno-PIE

$ ./addr
buf_stack addr: 0x7ffcd3fcffc0
buf_heap addr: 0xb97260
libc_base addr: 0x7fd7504cd000
printf addr: 0x7fd750531f00
main addr: 0x400667
$ ./addr
buf_stack addr: 0x7ffe4c661f90
buf_heap addr: 0x176d260
libc_base addr: 0x7ffad9e1b000
printf addr: 0x7ffad9e7ff00
main addr: 0x400667
$ ./addr
buf_stack addr: 0x7ffcf2386d80
buf_heap addr: 0x840260
libc_base addr: 0x7fed2664b000
printf addr: 0x7fed266aff00
main addr: 0x400667
```

- 코드 영역의 main 함수를 제외한 다른 영역의 주소들은 실행할 때마다 변경된다.
	실행할 때마다 주소가 변경되기 때문에 바이너를 실행하기 전에 해당 영역의 주소를 예측할 수 없다
- 바이너리를 반복해서 실행해도 libc_base 주소 하위 12비트 값과 printf 주소 하위 12비트 값은 변경되지 않는다.
	리눅스는 ASLR이 적용됐을 때, 파일을 페이지(page) 단위로 임의 주소에 매핑한다. 따라서 페이지의 크기인 12비트 이하로는 주소가 변경되지 않는다
- libc_base 와 printf 의 주소 차이는 항상 같다
	ASLR이 적용되면, 라이브러리는 임의 주소에 매핑된다. 그러나 라이브러리 파일을 그대로 매핑하는 것이므로 매핑된 주소로부터 라이브러리의 다른 심볼들 까지의 거리(offset)는 항상 같다.

```
>>> hex(0x7fd7504cd000 - 0x7fd750531f00) # libc_base addr - printf addr
'-0x64f00'
>>> hex(0x7ffad9e1b000 - 0x7ffad9e7ff00)
'-0x64f00'
```

```
$ objdump -D /lib/x86_64-linux-gnu/libc.so.6 | grep 064f00 -A3
0000000000064f00 <_IO_printf@@GLIBC_2.2.5>:
   64f00: 48 81 ec d8 00 00 00  sub    $0xd8,%rsp
   64f07: 84 c0                 test   %al,%al
   64f09: 48 89 74 24 28        mov    %rsi,0x28(%rsp)
```