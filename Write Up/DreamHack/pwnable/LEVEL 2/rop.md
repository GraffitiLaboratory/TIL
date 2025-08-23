#ROP 

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

