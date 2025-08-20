#라이브러리 #링크

### 라이브러리

라이브러리는 컴퓨터 시스템에서, 프로그램들이 함수나 변수를 공유해서 사용할 수 있게 한다.
대개의 프로그램은 서로 공통으로 사용하는 함수들이 많다.
예를들어, printf, scanf, strlen, memcpy, malloc 등

C의 표준 라이브러리 : libc
/lib/x86_64-linux-gnu/libc.so.6 

### 링크

링크(Link)는 많은 프로그래밍 언어에서 컴파일의 마지막 단계로 알려져 있다.
프로그램에서 어떤 라이브러리의 함수를 사용한다면, 호출된 함수와 실제 라이브러리의 함수가 링크 과정에서 서로 연결된다.

``` c
// Name: hello-world.c
// Compile: gcc -o hello-world hello-world.c

#include <stdio.h>

int main() {
  puts("Hello, world!");
  return 0;
}
```

```
// Path: /usr/include/stdio.h

...
/* Write a string, followed by a newline, to stdout.

   This function is a possible cancellation point and therefore not
   marked with __THROW.  */
extern int puts (const char *__s);
...
```

리눅스에서 C 소스 코드는 전처리, 컴파일, 어셈블 과정을 거쳐 ELF 형식을 갖춘 오브젝트 파일(Object file)로 번역된다.
```
$ gcc -c hello-world.c -o hello-world.o
```

오브젝트 파일은 실행 가능한 형식을 갖추고 있지만, 라이브러리 함수들의 정의가 어디 있는지 알지 못하므로 실행은 불가능한 상태이다.


```
$ readelf -s hello-world.o | grep puts
    11: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND puts
```
puts 의 선언이 stdio.h에 있어서 심볼(Symbol)로는 기록되어 있지만, 심볼에 대한 자세한 내용은 하나도 기록되어 있지 않은 것을 볼 수 있다.

명령어 구조
readelf :
ELF(Executable and Linkable Format) 바이너리의 내부 구조를 보여주는 툴
-s : 
심볼 테이블(Symbol Table)을 출력함.
심볼 테이블에는 함수, 변수 이름, 라이브러리 참조 등 링크에 필요한 정보가 있다.

심볼번호  |  심볼의 주소  |  심볼 크기  |  심볼 타임  |  심볼의 바인딩  |  심볼의 가시성  |  섹션 인덱스


### 링크 - 링크 후
완전히 컴파일 후 링크 상태 확인
```
$ gcc -o hello-world hello-world.c
$ readelf -s hello-world | grep puts
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5 (2)
    46: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@@GLIBC_2.2.5
$ ldd hello-world
        linux-vdso.so.1 (0x00007ffec3995000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fee37831000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fee37e24000)
```

ldd
: ELF 실행파일이 어떤 공유 라이브러리에 의존하는지 보여 줌

#### 표준 라이브러리의 경로 확인
```
$ ld --verbose | grep SEARCH_DIR | tr -s ' ;' '\n'
SEARCH_DIR("=/usr/local/lib/x86_64-linux-gnu")
SEARCH_DIR("=/lib/x86_64-linux-gnu")
SEARCH_DIR("=/usr/lib/x86_64-linux-gnu")
SEARCH_DIR("=/usr/lib/x86_64-linux-gnu64")
SEARCH_DIR("=/usr/local/lib64")
SEARCH_DIR("=/lib64")
SEARCH_DIR("=/usr/lib64")
SEARCH_DIR("=/usr/local/lib")
SEARCH_DIR("=/lib")
SEARCH_DIR("=/usr/lib")
SEARCH_DIR("=/usr/x86_64-linux-gnu/lib64")
SEARCH_DIR("=/usr/x86_64-linux-gnu/lib")
```

ld --verbose
: ld - GNU 링커
: --verbose - 링커가 링킹할 때 기본적으로 사용하는 옵션과 검색 경로, 스크립트 등을 자세히 출력

| grep SEARCH_DIR
: 출력된 내용 중 SEARCH_DIR 이 포함된 줄만 추려 줌

| tr -s ' ;' '\n'
: tr - 문자 변환 / 치환
: -s - 연속된 문자를 하나로 줄임
' ;' '\n' - 공백( )이나 세미콜론을 줄바끔으로 바꿔라.

링크 과정을 거치고 나면 프로그램에서 puts 를 호출할 때, puts 의 정의가 있는 libc에서 puts의 코드를 찾고, 해당 코드를 실행함.


### 라이브러리와 링크의 종류

동적 링크 : 
동적 라이브러리를 링크하는 것
동적 링크는 바이너리를 실행하면 동적 라이브러리가 프로세스의 메모리에 매핑된다.
그리고 실행 중에 라이브러리의 함수를 호출하면 매핑된 라이브러리에서 호출할 함수의 주소를 찾고, 그 함수를 실행한다.

정적 링크 : 
정적 라이브러리를 링크하는 것
정적 링크를 하면 바이너리에 정적 라이브라리의 필요한 모든 함수가 포함된다.
따라서 해당 함수를 호출할 때, 라이브러리를 참조하는 것이 아니라, 자신의 함수를 호출하는 것처럼 호출한다.

### 동적 링크 vs. 정적 링크
```
$ gcc -o static hello-world.c -static
$ gcc -o dynamic hello-world.c -no-pie
```

```
$ ls -lh ./static ./dynamic
-rwxrwxr-x 1 dreamhack dreamhack  16K May 22 02:01 ./dynamic
-rwxrwxr-x 1 dreamhack dreamhack 880K May 22 02:01 ./static
```

### 호출

static 에서는 puts 가 있는 0x40c140을 직접 호출한다. 반면 dynamic 에서는 puts 의 plt 주소인 0x401040 을 호출한다.
이런 차이가 발생하는 이유는, 동적 링크된 바이너리는 함수의 주소를 라이브러리에서 "찾아야"하기 때문이다. 
plt는 이 과정에서 사용되는 테이블이다.

static 에서의 puts

```
 main:
  push   rbp
  mov    rbp,rsp
  lea    rax,[rip+0x96880] # 0x498004
  mov    rdi,rax
  call   0x40c140 <puts>
  mov    eax,0x0
  pop    rbp
  ret
```

dynamic 에서의 puts
```
main: 
 push   rbp
 mov    rbp,rsp
 lea    rdi,[rip+0xebf] # 0x402004
 mov    rdi,rax
 call   0x401040 <puts@plt>
 mov    eax,0x0
 pop    rbp
 ret
```

