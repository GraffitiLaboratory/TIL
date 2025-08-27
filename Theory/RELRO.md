리눅스는 ELF가 GOT (Global Offset Table) 이라는 테이이블을 활용하여 반복되는 라이브러리 함수의 호출 비용을 줄인다
GOT 에 값을 채우는 방식은 다양한데 그 중 하나는 함수가 처음 호출될 때 함수의 주소를 구하고, 이를 GOT에 적는 Lazy Binding이 있다.

Lazy binding을 하는 바이너리는 실행 중에 GOT 테이블을 업데이트할 수 있어야 하므로 GOT가 존재하는 메모리 영역에 쓰기 권한이 부여된다. 그런데 이는 바이너리를 취약하게 만드는 원인이 된다.

또한 ELF의 데이터 세그먼트에는 프로세스의 초기화 및 종료와 관련된 .init_array, .fini_array 가 있다.
이 영역들은 프로세스의 시작과 종료에 실행할 함수들의 주소를 저장하고 있는데, 여기에도 공격자가 임의로 값을 쓸 수 있다면, 프로세스의 실행 흐름이 조작될 수 있다.

리눅스 개발자들은 이러한 문제를 해결하고자 프로세스의 데이터 세그먼트를 보호하는 RELocation Read-Only (RELRO)을 개발했다. RELRO는 쓰기 권한이 불필요한 데이터 세그먼트에 쓰기 권한을 제거한다.

RELRO는 RELRO를 적용하는 범위에 따라 두 가지로 구분된다. 하나는 RELRO를 부분적으로 적용하는 Partial RELRO이고, 나머지는 가장 넓은 영역에 RELRO를 적용하는  Full RELRO이다.

### Partial RELRO

``` c
// Name: relro.c
// Compile:  gcc -o prelro relro.c -no-pie -fnop-PIE
/*
-no-pie : 실행파일을 PIE(Position Independent Executable)가 아닌 고정된 주소에 로드되는 실행 파일로 만듬.
-fno-PIE : 코드도 PIE용으로 컴파일하지 않음.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/*
/proc/self 는 현재 실행중인 자기 자신 프로세스를 말함
/proc/self/maps 는 해당 프로세스의 메모리 맵(메모리 구역별 주소, 권한, 매핑된 파일 등)을 보여줌.
fgetc(fp)로 /proc/self/maps 내용을 한 글자씩 읽어서 putchar()로 출력함.
결과적으로 자기 자신의 메모리 매핑 테이블을 그대로 터미널에 보여주는 프로그램.
*/
int main() {
    FILE *fp;
    char ch;
    fp = fopen("/proc/self/maps", "r");
    while (1) {
        ch = fgetc(fp);
        if (ch == EOF) break;
        putchar(ch);
    }
    return 0;
}
```


```
$ gcc -o prelro -no-pie relro.c

$ checksec prelro
[*] '/home/dreamhack/prelro'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
PIE를 해제하고 컴파일하게 되면 Partial RELRO를 적용한다.

### Partial RELRO 권한

```
$ ./prelro
00400000-00401000 r--p 00000000 08:02 2886150                            /home/dreamhack/prelro
00401000-00402000 r-xp 00001000 08:02 2886150                            /home/dreamhack/prelro
00402000-00403000 r--p 00002000 08:02 2886150                            /home/dreamhack/prelro
00403000-00404000 r--p 00002000 08:02 2886150                            /home/dreamhack/prelro
00404000-00405000 rw-p 00003000 08:02 2886150                            /home/dreamhack/prelro
0130d000-0132e000 rw-p 00000000 00:00 0                                  [heap]
7f108632c000-7f108632f000 rw-p 00000000 00:00 0
7f108632f000-7f1086357000 r--p 00000000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f1086357000-7f10864ec000 r-xp 00028000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f10864ec000-7f1086544000 r--p 001bd000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f1086544000-7f1086548000 r--p 00214000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f1086548000-7f108654a000 rw-p 00218000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f108654a000-7f1086557000 rw-p 00000000 00:00 0
7f1086568000-7f108656a000 rw-p 00000000 00:00 0
7f108656a000-7f108656c000 r--p 00000000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f108656c000-7f1086596000 r-xp 00002000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f1086596000-7f10865a1000 r--p 0002c000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f10865a2000-7f10865a4000 r--p 00037000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f10865a4000-7f10865a6000 rw-p 00039000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffe55580000-7ffe555a1000 rw-p 00000000 00:00 0                          [stack]
7ffe555de000-7ffe555e2000 r--p 00000000 00:00 0                          [vvar]
7ffe555e2000-7ffe555e4000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```

00404000-00405000 rw-p 00003000 08:01 1441804                            /root/WarGame/DreamHack/theory/System_Hacking/12.PIE&RELRO/prelro

prelro를 실행하면 0x404000 부터 0x405000까지의 주소는 쓰기 권한이 있음을 알 수 있다.


```
$ objdump -h ./prelro

./prelro:     file format elf64-x86-64

Sections:
Idx Name          Size      VMA               LMA               File off  Algn
...
 19 .init_array   00000008  0000000000403e10  0000000000403e10  00002e10  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 20 .fini_array   00000008  0000000000403e18  0000000000403e18  00002e18  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 21 .dynamic      000001d0  0000000000403e20  0000000000403e20  00002e20  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 22 .got          00000010  0000000000403ff0  0000000000403ff0  00002ff0  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 23 .got.plt      00000030  0000000000404000  0000000000404000  00003000  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 24 .data         00000010  0000000000404030  0000000000404030  00003030  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 25 .bss          00000008  0000000000404040  0000000000404040  00003040  2**0
                  ALLOC
...
```

objdump를 이용하여 섹션 헤더를 확인해보면 해당 영역에는 .got.plt, .data, .bss 가 활당되어 있다.
따라서 이 섹션에는 쓰기가 가능하다.
반면, .init_array 와 .fini_array 는 각각 0x403e10, 0x403e18에 할당되어 있는데 모드 쓰기 권한이 없는 00403000 ~ 00404000 사이에 존재하므로 쓰기가 불가능하다.

#### .got 와 .got.plt

Partial RELRO 가 적용된 바이너리는 got와 관련된 섹션이 .got 와 .got.plt 로 두 개가 존재한다.
전역 변수 중에서 실행되는 시점에 바인딩(now binding)되는 변수는 .got에 위치한다. 바이너리가 실행될 때는 이미 바인딩이 완료되어있으므로 이 영역에 쓰기 권한을 부여하지 않는다.

반면 실행 중에 바인딩(lazy binding)되는 변수는 .got.plt 에 위치한다. 이 영역은 실행중에 값이 써져야 하므로 쓰기 권한이 부여된다. 
Partial RELRO 가 적용된 바이너리에서 대부분 함수들의 GOT엔트리는 .got.plt 에 저장된다.

### Full RELRO
```
$ gcc -o frelro relro.c

$ checksec frelro
[*] '/home/dreamhack/frelro'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
별도의 컴파일 옵션없이 컴파일하면 Full RELRO 가 적용된 바이너리가 생성된다.

```
$ ./frelro
563782c64000-563782c65000 r--p 00000000 08:02 2886178                    /home/dreamhack/frelro
563782c65000-563782c66000 r-xp 00001000 08:02 2886178                    /home/dreamhack/frelro
563782c66000-563782c67000 r--p 00002000 08:02 2886178                    /home/dreamhack/frelro
563782c67000-563782c68000 r--p 00002000 08:02 2886178                    /home/dreamhack/frelro
563782c68000-563782c69000 rw-p 00003000 08:02 2886178                    /home/dreamhack/frelro
563784631000-563784652000 rw-p 00000000 00:00 0                          [heap]
7f966f91f000-7f966f922000 rw-p 00000000 00:00 0
7f966f922000-7f966f94a000 r--p 00000000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f966f94a000-7f966fadf000 r-xp 00028000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f966fadf000-7f966fb37000 r--p 001bd000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f966fb37000-7f966fb3b000 r--p 00214000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f966fb3b000-7f966fb3d000 rw-p 00218000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f966fb3d000-7f966fb4a000 rw-p 00000000 00:00 0
7f966fb5b000-7f966fb5d000 rw-p 00000000 00:00 0
7f966fb5d000-7f966fb5f000 r--p 00000000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f966fb5f000-7f966fb89000 r-xp 00002000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f966fb89000-7f966fb94000 r--p 0002c000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f966fb95000-7f966fb97000 r--p 00037000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f966fb97000-7f966fb99000 rw-p 00039000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffc1bace000-7ffc1baef000 rw-p 00000000 00:00 0                          [stack]
7ffc1bb22000-7ffc1bb26000 r--p 00000000 00:00 0                          [vvar]
7ffc1bb26000-7ffc1bb28000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```
frelro를 실행하며 메모리 맵을 확인해 보면,
프로그램의 시작은 563782c64000, 쓰기권한이 있는 영역은 563782c68000-563782c69000 인 것을 확인할 수 있다.


```
$ objdump -h ./frelro

./frelro:     file format elf64-x86-64

Sections:
Idx Name          Size      VMA               LMA               File off  Algn
...
 20 .init_array   00000008  0000000000003da8  0000000000003da8  00002da8  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 21 .fini_array   00000008  0000000000003db0  0000000000003db0  00002db0  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 22 .dynamic      000001f0  0000000000003db8  0000000000003db8  00002db8  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 23 .got          00000058  0000000000003fa8  0000000000003fa8  00002fa8  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 24 .data         00000010  0000000000004000  0000000000004000  00003000  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 25 .bss          00000008  0000000000004010  0000000000004010  00003010  2**0
                  ALLOC
...
```
섹션 헤더 정보를 확인해 보자.
got에는 쓰기 권한이 제거되어 있으며 data와 bss에만 쓰기 권한이 있는 것을 확인할 수 있다.

.data 섹션의 오프셋은 0x4000이다 . 이를  .frelro가 매핑된 563782c64000에 더하면 563782c68000이 되며, 이는 쓰기 권한이 있는 영역에 속한다.
.bss 섹션 역시 동일한 방법으로 계산해보면 쓰기 권한이 존재하는 영역에 속한다.

Full RELRO가 적용되면 라이브러리 함수들의 주소가 바이너리의 로딩 시점에 모두 바인딩된다. 따라서 GOT 에는 쓰기권한이 부여되지 않는다.