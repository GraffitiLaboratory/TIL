#vmmap #readelf #objdump

### NX disable

$ gcc -o r2s r2s.c -zexecstack
컴파일 시 -zexecstack  옵션을 사용하면 NX 기능이 꺼지게 된다.
### vmmap

현재 디버깅 중인 프로세스의 가상 메모리 맵을 보여주는 명령어
즉, 프로세스가 사용하는 메모리 영역을 정리해서 보여 줌.

출력되는 정보
- Start - End 주소
  : 이 메모리 구간의 시작 주소와 끝 주소
- Perms(권한)
  : rwx 형태로 읽기(Read), 쓰기(Write), 실행(Execute) 권한을 나타냄
  : 예 r-xp -> 읽기 + 실행 가능, private mapping
- Offset
  : 매핑된 파일 내에서의 오프셋(파일 기반 매핑일 경우)
- Device / Inode
  : 어떤 디바이스 / 파일에서 매핑되었는지
- Mapping (파일 이름 또는 구분자)
  : 해당 메모리 영역이 무엇인지 표시
  : [heap] -> 힙 영역
  : [stack] -> 스택 영역
  : /lib/x86_64-linux-gnu/libc.so.6 -> libc 라이브러리
  : [vdso] -> 커널이 제공하는 가상 함수 영역

```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
          0x400000           0x401000 r--p     1000      0 /home/dreamhack/nx
          0x401000           0x402000 r-xp     1000   1000 /home/dreamhack/nx
          0x402000           0x403000 r--p     1000   2000 /home/dreamhack/nx
          0x403000           0x404000 r--p     1000   2000 /home/dreamhack/nx
          0x404000           0x405000 rw-p     1000   3000 /home/dreamhack/nx
    0x7ffff7d7f000     0x7ffff7d82000 rw-p     3000      0 [anon_7ffff7d7f]
    0x7ffff7d82000     0x7ffff7daa000 r--p    28000      0 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7daa000     0x7ffff7f3f000 r-xp   195000  28000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f3f000     0x7ffff7f97000 r--p    58000 1bd000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f97000     0x7ffff7f9b000 r--p     4000 214000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f9b000     0x7ffff7f9d000 rw-p     2000 218000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f9d000     0x7ffff7faa000 rw-p     d000      0 [anon_7ffff7f9d]
    0x7ffff7fbb000     0x7ffff7fbd000 rw-p     2000      0 [anon_7ffff7fbb]
    0x7ffff7fbd000     0x7ffff7fc1000 r--p     4000      0 [vvar]
    0x7ffff7fc1000     0x7ffff7fc3000 r-xp     2000      0 [vdso]
    0x7ffff7fc3000     0x7ffff7fc5000 r--p     2000      0 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fc5000     0x7ffff7fef000 r-xp    2a000   2000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fef000     0x7ffff7ffa000 r--p     b000  2c000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000  37000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffd000     0x7ffff7fff000 rw-p     2000  39000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]

```

### 이 외...

readelf -l ./r2s

objdump -x ./r2s | grep LOAD

### NX의 다양한 명칭

인텔 : XD (eXecute Disable)
AMD : NX
윈도우 : DEP (Data Execution Prevention)
ARM : XN (eXecute Never)

### 5.4.0 미만 버전 리눅스 커널에서의 NX

5.4.0 미만 버전은 스택 영역 뿐만 아니라 힙, 데이터 영역 등 읽기(r) 권한이 있는 모든 페이지에 실행(x) 권한을 부여한다.
이는 5.4.0 이전 버전의 커널을 NX 미적용 시, 프로세스의 Personality에 읽기 권한이 있는 모든 페이지에 실행 권한을 부여하는 READ_IMPLIES_EXEC 플래그를 설정하기 때문이다.

5.4.0 이상 버전의 커널은 READ_IMPLIES_EXEC 를 설정하지 않고, 로더가 따로 스택 영역([stack])에만 실행 권한을 부여한다.
