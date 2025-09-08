#UAF

Use After Free는 메모리 참조에 사용한 포인터를 메모리 해제 후에 적절히 초기화하지 않아서, 또는 해제한 메모리를 초기화하지 않고 다음 청크에 재할당해주면서  발생하는 취약점.

### Dangling Pointer

Dangling Pointer는 유효하지 않은 메모리 영역을 가리키는 포인터를 말한다. 메모리의 동적할당에 사용되는 malloc 함수는 할당한 메모리의 주소를 반환한다. 일반적으로, 메모리를 동적 할당할 때는 포인터를 선언하고, 그 포인터에 malloc 함수가 할당한 메모리의 주소를 저장한다. 그리고 그 포인터를 참조하여 할당한 메모리에 접근한다.

메모리를 해제할 때는 free 함수를 호출한다. 그런데 free 함수는 청크를 ptmalloc 에 반환하기만 할 뿐, 청크의 주소를 담고 있던 포인터를 초기화하지는 않는다. 따라서 free 의 호출 이후에 프로그래머가 포인터를 초기화하지 않으면, 포인터는 해제된 청크를 가리키는 Dangling Pointer가 된다.

Dangling Pointer가 생긴다고 해서 프로그램이 보안적으로 취약한 것은 아니다. 그러나 Dangling Pointer 는 프로그램이 예상치 못한 동작을 할 가능성을 키우며, 경우에 따라서는 공격자에게 공격 수단으로 활용될 수도 있다.

``` c
// Name: dangling_ptr.c
// Compile: gcc -o dangling_ptr dangling_ptr.c -no-pie

#include <stdio.h>
#include <stdlib.h>

int main() {
    char *ptr = NULL;
    int idx;

    while (1) {
        printf("> ");
        scanf("%d", &idx);
        switch (idx) {
            case 1:
                if (ptr) {
                    printf("Already allocated\n");
                    break;
                }
                ptr = malloc(256);
                break;
            case 2:
                if (!ptr) {
                    printf("Empty\n");
                }
                free(ptr);
                break;
            default:
                break;
        }
    }
}
```

```
$ ./dangling_ptr
> 1
> 2
> 2
free(): double free detected in tcache 2
Aborted (core dumped)
```

예제에서는 청크를 해제한 후에 청크를 가리키던 ptr 변수를 초기화하지 않았다. 따라서 다음과 같이 청크를 할당하고 해제하면, ptr 은 이전에 할당한 청크의 주소를 가리키는 Dangling Pointer 가 된다.

이를 Double Free Bug 라고 하는데, 프로그램에 심각한 보안 위협이 되는 소프트웨어 취약점이므로 명심해 두도록 한다.

### Use After Free

Use After Free는 문자 그대로, 해제된 메모리에 접근할 수 있을 때 발생하는 취약점이다. 앞서 살펴봤던 dangling_ptr.c 와 같이 Dangling Pointer로 인해 발생하기도 하지만, 새롭게 할당한 영역을 초기화 하지 않고 사용하면서 발생하기도 한다.

malloc 과 free 함수는 할당 또는 해제할 메모리의 데이터를 초기화하지 않는다. 그래서 새롭게 할당한 청크를 프로그래머가 명시적으로 초기화하지 않으면, 메모리에 남아있던 메이터가 유출되거나 사용될 수 있다.

``` c
// Name: uaf.c
// Compile: gcc -o uaf uaf.c -no-pie

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct NameTag {
    char team_name[16];
    char name[32];
    void (*func)();
};

struct Secret {
   char secret_name[16];
   char secret_info[32];
   long code;
};

int main() {
    int idx;

    struct NameTag *nametag;
    struct Secret *secret;

    secret = malloc(sizeof(struct Secret));

    strcpy(secret->secret_name, "ADMIN PASSWORD");
    strcpy(secret->secret_info, "P@ssw0rd!@#");
    secret->code = 0x1337;

    free(secret);
    secret = NULL;

    nametag = malloc(sizeof(struct NameTag));

    strcpy(nametag->team_name, "security team");
    memcpy(nametag->name, "S", 1);

    printf("Team Name: %s\n", nametag->team_name);
    printf("Name: %s\n", nametag->name);

    if (nametag->func) {
        printf("Nametag function: %p\n", nametag->func);
        nametag->func();
    }
}
```

```
$ gcc -o uaf uaf.c -no-pie
$ ./uaf
Team Name: security team
Name: S@ssw0rd!@#
Nametag function: 0x1337
Segmentation fault (core dumped)
```

Name으로 secret_info 의 문자열이 출력되고, 값을 입력한 적 없는 함수 포인터가 0x1337을 가리키는 것을 확인할 수 있다.


### uaf 동적 분석

ptmalloc2는 새로운 할당 요청이 들어왔을 때, 요청된 크기와 비슷한 청크가 bin 이나 tcache에 있는지 확인한다. 그리고 만약 있다면, 해당 청크를 꺼내어 사용한다.
예제 코드에서 Nametag 와 Secret 은 같은 크기의 구조체이다. 그러므로 앞서 할당한 secret 을 해제하고, nametag 를 할당하면, nametag 는 secret과 같은 메모리 영역을 사용하게 된다. 이 때 free 는 해제한 메모리 데이터럴 초기화하지 않으므로, nametag 에는 secret의 값이 일부 남아있게 된다.

```
$ gdb uaf
pwndbg> disass main
Dump of assembler code for function main:
...
   0x0000000000400647 <+96>:    mov    rax,QWORD PTR [rbp-0x10]
   0x000000000040064b <+100>:   mov    rdi,rax
   0x000000000040064e <+103>:   call   0x4004c0 <free@plt>
   0x0000000000400653 <+108>:   mov    QWORD PTR [rbp-0x10],0x0
...
End of assembler dump.
pwndbg> b *main+108
Breakpoint 1 at 0x400653
pwndbg> r
Starting program: /home/dreamhack/uaf

Breakpoint 1, 0x0000000000400653 in main ()
...
───────────────────────────────────[ DISASM ]───────────────────────────────────
 ► 0x400653 <main+108>    mov    qword ptr [rbp - 0x10], 0
...
Breakpoint *main+108
```


heap 확인
```
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x602000
Size: 0x251

Free chunk (tcachebins) | PREV_INUSE
Addr: 0x602250
Size: 0x41
fd: 0x00

Top chunk | PREV_INUSE
Addr: 0x602290
Size: 0x20d71
}
```
총 3개의 청크가 존재하는데, 0x602250 이 우리가 살펴보고자 하는 secret 에 해당하는 청크이다. 해제(free) 되었기 때문에 tcache 의 엔트리에 들어가 있는 상태이다.

추가로 0x602000 는 tcache 와 관련된 공간으로 tcache_perthread_struct 구조체에 해당하며, libc 단에서 힙 영역을 초기화할 때 할당하는 청크이다.


```
pwndbg> x/10gx 0x602250
0x602250:	0x0000000000000000	0x0000000000000041
0x602260:	0x0000000000000000	0x0000000000602010
0x602270:	0x6472307773734050	0x0000000000234021
0x602280:	0x0000000000000000	0x0000000000000000
0x602290:	0x0000000000001337	0x0000000000020d71
pwndbg> x/s 0x602270
0x602270:	"P@ssw0rd!@#"
pwndbg>
```
이미 해제된 secret 이 사용하던 메모리 영역을 출력한 모습이다. secret_name 에 해당하는 부분은 적절한 fd 와 bk 값으로 초기화 되었지만,  secret_info 에 해당하는 부분은 값이 그대로 남아있는 모습을 확인할 수 있다.


```
pwndbg> b *main+207
Breakpoint 2 at 0x4006b6
pwndbg> c
Continuing.

Breakpoint 2, 0x00000000004006b6 in main ()
...
───────────────────────────────────[ DISASM ]───────────────────────────────────
 ► 0x4006b6 <main+207>    call   printf@plt <0x4004d0>
        format: 0x4007a6 ◂— 'Team Name: %s\n'
        vararg: 0x602260 ◂— 'security team'

   0x4006bb <main+212>    mov    rax, qword ptr [rbp - 8]
   0x4006bf <main+216>    add    rax, 0x10
...
Breakpoint *main+207
pwndbg> x/10gx 0x602250
0x602250:   0x0000000000000000  0x0000000000000041
0x602260:   0x7974697275636573  0x0000006d61657420
0x602270:   0x6472307773734053  0x0000000000234021
0x602280:   0x0000000000000000  0x0000000000000000
0x602290:   0x0000000000001337  0x0000000000020d71
pwndbg> x/s 0x602260
0x602260:   "security team"
pwndbg> x/s 0x602270
0x602270:   "S@ssw0rd!@#"
pwndbg> x/gx 0x602290
0x602290:   0x0000000000001337
pwndbg>
```
다음으로, nametag 를 할당하고, printf 하수를 호출하는 시점에서 nametag 멤버 변수들의 값을 확인해 보자.

예제를 통해 살펴봤듯, 동적 할당한 청크를 해제한 뒤에는 해제된 메모리 영역에 이전 객체의 데이터가 남는다. 이러한 특징을 공격자가 이용한다면 초기화  되지 않은 메모리의 값을 읽어내거나, 새로운 객체가 악의적인 값을 사용하도록 유도하여 프로그램이 정상적인 실행을 방해할 수 있다.


### Dangling Pointer
해제된 메모리를 가리키고 있는 포인터. UAF가 발생하는 원인이 될 수 있다.

### Use-After-Free(UAF)
해제된 메모리에 접근할 수 있을 때 발생하는 취약점.