Double Free Bug(DFB) 는 같은 청크를 두 번 해제할 수 있는 버그를 말한다. ptmalloc2 에서 발생하는 버그 중 하나이며, 공격자에게 임의 주소 쓰기, 임의 주소 읽기, 임의 코드 실행, 서비스 거부 등의 수단으로 활용될 수 있다.

dangling pointer는 Double Free Bug를 유발하는 대표적인 원인이다. 코드 상에서 dangling pointer 가 생성되는지, 그리고 이를 대상으로 free 를 호출하는 것이 가능하지 살피면 Double free bug 가 존재하는지 가늠할 수 있다.

Double free bug를 이용하면 duplicated free list 를 만드는 것이 가능한데, 이는 청크와 연결리스트의 구조때문이다. 
ptmalloc2 에서 free list의 각 청크들은 fd 와  bk로 연결된다. fd 는 자신보다 이후에 해제된 청크를, bk는 이전에 해제된 청크를 가리킨다.

그런데, 해제된 청크에서 fd 와 bk 값을 저장하는 공간은 할당된 청크에서 데이터를 저장하는데 사용된다. 그러므로 만약 어떤 청크가 free list 에 중복해서 포함된다면, 첫 번째 재할당에서 fd 와 bk 를 조작하여 free list에 임의 주소를 포함 시킬 수 있다.
![](https://dreamhack-lecture.s3.amazonaws.com/media/9865af4a729be22dcb8a62df9b2f8f8b0cbddb9fcdce8198ff79dc31c8ac193d.png)
초기에는 double free에 대한 검사가 미흡하여 Double free bug가 있으면 손쉽게 트리거 할 수 있었다 . 특히, glibc 2.26 버번부터 도입된 tcache는 도입 당시에 보호 기법이 전무하여 double free의 쉬운 먹잇감이 되었다.

하지만 시간이 흐르면서 관련한 보호 기법이 glibc 에 구현되었고 이를 우회하지 않으면 같은 청크를 두 번 해제하는 즉시 프로세스가 종료된다.

``` c
// Name: dfb.c
// Compile: gcc -o dfb dfb.c

#include <stdio.h>
#include <stdlib.h>

int main() {
    char *chunk;
    chunk = malloc(0x50);

    printf("Address of chunk: %p\n", chunk);

    free(chunk);
    free(chunk);
}
```
컴파일하고 실행하면 tcatch에 대한 double free 가 감지되어 프로그램이 비정상 종료되는 것을 확인할 수 있다.
```
$ ./dfb
Address of chunk: 0x55ce62641260
free(): double free detected in tcache 2
zsh: abort      ./dfb
```

