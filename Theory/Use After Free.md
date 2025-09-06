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

