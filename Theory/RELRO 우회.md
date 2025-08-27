Partial RELRO 의 경우,
.init_array, .fini_array 에 대한 쓰기 권한이 제거되어 두 영역을 덮어쓰는 공격을 수행하기 어렵다.
하지만, .got.plt 영역에 대한 쓰기 권한이 존재하므로 GOT overwrite 공격을 활용할 수 있다.

Full RELRO의 경우,
.init_array, .fini_array 뿐만 아니라 .got 영역에도 쓰기 권한이 제거되었다.
그래서 공격자들은 덮어쓸 수 있는 다른 함수 포인터를 찾다가 라이브러리에 위치한 hook을 찾아냈다.
라이브러리의 대표적인 hook이 malloc hook 과 free hook 이다.
원래 이 함수포인터는 동적 메모리의 할당과 해제 과정에서 발생하는 버그를 디버깅하기 쉽게 하려고 만들어졌다.

malloc 함수의 코드를 살펴보면, 함수의 시작 부분에서 \_\_malloc_hook 이 존재하는지 검사하고, 존재하면 이를 호출한다.
\_\_malloc_hook 은 libc.so 에서 쓰기 가능한 영역에 위치한다. 따라서 공격자는 libc가 매핑된 주소를 알 때, 이 변수를 조작하고 malloc 을 호출하여 실행 흐름을 조작할 수 있다.
이와 같은 공격 기법을 통틀어 Hook Overwrite 이라 한다.
``` c
void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;
  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook); // read hook
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0)); // call hook
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  checked_request2size (bytes, tbytes);
  size_t tc_idx = csize2tidx (tbytes);
  // ...
```

