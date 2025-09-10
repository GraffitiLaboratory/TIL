### 정적 패치 분석

#### 1. tcache_entry

Tcache에 도입된 보호 기법을 분석하기 위해, 패치된 코드의 diff를 살펴본다. 먼저 하단 코드를 보면 double free  를 탐지하기 위해 key 포인터가 tcache_entry에 추가 되었음을 알 수 있다.
``` c
typedef struct tcache_entry {
  struct tcache_entry *next;
+ /* This field exists to detect double frees.  */
+ struct tcache_perthread_struct *key;
} tcache_entry;
```
tcache_entry 는 해제된 tcache 청크들이 갖는 구조이다. 일반 청크의 fd 가 next 로 대체되고, LIFO 형태로 사용되므로 bk 에 대응되는 값은 없다.

ket: 주석대로 Double Free 탐지를 위한 필드
	원래 tcache는 double free검사가 거의 없어서, 같은 청크가 두 번 들어가면 공격자가 악용할 수 있음.
	그래서 glibc에서 이 key 필드를 추가하여, 현재 이 청크가 어떤 tcache에 속하는지 기록하도록 함.
	만약 같은 청크를 다시 free 하면, 이 key 값이 꼬여서 "아, 이거 double free 구나" 하고 바로 에러를 발생시킬 수 있음.

#### 2. tcache_put
``` c
tcache_put(mchunkptr chunk, size_t tc_idx) {
  tcache_entry *e = (tcache_entry *)chunk2mem(chunk);
  assert(tc_idx < TCACHE_MAX_BINS);
  
+ /* Mark this chunk as "in the tcache" so the test in _int_free will detect a
+      double free.  */
+ e->key = tcache;
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```
tcache_put 은 해제한 청크를 tcache에 추가하는 함수이다. 상단의 코드를 보면 tcache_put 함수는 해제되는 청크의 key에 tcache 라는 값을 대입하도록 변경되었다. 여기서 tcache 는 tcache_perthread 라는 구조체 변수를 가리킨다.

청크를 tcache_entry 로 변환
	chunk2mem(chunk)은 malloc에서 실제로 사용자에게 주는 포인터 위치를 가리킴.
	즉, 해제된 청크를 tcache_entry 구조체처럼 취급하기 시작함.
tcache bin 인덱스 확인
	tcache에는 bin(크기별 리스트)이 여러 개 있음.
	인덱스(tc_idx)가 유효한 범위인지 검사.
Double Free 탐지를 위한 key 세팅
	현재 청크가 어느 tcache 구조체(per-thread)에 속하는지 key에 기록해 둠.
	나중에 \_int_free 가 같은 청크를 다시 free 하려고 할 때 key 를 검사해서 "이미 tcache에 있는 청크인데 또 free 하네" -> double free 를 감지할 수 있음.
해제된 청크를 tcache  리스트에 삽입
	단일 연결리스트에 push 하듯이 tcache의 맨 앞에 추가
해당 bin의 개수 증가
	해당 크기 bin 안의 청크 개수 카운트 증가.

#### 3. tcache_get
``` c
tcache_get (size_t tc_idx)
   assert (tcache->entries[tc_idx] > 0);
   tcache->entries[tc_idx] = e->next;
   --(tcache->counts[tc_idx]);
+  e->key = NULL;
   return (void *) e;
 }
```
tcache 에 연결된 청크를 재사용할 때 사용하는 함수이다. 상단 코드를 보면 tcache_get 함수는 재사용하는 청크의 key 값에 NULL을 대입하도록 변경되었다.

빈 bin 확인
	해당 bin(tc_idx)에 청크가 없으면 안 되므로, 반드시 하나 이상 있어야 한다는 검사
리스트에서 청크 꺼내기
	tcache->entries[tc_idx] 는 현재 bin의 맨 앞 청크를 가리킴
	그 중 하나(e) 를 꺼내고, 리스트 헤드를 e->next 로 갱신.
	즉, pop 연산이 일어난 것.
카운트 감소
	해당 bin 에 남아 있는 청크 개수 감소
key 초기화
	아까 tcache_put 에서 e->key = tcache; 로 표시했던 걸 여기서 지워줌
	이유: 이제 이 청크는 다시 사용자에게 반환되는 상태라서, 더 이상 "tcache 안에 있다"라고 표시하면 안 되기 때문
	만약 이걸 초기화 하지 않으면, 이후 정상적인 free 에서도 double free로 오인할 수 있음.
사용자에게 반환
	꺼낸 청크를 사용자에게 포인터 형태로 돌려줌.

#### 4. \_int_free
\_int_free 은 청크를 해제할 때 호출되는 함수이다. 하단의 코드의 20번째 줄 이하를 보면, 재할당하려는 청크의 key 값이 tcache 이면 Doube Free가 발생했다고 보고 프로그램을 abort 시킨다.
``` c
_int_free (mstate av, mchunkptr p, int have_lock)
 #if USE_TCACHE
    {
     size_t tc_idx = csize2tidx (size);
-
-    if (tcache
-       && tc_idx < mp_.tcache_bins
-       && tcache->counts[tc_idx] < mp_.tcache_count)
+    if (tcache != NULL && tc_idx < mp_.tcache_bins)
       {
-       tcache_put (p, tc_idx);
-       return;
+       /* Check to see if it's already in the tcache.  */
+       tcache_entry *e = (tcache_entry *) chunk2mem (p);
+
+       /* This test succeeds on double free.  However, we don't 100%
+          trust it (it also matches random payload data at a 1 in
+          2^<size_t> chance), so verify it's not an unlikely
+          coincidence before aborting.  */
+       if (__glibc_unlikely (e->key == tcache))
+         {
+           tcache_entry *tmp;
+           LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
+           for (tmp = tcache->entries[tc_idx];
+                tmp;
+                tmp = tmp->next)
+             if (tmp == e)
+               malloc_printerr ("free(): double free detected in tcache 2");
+           /* If we get here, it was a coincidence.  We've wasted a
+              few cycles, but don't abort.  */
+         }
+
+       if (tcache->counts[tc_idx] < mp_.tcache_count)
+         {
+           tcache_put (p, tc_idx);
+           return;
+         }
       }
   }
  #endif
```

20번째 줄의 조건문만 통과하면 double free를 일으킬 수 있다.

기본 조건 확인
	tcache != NULL : tcache 활성화 여부
	tc_idx < mp_.tcache_bins : 인덱스 범위 검사
double free 탐지 시도
	chunk2mem(p) 로 사용자 영역 포인터 얻기
	그걸 tcache_entry 로 캐스팅
	e->key 가 현재 tcache 와 같으면, 이 청크는 이미 tcache에 들어가 있는 것
	즉, double free 가능성 발견.


### 동적 패치 분석

 먼저, 청크 할당 직후에 중단점을 설정하고 실행
 ```
 $ gdb -q double_free
pwndbg> disass main
   0x00005555555546da <+0>:     push   rbp
   0x00005555555546db <+1>:     mov    rbp,rsp
   0x00005555555546de <+4>:     sub    rsp,0x10
   0x00005555555546e2 <+8>:     mov    edi,0x50
   0x00005555555546e7 <+13>:    call   0x5555555545b0 <malloc@plt>
   0x00005555555546ec <+18>:    mov    QWORD PTR [rbp-0x8],rax
   ...
pwndbg> b *main+18
Breakpoint 1 at 0x5555555546ec
pwndbg> r
 ```

heap 명령어로 청크들의 정보를 조회
```
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555756000
Size: 0x251

Allocated chunk | PREV_INUSE
Addr: 0x555555756250
Size: 0x61

Top chunk | PREV_INUSE
Addr: 0x5555557562b0
Size: 0x20d51
```

이 중 malloc(0x50) 으로 생성한 chunk 의 주소는 0x555555756250 이다.해당 메모리 값을 덤프하면, 아무런 데이터가 입력되지 않았음을 확인할 수 있다.

```
pwndbg> x/4gx 0x555555756250
0x555555756250: 0x0000000000000000      0x0000000000000061
0x555555756260: 0x0000000000000000      0x0000000000000000
```

0x555555756250(청크 베이스, mchunkptr 위치)
	첫 qword 0x0 : 보통 prev_size(사용 중이면 무의미).
	두번째 qword 0x61 : size 필드 0x61 = 0x60 | PREV_INUSE 비트(=1) 이므로 usable size = 0x60
	-> 즉, 청크는 현재 할당(lalocated) 상태이다.
0x555555756260(사용자 포인터 위치, chunk + 0x10)
	두 워드 모두 0x0 : 사용자 데이터가 0으로 초기화 되어 있거나 아직 쓰지 않은 상태.
	tcache에 들어가 있지 않음을 의미(아직 free 가 일어나지 않았으므로 당연).
요약 : 현재는 할당된 청크(allocated) 상태이고, 아직 free() 가 일어나지 않아 tcache 관련 next / key 필드에 값이 없음.


이후의 참조를 위해 청크를 gdb에서 chunk 변수로 정의.
```
pwndbg> set $chunk=(tcache_entry *)0x555555756260
```

tcache_entry 포인터 타입으로 캐스팅 해 준 이유는 tcache_entry 구조체에 key값을 확인할 수 있기 때문이다.


chunk를 해제할 때까지 실행하고, 청크의 메모리를 출력
```
pwndbg> disass main
   0x0000555555554703 <+41>:    call   0x5555555545a0 <printf@plt>
   0x0000555555554708 <+46>:    mov    rax,QWORD PTR [rbp-0x8]
   0x000055555555470c <+50>:    mov    rdi,rax
   0x000055555555470f <+53>:    call   0x555555554590 <free@plt>
   0x0000555555554714 <+58>:    mov    rax,QWORD PTR [rbp-0x8]
pwndbg> b *main+58
Breakpoint 2 at 0x0000555555554714
pwndbg> c
pwndbg> print *($chunk)
$1 = {
  next = 0x0,
  key = 0x555555756010
}
```
free() 가 호출되면서 glibc는 이 청크를 tcache bin에 넣음.
그 과정에서 사용자 영역의 앞부분이 tcache_entry 구조체처럼 사용됨

즉, 
next = 0x0
-> 같은 bin에 다른 청크가 아직 없으므로 다음 노드 없음.
key = 0x555555756010
-> 현재 스레드의 tcache 구조체 주소(스레드별 캐시)
이 필드는 double free를 감지하기 위한 용도로 기록됨.


0x555555756010 주소인 현재 스레드의 tcache 메모리를 조회하면, 
해제한 chunk의 주소 0x555555756260가 entry에 포함되 있음을 알 수 있는데, 이는 tcache_prethread 에 tcache들이 저장되기 때문이다.
```
print *(tcache_perthread_struct *)0x555555756010
$2 = {
  counts = "\000\000\000\000\001", '\000' <repeats 58 times>,
  entries = {0x0, 0x0, 0x0, 0x0, 0x555555756260, 0x0 <repeats 59 times>}
}
```

이 상태에서 실행을 재개하면 key 값을 변경하지 않고, 다시 free 를 호출하므로, abort 가 발생한다.

동적분석 시 문제점.
https://dreamhack.io/forum/qna/3956/

heap, stack, tcache 명령 사용 가능.



### 우회 기법

앞의 분석을 통해 알 수 있듯, if (__glibc_unlikely (e->key == tcache)) 만 통과하면 tcache 청크를 double free 시킬 수 있다.

다시 말해, 해제된 청크의 key 값을 1비트만이라도 바꿀 수 있다면 이 보호 기법을 우회할 수 있다.

``` c
+       /* This test succeeds on double free.  However, we don't 100%
+          trust it (it also matches random payload data at a 1 in
+          2^<size_t> chance), so verify it's not an unlikely
+          coincidence before aborting.  */
+       if (__glibc_unlikely (e->key == tcache)) // Bypass it!
+         {
+           ...
+             if (tmp == e)
+               malloc_printerr ("free(): double free detected in tcache 2");
+         }
+           ...
+       if (tcache->counts[tc_idx] < mp_.tcache_count)
+         {
+           tcache_put (p, tc_idx);
+           return;
+         }
       }
```


