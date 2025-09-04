### 타입 에러

변수의 자료형을 선언할 때는 변수를 활용하는 동안 담게 될 값의 크기, 용도, 부호 여부를 고려해야 한다.
Type Error 는 이러한 고려없이 부적절한 자료형을 사용하였을 때 발생한다.

### Out of Range: 데이터 유실

int 타입의 res에 unsigned long long 타입의 값을 반환하는 경우.
``` c
// Name: out_of_range.c
// Compile: gcc -o out_of_range out_of_range.c

#include <stdio.h>

unsigned long long factorial(unsigned int n) {
    unsigned long long res = 1;

    for (int i = 1; i <= n; i++) {
        res *= i;
    }

    return res;
}

int main() {
    unsigned int n;
    unsigned int res;

    printf("Input integer n: ");
    scanf("%d", &n);

    if (n >= 50) {
        fprintf(stderr, "Input is too large");
        return -1;
    }

    res = factorial(n);
    printf("Factorial of N: %u\n", res);
}
```

```
$ ./out_of_range
Input integer n: 17
Factorial of N: 4006445056
$ ./out_of_range
Input integer n: 18
Factorial of N: 3396534272
```

양수를 곱하기만 했는데, 값이 갑자기 작아진 이유는 res 에 저장될 수 있는 범위보다 훨씬 큰 값을 저장하려 했기 때문.

18! = 0x16beecca730000 이다. 이를 4바이트 크기의 res 에 대입하려 하면, 상위 4바이트는 버려지고, 하위 4바이트인 0xca730000만 옮겨진다.

이처럼 변수에 어떤 값을 대입할 때, 그 값이 변수에 저장될 수 있는 범위를 벗어나면, 저장할 수 있는 만큼만 저장하고 나머지는 모두 유실된다.

### Out of Range: 부호 반전과 값의 왜곡

unsigned int 로 만들어야 될 변수를 int로 만들었을 경우, 
입력값을 음수로 입력하면 if 조건문 검사를 우회할 수 있게 된다.

```c
// Name: oor_signflip.c
// Compile: gcc -o oor_signflip oor_signflip.c

#include <stdio.h>

unsigned long long factorial(unsigned int n) {
    unsigned long long res = 1;

    for (int i = 1; i <= n; i++) {
        res *= i;
    }

    return res;
}

int main() {
    int n;
    unsigned int res;

    printf("Input integer n: ");
    scanf("%d", &n);

    if (n > 50) {
        fprintf(stderr, "Input is too large");
        return -1;
    }

    res = factorial(n);
    printf("Factorial of N: %u\n", res);
}
```

int n 에 -1 을 저장하면, n 의 메모리 공간에 저장되는 값은 0xffffffff 이다. 이렇게 저장되는 이유는 2의 보수에 의해 저장되기 때문이다.

그런데 factorial 함수는 unsigned int n 을 인자로 받으므로, 이 값은 부호없는 정수인 4294967295 로 전달되고, 결국 4294967295 번 반복문을 실행하게 된다. 당연히 시간이 오래 걸릴 뿐만 아니라 값이 너무 커져서 연산도 제대로 이루어지지 않는다.

이런 문제를 예방하려면 양수로만 쓰일 값에 반드시 unsigned 를 붙이는 습관을 들여야 한다..


### Out of Range 와 버퍼 오버플로우

다음 코드는 잘못된 자료형의 사용이 스택 버퍼 오버플로우로 이어지는 코드이다.
버퍼 오버플로우를 막기 위해 size 가 32 보다 작은지 검사한다. 그러나 size 가 int 형이므로 음수를 전달하여 검사를 우회할 수 있다.

``` c
// Name: oor_bof.c
// Compile: gcc -o oor_bof oor_bof.c -m32

#include <stdio.h>
#include <unistd.h>

#define BUF_SIZE 32

int main() {
  char buf[BUF_SIZE];
  int size;
  
  printf("Input length: ");
  scanf("%d", &size);
  
  if (size > BUF_SIZE) {
    fprintf(stderr, "Buffer Overflow Detected");
    return -1;
  }
  
  read(0, buf, size);
  return 0;
}
```

이 때, read 함수의 3번째 인자는 부호가 없는 size_t 형이므로, 음수를 전달하면 매우 큰 수로 해석된다.

ssize_t read(int fd, void \*buf, size_t count);

실제로 size 에 -1 을 입력하고 32바이트보다 큰 데이터를 입력하면 다음과 같이 스택 버퍼 오버플로우가 발생한다.
```
$ ./oor_bof
Input length: -1
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
*** stack smashing detected ***: <unknown> terminated
Aborted (core dumped)
```

##### 64비트로 컴파일 했을 때는 안되는 이유
64비트 환경에서 -1 은 0xffffffffffffffff 이다. size_t 는 64비트 환경에서 8바이트 크기의 부호 없는 정수를 나타내므로, size_t 로 환산하면 -1은 18446744073709551615 이다. 
read 함수는 count 의 값으로 이렇게 큰 값이 들어오면 아무런 동작도 하지 않고 에러값을 반환한다.


### 타입 오버플로우와 언더플로우

변수의 값이 연산중에 자료형의 범위를 벗어나면 갑자기 크기가 작아지거나 커지는 현상이 발생하는데, 이런 현상을 Type Overflow / Underflow라고 부른다.
정수 자료형을 대상으로 발생하면 Type에 Integer 를 넣어 Integer Overflow / Underflow 라고 한다.

![](https://dreamhack-lecture.s3.amazonaws.com/media/e8255dc29297dc69ba881b786ecff9a9d4c1a584fcae72e7afe8a4f3f1077dae.png)

``` c
// Name: integer_example.c
// Compile: gcc -o integer_example integer_example.c

#include <limits.h>
#include <stdio.h>

/*
UINT_MAX -> unsigned int 가 가질 수 있는 최댓값(4294967295 on 32-bit unsigned int)
여기에 +1을 하면 값의 범위를 넘어감 -> 오버플로우 발생
UINT_MAX + 1 = 0

INT_MAX -> int 의 최댓값(2147483647 on 32-bit int)
여기에 +1 하면 범위를 벗어남.
INT_MAX + 1 = -2147483648

0 - 1 은 원래 음수(-1)가 되어야 함.
그런데 unsigned int 타입에서 저장하므로 음수는 표현 불가
0 - 1 = UINT_MAX (즉 4294967295)

INT_MIN -> int의 최솟값(-2147483648)
여기서 -1 을 하면 범위를 벗어남
보통, INT_MIN - 1 = INT_MAZ 가 됨.
*/
int main() {
  unsigned int a = UINT_MAX + 1;
  int b = INT_MAX + 1;

  unsigned int c = 0 - 1;
  int d = INT_MIN - 1;

  printf("%u\n", a);
  printf("%d\n", b);

  printf("%u\n", c);
  printf("%d\n", d);
  return 0;
}
```


### Integer Overflow 와 버퍼 오버플로우

integer overflow가 힙 버퍼 오버플로우로 이어지는 예제코드이다.
예제는 사용자로부터 size 값을 입력받고, size + 1  크기의 버퍼를 할당한다.
그리고 그 버퍼에 size 만큼 사용자 입력을 받는다.

``` c
// Name: integer_overflow.c
// Compile: gcc -o integer_overfolw integer_overflow.c -m32

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
    unsigned int size;
    scanf("%u", &size);

    char *buf = (char *)malloc(size + 1);
    unsigned int read_size = read(0, buf, size);

    buf[read_size] = 0;
    return 0;
}
```

만약 사용자가 size 에 unsigned int 의 최댓값인 4294967295 을 입력하면, integer overflow 로 인해 size + 1 은 0 이 된다.
이 값이 malloc에 전달되면, malloc 은 최소 할당 크기인 32바이트 만큼 청크를 할당한다.
반면 read 함수는 size 값을 그대로 사용한다.. 따라서 32바이트 크기의 청크에 4294967295 만큼 값을 쓸 수 있는, 힙 버퍼 오버플로우가 발생하게 된다.


### Type Overflow
변수가 저장할 수 있는 최댓값을 넘어서서 최솟값이 되는 버그

### Type Underflow
변수가 저장할 수 있는 최솟값보다 작아 최댓값이 되는 버그

### Most Significant Bit(MSB)
데이터의 최상위 비트, 부호를 표현하기 위해 사용됨.



