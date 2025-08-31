
``` c
// Name: oob_read.c
// Compile: gcc -o oob_read oob_read.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// 전역변수라서 프로그램의 데이터 영역(.bss)에 위치함. 크기는 256바이트.
char secret[256];

/*
파일 입출력을 위한 FILE *fp 선언.
secret.txt 파일을 읽기 전용("r")으로 열기
없으면 에러 메시지 출력 후 -1 반환
fgets 로 최대 255바이트를 secret에 저장(마지막에 \0 보장함.)
읽은 후 fp 닫기 
*/
int read_secret() {
  FILE *fp;

  if ((fp = fopen("secret.txt", "r")) == NULL) {
    fprintf(stderr, "`secret.txt` does not exist");
    return -1;
  }

  fgets(secret, sizeof(secret), fp);
  fclose(fp);

  return 0;
}

int main() {
  char *docs[] = {"COMPANY INFORMATION", "MEMBER LIST", "MEMBER SALARY",
                  "COMMUNITY"};
  // 전역변수 secret 의 주소를 secret_code 라는 포인터로 가리킴.
  char *secret_code = secret;
  int idx;

  // Read the secret file
  if (read_secret() != 0) {
    exit(-1);
  }

  // Exploit OOB to print the secret
  puts("What do you want to read?");
  for (int i = 0; i < 4; i++) {
    printf("%d. %s\n", i + 1, docs[i]);
  }
  printf("> ");
  scanf("%d", &idx);

  /*
  idx 가 4보다 크면 종료.
  하지만 0 이하의 값은 막지 않음.
  예를 들어, 0을 입력하면 docs[-1]에 접근 -> OOB 발생.
  */
  if (idx > 4) {
    printf("Detect out-of-bounds");
    exit(-1);
  }

  /*
  입력한 번호에 딸라 docs[idx-1] 출력.
  정상적인 경우 (1~4): 메뉴 항목 출력
  비정상 입력(0): docs[-1] 접근 -> 배열 앞에 있는 메모리(secret_code 변수 주소) 출력 가능.
  즉, Out-of-Bounds Read 발생 -> secret.txt 내용 유출 가능.
  */
  puts(docs[idx - 1]);
  return 0;
}
```

```
$ gcc -o oob oob.c
$ ./oob
In Bound:
arr: 0x7ffebc778b00
arr[0]: 0x7ffebc778b00

Out of Bounds:
arr[-1]: 0x7ffebc778afc
arr[100]: 0x7ffebc778c90
```

컴파일러는 배열의 범위를 명백히 벗어나는 -1 과 100 을 인덱스로 사용했음에도 아무런 경고를 띄워주지 않는다.
즉, OOB를 방지하는 것은 전적으로 개발자의 몫이다.

다음으로, arr[0] 와 arr[100] 의 주소 차이가 0x7ffebc778c90 - 0x7ffebc778b00 = 0x190 = 100 * 4 이다. 배열의 범위를 벗어난 인덱스를 참조해도 앞서 살펴본 식을 그대로 사용함을 확인할 수 있다.