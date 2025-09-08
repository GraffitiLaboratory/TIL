
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



### 3.

