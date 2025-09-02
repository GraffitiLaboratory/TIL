Path Traversal은 어떠한 서비스가 있을때, 사용자가 허용되지 않은 경로에 접근할 수 있는 취약점을 말함.
사용자가 접근하려는 경로에 대한 검사가 미흡하여 발생하며, 임의 파일 읽기 및 쓰기의 수단으로 활용될 수 있다.


### 절대 경로 와 상대 경로
리눅스에는 파일의 경로를 지정하는 두 가지 방법으로 절대경로(Absolute Path)와 상대경로(Relative Path)가 있다.

``` c
// Name: path_traversal.c
// Compile: gcc -o path_traversal path_traversal.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const int kMaxNameLen = 0x100;      // 파일 이름 256바이트
const int kMaxPathLen = 0x200;      // 파일 경로 512바이트
const int kMaxDataLen = 0x1000;     // 파일 내용 4096바이트
const char *kBasepath = "/tmp";     // 기본 디렉토리

int main() {
    char file_name[kMaxNameLen];
    char file_path[kMaxPathLen];
    char data[kMaxDataLen];
    FILE *fp = NULL;

    // Initialize local variables
    /*
    void *memset(void *s, int c, size_t n);
    메모리 영역 s 의 앞에서부터 n 바이트를 값 c 로 채워 넣는 함수
    */
    memset(file_name, '\0', kMaxNameLen);
    memset(file_path, '\0', kMaxPathLen);
    memset(data, '\0', kMaxDataLen);

    // Receive input from user
    /*
    char *fgets(char *s, int n, FILE *stream);
    s: 입력받은 문자열을  저장할 버퍼
    n: 읽을 수 있는 최대 길이 (n-1 글자 + 마지막 \0)
    stream: 입력 소스(여기서는 stdin -> 표준 입력, 즉 키보드)
    fgets는 채대 길이를 지정할 수 있고, 공백 포함 입력도 가능해서 안전한 입력함수로 많이 쓰임.
    */
    printf("File name: ");
    fgets(file_name, kMaxNameLen, stdin);

    // Trim trailing new line
    /*
    size_t strcspn(const char *s, const char *reject);
    문자열 s 에서 reject 에 포함된 문자 중 첫 번째로 나타나는 위치의 인덱스를 반환한다.
    즉 "hello\n"에서 "\n"을 찾으면 인데스 5를 반환.
    file_name 에서 개행문자 \n 이 나타나는 위치를 찾음
    그 위치에 '\0'을 넣어서 문자열 끝내기 
    즉, fgets가 저장한 개행 문자(\n)를 널문자(\0)로 교체해서 제거하는 코드
    */
    file_name[strcspn(file_name, "\n")] = '\0';

    // Construct the 'file_path'
    /*
    file_path -> 완성된 경로를 저장할 버퍼(최대 512바이트)
    kMaxPathLen -> 버퍼 크기 (0x200 = 512)
    "%s/%s" -> 문자열 형식: 기본경로/파일명
    kBasepath -> /tmp
    file_name -> 사용자가 입력한 파일명 

    보안 취약점
    사용자 입력 : ../../etc/passwd
    file_path : /tmp/../../etc/passwd
    실제 접근 경로 : /etc/passwd
    */
    snprintf(file_path, kMaxPathLen, "%s/%s", kBasepath, file_name);

    // Read the file and print its content
    // fprintf(stderr, ..) -> 에러 메시지를 표준 에러로 출력 
    // 표준 출력(stdout)이 아니라 에러 출력으로 보내기 때문에, 로그/리다이렉션 시에도 구분 가능.
    if ((fp = fopen(file_path, "r")) == NULL) {
        fprintf(stderr, "No file named %s", file_name);
        return -1;
    }

    fgets(data, kMaxDataLen, fp);
    printf("%s", data);

    fclose(fp);

    return 0;
}
```

File name: ../etc/passwd

path traversal은 서버의 중요한 데이터를 공격자에게 노출시키는 취약점이다.
만약 파일에 데이터를 쓸 수 있다면, /etc/passwd 를 조작하여 root의 비밀번호를 제거하거나, ssh 의 설정을 변경하는 등 서버에 위협이 되는 행위를 할 수 도 있다.


### 절대 경로 (Absolute Path)
루트 디렉토리에서 접근할 파일 및 디렉토리 위치까지 모두 표현하는 방식

### 상대 경로 (Relative Path)
현재 사용자의 위치를 기준으로 다른 파일이나 디렉터리의 경로를 표현하는 방식.

### Path Traversal
경로 문자열에 대한 검사가 미흡하여 허용되지 않는 경로에 접근할 수 있는 취약점


