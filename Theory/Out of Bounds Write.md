``` c
// Name: oob_write.c
// Compile: gcc -o obb_write obb_write.c

#include <stdio.h>
#include <stdlib.h>

// long 8 + pointer 8 + long 8 = 24byte
struct Student {
    long attending;
    char *name;
    long age;
};

/*
stu[10]: 학생 10명의 정보 저장 공간.
isAdmin: 전역변수 기본값은 0.
메모리에서 stu 배열 뒤쪽에 isAdmin 이 위치할 가능성이 높음.
*/
struct Student stu[10];
int isAdmin;

int main() {
    unsigned int idx;

    // Exploit OOB to read the secret
    puts("Who is present?");
    printf("(1-10)> ");
    scanf("%u", &idx);

    /*
    입력받은 인덱스에 해당하는 학생의 attending 필드를 1로 설정 
    올바른 값: 1~10 -> stu[0] ~ stu[9] 접근 -> 정상
    잘못된 값: 11 -> stu[10].attending 접근 (범위를 벗어난 쓰기)
    이때 stu[10]은 존재하지 않지만, 메모리상에서 바로 뒤에 있는 변수를 덮어쓰기 가능.
    배열 바로 뒤에 있는게 isAdmin -> 따라서 isAdmin이 1로 바뀜.
    */
    stu[idx - 1].attending = 1;

    if (isAdmin) printf("Access granted.\n");
    return 0;
}
```

디버거를 이용하여 stu와 isAdmin의 주소를 확인
```
pwndbg> i var isAdmin
Non-debugging symbols:
0x0000000000201130  isAdmin
pwndbg> i var stu
Non-debugging symbols:
0x0000000000201040  stu
pwndbg> print 0x201130-0x201040
$1 = 240
```
isAdmin 이 stu 보다 240바이트 높은 주소에 있음.
배열의 구성하는 Student 구조체의 크기라 24바이트이므로 , 10번째 인덱스를 참조하면 isAdmin을 조작할 수 있다.