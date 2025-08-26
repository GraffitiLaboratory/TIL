리눅스에서 ELF는 실행 파일(Executable)과 공유 오브젝트(Shared Object, SO)로 두 가지가 존재한다.
실행파일은 addr 처럼 일반적인 실행파일이 해당하고, 공유 오브젝트는 libc.so와 같은 라이브러리 파일이 해당한다.

공유 오브젝트는 기본적으로 재배치(Relocation)가 가능하도록 설계되어 있다.
재배치가 가능하다는 것은 메모리의 어느 주소에 적재되어도 코드의 의미가 훼손되지 않음을 의미하는데, 컴퓨터 과학에서는 이런 성질을 만족하는 코드를  Position-Independent Code(PIC) 라고 부른다.

```
$ file addr
addr: ELF 64-bit LSB executable
$ file /lib/x86_64-linux-gnu/libc.so.6
/lib/x86_64-linux-gnu/libc.so.6: ELF 64-bit LSB shared object
```

gcc는 PIC 컴파일을 지원한다.
PIC가 적용된 바이너리와 그렇지 않은 바이너리를 비교하기 위한 예제.

``` c
// Name: pic.c
// Compile: gcc -o pic pic.c
// 	      : gcc -o no_pic pic.c -fno-pic -no-pie
#include <stdio.h>
char *data = "Hello World!";
int main() {
  printf("%s", data);
  return 0;
}
```

PIC 미적용
```
0x0000000000401126 <+0>:     push   rbp
   0x0000000000401127 <+1>:     mov    rbp,rsp
   0x000000000040112a <+4>:     mov    rax,QWORD PTR [rip+0x2ee7]        # 0x404018 <data>
   0x0000000000401131 <+11>:    mov    rsi,rax
   0x0000000000401134 <+14>:    mov    edi,0x402011
   0x0000000000401139 <+19>:    mov    eax,0x0
   0x000000000040113e <+24>:    call   0x401030 <printf@plt>
   0x0000000000401143 <+29>:    mov    eax,0x0
   0x0000000000401148 <+34>:    pop    rbp
   0x0000000000401149 <+35>:    ret
```

PIC 적용
```
0x0000000000001139 <+0>:     push   rbp
   0x000000000000113a <+1>:     mov    rbp,rsp
   0x000000000000113d <+4>:     mov    rax,QWORD PTR [rip+0x2ed4]        # 0x4018 <data>
   0x0000000000001144 <+11>:    mov    rsi,rax
   0x0000000000001147 <+14>:    lea    rax,[rip+0xec3]        # 0x2011
   0x000000000000114e <+21>:    mov    rdi,rax
   0x0000000000001151 <+24>:    mov    eax,0x0
   0x0000000000001156 <+29>:    call   0x1030 <printf@plt>
   0x000000000000115b <+34>:    mov    eax,0x0
   0x0000000000001160 <+39>:    pop    rbp
   0x0000000000001161 <+40>:    ret
```

두 코드의 차이점을 확인해 보면
"%s"문자열을 printf에 전달하는 방식이 조금 다르다.
no_pic에서는 0x402011 라는 절대 주소로 문자열을 참조하고 있다.
pic에서는 \[rip+0xec3] 라는 rip를 기준으로 데이터를 상대참조 하고 있다.

바이너리가 매핑되는 주소가 바뀌면 0x402011 에 있던 데이터도 함께 이동하므로 no_pic의 코드는 제대로 실행되지 못한다.
그러나 pic의 코드는 rip를 기준으로 상대 참조(Relatvie Addressing)하기 때문에 바이너리가 무작위 주소에 매핑돼도 제대로 실행될 수 있다.