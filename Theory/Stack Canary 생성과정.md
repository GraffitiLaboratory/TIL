#canary #catch #watch 

카나리 값은 프로세스가 시작될 때, TLS에 전역 변수로 저장되고, 각 함수마다 프롤로그와 에필로그에서 이 값을 참조한다.

### stack canary 켜기 / 끄기

$ gcc -o r2s r2s.c -fstack-protector

$ gcc -o r2s r2s.c -fno-stack-protector

### TLS 주소 파악

fs는 TLS를 가리키므로 fs 의 값을 알면 TLS의 주소를 알 수 있다.
fs 의 값은 특정 시스템 콜을 사용해야만 조회하거나 설정할 수 있다.
여기서 fs의 값을 설정할 때 호출되는 arch_prctl(int code, unsigned long addr) 시스템 콜에 중단점을 설정

이 시스템 콜을 arch_prctl(ARCH_SET_FS, addr) 의 형태로 호출하면 fs의 값은 addr 로 설정된다.

#### catch
gdb에서 특정 이벤트가 발생했을 때, 프로세스를 중지시킴.

catch syscall arch_prctl

이 때, rdi 에 ARCH_SET_FS 값이,
rsi 에 addr 값이 저장됨.
TLS 를 0x7ffff7d7f740 에 저장할 것이며, fs 는 이를 가리키게 될 것이다.

pwndbg> info register $rsi
rsi 0x7ffff7d7f740 140737351513920

pwndbg> x/gx 0x7ffff7d7f740 + 0x28
0x7ffff7d7f768: 0x0000000000000000

### 카나리 값 설정
TLS의 주소를 알았으므로, gdb의 watch 명령어로 TLS + 0x28에 값을 쓸 때 프로세스를 중단.

#### watch
특정 주소에 저장된 값이 변겨오디면 프로세스를 중단시키는 명령어

pwndbg> watch *(0x7ffff7d7f740+0x28)
Hardware watchpoint 4: *(0x7ffff7d7f740+0x28)

```
pwndbg> continue
Continuing.

Hardware watchpoint 4: *(0x7ffff7d7f740+0x28)

Old value = 0
New value = 2005351680
security_init () at rtld.c:870
870	in rtld.c
```

```
pwndbg> x/gx 0x7ffff7d7f740+0x28
0x7ffff7d7f768:	0x8ab7f53277873d00
```
```
Breakpoint 3, 0x00005555555546ae in main ()
pwndbg> x/10i $rip
 ► 0x555555555169 <main>       endbr64
   0x55555555516d <main+4>     push   rbp
   0x55555555516e <main+5>     mov    rbp, rsp
   0x555555555171 <main+8>     sub    rsp, 0x10   
   0x555555555175 <main+12>    mov    rax, qword ptr fs:[0x28]
   0x55555555517e <main+21>    mov    qword ptr [rbp - 8], rax
   0x555555555182 <main+25>    xor    eax, eax
   0x555555555184 <main+27>    lea    rax, [rbp - 0x10]
   0x555555555188 <main+31>    mov    edx, 0x20
   0x55555555518d <main+36>    mov    rsi, rax
   0x555555555190 <main+39>    mov    edi, 0
pwndbg> ni
0x000055555555516d in main ()
pwndbg> ni
0x000055555555516e in main ()
pwndbg> ni
0x0000555555555171 in main ()
pwndbg> ni
0x0000555555555175 in main ()
pwndbg> ni
0x000055555555517e in main ()
pwndbg> i r $rax
rax            0x8ab7f53277873d00	9995727495074626816
pwndbg> 
```