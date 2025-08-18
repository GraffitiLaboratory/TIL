#checksec

```
$ checksec ./r2s
[*] '/home/dreamhack/r2s'    
  Arch:     amd64-64-little    
  RELRO:    Full RELRO
  Stack:    Canary found
  NX:       NX disabled
  PIE:      PIE enabled
  RWX:      Has RWX segments
```

Arch
: 프로그램이 64비트 리틀 엔디언 아키텍처로 컴파일 됨

RELRO(Relocation Read-Only)
: GOT(전역 오프셋 테이블)을 보호하는 기능
: Full RELRO는 GOT 영역이 실행 중 읽기 전용으로 설정되어, GOT overwrite 공격(예: 함수 주소 변조)이 불가능함.

Stack
: 스택에 스택 카나리(stack canary) 값이 삽입되어 있음
: 버퍼 오버프롤우 공격시, 리턴 주소를 덮기 전에 카나리를 덮게되는데, 프로그램이 이름 체크하고 종료해 스택 버퍼 오버플로우 탐지가 가능

NX(No-eXecute)
: No-eXecute 비트가 꺼져 있음
: 즉, 스택 / 힙 같은 메모리 영역도 실행 가능하다는 뜻 -> 공격자가 쉘코드를 삽입해 실행할 수 있다는 뜻

PIE(Position Independent Executable) 활성화
: 실행할 때마다 코드 영역이 랜덤한 주소에 로드됨 (ASLR 지원) -> 공격자가 코드 영역 주소를 예측하기 어렵게 만듬.

RWX
: 메모리의 일부 구간이 읽기 / 쓰기 / 실행 (RWX) 권한을 모두 가짐
: 정상적이라면 실행 가능한 영역은 쓰기 불가, 쓰기 가능한 영역은 실행 불가해야 보안에 유리한데, RWX 구간이 존재하면 쉘코드 실행 위험이 큼.

### 세그먼트 정보에서 읽기 / 쓰기 / 실행 권한 확인법

readelf -l ./r2s

objdump -x ./r2s | grep LOAD