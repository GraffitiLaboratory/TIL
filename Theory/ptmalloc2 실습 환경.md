
### GLibc 버전 확인

ldd --version


### 실습환경 Dockerfile
```
FROM ubuntu:18.04

# PATH에 python3.6 관련 패키지 경로를 추가 -> pip 패키지 실행 파일 인식 가능하게 함
# LC_CTYPE=C.UTF-8 -> 로케일 문제(예: gdb 출력 깨짐) 방지
ENV PATH="${PATH}:/usr/local/lib/python3.6/dist-packages/bin"
ENV LC_CTYPE=C.UTF-8

# ruby : one_gadget 설치용
# sudo : 권한 상승
# tmux : 세션 분할 / 멀티 작업
RUN apt update
RUN apt install -y \
    gcc \
    git \
    python3 \
    python3-pip \
    ruby \
    sudo \
    tmux \
    vim \
    wget

# install pwndbg
# 특정 태그(2023.03.19)로 고정해서 버전 호환성 유지
WORKDIR /root
RUN git clone https://github.com/pwndbg/pwndbg
WORKDIR /root/pwndbg
RUN git checkout 2023.03.19
RUN ./setup.sh

# install pwntools
# 최신 pip으로 업그래이드
RUN pip3 install --upgrade pip
RUN pip3 install pwntools

# install one_gadget command
# one_gadget: libc에서 execve("/bin/sh", ...) 가능한 gadget 찾는 툴 -> ret2libc 익스 시 매우 유용
RUN gem install elftools -v 1.1.3
RUN gem install one_gadget -v 1.9.0

WORKDIR /root
```

```
$ IMAGE_NAME=ubuntu1804 CONTAINER_NAME=my_container; \
docker build . -t $IMAGE_NAME; \
docker run -d -t --privileged --name=$CONTAINER_NAME $IMAGE_NAME; \
docker exec -it -u root $CONTAINER_NAME bash
```

1. 환경변수 설정
    IMAGE_NAME -> 도커 이미지 이름 (ubuntu1804)
    CONTAINER_NAME -> 컨테이너 이름 my_container
2. 도커 이미지 빌드
    현재 디렉토리(.)에 있는 Dockerfile 을 기반으로 이미지를 빌드
    빌드된 이미지에 태그(-t)로 ubuntu1804 이름을 붙임.
3. 컨테이너 실행
    -d -> 백그라운드(detached) 모드 실행
    -t -> TTY 할당
    --privileged -> 컨테이너에 추가 권한 부여 (커널 기능, 장치 접근 가능)
    --name=$CONTAINER_NAME → 컨테이너 이름 지정 (my_container)
    $IMAGE_NAME → 앞에서 빌드한 이미지(ubuntu1804)를 기반으로 실행
4. 컨테이너 내부 접속
    docker exec → 실행 중인 컨테이너 안에서 명령어 실행
    it → 대화형(interactive) 모드 + 터미널 할당
    -u root → root 권한으로 실행
    $CONTAINER_NAME → 접속할 컨테이너(my_container)
    bash → 컨테이너 안에서 bash 실행

