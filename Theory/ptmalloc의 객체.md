### 청크

청크(Chunk)는 덩어리라는 뜻으로, 여기서는 ptmalloc이 할당한 메모리 공간을 의미한다. 청크는 데이터와 헤더로 구성된다. 헤더는 청크 관리에 필요한 정보를 담고 있으며, 데이터 영역에는 사용자가 입력한 데이터가 저장된다.

![](https://dreamhack-lecture.s3.amazonaws.com/media/4b0c74248164c0b89c3c47d2beed97fd3b22a268520eb070b8c613e70b0d2fb9.png)
헤더는 청크이 상태를 나타내므로 사용 중인 청크(in-use)의 헤더와 해제된 청크(freed)의 헤더는 구조가 다소 다르다.
사용중인 청크는 fd 와 bk 를 사용하지 않고, 그 영역에 사용자가 입력한 데이터를 저장한다.

![[Chunk.png]]


### bin

bin 은 문자 그대로, 사용이 끝난 청크들이 저장되는 객체이다. 메모리의 낭비를 막고, 해제된 청크를 빠르게 재사용할 수 있게 한다.
ptmalloc 에는 총 128개의  bin이 정의되어 있다. 이 중 62개는 smallbin, 63개는 largebin, 1개는 unsortedbin으로 사용되고, 나머지 2개는 사용되지 않는다.

![](https://dreamhack-lecture.s3.amazonaws.com/media/8fad7686a29fc8373d5a0be0e9ca5b52da8688d3d49503d0b6b5effc5ca2ae3c.png)


### smallbin




![](https://dreamhack-lecture.s3.amazonaws.com/media/c065e7f4759319dfc276a90fd5366eb6f57a96654e32f71ee8bd0371dd785e82.gif)
