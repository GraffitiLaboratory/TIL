### 웹 서비스 분석

``` python
'''
#!/usr/bin/python3 : 이 파일을 실행할 때 파이썬 3 인터프리터를 사용
Flask : 파이썬의 웹 프레임워크. 간단히 웹 서버를 만들 수 있음.
request : 클라이언트(브라우저)로부터 들어오는 요청을 처리.
render_template : HTML 파일을 불러와 렌더링해서 클라이언트에게 응답
make_response : 응답(response) 객체를 직접 만들어 쿠키들을 붙일 수 있음.
redirect, url_for : 특정 경로로 리다이렉트 시킬 때 사용.
'''
#!/usr/bin/python3
from flask import Flask, request, render_template, make_response, redirect, url_for

app = Flask(__name__)

'''
flag.txt 파일에서 플래그를 읽어옴.
파일이 없으면 기본값 [**FLAG**] 사용.
'''
try:
    FLAG = open('./flag.txt', 'r').read()
except:
    FLAG = '[**FLAG**]'

'''
users 라는 딕셔너리(간단한 DB처럼 사용.)
아이디가 guest 면 비번도 guest.
아이디가 admin 이면 비번은 FLAG 값
즉, 관리자 계정의 비밀번호 = flag 값 이라는 뜻.
'''
users = {
    'guest': 'guest',
    'admin': FLAG
}

'''
/ 주소로 접속하면 실행됨.
쿠키에서 username 값을 가져옴.
    만약 쿠키에 username=admin 이 있으면 플래그를 보여줌.
    아니라면 "you are not admin" 출력
쿠키가 없다면 그냥 기본 index.html 랜더링
여기서 핵심은 쿠키를 조작하면 admin처럼 위장할 수 있다는 점.
'''
@app.route('/')
def index():
    username = request.cookies.get('username', None)
    if username:
        return render_template('index.html', text=f'Hello {username}, {"flag is " + FLAG if username == "admin" else "you are not admin"}')
    return render_template('index.html')

'''
GET 요청이면 로그인 페이지(login.html)을 보여줌.
POST 요청이면 입력받은 username / password 확인.
users[username] 는 딕셔너리에서 키 username의 값을 꺼내는 표현이다.
    키가 존재하면 그 값(예: 'guest' 또는 FLAG)이 pw에 저장된다.
    키가 없으면 파이썬은 KeyError 예외를 던진다.
존재하지 않는 유저이면 -> "not found user"
비밀번호가 맞으면:
    index 페이지로 리다이렉트.
    응답(response)에 username 이라는 쿠키를 심어서 브라우저로 전달.
비밀번호가 틀리면 "wrong password". 
'''
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            pw = users[username]
        except:
            return '<script>alert("not found user");history.go(-1);</script>'
        if pw == password:
            resp = make_response(redirect(url_for('index')) )
            resp.set_cookie('username', username)
            return resp 
        return '<script>alert("wrong password");history.go(-1);</script>'

app.run(host='0.0.0.0', port=8000)

```

### 취약점 분석

``` python
@app.route('/') # / 페이지 라우팅 
def index():
    username = request.cookies.get('username', None) # 이용자가 전송한 쿠키의 username 입력값을 가져옴
    if username: # username 입력값이 존재하는 경우
        return render_template('index.html', text=f'Hello {username}, {"flag is " + FLAG if username == "admin" else "you are not admin"}') # "admin"인 경우 FLAG 출력, 아닌 경우 "you are not admin" 출력
    return render_template('index.html')
```

이용자의 계정을 나타내는 username 변수가 request 에 포함된 쿠키에 의해 결정되어 문제가 발생한다.
쿠키는 클라이언트의 요청에 포함되는 정보로, 이용자가 임의로 조작할 수 있다. 서버는 별다른 검증없이 이용자 request 에 포함됨 쿠키를 신뢰하고, 이용자 인증 정보를 식별하기 때문에 공격자는 쿠키에 타 계정 정보를 삽입해 계정을 탈취할 수 있다.


### 익스플로잇

/login 페이지에서 guest:guest로 로그인
![](https://dreamhack-lecture.s3.amazonaws.com/media/90ee2823b42413da0299fd083e5f76e2ad391a518927977d8aaf1e2ac1a387d2.png)

console 창에서
document.cookie='username=admin'
입력 후 페이지 리로드하게 되면 쿠키정보가 admin으로 바뀌면서 flag를 확인 할 수 있다.
또는,
Application 창에서 Cookies 항목에서 Value값을 바로 'admin'으로 수정 후 리로드해도 된다.
![](https://dreamhack-lecture.s3.amazonaws.com/media/5b6a4093d1d30521df8edc322d483f83004efb07def4cb5b97888a3c80a99dd0.png)
