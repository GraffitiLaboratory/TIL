### 웹 서비스 분석

``` python
#!/usr/bin/python3
from flask import Flask, request, render_template, make_response, redirect, url_for

app = Flask(__name__)

# ./flag.txt 파일을 읽어 FLAG 변수에 저장. 실패함녀 대체 문자열을 쓴다.
try:
    FLAG = open('./flag.txt', 'r').read()
except:
    FLAG = '[**FLAG**]'

# users 는 사용자:비밀번호 매핑. 키가 사용자 이름, 값이 비밀번호(또는 여기서는 admin에는 FLAG가 들어가 있음.)
users = {
    'guest': 'guest',
    'user': 'user1234',
    'admin': FLAG
}


# this is our session storage
# 메모리 기반 세션 스토리지. 키: 세션ID(문자열), 값: username
# 프로세스 메모리에만 존재하므로 서버 재시작 시 초기화됨.
session_storage = {
}

"""
세션을 통해 이용자를 식별한다. 먼저 쿠키의 sessionid 의 값을 통해 session_storage 에서 해당 Session ID의 username을 조회한다. 만약 username 이 "admin"일 경우 FLAG를 출력한다.

request에서 sessionid쿠키를 읽어 session_id에 저장
session_storage[session_id] 를 통해 username을 조회하려 시도
    만약 키가 없으면 KeyError 를 잡아 일반 index 페이지를 렌더링한다.
    사실 session_id 가 None 이거나 키가 없는 경우 모두 KeyError -> 동일하게 처리
로그인된 경우에는 render_template('index.html', text=...)로 text 변수를 넘긴다.
text 내용은 username 이 admin 이면 FLAG를 노출하는 문자열이다.
즉, index 는 session_id에 해당하는 username만 확인하고, username이 'admin'이면 FLAG를 템플릿에 넣어 출력한다.
"""
@app.route('/')
def index():
    session_id = request.cookies.get('sessionid', None)
    try:
        # get username from session_storage
        username = session_storage[session_id]
    except KeyError:
        return render_template('index.html')

    return render_template('index.html', text=f'Hello {username}, {"flag is " + FLAG if username == "admin" else "you are not admin"}')

"""
GET 요청: 로그인 폼(login.html)을 렌더링
POST 요청: 폼에서 username, password 를 읽음.
try: pw = users[username] except: - 해당 사용자 존재 여부 확인.
비밀번호가 맞으면:
    os.urandom(32).hex() 로 세션ID를 생성하고, session_storage[session_id] = username 으로 세션 저장.
    response에 sessionid 쿠키를 설정하고 / 로 리다이렉트.
비밀번호가 틀리면 자바스크립트 alert 후 이전 페이지로 돌아가게 됨.
"""
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            # you cannot know admin's pw
            pw = users[username]
        except:
            return '<script>alert("not found user");history.go(-1);</script>'
        if pw == password:
            resp = make_response(redirect(url_for('index')) )
            session_id = os.urandom(32).hex()
            session_storage[session_id] = username
            resp.set_cookie('sessionid', session_id)
            return resp
        return '<script>alert("wrong password");history.go(-1);</script>'

"""
return session_storage 로 처리되어 세션 ID(키)와 사용자명(값)이 그대로 노출된다. 관리자 세션 ID가 포함되어 있음.
공격자는 이 세션 ID를 복사해 sessionid 쿠키로 설정하면 index에서 admin으로 판정되어 FLAG를 볼 수 있다.

admin인증 검사 코드가 주석처리되어 있고, 대신 session_storage를 그대로 반환하고 있다.
Flask에서 파이썬 dict를 반환하면 Flask가 JSON 응답(application/json)으로 변환해서 반환한다. 즉 서버의 세션 저장소가 노출된다.
"""
@app.route('/admin')
def admin():
    # developer's note: review below commented code and uncomment it (TODO)

    #session_id = request.cookies.get('sessionid', None)
    #username = session_storage[session_id]
    #if username != 'admin':
    #    return render_template('index.html')

    return session_storage

"""
os 를 여기서 import한다.
서버 시작 시 하나의 랜덤 세션 ID를 만들어 session_storage[that_id] = 'admin'으로 저장 
즉 초기 관리자 세션이 자동으로 생성된다.
print(session_storage)로 현재 세션 맵을 콘솔에 출력한다..
"""
if __name__ == '__main__':
    import os
    # create admin sessionid and save it to our storage
    # and also you cannot reveal admin's sesseionid by brute forcing!!! haha
    session_storage[os.urandom(32).hex()] = 'admin'
    print(session_storage)
    app.run(host='0.0.0.0', port=8000)

```

### 취약점 분석

admin 페이지 코드를 보면 전체 세션 정보가 포함된 session_storage 는 username이 admin인 관리자만 조회할 수 있도록 의도되었다.
하지만 해당 부분은 개발자에 의해 주석처리 되었으므로 인증을 거치지 않고 session_storage를 조회할 수 있음을 알 수 있다.

``` python
@app.route('/admin')
def admin():
    # developer's note: review below commented code and uncomment it (TODO)

    #session_id = request.cookies.get('sessionid', None)
    #username = session_storage[session_id]
    #if username != 'admin':
    #    return render_template('index.html')
      
    # 인증을 수행하는 위의 코드가 주석처리되어 인증을 하지 않고도 session_storage 조회 가능

    return session_storage
```


### 익스플로잇

먼저 이용자별 세션 정보를 조회한다. 
/admin 페이지에 접속하면 세션 정보 조회와 같이 현재 접속된 모든 이용자의 Session ID와 username 을 조회 할 수 있다.
![](https://dreamhack-lecture.s3.amazonaws.com/media/464db3b97e76b5c580ac0de7e38c59569d4b1e8f76068bb6693df03099d8168d.png)

이후 쿠키의 sessionid 값을 admin의 Session ID로 생성한다. 
웹 브라우저를 통해 쿠키 변조와 같이 웹 브라우저의 개발자 도구를 사용하면 쿠키의 정보를 수정할 수 있다.![](https://dreamhack-lecture.s3.amazonaws.com/media/9665987afe6e02fb3075c23ab529fcb8598fb4fce2ceace7145d60854f541850.png)
웹 브라우저를 통해 쿠키 변조

![](https://dreamhack-lecture.s3.amazonaws.com/media/c25a84cfa248ed54dc68d9f438c5e84fb90d69a06753884749dba40106632736.png)
FLAG 획득.