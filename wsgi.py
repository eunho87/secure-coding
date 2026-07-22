"""프로덕션 WSGI 진입점 (gunicorn + gevent-websocket 워커용).

로컬 개발: python app.py  (Werkzeug 개발 서버)
프로덕션:  gunicorn -k geventwebsocket.gunicorn.workers.GeventWebSocketWorker \\
             -w 1 wsgi:app --bind 0.0.0.0:$PORT

Flask-SocketIO(WebSocket)는 비동기 워커가 필요하다. 최신 gunicorn(23+)에서
eventlet 워커가 제거되었으므로 gevent + gevent-websocket 조합을 사용한다.
워커는 1개로 두고(-w 1), 수평 확장 시 메시지 큐(Redis)를 붙여야 한다.
"""
from app import app, init_db, socketio  # noqa: F401

# gunicorn이 import하는 시점에 테이블을 보장
init_db()
