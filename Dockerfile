# MyMarket — Secure Coding 중고거래 플랫폼
FROM python:3.11-slim

# 보안: 비루트 사용자로 실행
RUN useradd -m appuser
WORKDIR /app

# 의존성 먼저 설치 (레이어 캐시)
# 최신 gunicorn은 eventlet 워커를 제거했으므로 gevent + gevent-websocket 사용
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn gevent gevent-websocket

# 앱 복사
COPY . .

# 업로드/인스턴스 디렉터리 권한
RUN mkdir -p static/uploads instance && chown -R appuser:appuser /app
USER appuser

ENV PORT=8000 \
    SESSION_COOKIE_SECURE=1 \
    TRUST_PROXY=1
EXPOSE 8000

# WebSocket 지원을 위해 gevent-websocket 워커 1개로 실행
CMD ["sh", "-c", "gunicorn -k geventwebsocket.gunicorn.workers.GeventWebSocketWorker -w 1 wsgi:app --bind 0.0.0.0:${PORT}"]
