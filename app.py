"""
Tiny Second-hand Shopping Platform (Secure Coding 과제)

v2: 실거래 수준 기능 확장
- 에스크로 안전거래 (대금 보관 → 구매확정 시 지급, 분쟁 시 관리자 중재)
- 가격 제안(네고), 거래 후기/평점, 찜하기, 알림함
- 카테고리/상품 상태/다중 이미지/조회수, 검색 필터
- TOTP 2단계 인증, 세션 버전(비밀번호 변경 시 전 세션 무효화),
  일일 거래 한도, IP 로그인 rate limit, 관리자 기본 비밀번호 강제 변경

보안 적용 사항 요약:
- 비밀번호 bcrypt 해시 저장, SECRET_KEY 환경변수/랜덤 생성
- 모든 폼 CSRF 토큰 검증 (Flask-WTF), 서버측 입력 검증
- 세션 쿠키 HttpOnly/SameSite, 30분 만료, 민감 작업 시 비밀번호 재확인
- 로그인 실패 5회 시 5분 계정 잠금 + IP 단위 rate limit
- SQL 파라미터 바인딩, LIKE 이스케이프 (SQL Injection 방어)
- Socket.IO 인증 + 서버측 사용자명 + rate limit
- 보안 헤더 (CSP nonce, X-Frame-Options, HSTS 등)
- 파일 업로드 매직바이트 검증, 랜덤 파일명, 용량 제한
- 커스텀 에러 페이지, 감사 로그, 원자적 잔액 처리
"""
import base64
import functools
import hashlib
import hmac
import logging
import os
import re
import secrets
import sqlite3
import struct
import time
import uuid
from datetime import datetime, timedelta

import bcrypt
from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, send_from_directory, session, url_for)
from flask_socketio import SocketIO, emit, join_room, send
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'market.db')
UPLOAD_DIR = os.path.join(BASE_DIR, 'static', 'uploads')
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')

MAX_LOGIN_FAILURES = 5
LOCKOUT_MINUTES = 5
# IP당 5분 내 로그인 시도 허용 횟수 (테스트 시 환경변수로 조정 가능)
IP_LOGIN_LIMIT = int(os.environ.get('IP_LOGIN_LIMIT', '10'))
IP_LOGIN_WINDOW = 300
PRODUCT_BLOCK_THRESHOLD = 3   # 서로 다른 유저 신고 3회 이상 → 상품 차단
USER_DORMANT_THRESHOLD = 5    # 서로 다른 유저 신고 5회 이상 → 휴면 계정
MAX_PRICE = 100_000_000
MAX_CHARGE = 1_000_000        # 1회 최대 충전 금액
# 결제(충전) 게이트웨이: 'mock'(기본, 가상 PG) 또는 'toss'(토스페이먼츠 테스트/라이브)
PAYMENT_PROVIDER = os.environ.get('PAYMENT_PROVIDER', 'mock')
TOSS_CLIENT_KEY = os.environ.get('TOSS_CLIENT_KEY', '')   # 공개 키 (클라이언트 노출 OK)
TOSS_SECRET_KEY = os.environ.get('TOSS_SECRET_KEY', '')   # 비밀 키 (서버 전용, 절대 노출 금지)
TOSS_CONFIRM_API = 'https://api.tosspayments.com/v1/payments/confirm'
DAILY_SPEND_LIMIT = 5_000_000 # 일일 송금+구매 한도
FDS_VELOCITY_COUNT = 5        # FDS: 단시간 출금 허용 횟수
FDS_VELOCITY_WINDOW = '-10 minutes'
FDS_LARGE_AMOUNT = 1_000_000  # FDS: 관리자에게 알리는 고액 거래 기준
MAX_IMAGES = 5
CHAT_RATE_LIMIT = 5           # CHAT_RATE_WINDOW초 안에 허용되는 메시지 수
CHAT_RATE_WINDOW = 10

CATEGORIES = ['디지털기기', '가전제품', '가구/인테리어', '의류/패션', '도서',
              '스포츠/레저', '게임/취미', '뷰티/미용', '생활용품', '기타']
CONDITIONS = ['새상품', '거의 새것', '사용감 있음', '고장/부품용']

ESCROW_STATUS_LABEL = {
    'held': '거래 진행 중 (대금 보관)',
    'released': '거래 완료 (판매자 지급)',
    'refunded': '취소됨 (구매자 환불)',
    'cancel_requested': '취소 요청됨 (판매자 승인 대기)',
    'disputed': '분쟁 중 (관리자 중재 대기)',
}


def load_secret_key():
    """환경변수 우선, 없으면 instance/secret_key에 랜덤 키 생성/보관."""
    env_key = os.environ.get('SECRET_KEY')
    if env_key:
        return env_key
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    key_path = os.path.join(INSTANCE_DIR, 'secret_key')
    if os.path.exists(key_path):
        with open(key_path, 'r') as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(key)
    return key


app = Flask(__name__)
app.config['SECRET_KEY'] = load_secret_key()
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# HTTPS 환경(ngrok 등)에서는 SESSION_COOKIE_SECURE=1 로 실행
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE') == '1'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 다중 업로드 총 10MB 제한
app.config['WTF_CSRF_TIME_LIMIT'] = None

# ngrok 등 HTTPS 리버스 프록시 뒤에서 실행할 때 TRUST_PROXY=1 로 설정하면
# X-Forwarded-Proto/Host를 신뢰해 원래 스킴(https)을 올바르게 인식한다.
# (신뢰할 수 있는 프록시가 앞단에 있을 때만 켤 것 — 임의로 켜면 헤더 위조 위험)
if os.environ.get('TRUST_PROXY') == '1':
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

csrf = CSRFProtect(app)
# 외부 노출 시 CORS_ORIGINS 로 허용 오리진을 명시(미지정 시 same-origin만 허용)
_cors = os.environ.get('CORS_ORIGINS')
socketio = SocketIO(app, cors_allowed_origins=_cors.split(',') if _cors else None)

os.makedirs(UPLOAD_DIR, exist_ok=True)

handler = logging.FileHandler(os.path.join(BASE_DIR, 'app.log'))
handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{4,20}$')

# in-memory rate limit 상태 (다중 프로세스 배포 시 Redis 등으로 교체 필요)
_chat_history = {}
_login_attempts = {}


# ---------------------------------------------------------------------------
# DB
# ---------------------------------------------------------------------------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                bio TEXT DEFAULT '',
                balance INTEGER NOT NULL DEFAULT 0 CHECK(balance >= 0),
                is_admin INTEGER NOT NULL DEFAULT 0,
                is_dormant INTEGER NOT NULL DEFAULT 0,
                failed_logins INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                totp_secret TEXT,
                session_ver INTEGER NOT NULL DEFAULT 0,
                must_change_pw INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price INTEGER NOT NULL,
                category TEXT NOT NULL DEFAULT '기타',
                condition TEXT NOT NULL DEFAULT '사용감 있음',
                view_count INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'selling'
                    CHECK(status IN ('selling', 'reserved', 'sold')),
                is_blocked INTEGER NOT NULL DEFAULT 0,
                seller_id TEXT NOT NULL REFERENCES user(id),
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product_image (
                id TEXT PRIMARY KEY,
                product_id TEXT NOT NULL REFERENCES product(id) ON DELETE CASCADE,
                filename TEXT NOT NULL,
                sort INTEGER NOT NULL DEFAULT 0
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS favorite (
                user_id TEXT NOT NULL REFERENCES user(id),
                product_id TEXT NOT NULL REFERENCES product(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (user_id, product_id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS offer (
                id TEXT PRIMARY KEY,
                product_id TEXT NOT NULL REFERENCES product(id) ON DELETE CASCADE,
                buyer_id TEXT NOT NULL REFERENCES user(id),
                amount INTEGER NOT NULL CHECK(amount > 0),
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending', 'accepted', 'rejected')),
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS escrow (
                id TEXT PRIMARY KEY,
                product_id TEXT NOT NULL REFERENCES product(id),
                buyer_id TEXT NOT NULL REFERENCES user(id),
                seller_id TEXT NOT NULL REFERENCES user(id),
                amount INTEGER NOT NULL CHECK(amount > 0),
                status TEXT NOT NULL DEFAULT 'held'
                    CHECK(status IN ('held', 'released', 'refunded',
                                     'cancel_requested', 'disputed')),
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS review (
                id TEXT PRIMARY KEY,
                escrow_id TEXT NOT NULL REFERENCES escrow(id),
                reviewer_id TEXT NOT NULL REFERENCES user(id),
                target_id TEXT NOT NULL REFERENCES user(id),
                rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
                comment TEXT DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(escrow_id, reviewer_id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS notification (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES user(id),
                content TEXT NOT NULL,
                link TEXT DEFAULT '',
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL REFERENCES user(id),
                target_type TEXT NOT NULL CHECK(target_type IN ('user', 'product')),
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(reporter_id, target_type, target_id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS message (
                id TEXT PRIMARY KEY,
                room TEXT NOT NULL,
                sender_id TEXT NOT NULL REFERENCES user(id),
                content TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transfer (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL REFERENCES user(id),
                receiver_id TEXT NOT NULL REFERENCES user(id),
                amount INTEGER NOT NULL CHECK(amount > 0),
                memo TEXT DEFAULT '',
                kind TEXT NOT NULL DEFAULT 'transfer',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payment (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES user(id),
                amount INTEGER NOT NULL CHECK(amount > 0),
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending', 'paid', 'failed', 'canceled')),
                provider TEXT NOT NULL DEFAULT 'mock',
                provider_key TEXT DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ledger (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES user(id),
                delta INTEGER NOT NULL,
                balance_after INTEGER NOT NULL,
                ref_type TEXT NOT NULL,
                ref_id TEXT DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                action TEXT NOT NULL,
                detail TEXT DEFAULT '',
                ip TEXT DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        db.commit()

        # 관리자 계정이 없으면 생성 (비밀번호는 환경변수로 지정 가능)
        cursor.execute("SELECT id FROM user WHERE is_admin = 1")
        if cursor.fetchone() is None:
            admin_pw = os.environ.get('ADMIN_PASSWORD')
            # 기본 비밀번호 사용 시 최초 로그인에서 변경을 강제
            must_change = 0 if admin_pw else 1
            cursor.execute(
                "INSERT INTO user (id, username, password_hash, is_admin, "
                "must_change_pw) VALUES (?, ?, ?, 1, ?)",
                (str(uuid.uuid4()), 'admin',
                 hash_password(admin_pw or 'Admin123!'), must_change))
            db.commit()


# ---------------------------------------------------------------------------
# 헬퍼: 인증/비밀번호/TOTP
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except ValueError:
        return False


def valid_password(password: str) -> bool:
    """8~72자, 영문과 숫자를 반드시 포함."""
    if not isinstance(password, str) or not (8 <= len(password) <= 72):
        return False
    return bool(re.search(r'[A-Za-z]', password)) and bool(re.search(r'\d', password))


def totp_code(secret_b32: str, offset: int = 0, step: int = 30, digits: int = 6) -> str:
    """RFC 6238 TOTP (SHA-1, 30초, 6자리)."""
    key = base64.b32decode(secret_b32)
    counter = int(time.time() // step) + offset
    msg = struct.pack('>Q', counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    code = (struct.unpack('>I', digest[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def verify_totp(secret_b32: str, code: str) -> bool:
    if not isinstance(code, str) or not re.match(r'^\d{6}$', code):
        return False
    # 시계 오차 허용 (±1 스텝), 타이밍 공격 방지 비교
    return any(hmac.compare_digest(totp_code(secret_b32, o), code)
               for o in (-1, 0, 1))


def ip_rate_limited() -> bool:
    """IP 단위 로그인 시도 제한 (brute-force 완화)."""
    ip = request.remote_addr or 'unknown'
    now = time.time()
    attempts = [t for t in _login_attempts.get(ip, []) if now - t < IP_LOGIN_WINDOW]
    if len(attempts) >= IP_LOGIN_LIMIT:
        _login_attempts[ip] = attempts
        return True
    attempts.append(now)
    _login_attempts[ip] = attempts
    return False


# ---------------------------------------------------------------------------
# 헬퍼: 공용
# ---------------------------------------------------------------------------
def log_action(action, detail='', user_id=None):
    try:
        db = get_db()
        db.execute(
            "INSERT INTO audit_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)",
            (user_id or session.get('user_id'), action, detail[:500],
             request.remote_addr if request else ''))
        db.commit()
    except Exception:
        app.logger.exception('audit log failed')


def notify(user_id, content, link=''):
    db = get_db()
    db.execute(
        "INSERT INTO notification (id, user_id, content, link) VALUES (?, ?, ?, ?)",
        (str(uuid.uuid4()), user_id, content[:200], link[:200]))
    db.commit()


def get_user(user_id):
    cur = get_db().execute("SELECT * FROM user WHERE id = ?", (user_id,))
    return cur.fetchone()


def get_user_by_name(username):
    cur = get_db().execute("SELECT * FROM user WHERE username = ?", (username,))
    return cur.fetchone()


def get_product(product_id):
    cur = get_db().execute("SELECT * FROM product WHERE id = ?", (product_id,))
    return cur.fetchone()


def product_images(product_id):
    cur = get_db().execute(
        "SELECT filename FROM product_image WHERE product_id = ? ORDER BY sort",
        (product_id,))
    return [r['filename'] for r in cur.fetchall()]


def user_rating(user_id):
    cur = get_db().execute(
        "SELECT AVG(rating) AS avg, COUNT(*) AS cnt FROM review WHERE target_id = ?",
        (user_id,))
    row = cur.fetchone()
    return (round(row['avg'], 1) if row['avg'] else None), row['cnt']


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for('login'))
        if not g.user['is_admin']:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def detect_image(stream):
    """업로드 파일의 매직 바이트로 실제 이미지 여부 확인."""
    header = stream.read(12)
    stream.seek(0)
    if header.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'png'
    if header.startswith(b'\xff\xd8\xff'):
        return 'jpg'
    if header[:6] in (b'GIF87a', b'GIF89a'):
        return 'gif'
    if header[:4] == b'RIFF' and header[8:12] == b'WEBP':
        return 'webp'
    return None


def save_images(files, product_id, existing_count=0):
    """다중 이미지 검증 후 저장. (저장 수, 오류 메시지) 반환."""
    saved = 0
    db = get_db()
    for file in files:
        if file is None or file.filename == '':
            continue
        if existing_count + saved >= MAX_IMAGES:
            return saved, f'사진은 최대 {MAX_IMAGES}장까지 등록할 수 있습니다.'
        ext_ok = '.' in file.filename and \
            file.filename.rsplit('.', 1)[1].lower() in ('png', 'jpg', 'jpeg', 'gif', 'webp')
        kind = detect_image(file.stream)
        if not ext_ok or kind is None:
            return saved, '이미지 파일(png/jpg/gif/webp)만 업로드할 수 있습니다.'
        filename = uuid.uuid4().hex + '.' + kind
        file.save(os.path.join(UPLOAD_DIR, filename))
        db.execute(
            "INSERT INTO product_image (id, product_id, filename, sort) "
            "VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), product_id, filename, existing_count + saved))
        saved += 1
    db.commit()
    return saved, None


def dm_room(user_a: str, user_b: str) -> str:
    return 'dm:' + ':'.join(sorted([user_a, user_b]))


def validate_price(raw, max_value=MAX_PRICE):
    try:
        price = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    if not (0 < price <= max_value):
        return None
    return price


def daily_spent(user_id) -> int:
    """오늘 사용한 금액 (송금 + 에스크로 결제)."""
    db = get_db()
    row = db.execute(
        "SELECT COALESCE(SUM(amount), 0) AS s FROM transfer "
        "WHERE sender_id = ? AND kind = 'transfer' "
        "AND date(created_at) = date('now')", (user_id,)).fetchone()
    row2 = db.execute(
        "SELECT COALESCE(SUM(amount), 0) AS s FROM escrow "
        "WHERE buyer_id = ? AND date(created_at) = date('now')",
        (user_id,)).fetchone()
    return row['s'] + row2['s']


def apply_balance(db, user_id, delta, ref_type, ref_id=''):
    """모든 잔액 변경의 단일 통로: 원자적 갱신 + 원장(ledger) 기록.

    출금(delta<0)은 잔액이 충분할 때만 UPDATE되며(단일 문 안에서 검사),
    변경 후 잔액을 원장에 함께 남겨 사후 무결성 검증이 가능하다.
    """
    if delta < 0:
        cur = db.execute(
            "UPDATE user SET balance = balance + ? WHERE id = ? AND balance >= ?",
            (delta, user_id, -delta))
        if cur.rowcount != 1:
            return False
    else:
        db.execute("UPDATE user SET balance = balance + ? WHERE id = ?",
                   (delta, user_id))
    row = db.execute("SELECT balance FROM user WHERE id = ?",
                     (user_id,)).fetchone()
    db.execute(
        "INSERT INTO ledger (id, user_id, delta, balance_after, ref_type, ref_id) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), user_id, delta, row['balance'], ref_type, ref_id))
    return True


def issue_form_token():
    """거래 폼 1회용 토큰 발급 (이중 제출 방지). 세션에 최근 10개만 유지."""
    token = secrets.token_urlsafe(16)
    tokens = session.get('form_tokens', [])
    tokens.append(token)
    session['form_tokens'] = tokens[-10:]
    return token


def consume_form_token(token):
    """토큰이 유효하면 소비(삭제) 후 True. 재사용 시 False."""
    tokens = session.get('form_tokens', [])
    if not token or token not in tokens:
        return False
    tokens.remove(token)
    session['form_tokens'] = tokens
    return True


def require_transaction_auth(redirect_target):
    """거래 공통 재인증: 비밀번호 + (2FA 사용자는) TOTP 코드 + 1회용 폼 토큰.
    실패 시 flash 후 redirect 응답을 반환, 통과 시 None."""
    if not consume_form_token(request.form.get('form_token', '')):
        flash('이미 처리되었거나 만료된 요청입니다. 다시 시도해주세요.')
        return redirect(redirect_target)
    if not check_password(request.form.get('password', ''),
                          g.user['password_hash']):
        flash('비밀번호가 올바르지 않습니다.')
        return redirect(redirect_target)
    if g.user['totp_secret'] and not verify_totp(
            g.user['totp_secret'], request.form.get('totp_code', '').strip()):
        flash('2단계 인증 코드가 올바르지 않습니다.')
        return redirect(redirect_target)
    return None


def notify_admins(content, link=''):
    for row in get_db().execute("SELECT id FROM user WHERE is_admin = 1"):
        notify(row['id'], content, link)


def fds_check(user_id, amount):
    """간단한 이상거래탐지: 단시간 반복 출금 차단, 고액 거래는 관리자 알림.
    (차단 사유 문자열, 없으면 None) 반환."""
    db = get_db()
    recent = db.execute(
        "SELECT COUNT(*) AS c FROM ledger WHERE user_id = ? AND delta < 0 "
        "AND created_at >= datetime('now', ?)",
        (user_id, FDS_VELOCITY_WINDOW)).fetchone()['c']
    if recent >= FDS_VELOCITY_COUNT:
        log_action('fds_velocity_block', f'recent={recent} amount={amount}')
        notify_admins(f'[FDS] 단시간 반복 거래 차단: user={user_id}, '
                      f'10분 내 {recent}회 출금 시도')
        return '단시간에 거래가 너무 많습니다. 잠시 후 다시 시도해주세요. (이상거래 방지)'
    if amount >= FDS_LARGE_AMOUNT:
        log_action('fds_large_amount', f'amount={amount}')
        notify_admins(f'[FDS] 고액 거래 발생: user={user_id}, {amount:,}원',
                      url_for('admin_finance'))
    return None


def check_report_thresholds(db, target_type, target_id):
    """신고 누적 시 자동 차단/휴면 처리."""
    cur = db.execute(
        "SELECT COUNT(DISTINCT reporter_id) AS c FROM report "
        "WHERE target_type = ? AND target_id = ?", (target_type, target_id))
    count = cur.fetchone()['c']
    if target_type == 'product' and count >= PRODUCT_BLOCK_THRESHOLD:
        db.execute("UPDATE product SET is_blocked = 1 WHERE id = ?", (target_id,))
        log_action('auto_block_product', f'product={target_id} reports={count}')
    elif target_type == 'user' and count >= USER_DORMANT_THRESHOLD:
        db.execute("UPDATE user SET is_dormant = 1 WHERE id = ? AND is_admin = 0",
                   (target_id,))
        log_action('auto_dormant_user', f'user={target_id} reports={count}')
    db.commit()


# ---------------------------------------------------------------------------
# 요청 전/후 처리
# ---------------------------------------------------------------------------
@app.before_request
def load_logged_in_user():
    g.csp_nonce = secrets.token_urlsafe(16)
    g.user = None
    g.unread_notifications = 0
    user_id = session.get('user_id')
    if user_id:
        user = get_user(user_id)
        # 세션 버전 불일치(비밀번호 변경 등) 시 세션 무효화
        if (user is None or user['is_dormant']
                or session.get('ver') != user['session_ver']):
            session.clear()
            if user is not None and user['is_dormant']:
                flash('휴면 계정으로 전환되어 로그아웃되었습니다. 관리자에게 문의하세요.')
        else:
            g.user = user
            cur = get_db().execute(
                "SELECT COUNT(*) AS c FROM notification "
                "WHERE user_id = ? AND is_read = 0", (user_id,))
            g.unread_notifications = cur.fetchone()['c']
            # 기본 비밀번호 사용 중인 관리자: 비밀번호 변경 강제
            if user['must_change_pw'] and request.endpoint not in (
                    'profile', 'change_password', 'logout', 'static'):
                flash('보안을 위해 초기 비밀번호를 먼저 변경해야 합니다.')
                return redirect(url_for('profile'))


@app.after_request
def set_security_headers(response):
    nonce = getattr(g, 'csp_nonce', '')
    # 토스페이먼츠 위젯 사용 시에만 해당 도메인을 CSP에 허용 (기본은 strict)
    if PAYMENT_PROVIDER == 'toss':
        script_src = f"script-src 'self' 'nonce-{nonce}' https://js.tosspayments.com"
        style_src = "style-src 'self' 'unsafe-inline'"  # 위젯이 인라인 스타일 주입
        connect_src = "connect-src 'self' ws: wss: https://api.tosspayments.com"
        frame_src = "frame-src https://*.tosspayments.com; "
    else:
        script_src = f"script-src 'self' 'nonce-{nonce}'"
        style_src = "style-src 'self'"
        connect_src = "connect-src 'self' ws: wss:"
        frame_src = "frame-src 'none'; "
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        f"{script_src}; {style_src}; "
        "img-src 'self' data:; "
        f"{connect_src}; "
        f"{frame_src}"
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['Cache-Control'] = 'no-store'
    if app.config['SESSION_COOKIE_SECURE']:
        response.headers['Strict-Transport-Security'] = \
            'max-age=31536000; includeSubDomains'
    return response


@app.context_processor
def inject_globals():
    return {
        'current_user': g.get('user'),
        'csp_nonce': g.get('csp_nonce', ''),
        'unread_notifications': g.get('unread_notifications', 0),
        'CATEGORIES': CATEGORIES,
        'CONDITIONS': CONDITIONS,
        'ESCROW_STATUS_LABEL': ESCROW_STATUS_LABEL,
        'form_token': issue_form_token,
        'PAYMENT_PROVIDER': PAYMENT_PROVIDER,
    }


# ---------------------------------------------------------------------------
# 에러 핸들러 (내부 정보 비노출)
# ---------------------------------------------------------------------------
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('error.html', code=400,
                           message='잘못된 요청입니다. (CSRF 토큰 오류)'), 400


@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403, message='접근 권한이 없습니다.'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, message='페이지를 찾을 수 없습니다.'), 404


@app.errorhandler(413)
def too_large(e):
    return render_template('error.html', code=413,
                           message='업로드 용량 제한(10MB)을 초과했습니다.'), 413


@app.errorhandler(500)
def internal_error(e):
    app.logger.exception('internal server error')
    return render_template('error.html', code=500,
                           message='서버 내부 오류가 발생했습니다.'), 500


# ---------------------------------------------------------------------------
# 기본 / 인증
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    if g.user:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        password2 = request.form.get('password2', '')

        if not USERNAME_RE.match(username):
            flash('사용자명은 영문/숫자/밑줄 4~20자여야 합니다.')
            return redirect(url_for('register'))
        if not valid_password(password):
            flash('비밀번호는 8자 이상이며 영문과 숫자를 포함해야 합니다.')
            return redirect(url_for('register'))
        if password != password2:
            flash('비밀번호 확인이 일치하지 않습니다.')
            return redirect(url_for('register'))

        db = get_db()
        cur = db.execute("SELECT id FROM user WHERE username = ?", (username,))
        if cur.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        user_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO user (id, username, password_hash) VALUES (?, ?, ?)",
            (user_id, username, hash_password(password)))
        db.commit()
        log_action('register', f'username={username}', user_id=user_id)
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')


def complete_login(user):
    """검증이 끝난 사용자에 대해 세션 발급."""
    db = get_db()
    session.clear()  # 세션 고정 공격 방지
    session['user_id'] = user['id']
    session['ver'] = user['session_ver']
    session.permanent = True
    db.execute("UPDATE user SET failed_logins = 0, locked_until = NULL "
               "WHERE id = ?", (user['id'],))
    db.commit()
    log_action('login_success', f'username={user["username"]}', user_id=user['id'])


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if ip_rate_limited():
            flash('로그인 시도가 너무 많습니다. 잠시 후 다시 시도하세요.')
            log_action('login_ip_limited')
            return redirect(url_for('login'))

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        db = get_db()
        user = get_user_by_name(username) if USERNAME_RE.match(username) else None

        # 계정 잠금 확인
        if user and user['locked_until']:
            locked_until = datetime.fromisoformat(user['locked_until'])
            if datetime.utcnow() < locked_until:
                flash('로그인 실패가 반복되어 계정이 잠겼습니다. 잠시 후 다시 시도하세요.')
                log_action('login_locked', f'username={username}')
                return redirect(url_for('login'))

        if user and check_password(password, user['password_hash']):
            if user['is_dormant']:
                flash('휴면 계정입니다. 관리자에게 문의하세요.')
                log_action('login_dormant', f'username={username}')
                return redirect(url_for('login'))
            if user['totp_secret']:
                # 2단계 인증 필요: 아직 로그인 세션을 발급하지 않음
                session.clear()
                session['pending_2fa'] = user['id']
                session['pending_2fa_tries'] = 0
                return redirect(url_for('login_2fa'))
            complete_login(user)
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))

        # 실패 처리 (유저가 존재할 때만 카운트, 응답 메시지는 동일하게 유지)
        if user:
            failures = user['failed_logins'] + 1
            locked_until = None
            if failures >= MAX_LOGIN_FAILURES:
                locked_until = (datetime.utcnow()
                                + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
                failures = 0
            db.execute("UPDATE user SET failed_logins = ?, locked_until = ? "
                       "WHERE id = ?", (failures, locked_until, user['id']))
            db.commit()
        log_action('login_failed', f'username={username}')
        flash('아이디 또는 비밀번호가 올바르지 않습니다.')
        return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    pending_id = session.get('pending_2fa')
    if not pending_id:
        return redirect(url_for('login'))
    user = get_user(pending_id)
    if user is None or not user['totp_secret']:
        session.clear()
        return redirect(url_for('login'))
    if request.method == 'POST':
        tries = session.get('pending_2fa_tries', 0) + 1
        session['pending_2fa_tries'] = tries
        if tries > 5:
            session.clear()
            flash('인증 시도 횟수를 초과했습니다. 다시 로그인하세요.')
            log_action('2fa_too_many_tries', user_id=pending_id)
            return redirect(url_for('login'))
        code = request.form.get('code', '').strip()
        if verify_totp(user['totp_secret'], code):
            complete_login(user)
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        log_action('2fa_failed', user_id=pending_id)
        flash('인증 코드가 올바르지 않습니다.')
    return render_template('login_2fa.html')


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    log_action('logout')
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))


# ---------------------------------------------------------------------------
# 대시보드 / 검색
# ---------------------------------------------------------------------------
def product_list_query(where='', params=(), order='p.created_at DESC'):
    sql = (
        "SELECT p.*, u.username AS seller_name, "
        "(SELECT filename FROM product_image i WHERE i.product_id = p.id "
        " ORDER BY sort LIMIT 1) AS thumb, "
        "(SELECT COUNT(*) FROM favorite f WHERE f.product_id = p.id) AS fav_count "
        "FROM product p JOIN user u ON u.id = p.seller_id "
        "WHERE p.is_blocked = 0 " + where + " ORDER BY " + order)
    return get_db().execute(sql, params).fetchall()


@app.route('/dashboard')
def dashboard():
    # 상품 목록은 누구나(비로그인 포함) 볼 수 있어야 한다는 요구사항에 따라 공개.
    # 단, 채팅 등 상호작용 기능은 로그인 사용자에게만 제공.
    category = request.args.get('category', '')
    if category and category not in CATEGORIES:
        abort(400)
    if category:
        products = product_list_query("AND p.category = ?", (category,))
    else:
        products = product_list_query()
    chat_history = []
    if g.user:
        cur = get_db().execute(
            "SELECT m.content, m.created_at, u.username FROM message m "
            "JOIN user u ON u.id = m.sender_id WHERE m.room = 'global' "
            "ORDER BY m.created_at DESC LIMIT 50")
        chat_history = list(reversed(cur.fetchall()))
    return render_template('dashboard.html', products=products,
                           chat_history=chat_history, active_category=category)


@app.route('/search')
def search():
    q = request.args.get('q', '').strip()
    category = request.args.get('category', '')
    min_price = request.args.get('min_price', '').strip()
    max_price = request.args.get('max_price', '').strip()
    sort = request.args.get('sort', 'recent')

    if len(q) > 100 or (category and category not in CATEGORIES):
        abort(400)
    order = {'recent': 'p.created_at DESC',
             'price_asc': 'p.price ASC',
             'price_desc': 'p.price DESC',
             'popular': 'p.view_count DESC'}.get(sort)
    if order is None:
        abort(400)

    where, params = '', []
    if q:
        escaped = q.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        where += "AND (p.title LIKE ? ESCAPE '\\' OR p.description LIKE ? ESCAPE '\\') "
        params += [f'%{escaped}%', f'%{escaped}%']
    if category:
        where += "AND p.category = ? "
        params.append(category)
    if min_price:
        v = validate_price(min_price)
        if v is None:
            abort(400)
        where += "AND p.price >= ? "
        params.append(v)
    if max_price:
        v = validate_price(max_price)
        if v is None:
            abort(400)
        where += "AND p.price <= ? "
        params.append(v)

    products = product_list_query(where, tuple(params), order) \
        if (q or category or min_price or max_price) else []
    return render_template('search.html', products=products, query=q,
                           category=category, min_price=min_price,
                           max_price=max_price, sort=sort)


# ---------------------------------------------------------------------------
# 프로필 / 2FA / 사용자 조회
# ---------------------------------------------------------------------------
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    db = get_db()
    if request.method == 'POST':
        bio = request.form.get('bio', '').strip()
        if len(bio) > 500:
            flash('소개글은 500자 이내로 작성해주세요.')
            return redirect(url_for('profile'))
        db.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, g.user['id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    rating, rating_count = user_rating(g.user['id'])
    return render_template('profile.html', user=g.user, rating=rating,
                           rating_count=rating_count)


@app.route('/profile/password', methods=['POST'])
@login_required
def change_password():
    current = request.form.get('current_password', '')
    new = request.form.get('new_password', '')
    new2 = request.form.get('new_password2', '')
    if not check_password(current, g.user['password_hash']):  # 재인증
        flash('현재 비밀번호가 올바르지 않습니다.')
        return redirect(url_for('profile'))
    if not valid_password(new):
        flash('새 비밀번호는 8자 이상이며 영문과 숫자를 포함해야 합니다.')
        return redirect(url_for('profile'))
    if new != new2:
        flash('새 비밀번호 확인이 일치하지 않습니다.')
        return redirect(url_for('profile'))
    db = get_db()
    # 세션 버전 증가 → 다른 기기의 기존 세션 전부 무효화
    new_ver = g.user['session_ver'] + 1
    db.execute(
        "UPDATE user SET password_hash = ?, session_ver = ?, must_change_pw = 0 "
        "WHERE id = ?", (hash_password(new), new_ver, g.user['id']))
    db.commit()
    session['ver'] = new_ver  # 현재 세션은 유지
    log_action('password_change')
    flash('비밀번호가 변경되었습니다. 다른 기기의 로그인은 모두 해제됩니다.')
    return redirect(url_for('profile'))


@app.route('/profile/2fa/enable', methods=['POST'])
@login_required
def twofa_enable():
    if g.user['totp_secret']:
        flash('이미 2단계 인증이 활성화되어 있습니다.')
        return redirect(url_for('profile'))
    secret = base64.b32encode(secrets.token_bytes(20)).decode('ascii')
    session['pending_totp'] = secret
    uri = (f"otpauth://totp/MyMarket:{g.user['username']}"
           f"?secret={secret}&issuer=MyMarket")
    return render_template('twofa_setup.html', secret=secret, otpauth=uri)


@app.route('/profile/2fa/confirm', methods=['POST'])
@login_required
def twofa_confirm():
    secret = session.get('pending_totp')
    if not secret:
        return redirect(url_for('profile'))
    code = request.form.get('code', '').strip()
    if not verify_totp(secret, code):
        flash('인증 코드가 올바르지 않습니다. 다시 시도하세요.')
        uri = (f"otpauth://totp/MyMarket:{g.user['username']}"
               f"?secret={secret}&issuer=MyMarket")
        return render_template('twofa_setup.html', secret=secret, otpauth=uri)
    db = get_db()
    db.execute("UPDATE user SET totp_secret = ? WHERE id = ?",
               (secret, g.user['id']))
    db.commit()
    session.pop('pending_totp', None)
    log_action('2fa_enabled')
    flash('2단계 인증이 활성화되었습니다.')
    return redirect(url_for('profile'))


@app.route('/profile/2fa/disable', methods=['POST'])
@login_required
def twofa_disable():
    if not g.user['totp_secret']:
        return redirect(url_for('profile'))
    password = request.form.get('password', '')
    code = request.form.get('code', '').strip()
    if not check_password(password, g.user['password_hash']) \
            or not verify_totp(g.user['totp_secret'], code):
        flash('비밀번호 또는 인증 코드가 올바르지 않습니다.')
        return redirect(url_for('profile'))
    db = get_db()
    db.execute("UPDATE user SET totp_secret = NULL WHERE id = ?", (g.user['id'],))
    db.commit()
    log_action('2fa_disabled')
    flash('2단계 인증이 해제되었습니다.')
    return redirect(url_for('profile'))


@app.route('/user/<username>')
def user_profile(username):  # 프로필·판매목록 공개 열람
    if not USERNAME_RE.match(username):
        abort(404)
    user = get_user_by_name(username)
    if user is None:
        abort(404)
    cur = get_db().execute(
        "SELECT p.*, (SELECT filename FROM product_image i "
        " WHERE i.product_id = p.id ORDER BY sort LIMIT 1) AS thumb "
        "FROM product p WHERE p.seller_id = ? AND p.is_blocked = 0 "
        "ORDER BY p.created_at DESC", (user['id'],))
    products = cur.fetchall()
    rating, rating_count = user_rating(user['id'])
    reviews = get_db().execute(
        "SELECT r.rating, r.comment, r.created_at, u.username AS reviewer "
        "FROM review r JOIN user u ON u.id = r.reviewer_id "
        "WHERE r.target_id = ? ORDER BY r.created_at DESC LIMIT 10",
        (user['id'],)).fetchall()
    return render_template('user_profile.html', profile_user=user,
                           products=products, rating=rating,
                           rating_count=rating_count, reviews=reviews)


# ---------------------------------------------------------------------------
# 상품
# ---------------------------------------------------------------------------
def validate_product_form(form):
    title = form.get('title', '').strip()
    description = form.get('description', '').strip()
    price = validate_price(form.get('price'))
    category = form.get('category', '')
    condition = form.get('condition', '')
    if not title or len(title) > 100:
        return None, '상품명은 1~100자여야 합니다.'
    if not description or len(description) > 2000:
        return None, '상품 설명은 1~2000자여야 합니다.'
    if price is None:
        return None, f'가격은 1 ~ {MAX_PRICE:,} 사이의 정수여야 합니다.'
    if category not in CATEGORIES:
        return None, '카테고리를 선택해주세요.'
    if condition not in CONDITIONS:
        return None, '상품 상태를 선택해주세요.'
    return {'title': title, 'description': description, 'price': price,
            'category': category, 'condition': condition}, None


@app.route('/product/new', methods=['GET', 'POST'])
@login_required
def new_product():
    if request.method == 'POST':
        data, err = validate_product_form(request.form)
        if err:
            flash(err)
            return redirect(url_for('new_product'))
        db = get_db()
        product_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO product (id, title, description, price, category, "
            "condition, seller_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (product_id, data['title'], data['description'], data['price'],
             data['category'], data['condition'], g.user['id']))
        db.commit()
        _, img_err = save_images(request.files.getlist('images'), product_id)
        if img_err:
            flash(f'상품은 등록되었지만 일부 사진이 저장되지 않았습니다: {img_err}')
        else:
            flash('상품이 등록되었습니다.')
        log_action('product_create', f'product={product_id}')
        return redirect(url_for('view_product', product_id=product_id))
    return render_template('new_product.html')


@app.route('/product/<product_id>')
def view_product(product_id):  # 상품 상세 공개 열람 (구매/제안 등은 로그인 필요)
    db = get_db()
    product = get_product(product_id)
    if not product:
        abort(404)
    is_owner = g.user is not None and product['seller_id'] == g.user['id']
    is_admin = g.user is not None and g.user['is_admin']
    if product['is_blocked'] and not (is_owner or is_admin):
        flash('차단된 상품입니다.')
        return redirect(url_for('dashboard'))
    if not is_owner:
        db.execute("UPDATE product SET view_count = view_count + 1 WHERE id = ?",
                   (product_id,))
        db.commit()
        product = get_product(product_id)
    seller = get_user(product['seller_id'])
    images = product_images(product_id)
    fav_count = db.execute(
        "SELECT COUNT(*) AS c FROM favorite WHERE product_id = ?",
        (product_id,)).fetchone()['c']

    # 로그인 사용자 전용 컨텍스트 (익명은 기본값)
    is_faved, offers, my_offer, active_escrow = False, [], None, None
    if g.user is not None:
        is_faved = db.execute(
            "SELECT 1 FROM favorite WHERE product_id = ? AND user_id = ?",
            (product_id, g.user['id'])).fetchone() is not None
        if is_owner:
            offers = db.execute(
                "SELECT o.*, u.username AS buyer_name FROM offer o "
                "JOIN user u ON u.id = o.buyer_id WHERE o.product_id = ? "
                "ORDER BY o.created_at DESC", (product_id,)).fetchall()
        else:
            my_offer = db.execute(
                "SELECT * FROM offer WHERE product_id = ? AND buyer_id = ? "
                "ORDER BY created_at DESC LIMIT 1",
                (product_id, g.user['id'])).fetchone()
            active_escrow = db.execute(
                "SELECT * FROM escrow WHERE product_id = ? "
                "AND status IN ('held', 'cancel_requested', 'disputed') "
                "AND buyer_id = ?",
                (product_id, g.user['id'])).fetchone()
    rating, rating_count = user_rating(product['seller_id'])

    return render_template('view_product.html', product=product, seller=seller,
                           is_owner=is_owner, images=images,
                           fav_count=fav_count, is_faved=is_faved,
                           rating=rating, rating_count=rating_count,
                           offers=offers, my_offer=my_offer,
                           active_escrow=active_escrow)


@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    db = get_db()
    product = get_product(product_id)
    if not product:
        abort(404)
    if product['seller_id'] != g.user['id']:  # 소유자 확인 (IDOR 방지)
        abort(403)
    if product['status'] == 'reserved':
        flash('거래 진행 중인 상품은 수정할 수 없습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    if request.method == 'POST':
        data, err = validate_product_form(request.form)
        if err:
            flash(err)
            return redirect(url_for('edit_product', product_id=product_id))
        db.execute(
            "UPDATE product SET title = ?, description = ?, price = ?, "
            "category = ?, condition = ? WHERE id = ? AND seller_id = ?",
            (data['title'], data['description'], data['price'],
             data['category'], data['condition'], product_id, g.user['id']))
        db.commit()
        existing = len(product_images(product_id))
        _, img_err = save_images(request.files.getlist('images'),
                                 product_id, existing)
        if img_err:
            flash(img_err)
        log_action('product_edit', f'product={product_id}')
        flash('상품이 수정되었습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    return render_template('edit_product.html', product=product,
                           images=product_images(product_id))


@app.route('/product/<product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    db = get_db()
    product = get_product(product_id)
    if not product:
        abort(404)
    if product['seller_id'] != g.user['id'] and not g.user['is_admin']:
        abort(403)
    if product['status'] == 'reserved':
        flash('거래 진행 중인 상품은 삭제할 수 없습니다. 거래를 먼저 완료/취소하세요.')
        return redirect(url_for('view_product', product_id=product_id))
    db.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    log_action('product_delete', f'product={product_id}')
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('my_products'))


@app.route('/my/products')
@login_required
def my_products():
    cur = get_db().execute(
        "SELECT p.*, (SELECT filename FROM product_image i "
        " WHERE i.product_id = p.id ORDER BY sort LIMIT 1) AS thumb "
        "FROM product p WHERE p.seller_id = ? ORDER BY p.created_at DESC",
        (g.user['id'],))
    return render_template('my_products.html', products=cur.fetchall())


@app.route('/my/favorites')
@login_required
def my_favorites():
    cur = get_db().execute(
        "SELECT p.*, u.username AS seller_name, "
        "(SELECT filename FROM product_image i WHERE i.product_id = p.id "
        " ORDER BY sort LIMIT 1) AS thumb, "
        "(SELECT COUNT(*) FROM favorite f2 WHERE f2.product_id = p.id) AS fav_count "
        "FROM favorite f JOIN product p ON p.id = f.product_id "
        "JOIN user u ON u.id = p.seller_id "
        "WHERE f.user_id = ? AND p.is_blocked = 0 ORDER BY f.created_at DESC",
        (g.user['id'],))
    return render_template('my_favorites.html', products=cur.fetchall())


@app.route('/product/<product_id>/favorite', methods=['POST'])
@login_required
def toggle_favorite(product_id):
    db = get_db()
    product = get_product(product_id)
    if not product or product['is_blocked']:
        abort(404)
    cur = db.execute(
        "DELETE FROM favorite WHERE user_id = ? AND product_id = ?",
        (g.user['id'], product_id))
    if cur.rowcount == 0:
        db.execute(
            "INSERT INTO favorite (user_id, product_id) VALUES (?, ?)",
            (g.user['id'], product_id))
        flash('찜 목록에 추가했습니다.')
    else:
        flash('찜을 해제했습니다.')
    db.commit()
    return redirect(url_for('view_product', product_id=product_id))


@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    if not re.match(r'^[0-9a-f]{32}\.(png|jpg|gif|webp)$', filename):
        abort(404)
    return send_from_directory(UPLOAD_DIR, filename)


# ---------------------------------------------------------------------------
# 가격 제안 (네고)
# ---------------------------------------------------------------------------
@app.route('/product/<product_id>/offer', methods=['POST'])
@login_required
def make_offer(product_id):
    db = get_db()
    product = get_product(product_id)
    if not product or product['is_blocked']:
        abort(404)
    if product['seller_id'] == g.user['id']:
        flash('자신의 상품에는 가격 제안을 할 수 없습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    if product['status'] != 'selling':
        flash('판매 중인 상품에만 가격 제안이 가능합니다.')
        return redirect(url_for('view_product', product_id=product_id))
    amount = validate_price(request.form.get('amount'))
    if amount is None or amount >= product['price']:
        flash('가격 제안은 1원 이상, 판매가 미만이어야 합니다.')
        return redirect(url_for('view_product', product_id=product_id))
    pending = db.execute(
        "SELECT 1 FROM offer WHERE product_id = ? AND buyer_id = ? "
        "AND status = 'pending'", (product_id, g.user['id'])).fetchone()
    if pending:
        flash('이미 대기 중인 가격 제안이 있습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    db.execute(
        "INSERT INTO offer (id, product_id, buyer_id, amount) VALUES (?, ?, ?, ?)",
        (str(uuid.uuid4()), product_id, g.user['id'], amount))
    db.commit()
    notify(product['seller_id'],
           f"'{product['title']}'에 {amount:,}원 가격 제안이 도착했습니다.",
           url_for('view_product', product_id=product_id))
    log_action('offer_create', f'product={product_id} amount={amount}')
    flash('가격 제안을 보냈습니다.')
    return redirect(url_for('view_product', product_id=product_id))


@app.route('/offer/<offer_id>/respond', methods=['POST'])
@login_required
def respond_offer(offer_id):
    db = get_db()
    offer = db.execute("SELECT * FROM offer WHERE id = ?", (offer_id,)).fetchone()
    if not offer:
        abort(404)
    product = get_product(offer['product_id'])
    if not product or product['seller_id'] != g.user['id']:  # 판매자만 응답 가능
        abort(403)
    if offer['status'] != 'pending':
        flash('이미 처리된 제안입니다.')
        return redirect(url_for('view_product', product_id=product['id']))
    action = request.form.get('action', '')
    if action not in ('accept', 'reject'):
        abort(400)
    new_status = 'accepted' if action == 'accept' else 'rejected'
    db.execute("UPDATE offer SET status = ? WHERE id = ?", (new_status, offer_id))
    db.commit()
    if action == 'accept':
        notify(offer['buyer_id'],
               f"'{product['title']}' 가격 제안({offer['amount']:,}원)이 수락되었습니다. "
               "상품 페이지에서 구매를 진행하세요.",
               url_for('view_product', product_id=product['id']))
    else:
        notify(offer['buyer_id'],
               f"'{product['title']}' 가격 제안이 거절되었습니다.",
               url_for('view_product', product_id=product['id']))
    log_action('offer_' + new_status, f'offer={offer_id}')
    flash('제안을 처리했습니다.')
    return redirect(url_for('view_product', product_id=product['id']))


# ---------------------------------------------------------------------------
# 지갑 / 송금
# ---------------------------------------------------------------------------
def execute_transfer(db, sender_id, receiver_id, amount, memo='', kind='transfer'):
    """원자적 송금: 잔액 조건을 UPDATE 문 안에서 검사해 race condition 방지.
    양쪽 잔액 변동을 원장(ledger)에 기록한다."""
    transfer_id = str(uuid.uuid4())
    if not apply_balance(db, sender_id, -amount, kind + '_out', transfer_id):
        db.rollback()
        return False
    apply_balance(db, receiver_id, amount, kind + '_in', transfer_id)
    db.execute(
        "INSERT INTO transfer (id, sender_id, receiver_id, amount, memo, kind) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (transfer_id, sender_id, receiver_id, amount, memo[:100], kind))
    db.commit()
    return True


@app.route('/wallet')
@login_required
def wallet():
    db = get_db()
    transfers = db.execute(
        "SELECT t.*, s.username AS sender_name, r.username AS receiver_name "
        "FROM transfer t JOIN user s ON s.id = t.sender_id "
        "JOIN user r ON r.id = t.receiver_id "
        "WHERE t.sender_id = ? OR t.receiver_id = ? "
        "ORDER BY t.created_at DESC LIMIT 50",
        (g.user['id'], g.user['id'])).fetchall()
    escrows = db.execute(
        "SELECT e.*, p.title AS product_title, "
        "b.username AS buyer_name, s.username AS seller_name, "
        "(SELECT 1 FROM review r WHERE r.escrow_id = e.id "
        " AND r.reviewer_id = ?) AS reviewed "
        "FROM escrow e JOIN product p ON p.id = e.product_id "
        "JOIN user b ON b.id = e.buyer_id JOIN user s ON s.id = e.seller_id "
        "WHERE e.buyer_id = ? OR e.seller_id = ? "
        "ORDER BY e.created_at DESC LIMIT 50",
        (g.user['id'], g.user['id'], g.user['id'])).fetchall()
    ledger = db.execute(
        "SELECT * FROM ledger WHERE user_id = ? "
        "ORDER BY created_at DESC, rowid DESC LIMIT 50",
        (g.user['id'],)).fetchall()
    payments = db.execute(
        "SELECT * FROM payment WHERE user_id = ? "
        "ORDER BY created_at DESC LIMIT 20", (g.user['id'],)).fetchall()
    return render_template('wallet.html', transfers=transfers, escrows=escrows,
                           ledger=ledger, payments=payments,
                           daily_spent=daily_spent(g.user['id']),
                           daily_limit=DAILY_SPEND_LIMIT)


# ---------------------------------------------------------------------------
# 결제(충전) — PG 연동. mock(가상 PG) 또는 toss(토스페이먼츠 테스트/라이브)
# 흐름: /wallet/topup (주문 생성) → /payment/checkout (PG 결제창)
#       → 승인 콜백에서 금액 검증 + 멱등 크레딧
# ---------------------------------------------------------------------------
def finalize_topup(db, order_id, provider_key=''):
    """결제 승인 완료 처리 (멱등). pending→paid 조건부 UPDATE로 이중 충전 방지.
    성공 시 payment row 반환, 이미 처리된 경우 None."""
    cur = db.execute(
        "UPDATE payment SET status = 'paid', provider_key = ?, "
        "updated_at = datetime('now') WHERE id = ? AND status = 'pending'",
        (provider_key, order_id))
    if cur.rowcount != 1:
        db.rollback()
        return None
    pay = db.execute("SELECT * FROM payment WHERE id = ?", (order_id,)).fetchone()
    apply_balance(db, pay['user_id'], pay['amount'], 'topup', order_id)
    db.commit()
    return pay


def get_own_payment_or_404(order_id):
    pay = get_db().execute("SELECT * FROM payment WHERE id = ?",
                           (order_id,)).fetchone()
    if pay is None or pay['user_id'] != g.user['id']:  # IDOR 방지
        abort(404)
    return pay


@app.route('/wallet/topup', methods=['POST'])
@login_required
def topup():
    if not consume_form_token(request.form.get('form_token', '')):
        flash('이미 처리되었거나 만료된 요청입니다. 다시 시도해주세요.')
        return redirect(url_for('wallet'))
    amount = validate_price(request.form.get('amount'), MAX_CHARGE)
    if amount is None:
        flash(f'충전 금액은 1 ~ {MAX_CHARGE:,} 사이의 정수여야 합니다.')
        return redirect(url_for('wallet'))
    order_id = str(uuid.uuid4())
    db = get_db()
    db.execute(
        "INSERT INTO payment (id, user_id, amount, provider) VALUES (?, ?, ?, ?)",
        (order_id, g.user['id'], amount, PAYMENT_PROVIDER))
    db.commit()
    log_action('payment_create',
               f'order={order_id} amount={amount} provider={PAYMENT_PROVIDER}')
    return redirect(url_for('payment_checkout', order_id=order_id))


@app.route('/payment/checkout/<order_id>')
@login_required
def payment_checkout(order_id):
    pay = get_own_payment_or_404(order_id)
    if pay['status'] != 'pending':
        flash('이미 처리된 결제입니다.')
        return redirect(url_for('wallet'))
    return render_template('payment_checkout.html', pay=pay,
                           provider=PAYMENT_PROVIDER,
                           toss_client_key=TOSS_CLIENT_KEY)


@app.route('/payment/mock/confirm', methods=['POST'])
@login_required
def payment_mock_confirm():
    """가상 PG 승인/취소 (mock 모드 전용)."""
    if not consume_form_token(request.form.get('form_token', '')):
        flash('이미 처리되었거나 만료된 요청입니다.')
        return redirect(url_for('wallet'))
    pay = get_own_payment_or_404(request.form.get('order_id', ''))
    if pay['provider'] != 'mock':
        abort(400)
    db = get_db()
    if request.form.get('action') == 'approve':
        done = finalize_topup(db, pay['id'], provider_key='MOCK-' + pay['id'][:8])
        if done:
            log_action('payment_paid', f'order={pay["id"]} amount={pay["amount"]}')
            flash(f'{pay["amount"]:,}원이 충전되었습니다.')
        else:
            flash('이미 처리된 결제입니다.')
    else:
        db.execute("UPDATE payment SET status = 'canceled', "
                   "updated_at = datetime('now') WHERE id = ? AND status = 'pending'",
                   (pay['id'],))
        db.commit()
        flash('결제를 취소했습니다.')
    return redirect(url_for('wallet'))


@app.route('/payment/toss/success')
@login_required
def payment_toss_success():
    """토스페이먼츠 결제창 성공 리다이렉트 → 서버-서버 승인 후 크레딧."""
    order_id = request.args.get('orderId', '')
    payment_key = request.args.get('paymentKey', '')
    try:
        amount = int(request.args.get('amount', ''))
    except ValueError:
        abort(400)
    pay = get_own_payment_or_404(order_id)
    # 금액 위·변조 방지: 클라이언트가 보낸 금액이 서버 주문 금액과 정확히 일치해야 함
    if pay['provider'] != 'toss' or pay['status'] != 'pending' \
            or pay['amount'] != amount:
        flash('결제 정보가 일치하지 않습니다.')
        return redirect(url_for('wallet'))

    # 서버-서버 승인 (시크릿 키는 절대 클라이언트에 노출하지 않음)
    import base64 as _b64
    import json as _json
    from urllib import error as _urlerr
    from urllib import request as _urlreq
    auth = _b64.b64encode((TOSS_SECRET_KEY + ':').encode()).decode()
    body = _json.dumps({'paymentKey': payment_key, 'orderId': order_id,
                        'amount': amount}).encode()
    req = _urlreq.Request(TOSS_CONFIRM_API, data=body, headers={
        'Authorization': 'Basic ' + auth, 'Content-Type': 'application/json'})
    ok = False
    try:
        with _urlreq.urlopen(req, timeout=10) as resp:
            ok = resp.status == 200
    except _urlerr.HTTPError as e:
        app.logger.warning('toss confirm failed: %s', e.code)
    except Exception:
        app.logger.exception('toss confirm error')

    db = get_db()
    if ok and finalize_topup(db, order_id, provider_key=payment_key):
        log_action('payment_paid', f'order={order_id} amount={amount} provider=toss')
        flash(f'{amount:,}원이 충전되었습니다.')
    else:
        db.execute("UPDATE payment SET status = 'failed', "
                   "updated_at = datetime('now') WHERE id = ? AND status = 'pending'",
                   (order_id,))
        db.commit()
        flash('결제 승인에 실패했습니다.')
    return redirect(url_for('wallet'))


@app.route('/payment/toss/fail')
@login_required
def payment_toss_fail():
    order_id = request.args.get('orderId', '')
    if order_id:
        db = get_db()
        db.execute("UPDATE payment SET status = 'failed', "
                   "updated_at = datetime('now') "
                   "WHERE id = ? AND user_id = ? AND status = 'pending'",
                   (order_id, g.user['id']))
        db.commit()
    flash('결제가 취소되었거나 실패했습니다.')
    return redirect(url_for('wallet'))


@app.route('/wallet/transfer', methods=['POST'])
@login_required
def transfer():
    receiver_name = request.form.get('receiver', '').strip()
    amount = validate_price(request.form.get('amount'))
    memo = request.form.get('memo', '').strip()

    # 재인증(비밀번호 + 2FA) 및 이중 제출 방지
    denied = require_transaction_auth(url_for('wallet'))
    if denied:
        return denied
    if amount is None:
        flash('송금 금액이 올바르지 않습니다.')
        return redirect(url_for('wallet'))
    if daily_spent(g.user['id']) + amount > DAILY_SPEND_LIMIT:
        flash(f'일일 거래 한도({DAILY_SPEND_LIMIT:,}원)를 초과합니다.')
        return redirect(url_for('wallet'))
    fds_reason = fds_check(g.user['id'], amount)
    if fds_reason:
        flash(fds_reason)
        return redirect(url_for('wallet'))
    if len(memo) > 100:
        flash('메모는 100자 이내여야 합니다.')
        return redirect(url_for('wallet'))
    receiver = get_user_by_name(receiver_name) if USERNAME_RE.match(receiver_name) else None
    if receiver is None or receiver['is_dormant']:
        flash('받는 사용자를 찾을 수 없습니다.')
        return redirect(url_for('wallet'))
    if receiver['id'] == g.user['id']:
        flash('자기 자신에게는 송금할 수 없습니다.')
        return redirect(url_for('wallet'))

    db = get_db()
    if not execute_transfer(db, g.user['id'], receiver['id'], amount, memo):
        flash('잔액이 부족합니다.')
        return redirect(url_for('wallet'))
    notify(receiver['id'],
           f"{g.user['username']}님이 {amount:,}원을 송금했습니다.",
           url_for('wallet'))
    log_action('wallet_transfer', f'to={receiver["username"]} amount={amount}')
    flash(f'{receiver["username"]}님에게 {amount:,}원을 송금했습니다.')
    return redirect(url_for('wallet'))


# ---------------------------------------------------------------------------
# 에스크로 안전거래
# ---------------------------------------------------------------------------
@app.route('/product/<product_id>/buy', methods=['POST'])
@login_required
def buy_product(product_id):
    # 재인증(비밀번호 + 2FA) 및 이중 제출 방지
    denied = require_transaction_auth(url_for('view_product',
                                              product_id=product_id))
    if denied:
        return denied
    db = get_db()
    product = get_product(product_id)
    if not product or product['is_blocked']:
        abort(404)
    if product['status'] != 'selling':
        flash('현재 구매할 수 없는 상품입니다. (예약/판매완료)')
        return redirect(url_for('view_product', product_id=product_id))
    if product['seller_id'] == g.user['id']:
        flash('자신의 상품은 구매할 수 없습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    seller = get_user(product['seller_id'])
    if seller is None or seller['is_dormant']:
        flash('판매자가 거래할 수 없는 상태입니다.')
        return redirect(url_for('view_product', product_id=product_id))

    # 수락된 가격 제안이 있으면 그 금액으로 구매
    accepted = db.execute(
        "SELECT amount FROM offer WHERE product_id = ? AND buyer_id = ? "
        "AND status = 'accepted' ORDER BY created_at DESC LIMIT 1",
        (product_id, g.user['id'])).fetchone()
    price = accepted['amount'] if accepted else product['price']

    if daily_spent(g.user['id']) + price > DAILY_SPEND_LIMIT:
        flash(f'일일 거래 한도({DAILY_SPEND_LIMIT:,}원)를 초과합니다.')
        return redirect(url_for('view_product', product_id=product_id))
    fds_reason = fds_check(g.user['id'], price)
    if fds_reason:
        flash(fds_reason)
        return redirect(url_for('view_product', product_id=product_id))

    # 구매자 잔액 차감 (원자적, 원장 기록) 후 에스크로에 보관
    # — 판매자에게 바로 지급하지 않음
    escrow_id = str(uuid.uuid4())
    if not apply_balance(db, g.user['id'], -price, 'escrow_hold', escrow_id):
        db.rollback()
        flash('잔액이 부족합니다. 지갑에서 충전해주세요.')
        return redirect(url_for('view_product', product_id=product_id))
    db.execute(
        "INSERT INTO escrow (id, product_id, buyer_id, seller_id, amount) "
        "VALUES (?, ?, ?, ?, ?)",
        (escrow_id, product_id, g.user['id'], seller['id'], price))
    db.execute("UPDATE product SET status = 'reserved' WHERE id = ?",
               (product_id,))
    db.commit()
    notify(seller['id'],
           f"'{product['title']}'에 안전거래 결제({price:,}원)가 접수되었습니다. "
           "구매자가 수령 확인하면 대금이 지급됩니다.",
           url_for('view_product', product_id=product_id))
    log_action('escrow_create', f'escrow={escrow_id} price={price}')
    flash('안전거래가 시작되었습니다. 대금은 플랫폼이 보관하며, '
          '상품 수령 후 [구매 확정]을 눌러주세요.')
    return redirect(url_for('view_product', product_id=product_id))


def get_escrow_or_404(escrow_id):
    row = get_db().execute("SELECT * FROM escrow WHERE id = ?",
                           (escrow_id,)).fetchone()
    if row is None:
        abort(404)
    return row


def settle_escrow(db, escrow, outcome, allowed=('held', 'cancel_requested')):
    """에스크로 정산. outcome: 'release'(판매자 지급) 또는 'refund'(구매자 환불).

    상태 전이를 조건부 UPDATE 한 문장으로 수행해, 동시 요청이 들어와도
    단 한 번만 정산된다 (이중 지급/이중 환불 race condition 방지).
    성공 시 True, 이미 정산된 경우 False.
    """
    new_status = 'released' if outcome == 'release' else 'refunded'
    placeholders = ','.join('?' * len(allowed))
    cur = db.execute(
        f"UPDATE escrow SET status = ?, updated_at = datetime('now') "
        f"WHERE id = ? AND status IN ({placeholders})",
        (new_status, escrow['id'], *allowed))
    if cur.rowcount != 1:
        db.rollback()
        return False
    if outcome == 'release':
        apply_balance(db, escrow['seller_id'], escrow['amount'],
                      'escrow_release', escrow['id'])
        db.execute("UPDATE product SET status = 'sold' WHERE id = ?",
                   (escrow['product_id'],))
        db.execute(
            "INSERT INTO transfer (id, sender_id, receiver_id, amount, memo, kind) "
            "VALUES (?, ?, ?, ?, ?, 'purchase')",
            (str(uuid.uuid4()), escrow['buyer_id'], escrow['seller_id'],
             escrow['amount'], '안전거래 대금 지급'))
    else:
        apply_balance(db, escrow['buyer_id'], escrow['amount'],
                      'escrow_refund', escrow['id'])
        db.execute("UPDATE product SET status = 'selling' WHERE id = ?",
                   (escrow['product_id'],))
    db.commit()
    return True


@app.route('/escrow/<escrow_id>/confirm', methods=['POST'])
@login_required
def escrow_confirm(escrow_id):
    """구매자의 수령 확인 → 판매자에게 대금 지급."""
    db = get_db()
    escrow = get_escrow_or_404(escrow_id)
    if escrow['buyer_id'] != g.user['id']:
        abort(403)
    if not settle_escrow(db, escrow, 'release'):
        flash('처리할 수 없는 거래 상태입니다.')
        return redirect(url_for('wallet'))
    notify(escrow['seller_id'],
           f"구매자가 수령을 확인하여 {escrow['amount']:,}원이 지급되었습니다.",
           url_for('wallet'))
    log_action('escrow_release', f'escrow={escrow_id}')
    flash('구매가 확정되었습니다. 판매자에게 대금이 지급되었습니다. '
          '지갑에서 거래 후기를 남겨보세요!')
    return redirect(url_for('wallet'))


@app.route('/escrow/<escrow_id>/cancel', methods=['POST'])
@login_required
def escrow_cancel(escrow_id):
    """구매자의 취소 요청 → 판매자 승인 시 환불."""
    db = get_db()
    escrow = get_escrow_or_404(escrow_id)
    if escrow['buyer_id'] != g.user['id']:
        abort(403)
    if escrow['status'] != 'held':
        flash('처리할 수 없는 거래 상태입니다.')
        return redirect(url_for('wallet'))
    db.execute("UPDATE escrow SET status = 'cancel_requested', "
               "updated_at = datetime('now') WHERE id = ?", (escrow_id,))
    db.commit()
    notify(escrow['seller_id'],
           '구매자가 안전거래 취소를 요청했습니다. 지갑에서 승인해주세요.',
           url_for('wallet'))
    log_action('escrow_cancel_request', f'escrow={escrow_id}')
    flash('취소 요청을 보냈습니다. 판매자가 승인하면 환불됩니다.')
    return redirect(url_for('wallet'))


@app.route('/escrow/<escrow_id>/approve_cancel', methods=['POST'])
@login_required
def escrow_approve_cancel(escrow_id):
    """판매자의 취소 승인 → 구매자 환불."""
    db = get_db()
    escrow = get_escrow_or_404(escrow_id)
    if escrow['seller_id'] != g.user['id']:
        abort(403)
    if not settle_escrow(db, escrow, 'refund', allowed=('cancel_requested',)):
        flash('처리할 수 없는 거래 상태입니다.')
        return redirect(url_for('wallet'))
    notify(escrow['buyer_id'],
           f"판매자가 취소를 승인하여 {escrow['amount']:,}원이 환불되었습니다.",
           url_for('wallet'))
    log_action('escrow_refund', f'escrow={escrow_id}')
    flash('취소를 승인했습니다. 구매자에게 환불되었습니다.')
    return redirect(url_for('wallet'))


@app.route('/escrow/<escrow_id>/dispute', methods=['POST'])
@login_required
def escrow_dispute(escrow_id):
    """분쟁 신청 → 관리자 중재로 전환."""
    db = get_db()
    escrow = get_escrow_or_404(escrow_id)
    if g.user['id'] not in (escrow['buyer_id'], escrow['seller_id']):
        abort(403)
    if escrow['status'] not in ('held', 'cancel_requested'):
        flash('처리할 수 없는 거래 상태입니다.')
        return redirect(url_for('wallet'))
    db.execute("UPDATE escrow SET status = 'disputed', "
               "updated_at = datetime('now') WHERE id = ?", (escrow_id,))
    db.commit()
    other = escrow['seller_id'] if g.user['id'] == escrow['buyer_id'] \
        else escrow['buyer_id']
    notify(other, '안전거래에 분쟁이 접수되었습니다. 관리자가 중재합니다.',
           url_for('wallet'))
    log_action('escrow_dispute', f'escrow={escrow_id}')
    flash('분쟁이 접수되었습니다. 관리자가 확인 후 처리합니다.')
    return redirect(url_for('wallet'))


# ---------------------------------------------------------------------------
# 거래 후기
# ---------------------------------------------------------------------------
@app.route('/escrow/<escrow_id>/review', methods=['POST'])
@login_required
def review_escrow(escrow_id):
    db = get_db()
    escrow = get_escrow_or_404(escrow_id)
    if g.user['id'] not in (escrow['buyer_id'], escrow['seller_id']):
        abort(403)
    if escrow['status'] != 'released':
        flash('완료된 거래에만 후기를 남길 수 있습니다.')
        return redirect(url_for('wallet'))
    try:
        rating = int(request.form.get('rating', ''))
    except ValueError:
        rating = 0
    comment = request.form.get('comment', '').strip()
    if not (1 <= rating <= 5) or len(comment) > 200:
        flash('별점(1~5)과 200자 이내의 후기를 입력해주세요.')
        return redirect(url_for('wallet'))
    target_id = escrow['seller_id'] if g.user['id'] == escrow['buyer_id'] \
        else escrow['buyer_id']
    try:
        db.execute(
            "INSERT INTO review (id, escrow_id, reviewer_id, target_id, "
            "rating, comment) VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), escrow_id, g.user['id'], target_id,
             rating, comment))
        db.commit()
    except sqlite3.IntegrityError:
        flash('이미 이 거래에 후기를 남겼습니다.')
        return redirect(url_for('wallet'))
    notify(target_id, f"{g.user['username']}님이 거래 후기(★{rating})를 남겼습니다.",
           url_for('user_profile', username=g.user['username']))
    log_action('review_create', f'escrow={escrow_id} rating={rating}')
    flash('후기가 등록되었습니다.')
    return redirect(url_for('wallet'))


# ---------------------------------------------------------------------------
# 알림
# ---------------------------------------------------------------------------
@app.route('/notifications')
@login_required
def notifications():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM notification WHERE user_id = ? "
        "ORDER BY created_at DESC LIMIT 50", (g.user['id'],)).fetchall()
    db.execute("UPDATE notification SET is_read = 1 WHERE user_id = ?",
               (g.user['id'],))
    db.commit()
    return render_template('notifications.html', notifications=rows)


# ---------------------------------------------------------------------------
# 신고
# ---------------------------------------------------------------------------
@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    db = get_db()
    if request.method == 'POST':
        target_type = request.form.get('target_type', '')
        target_name = request.form.get('target', '').strip()
        reason = request.form.get('reason', '').strip()

        if target_type not in ('user', 'product'):
            flash('신고 대상 유형이 올바르지 않습니다.')
            return redirect(url_for('report'))
        if not reason or len(reason) > 500:
            flash('신고 사유는 1~500자로 작성해주세요.')
            return redirect(url_for('report'))

        if target_type == 'user':
            target = get_user_by_name(target_name) if USERNAME_RE.match(target_name) else None
            if target is None:
                flash('해당 사용자를 찾을 수 없습니다.')
                return redirect(url_for('report'))
            if target['id'] == g.user['id']:
                flash('자기 자신은 신고할 수 없습니다.')
                return redirect(url_for('report'))
            if target['is_admin']:
                flash('관리자는 신고할 수 없습니다.')
                return redirect(url_for('report'))
            target_id = target['id']
        else:
            product = get_product(target_name)
            if product is None:
                flash('해당 상품을 찾을 수 없습니다.')
                return redirect(url_for('report'))
            if product['seller_id'] == g.user['id']:
                flash('자신의 상품은 신고할 수 없습니다.')
                return redirect(url_for('report'))
            target_id = product['id']

        try:
            db.execute(
                "INSERT INTO report (id, reporter_id, target_type, target_id, reason) "
                "VALUES (?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), g.user['id'], target_type, target_id, reason))
            db.commit()
        except sqlite3.IntegrityError:  # 동일 대상 중복 신고 방지
            flash('이미 신고한 대상입니다.')
            return redirect(url_for('report'))

        log_action('report', f'type={target_type} target={target_id}')
        check_report_thresholds(db, target_type, target_id)
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))

    prefill_type = request.args.get('type', 'user')
    prefill_target = request.args.get('target', '')
    if prefill_type not in ('user', 'product'):
        prefill_type = 'user'
    return render_template('report.html', prefill_type=prefill_type,
                           prefill_target=prefill_target[:100])


# ---------------------------------------------------------------------------
# 1:1 채팅
# ---------------------------------------------------------------------------
@app.route('/chats')
@login_required
def chat_list():
    cur = get_db().execute(
        "SELECT DISTINCT room FROM message WHERE room LIKE 'dm:%' "
        "AND (room LIKE ? OR room LIKE ?)",
        (f'%:{g.user["id"]}', f'%:{g.user["id"]}:%'))
    partners = []
    for row in cur.fetchall():
        ids = row['room'][3:].split(':')
        other_id = ids[0] if ids[1] == g.user['id'] else ids[1]
        other = get_user(other_id)
        if other:
            partners.append(other)
    return render_template('chat_list.html', partners=partners)


@app.route('/chat/<username>')
@login_required
def private_chat(username):
    if not USERNAME_RE.match(username):
        abort(404)
    other = get_user_by_name(username)
    if other is None or other['id'] == g.user['id']:
        abort(404)
    room = dm_room(g.user['id'], other['id'])
    cur = get_db().execute(
        "SELECT m.content, m.created_at, u.username FROM message m "
        "JOIN user u ON u.id = m.sender_id WHERE m.room = ? "
        "ORDER BY m.created_at ASC LIMIT 200", (room,))
    return render_template('chat_private.html', other=other,
                           chat_history=cur.fetchall())


# ---------------------------------------------------------------------------
# 관리자
# ---------------------------------------------------------------------------
@app.route('/admin')
@admin_required
def admin_dashboard():
    db = get_db()
    stats = {
        'users': db.execute("SELECT COUNT(*) c FROM user").fetchone()['c'],
        'dormant': db.execute("SELECT COUNT(*) c FROM user WHERE is_dormant=1").fetchone()['c'],
        'products': db.execute("SELECT COUNT(*) c FROM product").fetchone()['c'],
        'blocked': db.execute("SELECT COUNT(*) c FROM product WHERE is_blocked=1").fetchone()['c'],
        'reports': db.execute("SELECT COUNT(*) c FROM report WHERE status='pending'").fetchone()['c'],
        'escrows': db.execute("SELECT COUNT(*) c FROM escrow WHERE status IN "
                              "('held','cancel_requested','disputed')").fetchone()['c'],
        'disputes': db.execute("SELECT COUNT(*) c FROM escrow WHERE status='disputed'").fetchone()['c'],
    }
    return render_template('admin/dashboard.html', stats=stats)


@app.route('/admin/users')
@admin_required
def admin_users():
    cur = get_db().execute(
        "SELECT u.*, (SELECT COUNT(DISTINCT reporter_id) FROM report "
        " WHERE target_type='user' AND target_id=u.id) AS report_count "
        "FROM user u ORDER BY u.created_at DESC")
    return render_template('admin/users.html', users=cur.fetchall())


@app.route('/admin/user/<user_id>/dormant', methods=['POST'])
@admin_required
def admin_toggle_dormant(user_id):
    user = get_user(user_id)
    if user is None:
        abort(404)
    if user['is_admin']:
        flash('관리자 계정은 휴면 처리할 수 없습니다.')
        return redirect(url_for('admin_users'))
    db = get_db()
    new_state = 0 if user['is_dormant'] else 1
    db.execute("UPDATE user SET is_dormant = ? WHERE id = ?", (new_state, user_id))
    db.commit()
    log_action('admin_toggle_dormant', f'user={user_id} dormant={new_state}')
    flash('처리되었습니다.')
    return redirect(url_for('admin_users'))


@app.route('/admin/products')
@admin_required
def admin_products():
    cur = get_db().execute(
        "SELECT p.*, u.username AS seller_name, "
        "(SELECT COUNT(DISTINCT reporter_id) FROM report "
        " WHERE target_type='product' AND target_id=p.id) AS report_count "
        "FROM product p JOIN user u ON u.id = p.seller_id "
        "ORDER BY p.created_at DESC")
    return render_template('admin/products.html', products=cur.fetchall())


@app.route('/admin/product/<product_id>/block', methods=['POST'])
@admin_required
def admin_toggle_block(product_id):
    db = get_db()
    product = get_product(product_id)
    if product is None:
        abort(404)
    new_state = 0 if product['is_blocked'] else 1
    db.execute("UPDATE product SET is_blocked = ? WHERE id = ?",
               (new_state, product_id))
    db.commit()
    log_action('admin_toggle_block', f'product={product_id} blocked={new_state}')
    flash('처리되었습니다.')
    return redirect(url_for('admin_products'))


@app.route('/admin/reports')
@admin_required
def admin_reports():
    cur = get_db().execute(
        "SELECT r.*, u.username AS reporter_name FROM report r "
        "JOIN user u ON u.id = r.reporter_id ORDER BY r.created_at DESC")
    reports = []
    db = get_db()
    for row in cur.fetchall():
        item = dict(row)
        if row['target_type'] == 'user':
            t = get_user(row['target_id'])
            item['target_label'] = t['username'] if t else '(삭제된 사용자)'
        else:
            p = db.execute("SELECT title FROM product WHERE id = ?",
                           (row['target_id'],)).fetchone()
            item['target_label'] = p['title'] if p else '(삭제된 상품)'
        reports.append(item)
    return render_template('admin/reports.html', reports=reports)


@app.route('/admin/report/<report_id>/resolve', methods=['POST'])
@admin_required
def admin_resolve_report(report_id):
    db = get_db()
    cur = db.execute("UPDATE report SET status = 'resolved' WHERE id = ?",
                     (report_id,))
    db.commit()
    if cur.rowcount == 0:
        abort(404)
    log_action('admin_resolve_report', f'report={report_id}')
    flash('신고가 처리되었습니다.')
    return redirect(url_for('admin_reports'))


@app.route('/admin/escrows')
@admin_required
def admin_escrows():
    cur = get_db().execute(
        "SELECT e.*, p.title AS product_title, "
        "b.username AS buyer_name, s.username AS seller_name "
        "FROM escrow e JOIN product p ON p.id = e.product_id "
        "JOIN user b ON b.id = e.buyer_id JOIN user s ON s.id = e.seller_id "
        "ORDER BY CASE e.status WHEN 'disputed' THEN 0 ELSE 1 END, "
        "e.created_at DESC")
    return render_template('admin/escrows.html', escrows=cur.fetchall())


@app.route('/admin/escrow/<escrow_id>/resolve', methods=['POST'])
@admin_required
def admin_resolve_escrow(escrow_id):
    """분쟁 중재: 판매자 지급 또는 구매자 환불."""
    db = get_db()
    escrow = get_escrow_or_404(escrow_id)
    outcome = request.form.get('outcome', '')
    if outcome not in ('release', 'refund'):
        abort(400)
    if not settle_escrow(db, escrow, outcome, allowed=('disputed',)):
        flash('분쟁 상태의 거래만 중재할 수 있습니다.')
        return redirect(url_for('admin_escrows'))
    msg = ('관리자 중재 결과: 판매자에게 대금이 지급되었습니다.'
           if outcome == 'release'
           else '관리자 중재 결과: 구매자에게 환불되었습니다.')
    notify(escrow['buyer_id'], msg, url_for('wallet'))
    notify(escrow['seller_id'], msg, url_for('wallet'))
    log_action('admin_escrow_' + outcome, f'escrow={escrow_id}')
    flash('중재가 완료되었습니다.')
    return redirect(url_for('admin_escrows'))


@app.route('/admin/finance')
@admin_required
def admin_finance():
    """재무 무결성 감사: 각 사용자의 원장 합계와 실제 잔액 대조."""
    db = get_db()
    rows = db.execute(
        "SELECT u.id, u.username, u.balance, "
        "COALESCE((SELECT SUM(l.delta) FROM ledger l WHERE l.user_id = u.id), 0) "
        "AS ledger_sum FROM user u ORDER BY u.created_at").fetchall()
    mismatches = [r for r in rows if r['balance'] != r['ledger_sum']]
    totals = {
        'balance_sum': sum(r['balance'] for r in rows),
        'held': db.execute("SELECT COALESCE(SUM(amount),0) s FROM escrow "
                           "WHERE status IN ('held','cancel_requested','disputed')"
                           ).fetchone()['s'],
    }
    recent = db.execute(
        "SELECT l.*, u.username FROM ledger l JOIN user u ON u.id = l.user_id "
        "ORDER BY l.created_at DESC, l.rowid DESC LIMIT 100").fetchall()
    return render_template('admin/finance.html', rows=rows,
                           mismatches=mismatches, totals=totals, recent=recent)


@app.route('/admin/logs')
@admin_required
def admin_logs():
    cur = get_db().execute(
        "SELECT a.*, u.username FROM audit_log a "
        "LEFT JOIN user u ON u.id = a.user_id "
        "ORDER BY a.id DESC LIMIT 200")
    return render_template('admin/logs.html', logs=cur.fetchall())


# ---------------------------------------------------------------------------
# Socket.IO (전체 채팅 + 1:1 채팅)
# ---------------------------------------------------------------------------
def socket_user():
    """소켓 이벤트에서 인증된 활성 사용자 반환, 아니면 None."""
    user_id = session.get('user_id')
    if not user_id:
        return None
    user = get_user(user_id)
    if user is None or user['is_dormant'] \
            or session.get('ver') != user['session_ver']:
        return None
    return user


def chat_rate_limited(user_id):
    now = time.time()
    history = [t for t in _chat_history.get(user_id, []) if now - t < CHAT_RATE_WINDOW]
    if len(history) >= CHAT_RATE_LIMIT:
        _chat_history[user_id] = history
        return True
    history.append(now)
    _chat_history[user_id] = history
    return False


def valid_chat_message(data):
    if not isinstance(data, dict):
        return None
    msg = data.get('message')
    if not isinstance(msg, str):
        return None
    msg = msg.strip()
    if not msg or len(msg) > 500:
        return None
    return msg


@socketio.on('connect')
def handle_connect():
    if socket_user() is None:
        return False  # 미인증 연결 거부


@socketio.on('send_message')
def handle_send_message_event(data):
    user = socket_user()
    if user is None:
        return
    msg = valid_chat_message(data)
    if msg is None:
        return
    if chat_rate_limited(user['id']):
        emit('error_message', {'error': '메시지를 너무 자주 보내고 있습니다.'})
        return
    db = get_db()
    db.execute("INSERT INTO message (id, room, sender_id, content) "
               "VALUES (?, 'global', ?, ?)",
               (str(uuid.uuid4()), user['id'], msg))
    db.commit()
    # 사용자명은 클라이언트 입력이 아닌 서버 세션에서 가져옴 (사칭 방지)
    send({'message_id': str(uuid.uuid4()), 'username': user['username'],
          'message': msg}, broadcast=True)


@socketio.on('join_private')
def handle_join_private(data):
    user = socket_user()
    if user is None or not isinstance(data, dict):
        return
    other_name = data.get('username', '')
    if not isinstance(other_name, str) or not USERNAME_RE.match(other_name):
        return
    other = get_user_by_name(other_name)
    if other is None or other['id'] == user['id']:
        return
    join_room(dm_room(user['id'], other['id']))


@socketio.on('send_private')
def handle_send_private(data):
    user = socket_user()
    if user is None:
        return
    msg = valid_chat_message(data)
    if msg is None:
        return
    if chat_rate_limited(user['id']):
        emit('error_message', {'error': '메시지를 너무 자주 보내고 있습니다.'})
        return
    other_name = data.get('username', '')
    if not isinstance(other_name, str) or not USERNAME_RE.match(other_name):
        return
    other = get_user_by_name(other_name)
    if other is None or other['id'] == user['id']:
        return
    room = dm_room(user['id'], other['id'])  # 방 이름을 서버에서 계산 (권한 우회 방지)
    db = get_db()
    db.execute("INSERT INTO message (id, room, sender_id, content) "
               "VALUES (?, ?, ?, ?)",
               (str(uuid.uuid4()), room, user['id'], msg))
    db.commit()
    emit('private_message',
         {'username': user['username'], 'message': msg}, to=room)


if __name__ == '__main__':
    init_db()
    # HOST/PORT는 환경변수로 조정 가능.
    #  - 로컬 전용(기본): HOST=127.0.0.1 (외부에서 직접 접근 불가, ngrok과 함께 쓰기 안전)
    #  - LAN/직접 노출:   HOST=0.0.0.0 으로 실행 (방화벽·HTTPS 고려 필요)
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', '5000'))
    # debug=False: 스택 트레이스 노출 방지.
    # allow_unsafe_werkzeug: 로컬 실습용 개발 서버 허용 플래그.
    # 실제 운영 배포 시에는 gunicorn + eventlet/gevent 뒤에서 실행할 것.
    socketio.run(app, host=host, port=port, debug=False,
                 allow_unsafe_werkzeug=True)
