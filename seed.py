"""
데모용 시드 데이터 생성 스크립트.

로컬에서 '사고 파는' 시연을 쉽게 하도록 데모 계정과 상품(사진·중고 시세 반영)을
미리 등록한다. 상품 사진은 키워드 기반 무료 이미지(loremflickr, Flickr CC)를
내려받고, 실패하면 Pillow로 카테고리 색상 플레이스홀더를 생성한다.

실행:  python seed.py         (이미 시드되어 있으면 건너뜀)
       python seed.py --reset (데모 데이터 삭제 후 재생성)

모든 데모 계정의 비밀번호는 'Passw0rd1' 이다.
"""
import sys
import urllib.request
import uuid

import app as A

DEMO_PASSWORD = 'Passw0rd1'
MARKER = 'daangn_kim'  # 이 계정 존재 여부로 시드 여부 판단

# (username, 소개글, 초기잔액)
DEMO_USERS = [
    ('daangn_kim', '동네 중고 매너왕입니다. 직거래 선호해요!', 500_000),
    ('market_lee', '이사 정리 중이라 여러 물건 내놓습니다.', 300_000),
    ('hanguk_park', '디지털/게임 기기 위주로 판매합니다.', 200_000),
    ('buyer_choi', '좋은 물건 구합니다. 빠른 거래 환영!', 3_000_000),
]

# (판매자, 상품명, 설명, 가격, 카테고리, 상품상태, 이미지 키워드)
DEMO_PRODUCTS = [
    ('hanguk_park', '아이폰 13 128GB 미드나이트', '애플케어 만료, 배터리 성능 89%. 생활기스 약간 있고 정상 작동합니다. 박스/충전기 포함.', 550_000, '디지털기기', '사용감 있음', 'iphone'),
    ('hanguk_park', '삼성 갤럭시 버즈2 프로', '한 달 사용한 무선이어폰입니다. 노이즈캔슬링 좋아요. 케이스 포함.', 90_000, '디지털기기', '거의 새것', 'earbuds'),
    ('hanguk_park', 'LG 27인치 4K 모니터 27UP600', 'IPS 4K 모니터, USB-C 지원. 불량화소 없음. 박스 보관 중.', 180_000, '디지털기기', '거의 새것', 'monitor'),
    ('hanguk_park', '닌텐도 스위치 OLED 화이트', '조이콘 쏠림 없음. 동물의숲 에디션 아니고 일반 화이트. 젤다 게임칩 포함.', 320_000, '게임/취미', '거의 새것', 'nintendo+switch'),
    ('market_lee', '다이슨 V11 무선청소기', '2년 사용, 흡입력 정상. 배터리 교체한 지 6개월. 거치대/헤드 3종 포함.', 250_000, '가전제품', '사용감 있음', 'vacuum+cleaner'),
    ('market_lee', '스타벅스 미니 냉장고 20L', '미개봉 새제품입니다. 선물받았는데 자리가 없어 판매해요.', 70_000, '가전제품', '새상품', 'mini+fridge'),
    ('market_lee', '이케아 원목 책상 (140x60)', '재택근무용으로 쓰던 책상. 상판 흠집 약간. 직접 가져가실 분.', 45_000, '가구/인테리어', '사용감 있음', 'wooden+desk'),
    ('market_lee', '허먼밀러 아론 체어 리마스터드', '풀옵션 정품. 구매 1년, 상태 아주 좋습니다. 정품 보증서 있어요.', 650_000, '가구/인테리어', '거의 새것', 'office+chair'),
    ('daangn_kim', '나이키 에어포스1 270mm', '두어 번 신은 흰색 에어포스. 박스 있고 밑창 깨끗합니다.', 80_000, '의류/패션', '거의 새것', 'sneakers'),
    ('daangn_kim', '노스페이스 눕시 패딩 (L)', '작년 겨울 구매, 블랙 L 사이즈. 세탁 완료했습니다.', 120_000, '의류/패션', '사용감 있음', 'winter+jacket'),
    ('daangn_kim', '클린코드 + 리팩터링 도서 세트', '개발 서적 2권 세트. 밑줄/필기 거의 없습니다.', 35_000, '도서', '사용감 있음', 'programming+books'),
    ('daangn_kim', '트렉 FX2 하이브리드 자전거', '출퇴근용 하이브리드. 사이즈 M. 정비 완료, 라이트 포함.', 400_000, '스포츠/레저', '사용감 있음', 'bicycle'),
    ('market_lee', '4인용 캠핑 텐트 (원터치)', '두 번 사용한 원터치 텐트. 방수 잘 됩니다. 수납백 포함.', 130_000, '스포츠/레저', '사용감 있음', 'camping+tent'),
    ('hanguk_park', '레고 스타워즈 밀레니엄 팔콘', '미개봉 새제품. 소장용으로 샀다가 판매합니다.', 150_000, '게임/취미', '새상품', 'lego'),
    ('daangn_kim', '다이슨 에어랩 컴플리트', '헤어 스타일러 풀세트. 6개월 사용, 노즐 모두 있습니다.', 480_000, '뷰티/미용', '거의 새것', 'hair+styler'),
]


def fetch_image(keyword, lock):
    """키워드 매칭 이미지를 내려받고, 실패 시 Pillow 플레이스홀더 생성."""
    url = f"https://loremflickr.com/800/600/{keyword}?lock={lock}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        data = urllib.request.urlopen(req, timeout=20).read()
        if data[:3] == b'\xff\xd8\xff':
            return data, 'jpg'
    except Exception as e:
        print(f'    (다운로드 실패, 플레이스홀더 사용: {e})')
    return placeholder_image(keyword, lock), 'png'


def placeholder_image(label, seed):
    from io import BytesIO
    from PIL import Image, ImageDraw
    palette = [(255, 111, 15), (37, 99, 235), (22, 163, 74), (180, 83, 9),
               (139, 92, 246), (219, 39, 119)]
    c1 = palette[seed % len(palette)]
    img = Image.new('RGB', (800, 600), c1)
    d = ImageDraw.Draw(img)
    for y in range(600):  # 세로 그라데이션
        t = y / 600
        d.line([(0, y), (800, y)],
               fill=tuple(int(v * (1 - t * 0.5)) for v in c1))
    d.rectangle([40, 40, 760, 560], outline=(255, 255, 255), width=4)
    buf = BytesIO()
    img.save(buf, format='PNG')
    return buf.getvalue(), 'png'


def save_image(db, product_id, keyword, sort, lock):
    import os
    data, ext = fetch_image(keyword, lock)
    filename = uuid.uuid4().hex + '.' + ext
    with open(os.path.join(A.UPLOAD_DIR, filename), 'wb') as f:
        f.write(data)
    db.execute(
        "INSERT INTO product_image (id, product_id, filename, sort) "
        "VALUES (?, ?, ?, ?)",
        (str(uuid.uuid4()), product_id, filename, sort))
    return filename


def reset_demo(db):
    print('기존 데모 데이터를 삭제합니다...')
    ids = [r['id'] for r in db.execute(
        "SELECT id FROM user WHERE username IN ({})".format(
            ','.join('?' * len(DEMO_USERS))),
        [u[0] for u in DEMO_USERS]).fetchall()]
    if not ids:
        return
    ph = ','.join('?' * len(ids))
    prod_ids = [r['id'] for r in db.execute(
        f"SELECT id FROM product WHERE seller_id IN ({ph})", ids).fetchall()]
    if prod_ids:
        pph = ','.join('?' * len(prod_ids))
        db.execute(f"DELETE FROM product_image WHERE product_id IN ({pph})", prod_ids)
        db.execute(f"DELETE FROM offer WHERE product_id IN ({pph})", prod_ids)
    db.execute(f"DELETE FROM review WHERE reviewer_id IN ({ph}) OR target_id IN ({ph})",
               ids + ids)
    db.execute(f"DELETE FROM escrow WHERE buyer_id IN ({ph}) OR seller_id IN ({ph})",
               ids + ids)
    db.execute(f"DELETE FROM transfer WHERE sender_id IN ({ph}) OR receiver_id IN ({ph})",
               ids + ids)
    db.execute(f"DELETE FROM ledger WHERE user_id IN ({ph})", ids)
    db.execute(f"DELETE FROM notification WHERE user_id IN ({ph})", ids)
    db.execute(f"DELETE FROM message WHERE sender_id IN ({ph})", ids)
    db.execute(f"DELETE FROM product WHERE seller_id IN ({ph})", ids)
    db.execute(f"DELETE FROM user WHERE id IN ({ph})", ids)
    db.commit()


def run(reset=False):
    A.init_db()
    with A.app.app_context():
        db = A.get_db()
        if reset:
            reset_demo(db)
        if db.execute("SELECT 1 FROM user WHERE username = ?",
                      (MARKER,)).fetchone():
            print('이미 데모 데이터가 있습니다. 다시 만들려면: python seed.py --reset')
            return

        # 1) 데모 사용자
        uid = {}
        for username, bio, balance in DEMO_USERS:
            u = str(uuid.uuid4())
            uid[username] = u
            db.execute(
                "INSERT INTO user (id, username, password_hash, bio) "
                "VALUES (?, ?, ?, ?)",
                (u, username, A.hash_password(DEMO_PASSWORD), bio))
            A.apply_balance(db, u, balance, 'charge')  # 원장 기록 포함
        db.commit()
        print(f'데모 사용자 {len(DEMO_USERS)}명 생성')

        # 2) 데모 상품 + 사진
        pid = {}
        for i, (seller, title, desc, price, cat, cond, kw) in enumerate(DEMO_PRODUCTS):
            p = str(uuid.uuid4())
            pid[title] = p
            db.execute(
                "INSERT INTO product (id, title, description, price, category, "
                "condition, seller_id, view_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (p, title, desc, price, cat, cond, uid[seller], (i * 7) % 40))
            print(f'  [{i+1}/{len(DEMO_PRODUCTS)}] {title} — 사진 다운로드...')
            save_image(db, p, kw, 0, 1000 + i)
            db.commit()
        print(f'데모 상품 {len(DEMO_PRODUCTS)}개 생성')

        # 3) 진행 중인 가격 제안 (buyer_choi → 아이폰)
        target = pid['아이폰 13 128GB 미드나이트']
        db.execute(
            "INSERT INTO offer (id, product_id, buyer_id, amount) VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), target, uid['buyer_choi'], 500_000))
        A.notify(uid['hanguk_park'],
                 "'아이폰 13 128GB 미드나이트'에 500,000원 가격 제안이 도착했습니다.",
                 f"/product/{target}")

        # 4) 완료된 거래 + 후기 (평점 시연용): buyer_choi가 버즈2 구매 완료
        sold = pid['삼성 갤럭시 버즈2 프로']
        price = 90_000
        eid = str(uuid.uuid4())
        A.apply_balance(db, uid['buyer_choi'], -price, 'escrow_hold', eid)
        A.apply_balance(db, uid['hanguk_park'], price, 'escrow_release', eid)
        db.execute(
            "INSERT INTO escrow (id, product_id, buyer_id, seller_id, amount, status) "
            "VALUES (?, ?, ?, ?, ?, 'released')",
            (eid, sold, uid['buyer_choi'], uid['hanguk_park'], price))
        db.execute(
            "INSERT INTO transfer (id, sender_id, receiver_id, amount, memo, kind) "
            "VALUES (?, ?, ?, ?, '안전거래 대금 지급', 'purchase')",
            (str(uuid.uuid4()), uid['buyer_choi'], uid['hanguk_park'], price))
        db.execute("UPDATE product SET status = 'sold' WHERE id = ?", (sold,))
        db.execute(
            "INSERT INTO review (id, escrow_id, reviewer_id, target_id, rating, comment) "
            "VALUES (?, ?, ?, ?, 5, '설명대로 상태 좋고 친절하세요. 또 거래하고 싶어요!')",
            (str(uuid.uuid4()), eid, uid['buyer_choi'], uid['hanguk_park']))
        db.execute(
            "INSERT INTO review (id, escrow_id, reviewer_id, target_id, rating, comment) "
            "VALUES (?, ?, ?, ?, 5, '시간 약속 잘 지키는 좋은 구매자님입니다.')",
            (str(uuid.uuid4()), eid, uid['hanguk_park'], uid['buyer_choi']))

        # 5) 전체 채팅 예시 메시지
        for sender, msg in [
            ('daangn_kim', '안녕하세요! 오늘 직거래 가능한 분 계신가요?'),
            ('buyer_choi', '아이폰 판매자님 채팅 확인 부탁드려요~'),
            ('market_lee', '캠핑 텐트 상태 좋습니다. 문의 환영해요!'),
        ]:
            db.execute(
                "INSERT INTO message (id, room, sender_id, content) "
                "VALUES (?, 'global', ?, ?)",
                (str(uuid.uuid4()), uid[sender], msg))
        db.commit()

        print('\n완료! 데모 계정 (비밀번호 공통: Passw0rd1)')
        for username, _, bal in DEMO_USERS:
            print(f'  - {username}')
        print('  구매 시연은 buyer_choi 로 로그인하세요 (잔액 넉넉).')


if __name__ == '__main__':
    run(reset='--reset' in sys.argv)
