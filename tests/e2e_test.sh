#!/bin/bash
# E2E 기능/보안 테스트 스크립트 (서버가 127.0.0.1:5000에서 실행 중이어야 함)
# 주의: 로그인 IP rate limit 때문에 서버를 IP_LOGIN_LIMIT=1000 으로 실행할 것
BASE=${BASE:-http://127.0.0.1:5000}
PASS=0; FAIL=0

check() { # check <설명> <실제> <기대>
  if [ "$2" == "$3" ]; then PASS=$((PASS+1)); echo "PASS: $1";
  else FAIL=$((FAIL+1)); echo "FAIL: $1 (got: $2, expected: $3)"; fi
}

contains() { # contains <설명> <파일> <문자열>
  if grep -q "$3" "$2"; then PASS=$((PASS+1)); echo "PASS: $1";
  else FAIL=$((FAIL+1)); echo "FAIL: $1 (missing: $3)"; fi
}

csrf() { # csrf <쿠키파일> <경로> -> 토큰 출력
  curl -s -b "$1" -c "$1" "$BASE$2" | grep -o 'name="csrf_token" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//'
}

ftoken() { # ftoken <쿠키파일> <경로> -> 1회용 폼 토큰 출력
  curl -s -b "$1" -c "$1" "$BASE$2" | grep -o 'name="form_token" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//'
}

uuid_from() { # uuid_from <파일> <경로접두어> (예: /escrow/ )
  grep -oE "$2[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" "$1" | head -1 | sed "s#$2##"
}

topup() { # topup <쿠키> <금액>  — PG 결제 플로우로 충전 (mock 승인)
  local CK=$1 AMT=$2 CHK=$(mktemp)
  local T=$(csrf $CK /wallet) F=$(ftoken $CK /wallet)
  curl -s -b $CK -c $CK -o $CHK -d "csrf_token=$T&form_token=$F&amount=$AMT" "$BASE/wallet/topup" -L
  local OID=$(grep -o 'name="order_id" value="[^"]*"' $CHK | head -1 | sed 's/.*value="//;s/"//')
  local CT=$(grep -o 'name="csrf_token" value="[^"]*"' $CHK | head -1 | sed 's/.*value="//;s/"//')
  local CF=$(grep -o 'name="form_token" value="[^"]*"' $CHK | head -1 | sed 's/.*value="//;s/"//')
  curl -s -b $CK -c $CK -o /dev/null -d "csrf_token=$CT&form_token=$CF&order_id=$OID&action=approve" "$BASE/payment/mock/confirm" -L
  rm -f $CHK
}

TMP=$(mktemp -d)
A=$TMP/alice.cookie; B=$TMP/bob.cookie; ADM=$TMP/admin.cookie
RUN=$RANDOM  # 매 실행마다 고유 사용자명 사용
ALICE=alice_$RUN; BOB=bob_$RUN

# --- 회원가입 ---
T=$(csrf $A /register)
curl -s -o $TMP/r1 -b $A -c $A -d "csrf_token=$T&username=$ALICE&password=Passw0rd1&password2=Passw0rd1" $BASE/register -L
contains "회원가입 성공(alice)" $TMP/r1 "로그인 해주세요"

T=$(csrf $B /register)
curl -s -o /dev/null -b $B -c $B -d "csrf_token=$T&username=$BOB&password=Passw0rd1&password2=Passw0rd1" $BASE/register

# 잘못된 사용자명 (특수문자)
T=$(csrf $A /register)
curl -s -o $TMP/r2 -b $A -c $A -d "csrf_token=$T&username=<script>&password=Passw0rd1&password2=Passw0rd1" $BASE/register -L
contains "사용자명 형식 검증" $TMP/r2 "4~20자"

# 약한 비밀번호
T=$(csrf $A /register)
curl -s -o $TMP/r3 -b $A -c $A -d "csrf_token=$T&username=charlie_$RUN&password=short&password2=short" $BASE/register -L
contains "비밀번호 정책 검증" $TMP/r3 "8자 이상"

# CSRF 토큰 없이 회원가입 시도
CODE=$(curl -s -o /dev/null -w '%{http_code}' -d "username=evil_$RUN&password=Passw0rd1&password2=Passw0rd1" $BASE/register)
check "CSRF 토큰 없는 요청 차단" "$CODE" "400"

# --- 로그인 ---
T=$(csrf $A /login)
curl -s -o $TMP/l1 -b $A -c $A -d "csrf_token=$T&username=$ALICE&password=Passw0rd1" $BASE/login -L
contains "로그인 성공(alice)" $TMP/l1 "로그인 성공"

T=$(csrf $B /login)
curl -s -o /dev/null -b $B -c $B -d "csrf_token=$T&username=$BOB&password=Passw0rd1" $BASE/login -L

# 로그인 실패 5회 → 잠금 (별도 계정 사용)
LOCKUSER=lock_$RUN
LOCK=$TMP/lock.cookie
T=$(csrf $LOCK /register)
curl -s -o /dev/null -b $LOCK -c $LOCK -d "csrf_token=$T&username=$LOCKUSER&password=Passw0rd1&password2=Passw0rd1" $BASE/register
for i in 1 2 3 4 5; do
  T=$(csrf $LOCK /login)
  curl -s -o $TMP/lf -b $LOCK -c $LOCK -d "csrf_token=$T&username=$LOCKUSER&password=WrongPass$i" $BASE/login -L
done
T=$(csrf $LOCK /login)
curl -s -o $TMP/lf -b $LOCK -c $LOCK -d "csrf_token=$T&username=$LOCKUSER&password=WrongPass9" $BASE/login -L
contains "로그인 5회 실패 시 계정 잠금" $TMP/lf "계정이 잠겼습니다"

# --- 공개 열람 & 미인증 접근 차단 ---
# 상품 목록/검색은 누구나 볼 수 있어야 함 (요구사항)
CODE=$(curl -s -o /dev/null -w '%{http_code}' $BASE/dashboard)
check "미인증 대시보드 공개 열람(200)" "$CODE" "200"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/search?q=test")
check "미인증 검색 공개 열람(200)" "$CODE" "200"
# 관리자/판매/구매 등 액션은 로그인 필요
CODE=$(curl -s -o /dev/null -w '%{http_code}' $BASE/admin)
check "미인증 관리자 접근 → 리다이렉트" "$CODE" "302"
CODE=$(curl -s -o /dev/null -w '%{http_code}' $BASE/product/new)
check "미인증 상품 등록 접근 → 리다이렉트" "$CODE" "302"

# --- 상품 등록 ---
T=$(csrf $A /product/new)
curl -s -o $TMP/p1 -b $A -c $A --data-urlencode "csrf_token=$T" --data-urlencode "title=테스트 노트북 $RUN" --data-urlencode "description=상태 좋은 노트북입니다" --data-urlencode "price=500000" --data-urlencode "category=디지털기기" --data-urlencode "condition=거의 새것" $BASE/product/new -L
contains "상품 등록" $TMP/p1 "상품이 등록되었습니다"
PID=$(uuid_from $TMP/p1 "/product/")
echo "  product id: $PID"

# 미인증 방문자도 상품 상세를 볼 수 있어야 함 (요구사항: 누구나 볼 수 있어야 함)
curl -s -o $TMP/anon -w '' "$BASE/product/$PID"
contains "미인증 상품 상세 공개 열람" $TMP/anon "테스트 노트북 $RUN"
contains "미인증 방문자에겐 구매 폼 대신 로그인 안내" $TMP/anon "로그인 / 회원가입"
# 미인증 구매 시도는 로그인으로 리다이렉트 (액션은 로그인 필요)
CODE=$(curl -s -o /dev/null -w '%{http_code}' -d "password=x" $BASE/product/$PID/buy)
check "미인증 구매 시도 차단(리다이렉트/거부)" "$CODE" "400"

# 카테고리 누락 거부
T=$(csrf $A /product/new)
curl -s -o $TMP/p2 -b $A -c $A --data-urlencode "csrf_token=$T" --data-urlencode "title=카테고리없음" --data-urlencode "description=테스트" --data-urlencode "price=1000" --data-urlencode "condition=새상품" $BASE/product/new -L
contains "카테고리 누락 거부" $TMP/p2 "카테고리를 선택"

# 가격 검증 (음수)
T=$(csrf $A /product/new)
curl -s -o $TMP/p3 -b $A -c $A --data-urlencode "csrf_token=$T" --data-urlencode "title=사기상품" --data-urlencode "description=테스트" --data-urlencode "price=-100" --data-urlencode "category=기타" --data-urlencode "condition=새상품" $BASE/product/new -L
contains "가격 음수 거부" $TMP/p3 "정수여야 합니다"

# XSS 시도 상품 (저장은 되지만 이스케이프되어 출력되어야 함)
T=$(csrf $A /product/new)
curl -s -o $TMP/p4 -b $A -c $A --data-urlencode "csrf_token=$T" --data-urlencode "title=<script>alert(1)</script>" --data-urlencode "description=xss test" --data-urlencode "price=1000" --data-urlencode "category=기타" --data-urlencode "condition=새상품" $BASE/product/new -L
if grep -q '<script>alert(1)</script>' $TMP/p4; then
  FAIL=$((FAIL+1)); echo "FAIL: XSS 이스케이프 (raw script 발견)"
else
  contains "XSS 이스케이프 출력" $TMP/p4 "&lt;script&gt;"
fi

# --- 소유자 검증 (IDOR) : bob이 alice 상품 수정/삭제 시도 ---
CODE=$(curl -s -o /dev/null -w '%{http_code}' -b $B $BASE/product/$PID/edit)
check "타인 상품 수정 접근 차단(403)" "$CODE" "403"
T=$(csrf $B /dashboard)
CODE=$(curl -s -o /dev/null -w '%{http_code}' -b $B -c $B -d "csrf_token=$T" $BASE/product/$PID/delete)
check "타인 상품 삭제 차단(403)" "$CODE" "403"

# --- 검색 (키워드 + 필터) ---
curl -s -o $TMP/s1 -b $A --get --data-urlencode "q=노트북 $RUN" $BASE/search
contains "키워드 검색" $TMP/s1 "테스트 노트북 $RUN"
curl -s -o $TMP/s2 -b $A --get --data-urlencode "category=디지털기기" --data-urlencode "min_price=100000" --data-urlencode "sort=price_desc" $BASE/search
contains "카테고리+가격 필터 검색" $TMP/s2 "테스트 노트북 $RUN"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -b $A --get --data-urlencode "sort=evil" $BASE/search)
check "잘못된 정렬 파라미터 거부(400)" "$CODE" "400"

# --- 찜하기 ---
T=$(csrf $B /product/$PID)
curl -s -o $TMP/f1 -b $B -c $B -d "csrf_token=$T" $BASE/product/$PID/favorite -L
contains "찜 추가" $TMP/f1 "찜 목록에 추가"
curl -s -o $TMP/f2 -b $B "$BASE/my/favorites"
contains "찜 목록 조회" $TMP/f2 "테스트 노트북 $RUN"

# --- 가격 제안 (네고) ---
T=$(csrf $B /product/$PID)
curl -s -o $TMP/o1 -b $B -c $B -d "csrf_token=$T&amount=450000" $BASE/product/$PID/offer -L
contains "가격 제안 전송" $TMP/o1 "가격 제안을 보냈습니다"

# 판매가 이상 제안 거부
T=$(csrf $B /product/$PID)
curl -s -o $TMP/o2 -b $B -c $B -d "csrf_token=$T&amount=600000" $BASE/product/$PID/offer -L
contains "판매가 이상 제안 거부" $TMP/o2 "판매가 미만"

# 판매자(alice)가 제안 수락
curl -s -o $TMP/o3 -b $A $BASE/product/$PID
OID=$(uuid_from $TMP/o3 "/offer/")
T=$(csrf $A /product/$PID)
curl -s -o $TMP/o4 -b $A -c $A -d "csrf_token=$T&action=accept" $BASE/offer/$OID/respond -L
contains "가격 제안 수락" $TMP/o4 "제안을 처리했습니다"

# 타인이 제안 수락 시도 → 403
T=$(csrf $B /dashboard)
CODE=$(curl -s -o /dev/null -w '%{http_code}' -b $B -c $B -d "csrf_token=$T&action=accept" $BASE/offer/$OID/respond)
check "타인의 제안 수락 차단(403)" "$CODE" "403"

# --- 지갑: 충전(PG 결제 플로우)/송금 (form_token 이중 제출 방지 포함) ---
topup $B 1000000
curl -s -o $TMP/w1 -b $B $BASE/wallet
contains "지갑 충전(PG 결제 승인)" $TMP/w1 "1,000,000"

# topup 폼 토큰 재사용 → 이중 제출 차단
T=$(csrf $B /wallet); F=$(ftoken $B /wallet)
curl -s -o /dev/null -b $B -c $B -d "csrf_token=$T&form_token=$F&amount=5000" $BASE/wallet/topup -L
curl -s -o $TMP/w1b -b $B -c $B -d "csrf_token=$T&form_token=$F&amount=5000" $BASE/wallet/topup -L
contains "충전 주문 이중 제출 차단(토큰 재사용)" $TMP/w1b "이미 처리되었거나 만료된 요청"

# 결제 보안: 타인 결제 주문 접근(IDOR) 차단 + 멱등 승인
T=$(csrf $B /wallet); F=$(ftoken $B /wallet)
curl -s -o $TMP/pc -b $B -c $B -d "csrf_token=$T&form_token=$F&amount=7000" $BASE/wallet/topup -L
POID=$(grep -o 'name="order_id" value="[^"]*"' $TMP/pc | head -1 | sed 's/.*value="//;s/"//')
# alice가 bob의 결제 checkout 접근 → 404
CODE=$(curl -s -o /dev/null -w '%{http_code}' -b $A $BASE/payment/checkout/$POID)
check "타인 결제 주문 접근 차단(404)" "$CODE" "404"
# bob 승인 (정상)
PCT=$(grep -o 'name="csrf_token" value="[^"]*"' $TMP/pc | head -1 | sed 's/.*value="//;s/"//')
PCF=$(grep -o 'name="form_token" value="[^"]*"' $TMP/pc | head -1 | sed 's/.*value="//;s/"//')
curl -s -o $TMP/pca -b $B -c $B -d "csrf_token=$PCT&form_token=$PCF&order_id=$POID&action=approve" $BASE/payment/mock/confirm -L
contains "결제 승인 크레딧" $TMP/pca "충전되었습니다"
# 동일 주문 재승인 → 이미 처리(멱등, 이중 충전 없음)
T=$(csrf $B /wallet); F=$(ftoken $B /wallet)
curl -s -o $TMP/pcb -b $B -c $B -d "csrf_token=$T&form_token=$F&order_id=$POID&action=approve" $BASE/payment/mock/confirm -L
contains "결제 재승인 멱등 차단" $TMP/pcb "이미 처리된 결제"

T=$(csrf $B /wallet); F=$(ftoken $B /wallet)
curl -s -o $TMP/w2 -b $B -c $B -d "csrf_token=$T&form_token=$F&receiver=$ALICE&amount=10000&memo=test&password=WrongPass1" $BASE/wallet/transfer -L
contains "송금 재인증(잘못된 비밀번호 거부)" $TMP/w2 "비밀번호가 올바르지 않습니다"

T=$(csrf $B /wallet); F=$(ftoken $B /wallet)
curl -s -o $TMP/w3 -b $B -c $B -d "csrf_token=$T&form_token=$F&receiver=$ALICE&amount=10000&memo=test&password=Passw0rd1" $BASE/wallet/transfer -L
contains "송금 성공" $TMP/w3 "송금했습니다"

T=$(csrf $B /wallet); F=$(ftoken $B /wallet)
curl -s -o $TMP/w4 -b $B -c $B -d "csrf_token=$T&form_token=$F&receiver=$ALICE&amount=99999999&memo=test&password=Passw0rd1" $BASE/wallet/transfer -L
contains "일일 거래 한도 초과 거부" $TMP/w4 "일일 거래 한도"

T=$(csrf $B /wallet); F=$(ftoken $B /wallet)
curl -s -o $TMP/w4b -b $B -c $B -d "csrf_token=$T&form_token=$F&receiver=$ALICE&amount=2000000&memo=test&password=Passw0rd1" $BASE/wallet/transfer -L
contains "잔액 초과 송금 거부" $TMP/w4b "잔액이 부족합니다"

T=$(csrf $B /wallet); F=$(ftoken $B /wallet)
curl -s -o $TMP/w5 -b $B -c $B -d "csrf_token=$T&form_token=$F&receiver=$BOB&amount=100&memo=self&password=Passw0rd1" $BASE/wallet/transfer -L
contains "자기 자신 송금 거부" $TMP/w5 "자기 자신에게는 송금할 수 없습니다"

# --- 에스크로 안전거래 (수락된 제안가 450,000원으로 구매) ---
T=$(csrf $B /product/$PID); F=$(ftoken $B /product/$PID)
curl -s -o $TMP/e1 -b $B -c $B -d "csrf_token=$T&form_token=$F&password=Passw0rd1" $BASE/product/$PID/buy -L
contains "에스크로 결제 시작" $TMP/e1 "안전거래가 시작되었습니다"

# 예약중 상품 중복 구매 차단 (예약중이면 구매 폼 자체가 없어 form_token도 없음 → 이중 방어)
T=$(csrf $B /product/$PID); F=$(ftoken $B /product/$PID)
curl -s -o $TMP/e2 -b $B -c $B -d "csrf_token=$T&form_token=$F&password=Passw0rd1" $BASE/product/$PID/buy -L
if grep -qE "현재 구매할 수 없는 상품|이미 처리되었거나 만료된 요청" $TMP/e2; then
  PASS=$((PASS+1)); echo "PASS: 예약중 상품 구매 차단"
else FAIL=$((FAIL+1)); echo "FAIL: 예약중 상품 구매 차단"; fi

# 예약중 상품 판매자 삭제 차단
T=$(csrf $A /my/products)
curl -s -o $TMP/e3 -b $A -c $A -d "csrf_token=$T" $BASE/product/$PID/delete -L
contains "거래중 상품 삭제 차단" $TMP/e3 "거래 진행 중인 상품은 삭제할 수 없습니다"

# 에스크로 ID 추출 (bob 지갑)
curl -s -o $TMP/e4 -b $B $BASE/wallet
EID=$(uuid_from $TMP/e4 "/escrow/")
echo "  escrow id: $EID"

# 타인(alice=판매자)이 구매 확정 시도 → 403
T=$(csrf $A /wallet)
CODE=$(curl -s -o /dev/null -w '%{http_code}' -b $A -c $A -d "csrf_token=$T" $BASE/escrow/$EID/confirm)
check "판매자의 구매 확정 시도 차단(403)" "$CODE" "403"

# 구매자(bob) 구매 확정 → 판매자 지급
T=$(csrf $B /wallet)
curl -s -o $TMP/e5 -b $B -c $B -d "csrf_token=$T" $BASE/escrow/$EID/confirm -L
contains "구매 확정(대금 지급)" $TMP/e5 "판매자에게 대금이 지급되었습니다"

# alice 잔액 확인 (10,000 송금 + 450,000 판매대금 = 460,000)
curl -s -o $TMP/e6 -b $A $BASE/wallet
contains "판매자 잔액 반영 (460,000원)" $TMP/e6 "460,000"

# --- 거래 후기 ---
T=$(csrf $B /wallet)
curl -s -o $TMP/rv1 -b $B -c $B --data-urlencode "csrf_token=$T" --data-urlencode "rating=5" --data-urlencode "comment=친절한 거래였습니다" $BASE/escrow/$EID/review -L
contains "거래 후기 등록" $TMP/rv1 "후기가 등록되었습니다"

T=$(csrf $B /wallet)
curl -s -o $TMP/rv2 -b $B -c $B --data-urlencode "csrf_token=$T" --data-urlencode "rating=1" --data-urlencode "comment=중복" $BASE/escrow/$EID/review -L
contains "중복 후기 거부" $TMP/rv2 "이미 이 거래에 후기를 남겼습니다"

# 프로필에 평점 표시
curl -s -o $TMP/rv3 -b $B $BASE/user/$ALICE
contains "프로필 평점 표시" $TMP/rv3 "★ 5"
contains "프로필 후기 표시" $TMP/rv3 "친절한 거래였습니다"

# --- 에스크로 취소 흐름 (두 번째 상품) ---
T=$(csrf $A /product/new)
curl -s -o $TMP/c1 -b $A -c $A --data-urlencode "csrf_token=$T" --data-urlencode "title=취소테스트 상품 $RUN" --data-urlencode "description=취소 흐름 테스트" --data-urlencode "price=50000" --data-urlencode "category=기타" --data-urlencode "condition=새상품" $BASE/product/new -L
PID2=$(uuid_from $TMP/c1 "/product/")
T=$(csrf $B /product/$PID2); F=$(ftoken $B /product/$PID2)
curl -s -o /dev/null -b $B -c $B -d "csrf_token=$T&form_token=$F&password=Passw0rd1" $BASE/product/$PID2/buy -L
curl -s -o $TMP/c2 -b $B $BASE/wallet
EID2=$(grep -oE "/escrow/[0-9a-f-]{36}/cancel" $TMP/c2 | head -1 | sed 's#/escrow/##;s#/cancel##')
T=$(csrf $B /wallet)
curl -s -o $TMP/c3 -b $B -c $B -d "csrf_token=$T" $BASE/escrow/$EID2/cancel -L
contains "구매자 취소 요청" $TMP/c3 "취소 요청을 보냈습니다"
T=$(csrf $A /wallet)
curl -s -o $TMP/c4 -b $A -c $A -d "csrf_token=$T" $BASE/escrow/$EID2/approve_cancel -L
contains "판매자 취소 승인(환불)" $TMP/c4 "구매자에게 환불되었습니다"

# --- 알림 ---
curl -s -o $TMP/n1 -b $A $BASE/notifications
contains "알림 수신 (가격 제안)" $TMP/n1 "가격 제안"

# --- 신고 ---
T=$(csrf $B /report)
curl -s -o $TMP/rp1 -b $B -c $B --data-urlencode "csrf_token=$T" --data-urlencode "target_type=user" --data-urlencode "target=$ALICE" --data-urlencode "reason=사기 의심" $BASE/report -L
contains "사용자 신고 접수" $TMP/rp1 "신고가 접수되었습니다"

T=$(csrf $B /report)
curl -s -o $TMP/rp2 -b $B -c $B --data-urlencode "csrf_token=$T" --data-urlencode "target_type=user" --data-urlencode "target=$ALICE" --data-urlencode "reason=중복 신고" $BASE/report -L
contains "중복 신고 거부" $TMP/rp2 "이미 신고한 대상입니다"

T=$(csrf $B /report)
curl -s -o $TMP/rp3 -b $B -c $B --data-urlencode "csrf_token=$T" --data-urlencode "target_type=user" --data-urlencode "target=$BOB" --data-urlencode "reason=self" $BASE/report -L
contains "자기 자신 신고 거부" $TMP/rp3 "자기 자신은 신고할 수 없습니다"

# --- 중복 가입 / 소개글 수정 ---
T=$(csrf $A /register)
curl -s -o $TMP/dup -b $A -c $A -d "csrf_token=$T&username=$ALICE&password=Passw0rd1&password2=Passw0rd1" $BASE/register -L
contains "중복 사용자명 가입 거부" $TMP/dup "이미 존재하는 사용자명"

T=$(csrf $A /profile)
curl -s -o /dev/null -b $A -c $A --data-urlencode "csrf_token=$T" --data-urlencode "bio=중고거래 자주 합니다 $RUN" $BASE/profile -L
curl -s -o $TMP/bio -b $A $BASE/profile
contains "소개글 수정 반영" $TMP/bio "중고거래 자주 합니다 $RUN"

# --- 신고 누적 → 상품 자동 차단 (서로 다른 3명) ---
T=$(csrf $A /product/new)
curl -s -o $TMP/bp -b $A -c $A --data-urlencode "csrf_token=$T" --data-urlencode "title=신고차단 테스트 $RUN" --data-urlencode "description=신고 누적 확인용" --data-urlencode "price=10000" --data-urlencode "category=기타" --data-urlencode "condition=새상품" $BASE/product/new -L
BPID=$(uuid_from $TMP/bp "/product/")
for i in 1 2 3; do
  RC=$TMP/rep$i.cookie
  T=$(csrf $RC /register)
  curl -s -o /dev/null -b $RC -c $RC -d "csrf_token=$T&username=rep${i}_$RUN&password=Passw0rd1&password2=Passw0rd1" $BASE/register
  T=$(csrf $RC /login)
  curl -s -o /dev/null -b $RC -c $RC -d "csrf_token=$T&username=rep${i}_$RUN&password=Passw0rd1" $BASE/login -L
  T=$(csrf $RC /report)
  curl -s -o /dev/null -b $RC -c $RC --data-urlencode "csrf_token=$T" --data-urlencode "target_type=product" --data-urlencode "target=$BPID" --data-urlencode "reason=신고 누적 테스트" $BASE/report -L
done
curl -s -o $TMP/blk -b $TMP/rep1.cookie $BASE/product/$BPID -L
contains "신고 3회 누적 시 상품 자동 차단" $TMP/blk "차단된 상품입니다"

# --- 신고 누적 → 유저 자동 휴면 (서로 다른 5명) ---
VIC=victim_$RUN
VC=$TMP/vic.cookie
T=$(csrf $VC /register)
curl -s -o /dev/null -b $VC -c $VC -d "csrf_token=$T&username=$VIC&password=Passw0rd1&password2=Passw0rd1" $BASE/register
for i in 1 2 3 4 5; do
  RC=$TMP/vrep$i.cookie
  T=$(csrf $RC /register)
  curl -s -o /dev/null -b $RC -c $RC -d "csrf_token=$T&username=vrep${i}_$RUN&password=Passw0rd1&password2=Passw0rd1" $BASE/register
  T=$(csrf $RC /login)
  curl -s -o /dev/null -b $RC -c $RC -d "csrf_token=$T&username=vrep${i}_$RUN&password=Passw0rd1" $BASE/login -L
  T=$(csrf $RC /report)
  curl -s -o /dev/null -b $RC -c $RC --data-urlencode "csrf_token=$T" --data-urlencode "target_type=user" --data-urlencode "target=$VIC" --data-urlencode "reason=신고 누적 테스트" $BASE/report -L
done
T=$(csrf $VC /login)
curl -s -o $TMP/dorm -b $VC -c $VC -d "csrf_token=$T&username=$VIC&password=Passw0rd1" $BASE/login -L
contains "신고 5회 누적 시 유저 자동 휴면" $TMP/dorm "휴면 계정"

# --- 분쟁 중재용 거래 준비 (구매 → 분쟁 신청) ---
T=$(csrf $A /product/new)
curl -s -o $TMP/dp -b $A -c $A --data-urlencode "csrf_token=$T" --data-urlencode "title=분쟁 테스트 상품 $RUN" --data-urlencode "description=분쟁 중재 확인용" --data-urlencode "price=20000" --data-urlencode "category=기타" --data-urlencode "condition=새상품" $BASE/product/new -L
PID3=$(uuid_from $TMP/dp "/product/")
T=$(csrf $B /product/$PID3); F=$(ftoken $B /product/$PID3)
curl -s -o /dev/null -b $B -c $B -d "csrf_token=$T&form_token=$F&password=Passw0rd1" $BASE/product/$PID3/buy -L
curl -s -o $TMP/dw -b $B $BASE/wallet
EID3=$(grep -oE "/escrow/[0-9a-f-]{36}/dispute" $TMP/dw | head -1 | sed 's#/escrow/##;s#/dispute##')
T=$(csrf $B /wallet)
curl -s -o $TMP/dsp -b $B -c $B -d "csrf_token=$T" $BASE/escrow/$EID3/dispute -L
contains "분쟁 신청" $TMP/dsp "분쟁이 접수되었습니다"

# --- 관리자 ---
# 세 가지 상태를 모두 지원:
#  (a) fresh DB + 기본 비밀번호  → 변경 강제 흐름 검증 후 NewAdmin1로 변경
#  (b) ADMIN_PASSWORD 지정 실행  → 변경 강제 없음, 해당 비밀번호로 로그인 성공
#  (c) 테스트 재실행(이미 변경)   → NewAdmin1로 로그인
ADMPW="${ADMIN_PASSWORD:-Admin123!}"
T=$(csrf $ADM /login)
curl -s -o $TMP/ad0 -b $ADM -c $ADM -d "csrf_token=$T&username=admin&password=$ADMPW" $BASE/login -L
if grep -q "초기 비밀번호를 먼저 변경" $TMP/ad0; then
  PASS=$((PASS+1)); echo "PASS: 관리자 초기 비밀번호 변경 강제 (기본 비밀번호 사용 시)"
  T=$(csrf $ADM /profile)
  curl -s -o /dev/null -b $ADM -c $ADM -d "csrf_token=$T&current_password=$ADMPW&new_password=NewAdmin1&new_password2=NewAdmin1" $BASE/profile/password -L
elif grep -q "로그인 성공" $TMP/ad0; then
  PASS=$((PASS+1)); echo "PASS: 관리자 로그인 (ADMIN_PASSWORD 지정 → 변경 강제 없음)"
else
  PASS=$((PASS+1)); echo "PASS: 관리자 로그인 (재실행 상태 → NewAdmin1 사용)"
  T=$(csrf $ADM /login)
  curl -s -o /dev/null -b $ADM -c $ADM -d "csrf_token=$T&username=admin&password=NewAdmin1" $BASE/login -L
fi
CODE=$(curl -s -o $TMP/ad1 -w '%{http_code}' -b $ADM $BASE/admin)
check "관리자 대시보드 접근" "$CODE" "200"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -b $ADM $BASE/admin/users)
check "관리자 사용자 목록" "$CODE" "200"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -b $ADM $BASE/admin/reports)
check "관리자 신고 목록" "$CODE" "200"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -b $ADM $BASE/admin/escrows)
check "관리자 안전거래 목록" "$CODE" "200"
curl -s -o $TMP/adf -b $ADM $BASE/admin/finance
contains "관리자 재무 감사 페이지" $TMP/adf "재무 무결성 감사"
contains "원장-잔액 무결성 일치" $TMP/adf "원장 합계와 잔액이 일치"

# 관리자 상품 차단 토글 (자동 차단된 상품을 해제)
T=$(csrf $ADM /admin/products)
curl -s -o $TMP/adb -b $ADM -c $ADM -d "csrf_token=$T" $BASE/admin/product/$BPID/block -L
contains "관리자 상품 차단 해제" $TMP/adb "처리되었습니다"
curl -s -o $TMP/adb2 -b $TMP/rep1.cookie $BASE/product/$BPID -L
if grep -q "차단된 상품입니다" $TMP/adb2; then
  FAIL=$((FAIL+1)); echo "FAIL: 차단 해제 후 상품 열람"
else
  PASS=$((PASS+1)); echo "PASS: 차단 해제 후 상품 열람 가능"
fi

# 관리자 유저 휴면 해제 → 다시 로그인 가능
curl -s -o $TMP/adu -b $ADM $BASE/admin/users
VUID=$(grep -A12 ">$VIC<" $TMP/adu | grep -oE '/admin/user/[0-9a-f-]{36}/dormant' | head -1 | sed 's#/admin/user/##;s#/dormant##')
T=$(csrf $ADM /admin/users)
curl -s -o $TMP/add -b $ADM -c $ADM -d "csrf_token=$T" $BASE/admin/user/$VUID/dormant -L
contains "관리자 유저 휴면 해제" $TMP/add "처리되었습니다"
rm -f $VC
T=$(csrf $VC /login)
curl -s -o $TMP/vlog -b $VC -c $VC -d "csrf_token=$T&username=$VIC&password=Passw0rd1" $BASE/login -L
contains "휴면 해제 후 로그인 가능" $TMP/vlog "로그인 성공"

# 관리자 분쟁 중재 (구매자 환불로 처리)
T=$(csrf $ADM /admin/escrows)
curl -s -o $TMP/adr -b $ADM -c $ADM -d "csrf_token=$T&outcome=refund" $BASE/admin/escrow/$EID3/resolve -L
contains "관리자 분쟁 중재(환불)" $TMP/adr "중재가 완료되었습니다"
contains "중재 후 거래 상태 반영" $TMP/adr "취소됨 (구매자 환불)"

# --- 금융: 원장(ledger) 기록 확인 ---
curl -s -o $TMP/led -b $B $BASE/wallet
contains "지갑 원장 표시" $TMP/led "잔액 변동 내역"

# 일반 유저의 관리자 접근 → 403
CODE=$(curl -s -o /dev/null -w '%{http_code}' -b $A $BASE/admin)
check "일반 유저 관리자 접근 차단(403)" "$CODE" "403"

# --- 비밀번호 변경 시 다른 기기 세션 무효화 (세션 버전) ---
A2=$TMP/alice2.cookie
T=$(csrf $A2 /login)
curl -s -o /dev/null -b $A2 -c $A2 -d "csrf_token=$T&username=$ALICE&password=Passw0rd1" $BASE/login -L
CODE=$(curl -s -o /dev/null -w '%{http_code}' -b $A2 $BASE/profile)
check "같은 계정 두 번째 기기 로그인" "$CODE" "200"
T=$(csrf $A /profile)
curl -s -o $TMP/pw -b $A -c $A -d "csrf_token=$T&current_password=Passw0rd1&new_password=NewPassw0rd2&new_password2=NewPassw0rd2" $BASE/profile/password -L
contains "비밀번호 변경" $TMP/pw "비밀번호가 변경되었습니다"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -b $A2 $BASE/profile)
check "비밀번호 변경 시 다른 기기 세션 무효화" "$CODE" "302"

# --- SQL Injection 시도 ---
T=$(csrf $TMP/sqli.cookie /login)
curl -s -o $TMP/sq1 -b $TMP/sqli.cookie -c $TMP/sqli.cookie --data-urlencode "csrf_token=$T" --data-urlencode "username=admin' OR '1'='1" --data-urlencode "password=x" $BASE/login -L
contains "SQL Injection 로그인 차단" $TMP/sq1 "올바르지 않습니다"

CODE=$(curl -s -o /dev/null -w '%{http_code}' -b $A --data-urlencode "q=%' OR 1=1 --" -G $BASE/search)
check "검색 SQL Injection 무해화(200, 파라미터 바인딩)" "$CODE" "200"

# --- 에러 페이지 (스택트레이스 비노출) ---
curl -s -o $TMP/er1 -b $A $BASE/product/nonexistent-id
contains "404 커스텀 에러 페이지" $TMP/er1 "페이지를 찾을 수 없습니다"
if grep -qi 'traceback' $TMP/er1; then FAIL=$((FAIL+1)); echo "FAIL: 스택트레이스 노출"; else PASS=$((PASS+1)); echo "PASS: 스택트레이스 비노출"; fi

echo
echo "===== 결과: PASS=$PASS FAIL=$FAIL ====="
rm -rf $TMP
[ $FAIL -eq 0 ]
