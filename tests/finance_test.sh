#!/bin/bash
# 금융 보안 집중 테스트: 에스크로 이중 정산(race condition) 방지 + 원장 무결성
# 서버가 127.0.0.1:5000에서 IP_LOGIN_LIMIT=1000 으로 실행 중이어야 함
BASE=${BASE:-http://127.0.0.1:5000}
PASS=0; FAIL=0
DB=$HOME/secure-coding/market.db

csrf() { curl -s -b "$1" -c "$1" "$BASE$2" | grep -o 'name="csrf_token" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//'; }
ftoken() { curl -s -b "$1" -c "$1" "$BASE$2" | grep -o 'name="form_token" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//'; }
uuid_from() { grep -oE "$2[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" "$1" | head -1 | sed "s#$2##"; }
# sqlite3 CLI가 없어 python3로 조회
sq() { python3 -c "import sqlite3,sys; print(sqlite3.connect('$DB').execute(sys.argv[1]).fetchone()[0])" "$1"; }
bal() { sq "SELECT balance FROM user WHERE username='$1'"; }
topup() { # topup <쿠키> <금액> — PG 결제 플로우 충전(mock 승인)
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
S=$TMP/seller.cookie; B=$TMP/buyer.cookie
R=$RANDOM; SELLER=selr_$R; BUYER=buyr_$R

# 계정 준비
for U in $SELLER $BUYER; do
  CK=$TMP/$U.cookie
  T=$(csrf $CK /register)
  curl -s -o /dev/null -b $CK -c $CK -d "csrf_token=$T&username=$U&password=Passw0rd1&password2=Passw0rd1" $BASE/register
done
S=$TMP/$SELLER.cookie; B=$TMP/$BUYER.cookie
T=$(csrf $S /login); curl -s -o /dev/null -b $S -c $S -d "csrf_token=$T&username=$SELLER&password=Passw0rd1" $BASE/login -L
T=$(csrf $B /login); curl -s -o /dev/null -b $B -c $B -d "csrf_token=$T&username=$BUYER&password=Passw0rd1" $BASE/login -L

# 판매자 상품 등록
T=$(csrf $S /product/new)
curl -s -o $TMP/p -b $S -c $S --data-urlencode "csrf_token=$T" --data-urlencode "title=race테스트 $R" --data-urlencode "description=동시성 테스트" --data-urlencode "price=100000" --data-urlencode "category=기타" --data-urlencode "condition=새상품" $BASE/product/new -L
PID=$(uuid_from $TMP/p "/product/")

# 구매자 충전(PG 결제) 후 에스크로 결제
topup $B 1000000
T=$(csrf $B /product/$PID); F=$(ftoken $B /product/$PID)
curl -s -o /dev/null -b $B -c $B -d "csrf_token=$T&form_token=$F&password=Passw0rd1" $BASE/product/$PID/buy -L
curl -s -o $TMP/w -b $B $BASE/wallet
EID=$(uuid_from $TMP/w "/escrow/")
echo "  escrow id: $EID"

SELLER_BEFORE=$(bal $SELLER)

# --- 이중 정산 방지: 동일 에스크로에 confirm 20회 동시 요청 ---
T=$(csrf $B /wallet)
for i in $(seq 1 20); do
  curl -s -o /dev/null -b $B -c $B -d "csrf_token=$T" $BASE/escrow/$EID/confirm &
done
wait

SELLER_AFTER=$(bal $SELLER)
GAIN=$((SELLER_AFTER - SELLER_BEFORE))
if [ "$GAIN" -eq 100000 ]; then
  PASS=$((PASS+1)); echo "PASS: 에스크로 이중 정산 방지 (판매자 잔액 +100,000 정확히 1회)"
else
  FAIL=$((FAIL+1)); echo "FAIL: 이중 정산 (판매자 잔액 증가액=$GAIN, 기대=100000)"
fi

# 원장에 escrow_release 기록이 정확히 1건인지
REL=$(sq "SELECT COUNT(*) FROM ledger WHERE ref_id='$EID' AND ref_type='escrow_release'")
if [ "$REL" -eq 1 ]; then
  PASS=$((PASS+1)); echo "PASS: 원장 escrow_release 기록 정확히 1건"
else
  FAIL=$((FAIL+1)); echo "FAIL: 원장 escrow_release 기록 $REL 건 (기대 1)"
fi

# --- 원장-잔액 무결성: 모든 사용자 잔액 == 원장 delta 합계 ---
MISMATCH=$(sq "SELECT COUNT(*) FROM user u WHERE u.balance <> COALESCE((SELECT SUM(delta) FROM ledger l WHERE l.user_id=u.id),0)")
if [ "$MISMATCH" -eq 0 ]; then
  PASS=$((PASS+1)); echo "PASS: 전체 원장-잔액 무결성 일치 (불일치 0건)"
else
  FAIL=$((FAIL+1)); echo "FAIL: 원장-잔액 불일치 $MISMATCH 건"
fi

# --- 잔액 음수 불가 (CHECK 제약): 잔액 초과 인출 시도해도 음수 안 됨 ---
NEG=$(sq "SELECT COUNT(*) FROM user WHERE balance < 0")
if [ "$NEG" -eq 0 ]; then
  PASS=$((PASS+1)); echo "PASS: 음수 잔액 계정 없음 (CHECK 제약)"
else
  FAIL=$((FAIL+1)); echo "FAIL: 음수 잔액 계정 $NEG 건"
fi

# --- 결제 멱등성: 동일 충전 주문 승인 20회 동시 요청 → 1회만 크레딧 ---
PB_BEFORE=$(bal $BUYER)
T=$(csrf $B /wallet); F=$(ftoken $B /wallet)
curl -s -b $B -c $B -o $TMP/po -d "csrf_token=$T&form_token=$F&amount=30000" $BASE/wallet/topup -L
POID=$(grep -o 'name="order_id" value="[^"]*"' $TMP/po | head -1 | sed 's/.*value="//;s/"//')
PCT=$(grep -o 'name="csrf_token" value="[^"]*"' $TMP/po | head -1 | sed 's/.*value="//;s/"//')
PCF=$(grep -o 'name="form_token" value="[^"]*"' $TMP/po | head -1 | sed 's/.*value="//;s/"//')
for i in $(seq 1 20); do
  curl -s -o /dev/null -b $B -c $B -d "csrf_token=$PCT&form_token=$PCF&order_id=$POID&action=approve" $BASE/payment/mock/confirm &
done
wait
PB_AFTER=$(bal $BUYER)
PGAIN=$((PB_AFTER - PB_BEFORE))
if [ "$PGAIN" -eq 30000 ]; then
  PASS=$((PASS+1)); echo "PASS: 결제 이중 크레딧 방지 (구매자 잔액 +30,000 정확히 1회)"
else
  FAIL=$((FAIL+1)); echo "FAIL: 결제 이중 크레딧 (증가액=$PGAIN, 기대=30000)"
fi
PAID=$(sq "SELECT COUNT(*) FROM ledger WHERE ref_id='$POID' AND ref_type='topup'")
if [ "$PAID" -eq 1 ]; then
  PASS=$((PASS+1)); echo "PASS: 원장 topup 기록 정확히 1건"
else
  FAIL=$((FAIL+1)); echo "FAIL: 원장 topup 기록 $PAID 건 (기대 1)"
fi

echo
echo "===== 금융 테스트 결과: PASS=$PASS FAIL=$FAIL ====="
rm -rf $TMP
[ $FAIL -eq 0 ]
