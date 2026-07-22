#!/bin/bash
# 소켓 인증, 파일 업로드 검증, 2단계 인증(TOTP) 테스트
BASE=${BASE:-http://127.0.0.1:5000}
PASS=0; FAIL=0
C=/tmp/extra.cookie; rm -f $C
U=extra_$RANDOM

check() {
  if [ "$2" == "$3" ]; then PASS=$((PASS+1)); echo "PASS: $1";
  else FAIL=$((FAIL+1)); echo "FAIL: $1 (got: $2, expected: $3)"; fi
}
contains() {
  if grep -q "$3" "$2"; then PASS=$((PASS+1)); echo "PASS: $1";
  else FAIL=$((FAIL+1)); echo "FAIL: $1 (missing: $3)"; fi
}
csrf() {
  curl -s -b $C -c $C "$BASE$1" | grep -o 'name="csrf_token" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//'
}
totp() { # totp <base32 secret> [offset]
  python3 - "$1" "${2:-0}" <<'EOF'
import base64, hashlib, hmac, struct, sys, time
secret, offset = sys.argv[1], int(sys.argv[2])
key = base64.b32decode(secret)
counter = int(time.time() // 30) + offset
digest = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
o = digest[-1] & 0x0F
print(str((struct.unpack('>I', digest[o:o+4])[0] & 0x7FFFFFFF) % 10**6).zfill(6))
EOF
}

# --- 1. 미인증 socket.io 핸드셰이크 → 연결 거부 ---
R=$(curl -s "$BASE/socket.io/?EIO=4&transport=polling")
SID=$(echo "$R" | grep -o '"sid":"[^"]*"' | head -1 | sed 's/"sid":"//;s/"//')
curl -s -o /dev/null "$BASE/socket.io/?EIO=4&transport=polling&sid=$SID" -d '40'
R3=$(curl -s "$BASE/socket.io/?EIO=4&transport=polling&sid=$SID")
if echo "$R3" | grep -q "rejected"; then PASS=$((PASS+1)); echo "PASS: 미인증 소켓 연결 거부";
else FAIL=$((FAIL+1)); echo "FAIL: 미인증 소켓 연결 거부 ($R3)"; fi

# --- 계정 준비 ---
T=$(csrf /register)
curl -s -o /dev/null -b $C -c $C -d "csrf_token=$T&username=$U&password=Passw0rd1&password2=Passw0rd1" $BASE/register
T=$(csrf /login)
curl -s -o /dev/null -b $C -c $C -d "csrf_token=$T&username=$U&password=Passw0rd1" $BASE/login -L

# --- 2. 가짜 이미지 (텍스트를 .png로 위장) → 거부 ---
echo "this is not an image" > /tmp/fake.png
T=$(csrf /product/new)
curl -s -o /tmp/up1 -b $C -c $C -F "csrf_token=$T" -F "title=fake image test" -F "description=test" -F "price=1000" -F "category=기타" -F "condition=새상품" -F "images=@/tmp/fake.png;type=image/png" $BASE/product/new -L
contains "가짜 이미지 업로드 거부" /tmp/up1 "이미지 파일(png/jpg/gif/webp)만"

# --- 3. 진짜 PNG (1x1 픽셀) → 성공 ---
printf '\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0dIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x0aIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\x0d\x0a\x2d\xb4\x00\x00\x00\x00IEND\xaeB\x60\x82' > /tmp/real.png
T=$(csrf /product/new)
curl -s -o /tmp/up2 -b $C -c $C -F "csrf_token=$T" -F "title=real image test" -F "description=test" -F "price=1000" -F "category=기타" -F "condition=새상품" -F "images=@/tmp/real.png;type=image/png" $BASE/product/new -L
contains "정상 이미지 업로드 성공" /tmp/up2 "상품이 등록되었습니다"

# --- 4. 2단계 인증 (TOTP) 활성화 → 로그인 흐름 ---
T=$(csrf /profile)
curl -s -o /tmp/2fa1 -b $C -c $C -d "csrf_token=$T" $BASE/profile/2fa/enable
SECRET=$(grep -o '시크릿 키: [A-Z2-7]*' /tmp/2fa1 | sed 's/시크릿 키: //')
if [ -n "$SECRET" ]; then PASS=$((PASS+1)); echo "PASS: 2FA 시크릿 발급";
else FAIL=$((FAIL+1)); echo "FAIL: 2FA 시크릿 발급"; fi

CODE=$(totp $SECRET)
T=$(grep -o 'name="csrf_token" value="[^"]*"' /tmp/2fa1 | head -1 | sed 's/.*value="//;s/"//')
curl -s -o /tmp/2fa2 -b $C -c $C -d "csrf_token=$T&code=$CODE" $BASE/profile/2fa/confirm -L
contains "2FA 활성화" /tmp/2fa2 "2단계 인증이 활성화"

# 로그아웃 후 재로그인 → 2FA 요구
T=$(csrf /profile)
curl -s -o /dev/null -b $C -c $C -d "csrf_token=$T" $BASE/logout -L
T=$(csrf /login)
curl -s -o /tmp/2fa3 -b $C -c $C -d "csrf_token=$T&username=$U&password=Passw0rd1" $BASE/login -L
contains "비밀번호만으로는 로그인 불가 (2FA 요구)" /tmp/2fa3 "6자리 코드를 입력"

# 잘못된 코드 → 거부
T=$(csrf /login/2fa)
curl -s -o /tmp/2fa4 -b $C -c $C -d "csrf_token=$T&code=000000" $BASE/login/2fa -L
contains "잘못된 2FA 코드 거부" /tmp/2fa4 "인증 코드가 올바르지 않습니다"

# 올바른 코드 → 로그인 성공
CODE=$(totp $SECRET)
T=$(csrf /login/2fa)
curl -s -o /tmp/2fa5 -b $C -c $C -d "csrf_token=$T&code=$CODE" $BASE/login/2fa -L
contains "올바른 2FA 코드 로그인 성공" /tmp/2fa5 "로그인 성공"

rm -f /tmp/fake.png /tmp/real.png /tmp/up1 /tmp/up2 /tmp/2fa1 /tmp/2fa2 /tmp/2fa3 /tmp/2fa4 /tmp/2fa5
echo
echo "===== 결과: PASS=$PASS FAIL=$FAIL ====="
[ $FAIL -eq 0 ]
