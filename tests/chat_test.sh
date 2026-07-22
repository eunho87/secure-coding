#!/bin/bash
# 채팅 테스트 — 전체 채팅 브로드캐스트, 1:1 채팅 전달과 방 격리, 내역 보존
# Socket.IO(engine.io) 폴링 프로토콜을 curl로 직접 주고받아 확인한다.
# 서버가 127.0.0.1:5000 에서 IP_LOGIN_LIMIT=1000 으로 실행 중이어야 한다.
BASE=${BASE:-http://127.0.0.1:5000}
DB=${DB:-$HOME/secure-coding/market.db}
PASS=0; FAIL=0

ok()   { PASS=$((PASS+1)); echo "PASS: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL: $1 ${2:-}"; }
sq()   { python3 -c "import sqlite3,sys; print(sqlite3.connect('$DB').execute(sys.argv[1]).fetchone()[0])" "$1"; }

csrf() { curl -s -b "$1" -c "$1" "$BASE$2" | grep -o 'name="csrf_token" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//'; }

signup() { # signup <쿠키> <사용자명>
  local C=$1 U=$2 T
  T=$(csrf $C /register)
  curl -s -o /dev/null -b $C -c $C -d "csrf_token=$T&username=$U&password=Passw0rd1&password2=Passw0rd1" $BASE/register
  T=$(csrf $C /login)
  curl -s -o /dev/null -b $C -c $C -d "csrf_token=$T&username=$U&password=Passw0rd1" $BASE/login -L
}

sio_connect() { # sio_connect <쿠키> -> sid 출력 (네임스페이스 연결까지)
  local C=$1 SID
  SID=$(curl -s -b $C -c $C "$BASE/socket.io/?EIO=4&transport=polling" \
        | grep -o '"sid":"[^"]*"' | head -1 | sed 's/"sid":"//;s/"//')
  curl -s -o /dev/null -b $C -c $C -X POST \
       "$BASE/socket.io/?EIO=4&transport=polling&sid=$SID" --data-raw '40'
  curl -s -o /dev/null -b $C -c $C "$BASE/socket.io/?EIO=4&transport=polling&sid=$SID"
  echo "$SID"
}

sio_emit() { # sio_emit <쿠키> <sid> <페이로드>
  curl -s -o /dev/null -b $1 -c $1 -X POST \
       "$BASE/socket.io/?EIO=4&transport=polling&sid=$2" --data-raw "$3"
}

sio_poll() { # sio_poll <쿠키> <sid> -> 큐에 쌓인 패킷 출력
  curl -s --max-time 5 -b $1 -c $1 "$BASE/socket.io/?EIO=4&transport=polling&sid=$2"
}

TMP=$(mktemp -d)
RUN=$RANDOM
A=$TMP/a.cookie; B=$TMP/b.cookie; C=$TMP/c.cookie
UA=chatA_$RUN; UB=chatB_$RUN; UC=chatC_$RUN

signup $A $UA; signup $B $UB; signup $C $UC
SIDA=$(sio_connect $A); SIDB=$(sio_connect $B); SIDC=$(sio_connect $C)
if [ -n "$SIDA" ] && [ -n "$SIDB" ]; then ok "인증 사용자 소켓 연결"; else bad "인증 사용자 소켓 연결"; fi

# --- 1. 전체 채팅 브로드캐스트 ---
# 소켓 응답 JSON은 한글을 \uXXXX로 이스케이프하므로, 전달 확인은 ASCII 메시지로 한다
MSG="global-chat-test-$RUN"
sio_emit $A "$SIDA" "42[\"send_message\",{\"message\":\"$MSG\"}]"
sleep 1
OUT=$(sio_poll $B "$SIDB")
if echo "$OUT" | grep -q "$MSG"; then ok "전체 채팅이 다른 접속자에게 전달"; else bad "전체 채팅이 다른 접속자에게 전달"; fi
# 발신자명을 클라이언트가 아닌 서버 세션에서 채우는지 (사칭 방지)
if echo "$OUT" | grep -q "$UA"; then ok "발신자명은 서버 세션 기준으로 표시"; else bad "발신자명은 서버 세션 기준으로 표시"; fi

# --- 2. 1:1 채팅 전달 ---
# (메시지 문자열이 고유하므로 큐를 따로 비우지 않는다. 같은 sid로 폴링이
#  겹치면 engine.io가 세션을 끊기 때문에 폴링은 검증 시점에만 한 번씩 한다.)
sio_emit $A "$SIDA" "42[\"join_private\",{\"username\":\"$UB\"}]"
sio_emit $B "$SIDB" "42[\"join_private\",{\"username\":\"$UA\"}]"
sleep 1
DM="dm-chat-test-$RUN"
sio_emit $A "$SIDA" "42[\"send_private\",{\"username\":\"$UB\",\"message\":\"$DM\"}]"
sleep 1
OUT=$(sio_poll $B "$SIDB")
if echo "$OUT" | grep -q "$DM"; then ok "1:1 채팅이 상대에게 전달"; else bad "1:1 채팅이 상대에게 전달"; fi

# --- 3. 제3자에게는 전달되지 않음 (방 격리) ---
SECRET="secret-dm-$RUN"
sio_emit $A "$SIDA" "42[\"send_private\",{\"username\":\"$UB\",\"message\":\"$SECRET\"}]"
sleep 1
OUT=$(sio_poll $C "$SIDC")
if echo "$OUT" | grep -q "$SECRET"; then bad "1:1 채팅 방 격리 (제3자에게 노출됨)"; else ok "1:1 채팅이 제3자에게 노출되지 않음"; fi

# --- 4. 새로고침 후 내역 보존 ---
curl -s -b $A "$BASE/chat/$UB" -o $TMP/hist
if grep -q "$DM" $TMP/hist; then ok "새로고침 후 1:1 대화 내역 로드"; else bad "새로고침 후 1:1 대화 내역 로드"; fi
curl -s -b $A "$BASE/dashboard" -o $TMP/dash
if grep -q "$MSG" $TMP/dash; then ok "새로고침 후 전체 채팅 내역 로드"; else bad "새로고침 후 전체 채팅 내역 로드"; fi

# --- 5. 길이 제한(500자 초과) 서버 거부 ---
LONG=$(python3 -c "print('x'*501)")
sio_emit $A "$SIDA" "42[\"send_message\",{\"message\":\"$LONG\"}]"
sleep 1
OUT=$(sio_poll $B "$SIDB")
if echo "$OUT" | grep -q 'xxxxxxxxxx'; then bad "500자 초과 메시지 거부"; else ok "500자 초과 메시지 거부"; fi

# --- 6. DB 저장 위치 확인 (1:1은 dm 방에 저장) ---
CNT=$(sq "SELECT COUNT(*) FROM message WHERE content='$DM'")
if [ "$CNT" = "1" ]; then ok "1:1 메시지 DB 저장(1건)"; else bad "1:1 메시지 DB 저장" "(count=$CNT)"; fi
ROOM=$(sq "SELECT room FROM message WHERE content='$DM'")
case "$ROOM" in dm:*) ok "1:1 메시지는 dm 방으로 분리 저장" ;; *) bad "1:1 메시지는 dm 방으로 분리 저장" "(room=$ROOM)" ;; esac

rm -rf $TMP
echo
echo "===== 채팅 테스트 결과: PASS=$PASS FAIL=$FAIL ====="
[ $FAIL -eq 0 ]
