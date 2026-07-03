#!/usr/bin/env bash
set -e

PORT=18080
BASE_URL="http://127.0.0.1:$PORT"
TEST_APP="tests/test_app"
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

pass() {
  TESTS_RUN=$((TESTS_RUN + 1))
  TESTS_PASSED=$((TESTS_PASSED + 1))
  echo -e "${GREEN}PASS${NC}: $1"
}

fail() {
  TESTS_RUN=$((TESTS_RUN + 1))
  TESTS_FAILED=$((TESTS_FAILED + 1))
  echo -e "${RED}FAIL${NC}: $1"
  echo "  Expected: $2"
  echo "  Got:      $3"
}

check() {
  local desc="$1"
  local expected="$2"
  local got="$3"
  if [ "$got" = "$expected" ]; then
    pass "$desc"
  else
    fail "$desc" "$expected" "$got"
  fi
}

# Build test app
echo "Building test app..."
nim c --path:src -o:$TEST_APP tests/test_app.nim 2>/dev/null

# Create public dir for static file tests
mkdir -p tests/public
echo "<h1>static</h1>" > tests/public/index.html

# Start server
echo "Starting server on port $PORT..."
./$TEST_APP $PORT &
SERVER_PID=$!
sleep 2

# Check server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
  echo -e "${RED}Server failed to start${NC}"
  exit 1
fi

echo ""
echo "Running tests..."
echo "================"

# === Basic routing ===
RESP=$(curl -s $BASE_URL/)
check "GET / returns welcome" "Welcome to servy!" "$RESP"

RESP=$(curl -s $BASE_URL/get)
check "GET /get returns GET request" "GET request" "$RESP"

RESP=$(curl -s -X POST $BASE_URL/post)
check "POST /post returns POST request" "POST request" "$RESP"

RESP=$(curl -s -X PUT $BASE_URL/put)
check "PUT /put returns PUT request" "PUT request" "$RESP"

RESP=$(curl -s -X DELETE $BASE_URL/delete)
check "DELETE /delete returns DELETE request" "DELETE request" "$RESP"

# === URL parameters ===
RESP=$(curl -s $BASE_URL/user/alice)
check "GET /user/alice returns user=alice" "user=alice" "$RESP"

RESP=$(curl -s $BASE_URL/multi/foo/bar)
check "GET /multi/foo/bar returns params" "first=foo second=bar" "$RESP"

# === Query parameters ===
RESP=$(curl -s "$BASE_URL/query?page=1&limit=10")
check "GET /query with params" "query: page=1, limit=10" "$RESP"

# === Form data ===
RESP=$(curl -s -X POST -d "username=john&password=doe" $BASE_URL/form-urlencoded)
check "POST /form-urlencoded" "username=john password=doe" "$RESP"

# === Cookies ===
RESP=$(curl -s -b "session=xyz" $BASE_URL/cookies)
check "GET /cookies with cookie" "cookies: session=xyz" "$RESP"

# === Set cookie header ===
HEADER=$(curl -s -D - $BASE_URL/set-cookie 2>&1 | grep -i "set-cookie" | tr -d '\r')
check "GET /set-cookie sets header" "set-cookie: session=abc123; Path=/" "$HEADER"

# === Response headers ===
HEADERS=$(curl -s -D - $BASE_URL/headers 2>&1 | grep -iE "x-custom|x-another" | tr -d '\r' | sort)
EXPECTED="x-another: another-value
x-custom: test-value"
check "GET /headers sets custom headers" "$EXPECTED" "$HEADERS"

# === Abort ===
CODE=$(curl -s -o /dev/null -w "%{http_code}" $BASE_URL/abort)
check "GET /abort returns 403" "403" "$CODE"

RESP=$(curl -s $BASE_URL/abort)
check "GET /abort body" "forbidden" "$RESP"

CODE=$(curl -s -o /dev/null -w "%{http_code}" $BASE_URL/abort404)
check "GET /abort404 returns 404" "404" "$CODE"

RESP=$(curl -s $BASE_URL/abort404)
check "GET /abort404 body" "not found" "$RESP"

# === Redirect ===
CODE=$(curl -s -o /dev/null -w "%{http_code}" $BASE_URL/redirect)
check "GET /redirect returns 301" "301" "$CODE"

LOCATION=$(curl -s -D - $BASE_URL/redirect 2>&1 | grep -i "location" | tr -d '\r')
check "GET /redirect Location header" "location: /" "$LOCATION"

# === Static files ===
RESP=$(curl -s $BASE_URL/static/index.html)
check "GET /static/index.html" "<h1>static</h1>" "$RESP"

# === Basic auth ===
RESP=$(curl -s -o /dev/null -w "%{http_code}" $BASE_URL/protected)
check "GET /protected without auth returns 401" "401" "$RESP"

RESP=$(curl -s -H "Authorization: Basic d3Jvbmc6cGFzc3dvcmQ=" -o /dev/null -w "%{http_code}" $BASE_URL/protected)
check "GET /protected wrong creds returns 401" "401" "$RESP"

RESP=$(curl -s -H "Authorization: Basic YWRtaW46c2VjcmV0" $BASE_URL/protected)
check "GET /protected correct creds returns handler" "GET request" "$RESP"

# === 404 ===
RESP=$(curl -s $BASE_URL/nonexistent)
check "GET /nonexistent returns 404 message" "nothing at /nonexistent" "$RESP"

# === WebSocket ===
WS_RESULT=$(python3 -c "
import websocket, sys
try:
    ws = websocket.create_connection('ws://127.0.0.1:$PORT/ws', timeout=3)
    msg = ws.recv()
    if 'Welcome to WebSocket!' not in msg:
        print('FAIL')
        sys.exit(1)
    ws.send('hello')
    reply = ws.recv()
    if 'echo: hello' not in reply:
        print('FAIL')
        sys.exit(1)
    ws.close()
    print('PASS')
except Exception as e:
    print('FAIL: ' + str(e))
    sys.exit(1)
" 2>/dev/null)

if [ "$WS_RESULT" = "PASS" ]; then
  pass "WebSocket handshake + echo"
else
  fail "WebSocket handshake + echo" "PASS" "$WS_RESULT"
fi

# Cleanup
kill $SERVER_PID 2>/dev/null || true
sleep 1
kill -9 $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true
rm -f $TEST_APP

echo ""
echo "================"
echo "Results: $TESTS_PASSED passed, $TESTS_FAILED failed, $TESTS_RUN total"

if [ $TESTS_FAILED -gt 0 ]; then
  exit 1
fi
