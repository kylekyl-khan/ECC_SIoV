#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# 允許傳入任意參數，預設值如下
COUNT="${COUNT:-3}"
MSIZE="${MSIZE:-64}"
VERIFY="${VERIFY:-on}"
TRACE="${TRACE:-off}"
RBITS="${RBITS:-160}"
QBITS="${QBITS:-512}"

make -s
echo "[RUN] count=$COUNT msize=$MSIZE verify=$VERIFY trace=$TRACE rbits=$RBITS qbits=$QBITS"
./bin/siov --count "$COUNT" --message-size "$MSIZE" --verify "$VERIFY" --trace "$TRACE" \
           --rbits "$RBITS" --qbits "$QBITS"
