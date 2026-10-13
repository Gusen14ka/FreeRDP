#!/bin/sh
# Unit-тесты классификатора и записи трассы. Не требуют сборки FreeRDP.
#   sh client/quic/tests/run_tests.sh
set -e
cd "$(dirname "$0")"
Q=..
OUT=$(mktemp -d)
CFLAGS="-std=gnu11 -Wall -Wextra -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -I$Q"
cc $CFLAGS test_classify.c -o "$OUT/test_classify"
cc $CFLAGS -pthread test_trace_writer.c "$Q/quic_trace_writer.c" -o "$OUT/test_trace_writer"
echo "== классификатор";   "$OUT/test_classify"
echo "== запись трассы";   "$OUT/test_trace_writer"
rm -rf "$OUT"
echo "== все тесты пройдены"
