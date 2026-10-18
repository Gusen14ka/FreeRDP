#!/bin/sh
# Unit-тесты классификатора и записи трассы. Не требуют сборки FreeRDP.
#   sh client/quic/tests/run_tests.sh
set -e                 # остановиться на первой ошибке
cd "$(dirname "$0")"   # работать из папки tests/, откуда бы ни запустили
Q=..                   # папка с исходниками (client/quic)
OUT=$(mktemp -d)       # временная папка для бинарников тестов
# -fsanitize=address,undefined — AddressSanitizer и UBSan: ловят выход за
# границы буфера и неопределённое поведение прямо во время теста
CFLAGS="-std=gnu11 -Wall -Wextra -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -I$Q"
cc $CFLAGS test_classify.c -o "$OUT/test_classify"                              # классификатор — только заголовок
cc $CFLAGS -pthread test_trace_writer.c "$Q/quic_trace_writer.c" -o "$OUT/test_trace_writer"  # запись + pthread
echo "== классификатор";   "$OUT/test_classify"
echo "== запись трассы";   "$OUT/test_trace_writer"
rm -rf "$OUT"          # убрать временные бинарники
echo "== все тесты пройдены"
