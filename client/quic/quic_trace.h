#pragma once

/* ================================================================
 * Трассировщик PDU для обычного (TCP) клиента xfreerdp.
 *
 * Включается переменной окружения:
 *   RDP_TRACE=/путь/trace.csv          — куда писать (обязательно)
 *   RDP_TRACE_META="scenario=... ..."  — строка метаданных в шапку (необязательно)
 * Без RDP_TRACE все функции ничего не делают.
 *
 * Как работает: оборачивает ReadPdu/WritePdu транспорта FreeRDP —
 * те же точки, где форк раскладывает PDU по QUIC-стримам. Каждое целое
 * PDU (уже после TLS) классифицируется тем же quic_classify.h и пишется
 * строкой в CSV (формат — в quic_trace_writer.h).
 *
 * В режиме xfreerdp-quic трасса не пишется: QUIC-транспорт
 * в PostConnect заменяет ReadPdu/WritePdu своими.
 * ================================================================ */

#include <freerdp/freerdp.h>

/* Вызывать в начале PreConnect: открывает трассу и ставит обёртки. */
BOOL quic_trace_pre_connect(freerdp* instance);

/* Вызывать в конце PostConnect: пишет в шапку номера MCS-каналов по именам. */
void quic_trace_post_connect(freerdp* instance);

/* Вызывать в PostDisconnect: сбрасывает и закрывает файл. */
void quic_trace_close(void);
