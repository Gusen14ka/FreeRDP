#pragma once

#include <freerdp/freerdp.h>
#include <freerdp/transport_io.h>
#include "quic_bridge.h"

/* ----------------------------------------------------------------
 * Определение типа PDU по первым байтам
 *
 * RDP использует два формата:
 *
 * Slow-path (TPKT):
 *   [0x03][0x00][2B length][X.224][MCS][Security][RDP PDU]
 *   Первый байт всегда 0x03
 *
 * Fast-path:
 *   [1B header][1-2B length][data]
 *   Первый байт: биты 0-1 = action (0 = fast-path)
 *                биты 2-5 = numEvents (для input) или updateCode
 *                биты 6-7 = секьюрити флаги
 * ---------------------------------------------------------------- */

/* Определить канал для исходящего PDU */
QuicChannel quic_transport_classify_pdu(const uint8_t* buf, size_t len);

/* Установить наши колбэки на транспорт FreeRDP.
 * Вызывать ПОСЛЕ установки соединения (в PostConnect callback).
 * ctx — наш QuicBridgeContext */
BOOL quic_transport_install(freerdp* instance, QuicBridgeContext* ctx);