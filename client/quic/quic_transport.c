#include "quic_transport.h"

#include <freerdp/transport_io.h>
#include <freerdp/freerdp.h>

#include <poll.h>
#include <string.h>
#include <stdio.h>

/* Реальные константы из публичных заголовков */
#include <freerdp/crypto/er.h>

/* SEC_* константы нужны для классификации PDU.
 * Они в rdp.h который внутренний.
 * Определяем только те что нам нужны — они не изменятся,
 * это часть протокола RDP зафиксированная в MS-RDPBCGR */
#define QUIC_SEC_EXCHANGE_PKT    0x0001
#define QUIC_SEC_INFO_PKT        0x0040
#define QUIC_SEC_LICENSE_PKT     0x0080
#define QUIC_SEC_AUTODETECT_REQ  0x1000
#define QUIC_SEC_AUTODETECT_RSP  0x2000
#define QUIC_SEC_HEARTBEAT       0x4000

#define QUIC_PDU_TYPE_DATA       0x07

#define QUIC_DATA_PDU_INPUT      0x1C
#define QUIC_DATA_PDU_UPDATE     0x02
#define QUIC_DATA_PDU_POINTER    0x1B

/* Offsets в slow-path PDU */
#define TPKT_X224_SIZE   7   /* TPKT(4) + X.224(3) */
#define MCS_MIN_SIZE     8
#define SEC_HDR_OFFSET   (TPKT_X224_SIZE + MCS_MIN_SIZE)
#define SHARE_CTRL_OFFSET (SEC_HDR_OFFSET + 2)

QuicChannel quic_transport_classify_pdu(const uint8_t* buf, size_t len)
{
    if (len < 2) return QUIC_CHANNEL_CONTROL;

    uint8_t first = buf[0];

    /* Fast-path: биты 0-1 = 0x00
     * На клиентской стороне fast-path = input events */
    if ((first & 0x03) == 0x00)
        return QUIC_CHANNEL_INPUT;

    /* Slow-path: TPKT header */
    if (first != 0x03)
        return QUIC_CHANNEL_CONTROL;

    /* Проверяем Security Flags */
    if (len >= (size_t)(SEC_HDR_OFFSET + 2)) {
        uint16_t sec = (uint16_t)(buf[SEC_HDR_OFFSET] |
                      (buf[SEC_HDR_OFFSET + 1] << 8));

        if (sec & (QUIC_SEC_EXCHANGE_PKT  |
                   QUIC_SEC_INFO_PKT      |
                   QUIC_SEC_LICENSE_PKT   |
                   QUIC_SEC_AUTODETECT_REQ|
                   QUIC_SEC_AUTODETECT_RSP|
                   QUIC_SEC_HEARTBEAT))
            return QUIC_CHANNEL_CONTROL;
    }

    /* Share Control Header */
    if (len >= (size_t)(SHARE_CTRL_OFFSET + 6)) {
        uint16_t pdu_type = (uint16_t)(buf[SHARE_CTRL_OFFSET + 2] |
                            (buf[SHARE_CTRL_OFFSET + 3] << 8));
        pdu_type &= 0x0F;

        if (pdu_type == QUIC_PDU_TYPE_DATA) {
            /* Share Data Header: +9 байт от начала Share Control */
            size_t data_type_off = SHARE_CTRL_OFFSET + 6 + 9;
            if (len > data_type_off) {
                uint8_t data_type = buf[data_type_off];
                if (data_type == QUIC_DATA_PDU_INPUT)
                    return QUIC_CHANNEL_INPUT;
                if (data_type == QUIC_DATA_PDU_UPDATE ||
                    data_type == QUIC_DATA_PDU_POINTER)
                    return QUIC_CHANNEL_GRAPHICS;
            }
            return QUIC_CHANNEL_CONTROL;
        }

        /* Не DATA — служебный */
        return QUIC_CHANNEL_CONTROL;
    }

    /* Виртуальный канал — MCS channelId != GLOBAL */
    if (len > 100) return QUIC_CHANNEL_VCHANNEL;

    return QUIC_CHANNEL_CONTROL;
}

/* ── WritePdu ─────────────────────────────────────────────────── */

static int quic_write_pdu(rdpTransport* transport, wStream* s)
{
    /* transport_get_context — публичная функция из transport_io.h */
    rdpContext* context = transport_get_context(transport);
    if (!context) return -1;

    /* freerdp_get_io_callback_context — публичная */
    QuicBridgeContext* bridge =
        (QuicBridgeContext*)freerdp_get_io_callback_context(context);
    if (!bridge) return -1;

    const uint8_t* buf = Stream_Buffer(s);
    size_t len         = Stream_Length(s);
    if (len == 0) return 0;

    QuicChannel ch = quic_transport_classify_pdu(buf, len);

    fprintf(stderr, "[quic_write] len=%-5zu channel=%s\n",
            len, QUIC_CHANNEL_NAMES[ch]);

    if (quic_bridge_write(bridge, ch, buf, (uint32_t)len) < 0)
        return -1;

    return 1;
}

/* ── ReadPdu ──────────────────────────────────────────────────── */

#define READ_BUF_SIZE (64 * 1024)

static int quic_read_pdu(rdpTransport* transport, wStream* s)
{
    rdpContext* context = transport_get_context(transport);
    if (!context) return -1;

    QuicBridgeContext* bridge =
        (QuicBridgeContext*)freerdp_get_io_callback_context(context);
    if (!bridge) return -1;

    struct pollfd fds[QUIC_CHANNEL_COUNT];
    for (int i = 0; i < QUIC_CHANNEL_COUNT; i++) {
        fds[i].fd      = bridge->fds[i];
        fds[i].events  = POLLIN;
        fds[i].revents = 0;
    }

    int ready = poll(fds, QUIC_CHANNEL_COUNT, 100);
    if (ready < 0)  return -1;
    if (ready == 0) return 0;

    for (int i = 0; i < QUIC_CHANNEL_COUNT; i++) {
        if (!(fds[i].revents & POLLIN)) continue;

        if (!Stream_EnsureCapacity(s, READ_BUF_SIZE))
            return -1;

        uint8_t* buf = Stream_Buffer(s);
        int n = quic_bridge_read(bridge, (QuicChannel)i,
                                 buf, READ_BUF_SIZE);
        if (n < 0) return -1;
        if (n == 0) continue;

        Stream_SetPosition(s, n);
        Stream_SealLength(s);
        Stream_ResetPosition(s);

        fprintf(stderr, "[quic_read] channel=%-9s len=%d\n",
                QUIC_CHANNEL_NAMES[i], n);
        return n;
    }
    return 0;
}

/* ── Установка колбэков ───────────────────────────────────────── */

BOOL quic_transport_install(freerdp* instance, QuicBridgeContext* ctx)
{
    if (!instance || !ctx) return FALSE;

    rdpContext* context = instance->context;

    /* Берём дефолтные колбэки — публичная функция */
    const rdpTransportIo* defaults = freerdp_get_io_callbacks(context);
    if (!defaults) return FALSE;

    rdpTransportIo io;
    memcpy(&io, defaults, sizeof(io));

    /* Заменяем только Read и Write */
    io.ReadPdu  = quic_read_pdu;
    io.WritePdu = quic_write_pdu;

    /* Сохраняем наш контекст — публичная функция */
    freerdp_set_io_callback_context(context, ctx);

    /* Устанавливаем — публичная функция */
    return freerdp_set_io_callbacks(context, &io);
}