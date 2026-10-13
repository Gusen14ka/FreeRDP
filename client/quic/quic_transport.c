#include "quic_transport.h"
#include "quic_classify.h"

#include <freerdp/transport_io.h>
#include <freerdp/freerdp.h>
#include <winpr/wlog.h>
#include <freerdp/log.h>

#include <poll.h>
#include <string.h>
#include <stdio.h>


#define TAG CLIENT_TAG("quic")

/* Классификация вынесена в общий quic_classify.h (одна на клиент,
 * прокси и трассировщик). Эта функция оставлена для совместимости API. */
QuicChannel quic_transport_classify_pdu(const uint8_t* buf, size_t len)
{
    return quic_classify_client_pdu(buf, len);
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

    // fprintf(stderr, "[quic_write] first=0x%02x len=%zu -> %s\n",
    //     buf[0], len, QUIC_CHANNEL_NAMES[quic_transport_classify_pdu(buf, len)]);

    QuicChannel ch = quic_transport_classify_pdu(buf, len);

    WLog_DBG(TAG, "[quic_write] len=%-5zu channel=%s\n",
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

    /* Порядок опроса по приоритету: служебные PDU всегда вперёд графики.
     * Фаза финализации RDP (Synchronize/Control/FontMap) требует строгого
     * порядка, а графика может её обогнать и сорвать активацию. */
    static const QuicChannel poll_order[QUIC_CHANNEL_COUNT] = {
        QUIC_CHANNEL_CONTROL,
        QUIC_CHANNEL_VCHANNEL,
        QUIC_CHANNEL_INPUT,
        QUIC_CHANNEL_GRAPHICS
    };

    struct pollfd fds[QUIC_CHANNEL_COUNT];
    for (int i = 0; i < QUIC_CHANNEL_COUNT; i++) {
        fds[i].fd      = bridge->fds[poll_order[i]];
        fds[i].events  = POLLIN;
        fds[i].revents = 0;
    }

    int ready = poll(fds, QUIC_CHANNEL_COUNT, 0);
    if (ready < 0)  return -1;
    if (ready == 0) return 0;

    for (int i = 0; i < QUIC_CHANNEL_COUNT; i++) {
        if (!(fds[i].revents & POLLIN)) continue;

        QuicChannel ch = poll_order[i];

        if (!Stream_EnsureCapacity(s, READ_BUF_SIZE))
            return -1;

        uint8_t* buf = Stream_Buffer(s);
        int n = quic_bridge_read(bridge, ch, buf, READ_BUF_SIZE);
        if (n < 0) return -1;
        if (n == 0) continue;

        Stream_SetPosition(s, n);
        Stream_SealLength(s);
        Stream_ResetPosition(s);

        WLog_DBG(TAG, "[quic_read] channel=%-9s len=%d\n", QUIC_CHANNEL_NAMES[ch], n);
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