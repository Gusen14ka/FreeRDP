/*
 * xfreerdp-quic — клиентская сторона.
 *
 * Запускается на машине пользователя.
 * Подключается к целевой машине через QUIC multistream
 * вместо обычного TCP.
 *
 * Flow:
 *   1. Парсим аргументы (хост, порт, user, pass)
 *   2. Создаём QuicBridgeContext
 *   3. Подключаемся к Go клиенту через Unix сокеты
 *   4. Инициализируем FreeRDP
 *   5. В PostConnect подменяем transport->io
 *   6. Запускаем основной цикл FreeRDP
 */

#include <freerdp/freerdp.h>
#include <freerdp/client.h>
#include <freerdp/channels/channels.h>
#include <winpr/synch.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "quic_bridge.h"
#include "quic_transport.h"

static HANDLE g_bridge_events[QUIC_CHANNEL_COUNT] = { 0 };

/* Хендл нужен только чтобы разбудить цикл. Само чтение сделает
 * transport_check_fds → quic_read_pdu на следующем проходе. */
static BOOL quic_bridge_event_cb(rdpContext* context, void* userdata)
{
    (void)context;
    (void)userdata;
    return TRUE;
}

/* Глобально для signal handler */
static freerdp* g_instance = NULL;

/* RdpClientEntry реализована в client/X11/xf_client.c — публичного
 * заголовка для неё нет (внутренний header X11-клиента), но сама функция
 * экспортируется из freerdp-client-x11 с обычной C-линковкой, поэтому
 * достаточно верного forward declaration без включения приватного .h */
extern int RdpClientEntry(RDP_CLIENT_ENTRY_POINTS* pEntryPoints);

/* Сохранённые "родные" X11-колбэки */
static BOOL (*orig_pre_connect)(freerdp*) = NULL;
static BOOL (*orig_post_connect)(freerdp*) = NULL;
static void (*orig_post_disconnect)(freerdp*) = NULL;
static BOOL (*orig_context_new)(freerdp*, rdpContext*) = NULL;
static void (*orig_context_free)(freerdp*, rdpContext*) = NULL;

static void handle_sigint(int sig)
{
    (void)sig;
    if (g_instance)
        freerdp_abort_connect_context(g_instance->context);
}

/* ── Контекст нашего клиента ─────────────────────────────────── */

typedef struct {
    rdpClientContext common;   /* ДОЛЖЕН быть первым полем */
    QuicBridgeContext* bridge;
} QuicClientContext;

/* ── Callbacks ───────────────────────────────────────────────── */

static BOOL quic_client_pre_connect(freerdp* instance)
{
    QuicBridgeContext* bridge =
        (QuicBridgeContext*)freerdp_get_io_callback_context(instance->context);

    fprintf(stderr, "[client] PreConnect: подключаемся к Go клиенту...\n");
    if (quic_bridge_connect(bridge) < 0) {
        fprintf(stderr, "[client] ОШИБКА: не могу подключиться к Go клиенту\n");
        fprintf(stderr, "[client] Убедись что Go клиент запущен и слушает на %s\n",
                QUIC_BRIDGE_SOCKET_DIR);
        return FALSE;
    }
    fprintf(stderr, "[client] Подключён к Go клиенту (все %d каналов)\n",
            QUIC_CHANNEL_COUNT);

    /* Родной X11 PreConnect — тут создаётся окно и т.п. */
    if (orig_pre_connect && !orig_pre_connect(instance))
        return FALSE;

    return TRUE;
}

static BOOL quic_client_post_connect(freerdp* instance)
{
    QuicBridgeContext* bridge =
        (QuicBridgeContext*)freerdp_get_io_callback_context(instance->context);

    /* Родной X11 PostConnect — инициализация GDI, отрисовка первого кадра */
    if (orig_post_connect && !orig_post_connect(instance))
        return FALSE;

    fprintf(stderr, "[client] PostConnect: устанавливаем QUIC транспорт\n");
    if (!quic_transport_install(instance, bridge)) {
        fprintf(stderr, "[client] ОШИБКА: не могу установить QUIC транспорт\n");
        return FALSE;
    }

    for (int i = 0; i < QUIC_CHANNEL_COUNT; i++) {
        g_bridge_events[i] = CreateFileDescriptorEvent(NULL, FALSE, FALSE,
                                                       bridge->fds[i], WINPR_FD_READ);
        if (!g_bridge_events[i]) {
            fprintf(stderr, "[client] ОШИБКА: хендл для канала %s\n", QUIC_CHANNEL_NAMES[i]);
            return FALSE;
        }
        if (!freerdp_client_channel_register(instance->context->channels,
                                             g_bridge_events[i], quic_bridge_event_cb, NULL)) {
            fprintf(stderr, "[client] ОШИБКА: не удалось зарегистрировать хендл %s\n",
                    QUIC_CHANNEL_NAMES[i]);
            return FALSE;
                                             }
    }

    const uint8_t ready_marker[] = "QUICMUX_READY";
    if (quic_bridge_write(bridge, QUIC_CHANNEL_CONTROL,
                           ready_marker, sizeof(ready_marker) - 1) < 0) {
        fprintf(stderr, "[client] ОШИБКА: не удалось отправить READY маркер\n");
        return FALSE;
                           }

    fprintf(stderr, "[client] QUIC транспорт активен\n");
    return TRUE;
}

static void quic_client_post_disconnect(freerdp* instance)
{
    for (int i = 0; i < QUIC_CHANNEL_COUNT; i++) {
        if (g_bridge_events[i]) {
            freerdp_client_channel_unregister(instance->context->channels, g_bridge_events[i]);
            CloseHandle(g_bridge_events[i]);
            g_bridge_events[i] = NULL;
        }
    }

    fprintf(stderr, "[client] PostDisconnect\n");
    if (orig_post_disconnect)
        orig_post_disconnect(instance);
}

/* ── Размер нашего контекста для FreeRDP ─────────────────────── */

static int quic_client_context_size(freerdp* instance)
{
    (void)instance;
    return sizeof(QuicClientContext);
}

static BOOL quic_wrapped_context_new(freerdp* instance, rdpContext* context)
{
    /* Сначала — родной X11 ContextNew. Он аллоцирует xfContext (гораздо
     * больше нашего старого QuicClientContext — Display*, Window и т.д.)
     * и попутно сам выставляет instance->PreConnect/PostConnect/
     * PostDisconnect на xf_pre_connect/xf_post_connect/xf_post_disconnect */
    if (orig_context_new && !orig_context_new(instance, context))
        return FALSE;

    /* Захватываем то, что он только что выставил, и подменяем на свои
     * обёртки, которые вызывают эти же оригиналы первым делом */
    orig_pre_connect     = instance->PreConnect;
    orig_post_connect    = instance->PostConnect;
    orig_post_disconnect = instance->PostDisconnect;

    instance->PreConnect     = quic_client_pre_connect;
    instance->PostConnect    = quic_client_post_connect;
    instance->PostDisconnect = quic_client_post_disconnect;

    QuicBridgeContext* bridge = quic_bridge_new();
    if (!bridge) {
        fprintf(stderr, "[client] ОШИБКА: не могу создать bridge\n");
        return FALSE;
    }
    freerdp_set_io_callback_context(context, bridge);

    return TRUE;
}

static void quic_wrapped_context_free(freerdp* instance, rdpContext* context)
{
    QuicBridgeContext* bridge =
        (QuicBridgeContext*)freerdp_get_io_callback_context(context);
    if (bridge)
        quic_bridge_free(bridge);

    if (orig_context_free)
        orig_context_free(instance, context);
}

/* ── main ─────────────────────────────────────────────────────── */

int main(int argc, char** argv)
{
    int rc = 1;

    RDP_CLIENT_ENTRY_POINTS ep = { 0 };
    ep.Size = sizeof(ep);
    ep.Version = RDP_CLIENT_INTERFACE_VERSION;
    if (RdpClientEntry(&ep) != 0) {
        fprintf(stderr, "RdpClientEntry() failed\n");
        return 1;
    }

    /* Подменяем ClientNew/ClientFree на наши обёртки. Родной X11 ClientNew
     * вызовется внутри них и расставит xf_pre_connect/xf_post_connect,
     * а мы поверх навесим логику моста — как и раньше */
    orig_context_new  = ep.ClientNew;
    orig_context_free = ep.ClientFree;
    ep.ClientNew  = quic_wrapped_context_new;
    ep.ClientFree = quic_wrapped_context_free;

    rdpContext* context = freerdp_client_context_new(&ep);
    if (!context) {
        fprintf(stderr, "freerdp_client_context_new() failed\n");
        return 1;
    }

    g_instance = context->instance;
    signal(SIGINT, handle_sigint);

    if (freerdp_client_settings_parse_command_line(context->settings, argc, argv, FALSE) < 0) {
        fprintf(stderr, "Ошибка парсинга аргументов\n");
        goto out;
    }

    fprintf(stderr, "[client] Подключаемся к %s...\n",
            freerdp_settings_get_string(context->settings, FreeRDP_ServerHostname));

    /* Запускает xf_client_thread: он сам делает freerdp_connect и крутит
     * полноценный цикл — RDP-события + события X-сервера (ввод, ресайз) */
    if (freerdp_client_start(context) != 0) {
        fprintf(stderr, "[client] freerdp_client_start() failed\n");
        goto out;
    }

    HANDLE thread = freerdp_client_get_thread(context);
    if (thread) {
        WaitForSingleObject(thread, INFINITE);
        DWORD code = 0;
        GetExitCodeThread(thread, &code);
        rc = (int)code;
    }

    freerdp_client_stop(context);

    out:
        freerdp_client_context_free(context);
    g_instance = NULL;
    return rc;
}