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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "quic_bridge.h"
#include "quic_transport.h"

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
    int exit_code = 1;

    RDP_CLIENT_ENTRY_POINTS entry_points = { 0 };
    entry_points.Size = sizeof(RDP_CLIENT_ENTRY_POINTS);
    entry_points.Version = RDP_CLIENT_INTERFACE_VERSION;
    RdpClientEntry(&entry_points);

    freerdp* instance = freerdp_new();
    if (!instance) {
        fprintf(stderr, "freerdp_new() failed\n");
        return 1;
    }

    g_instance = instance;
    signal(SIGINT, handle_sigint);

    instance->ContextSize = entry_points.ContextSize;
    orig_context_new  = entry_points.ClientNew;
    orig_context_free = entry_points.ClientFree;
    instance->ContextNew  = quic_wrapped_context_new;
    instance->ContextFree = quic_wrapped_context_free;

    /* PreConnect/PostConnect/PostDisconnect тут НЕ выставляем — их
     * расставит quic_wrapped_context_new после вызова оригинального
     * X11 ContextNew */

    if (!freerdp_context_new(instance)) {
        fprintf(stderr, "freerdp_context_new() failed\n");
        goto cleanup;
    }

    if (freerdp_client_settings_parse_command_line(
            instance->context->settings, argc, argv, FALSE) < 0) {
        fprintf(stderr, "Ошибка парсинга аргументов\n");
        goto cleanup_context;
    }

    fprintf(stderr, "[client] Подключаемся к %s...\n",
            freerdp_settings_get_string(instance->context->settings,
                                        FreeRDP_ServerHostname));

    if (!freerdp_connect(instance)) {
        fprintf(stderr, "[client] Не удалось подключиться\n");
        goto cleanup_context;
    }

    fprintf(stderr, "[client] Соединение установлено, запускаем основной цикл\n");

    while (!freerdp_shall_disconnect_context(instance->context)) {
        DWORD status = freerdp_check_event_handles(instance->context);
        if (status == WAIT_FAILED) {
            fprintf(stderr, "[client] freerdp_check_event_handles() failed\n");
            break;
        }
    }

    freerdp_disconnect(instance);
    exit_code = 0;

cleanup_context:
    freerdp_context_free(instance);
cleanup:
    freerdp_free(instance);
    g_instance = NULL;
    return exit_code;
}