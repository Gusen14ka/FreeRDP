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
#include <freerdp/client/cmdline.h>
#include <freerdp/client.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "quic_bridge.h"
#include "quic_transport.h"

/* Глобально для signal handler */
static freerdp* g_instance = NULL;

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
    QuicClientContext* ctx = (QuicClientContext*)instance->context;

    fprintf(stderr, "[client] PreConnect: подключаемся к Go клиенту...\n");

    /* Подключаемся к Unix сокетам Go клиента */
    if (quic_bridge_connect(ctx->bridge) < 0) {
        fprintf(stderr, "[client] ОШИБКА: не могу подключиться к Go клиенту\n");
        fprintf(stderr, "[client] Убедись что Go клиент запущен и слушает на %s\n",
                QUIC_BRIDGE_SOCKET_DIR);
        return FALSE;
    }

    fprintf(stderr, "[client] Подключён к Go клиенту (все %d каналов)\n",
            QUIC_CHANNEL_COUNT);
    return TRUE;
}

static BOOL quic_client_post_connect(freerdp* instance)
{
    QuicClientContext* ctx = (QuicClientContext*)instance->context;

    fprintf(stderr, "[client] PostConnect: устанавливаем QUIC транспорт\n");

    /*
     * Здесь TLS handshake уже завершён и соединение установлено.
     * Подменяем ReadPdu/WritePdu на наши реализации.
     * С этого момента весь трафик идёт через Unix сокеты → QUIC.
     */
    if (!quic_transport_install(instance, ctx->bridge)) {
        fprintf(stderr, "[client] ОШИБКА: не могу установить QUIC транспорт\n");
        return FALSE;
    }

    fprintf(stderr, "[client] QUIC транспорт активен\n");
    return TRUE;
}

static void quic_client_post_disconnect(freerdp* instance)
{
    fprintf(stderr, "[client] PostDisconnect\n");
    (void)instance;
}

/* ── Размер нашего контекста для FreeRDP ─────────────────────── */

static int quic_client_context_size(freerdp* instance)
{
    (void)instance;
    return sizeof(QuicClientContext);
}

static BOOL quic_client_context_new(freerdp* instance, rdpContext* context)
{
    QuicClientContext* ctx = (QuicClientContext*)context;

    ctx->bridge = quic_bridge_new();
    if (!ctx->bridge) {
        fprintf(stderr, "[client] ОШИБКА: не могу создать bridge\n");
        return FALSE;
    }

    return TRUE;
}

static void quic_client_context_free(freerdp* instance, rdpContext* context)
{
    QuicClientContext* ctx = (QuicClientContext*)context;
    quic_bridge_free(ctx->bridge);
}

/* ── main ─────────────────────────────────────────────────────── */

int main(int argc, char** argv)
{
    int exit_code = 1;

    /* Создаём экземпляр FreeRDP */
    freerdp* instance = freerdp_new();
    if (!instance) {
        fprintf(stderr, "freerdp_new() failed\n");
        return 1;
    }

    g_instance = instance;
    signal(SIGINT, handle_sigint);

    /* Регистрируем наш контекст и callbacks */
    instance->ContextSize      = quic_client_context_size(instance);
    instance->ContextNew       = quic_client_context_new;
    instance->ContextFree      = quic_client_context_free;
    instance->PreConnect       = quic_client_pre_connect;
    instance->PostConnect      = quic_client_post_connect;
    instance->PostDisconnect   = quic_client_post_disconnect;

    /* Аллоцируем контекст */
    if (!freerdp_context_new(instance)) {
        fprintf(stderr, "freerdp_context_new() failed\n");
        goto cleanup;
    }

    /* Парсим аргументы командной строки
     * Пример: xfreerdp-quic /v:target-host /u:user /p:pass
     * Параметры те же что у стандартного xfreerdp */
    if (freerdp_client_settings_parse_command_line(
            instance->context->settings, argc, argv, FALSE) < 0) {
        fprintf(stderr, "Ошибка парсинга аргументов\n");
        fprintf(stderr, "Использование: %s /v:хост /u:пользователь /p:пароль\n", argv[0]);
        goto cleanup_context;
    }

    fprintf(stderr, "[client] Подключаемся к %s...\n",
            freerdp_settings_get_string(instance->context->settings,
                                        FreeRDP_ServerHostname));

    /* Подключаемся — это запускает PreConnect → negotiate → TLS → PostConnect */
    if (!freerdp_connect(instance)) {
        fprintf(stderr, "[client] Не удалось подключиться\n");
        goto cleanup_context;
    }

    fprintf(stderr, "[client] Соединение установлено, запускаем основной цикл\n");

    /* Основной цикл — обрабатывает события пока соединение живо */
    while (!freerdp_shall_disconnect_context(instance->context)) {
        /*
         * freerdp_check_event_handles проверяет:
         * - входящие PDU (вызывает наш ReadPdu)
         * - события от оконной системы (X11/Wayland)
         * - таймауты
         */
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