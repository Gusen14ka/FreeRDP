/*
 * freerdp-quic-proxy — серверная сторона на целевой машине.
 *
 * Запускается рядом с xrdp / Windows RDS.
 * Принимает данные от Go сервера через Unix сокеты
 * и проксирует их в локальный RDP сервер по TCP.
 *
 * Flow:
 *   1. Слушаем на Unix сокетах (ждём Go сервер)
 *   2. Подключаемся к локальному RDP серверу (localhost:3389)
 *   3. Для каждого канала запускаем горутину read→write
 *   4. Работаем пока соединение живо
 *
 * Не использует FreeRDP — только Unix сокеты и BSD сокеты.
 * Целостность пакетов гарантируется wire format ([4B len][data])
 * и мьютексом на запись в TCP.
 */

#include "quic_bridge.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>

#define DEFAULT_RDP_HOST "127.0.0.1"
#define DEFAULT_RDP_PORT 3389
#define PDU_BUF_SIZE     (64 * 1024)

/* ── Контекст прокси ─────────────────────────────────────────── */

typedef struct {
    QuicBridgeContext* bridge;
    int                tcp_fd;       /* соединение к RDP серверу */
    pthread_mutex_t    write_lock;   /* мьютекс на запись в TCP  */
    int                running;      /* флаг работы              */
} ProxyContext;

static ProxyContext g_proxy = { 0 };

/* ── TCP подключение к RDP серверу ───────────────────────────── */

static int connect_to_rdp(const char* host, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    /* TCP_NODELAY — без буферизации, важно для RDP */
    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    struct sockaddr_in addr = { 0 };
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = inet_addr(host);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[proxy] Не могу подключиться к %s:%d: %s\n",
                host, port, strerror(errno));
        close(fd);
        return -1;
    }

    fprintf(stderr, "[proxy] Подключён к RDP серверу %s:%d\n", host, port);
    return fd;
}

/* ── Запись в TCP под мьютексом ──────────────────────────────── */

static int proxy_write_tcp(ProxyContext* ctx, const uint8_t* buf, size_t len)
{
    pthread_mutex_lock(&ctx->write_lock);

    size_t total = 0;
    while (total < len) {
        ssize_t w = write(ctx->tcp_fd, buf + total, len - total);
        if (w <= 0) {
            pthread_mutex_unlock(&ctx->write_lock);
            return -1;
        }
        total += (size_t)w;
    }

    pthread_mutex_unlock(&ctx->write_lock);
    return (int)total;
}

/* ── Горутина для одного канала: Unix сокет → TCP ────────────── */

typedef struct {
    ProxyContext* proxy;
    QuicChannel   channel;
} ChannelThreadArg;

static void* channel_thread(void* arg)
{
    ChannelThreadArg* a = (ChannelThreadArg*)arg;
    ProxyContext*     ctx = a->proxy;
    QuicChannel       ch  = a->channel;
    free(arg);

    uint8_t* buf = malloc(PDU_BUF_SIZE);
    if (!buf) {
        fprintf(stderr, "[proxy:%s] malloc failed\n", QUIC_CHANNEL_NAMES[ch]);
        return NULL;
    }

    fprintf(stderr, "[proxy:%s] поток запущен\n", QUIC_CHANNEL_NAMES[ch]);

    while (ctx->running) {
        /* Читаем один PDU из Unix сокета ([4B len][data]) */
        int n = quic_bridge_read(ctx->bridge, ch, buf, PDU_BUF_SIZE);
        if (n < 0) {
            fprintf(stderr, "[proxy:%s] read error, завершаем\n",
                    QUIC_CHANNEL_NAMES[ch]);
            ctx->running = 0;
            break;
        }
        if (n == 0) continue;

        fprintf(stderr, "[proxy:%s] → TCP %d байт\n", QUIC_CHANNEL_NAMES[ch], n);

        /* Пишем в TCP под мьютексом */
        if (proxy_write_tcp(ctx, buf, (size_t)n) < 0) {
            fprintf(stderr, "[proxy:%s] TCP write error\n", QUIC_CHANNEL_NAMES[ch]);
            ctx->running = 0;
            break;
        }
    }

    free(buf);
    return NULL;
}

/* ── Signal handler ───────────────────────────────────────────── */

static void handle_sigint(int sig)
{
    (void)sig;
    g_proxy.running = 0;
}

/* ── main ─────────────────────────────────────────────────────── */

int main(int argc, char** argv)
{
    const char* rdp_host = DEFAULT_RDP_HOST;
    int         rdp_port = DEFAULT_RDP_PORT;

    /* Простой парсинг аргументов */
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--host=", 7) == 0)
            rdp_host = argv[i] + 7;
        else if (strncmp(argv[i], "--port=", 7) == 0)
            rdp_port = atoi(argv[i] + 7);
        else if (strcmp(argv[i], "--help") == 0) {
            printf("Использование: %s [--host=IP] [--port=PORT]\n", argv[0]);
            printf("  --host  IP адрес RDP сервера (default: %s)\n", DEFAULT_RDP_HOST);
            printf("  --port  порт RDP сервера (default: %d)\n", DEFAULT_RDP_PORT);
            return 0;
        }
    }

    signal(SIGINT,  handle_sigint);
    signal(SIGTERM, handle_sigint);
    signal(SIGPIPE, SIG_IGN); /* игнорируем SIGPIPE при обрыве соединения */

    /* Инициализация */
    g_proxy.bridge  = quic_bridge_new();
    g_proxy.running = 1;
    pthread_mutex_init(&g_proxy.write_lock, NULL);

    if (!g_proxy.bridge) {
        fprintf(stderr, "[proxy] ОШИБКА: quic_bridge_new() failed\n");
        return 1;
    }

    fprintf(stderr, "[proxy] Ждём подключения Go сервера...\n");

    /* Слушаем Unix сокеты — блокирует пока Go сервер не подключится */
    if (quic_bridge_listen(g_proxy.bridge) < 0) {
        fprintf(stderr, "[proxy] ОШИБКА: quic_bridge_listen() failed\n");
        return 1;
    }

    fprintf(stderr, "[proxy] Go сервер подключён, соединяемся с RDP...\n");

    /* Подключаемся к локальному RDP серверу */
    g_proxy.tcp_fd = connect_to_rdp(rdp_host, rdp_port);
    if (g_proxy.tcp_fd < 0) {
        fprintf(stderr, "[proxy] ОШИБКА: не могу подключиться к RDP\n");
        return 1;
    }

    /* Запускаем поток для каждого канала */
    pthread_t threads[QUIC_CHANNEL_COUNT];
    for (int i = 0; i < QUIC_CHANNEL_COUNT; i++) {
        ChannelThreadArg* arg = malloc(sizeof(ChannelThreadArg));
        arg->proxy   = &g_proxy;
        arg->channel = (QuicChannel)i;

        if (pthread_create(&threads[i], NULL, channel_thread, arg) != 0) {
            fprintf(stderr, "[proxy] pthread_create failed для канала %s\n",
                    QUIC_CHANNEL_NAMES[i]);
            g_proxy.running = 0;
            break;
        }
    }

    fprintf(stderr, "[proxy] Все каналы запущены, работаем...\n");

    /* Ждём завершения всех потоков */
    for (int i = 0; i < QUIC_CHANNEL_COUNT; i++)
        pthread_join(threads[i], NULL);

    fprintf(stderr, "[proxy] Завершение\n");

    close(g_proxy.tcp_fd);
    quic_bridge_free(g_proxy.bridge);
    pthread_mutex_destroy(&g_proxy.write_lock);

    return 0;
}