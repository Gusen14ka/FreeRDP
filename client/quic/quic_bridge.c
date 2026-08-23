#include "quic_bridge.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <endian.h>

/* ----------------------------------------------------------------
 * Вспомогательные функции
 * ---------------------------------------------------------------- */

/* Читаем ровно n байт — повторяем read() пока не получим всё */
static int read_exact(int fd, uint8_t* buf, size_t n)
{
    size_t total = 0;
    while (total < n) {
        ssize_t r = read(fd, buf + total, n - total);
        if (r <= 0) return -1;  /* EOF или ошибка */
        total += (size_t)r;
    }
    return (int)total;
}

/* Пишем ровно n байт */
static int write_exact(int fd, const uint8_t* buf, size_t n)
{
    size_t total = 0;
    while (total < n) {
        ssize_t w = write(fd, buf + total, n - total);
        if (w <= 0) return -1;
        total += (size_t)w;
    }
    return (int)total;
}

/* Строим путь к сокету для канала */
static void channel_socket_path(QuicChannel ch, char* out, size_t out_size)
{
    snprintf(out, out_size, QUIC_BRIDGE_SOCKET_FMT, QUIC_CHANNEL_NAMES[ch]);
}

/* ----------------------------------------------------------------
 * Реализация API
 * ---------------------------------------------------------------- */

QuicBridgeContext* quic_bridge_new(void)
{
    QuicBridgeContext* ctx = calloc(1, sizeof(QuicBridgeContext));
    if (!ctx) return NULL;

    /* Все fd изначально закрыты */
    for (int i = 0; i < QUIC_CHANNEL_COUNT; i++)
        ctx->fds[i] = -1;

    /* Создаём директорию для сокетов */
    mkdir(QUIC_BRIDGE_SOCKET_DIR, 0700);

    return ctx;
}

void quic_bridge_free(QuicBridgeContext* ctx)
{
    if (!ctx) return;
    for (int i = 0; i < QUIC_CHANNEL_COUNT; i++) {
        if (ctx->fds[i] >= 0) {
            close(ctx->fds[i]);
            ctx->fds[i] = -1;
        }
    }
    free(ctx);
}

/* Клиентская сторона — подключаемся к Go клиенту */
int quic_bridge_connect(QuicBridgeContext* ctx)
{
    for (int i = 0; i < QUIC_CHANNEL_COUNT; i++) {
        char path[256];
        channel_socket_path((QuicChannel)i, path, sizeof(path));

        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
            perror("quic_bridge_connect: socket");
            return -1;
        }

        struct sockaddr_un addr = { 0 };
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

        if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            fprintf(stderr, "quic_bridge_connect: connect %s: %s\n",
                    path, strerror(errno));
            close(fd);
            return -1;
        }

        ctx->fds[i] = fd;
        fprintf(stderr, "[bridge] подключён канал %s → fd=%d\n",
                QUIC_CHANNEL_NAMES[i], fd);
    }
    return 0;
}

/* Серверная сторона — слушаем подключения от Go сервера */
int quic_bridge_listen(QuicBridgeContext* ctx)
{
    /* Создаём listener для каждого канала */
    int listeners[QUIC_CHANNEL_COUNT];

    for (int i = 0; i < QUIC_CHANNEL_COUNT; i++) {
        char path[256];
        channel_socket_path((QuicChannel)i, path, sizeof(path));

        /* Удаляем старый сокет если был */
        unlink(path);

        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
            perror("quic_bridge_listen: socket");
            return -1;
        }

        struct sockaddr_un addr = { 0 };
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

        if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            fprintf(stderr, "quic_bridge_listen: bind %s: %s\n",
                    path, strerror(errno));
            close(fd);
            return -1;
        }

        listen(fd, 1);
        listeners[i] = fd;
        fprintf(stderr, "[bridge] слушаем канал %s на %s\n",
                QUIC_CHANNEL_NAMES[i], path);
    }

    /* Принимаем подключения */
    for (int i = 0; i < QUIC_CHANNEL_COUNT; i++) {
        ctx->fds[i] = accept(listeners[i], NULL, NULL);
        if (ctx->fds[i] < 0) {
            perror("quic_bridge_listen: accept");
            return -1;
        }
        close(listeners[i]);
        fprintf(stderr, "[bridge] принят канал %s → fd=%d\n",
                QUIC_CHANNEL_NAMES[i], ctx->fds[i]);
    }

    return 0;
}

/* Записать PDU: [4B length LE][data] */
int quic_bridge_write(QuicBridgeContext* ctx, QuicChannel ch,
                      const uint8_t* buf, uint32_t len)
{
    if (ctx->fds[ch] < 0) return -1;

    /* Wire format: length в little-endian */
    uint32_t le_len = htole32(len);

    if (write_exact(ctx->fds[ch], (uint8_t*)&le_len, 4) < 0)
        return -1;
    if (write_exact(ctx->fds[ch], buf, len) < 0)
        return -1;

    return (int)len;
}

/* Прочитать один PDU */
int quic_bridge_read(QuicBridgeContext* ctx, QuicChannel ch,
                     uint8_t* buf, uint32_t buf_size)
{
    if (ctx->fds[ch] < 0) return -1;

    /* Читаем длину */
    uint32_t le_len = 0;
    if (read_exact(ctx->fds[ch], (uint8_t*)&le_len, 4) < 0)
        return -1;

    uint32_t len = le32toh(le_len);

    if (len > buf_size) {
        fprintf(stderr, "[bridge] PDU слишком большой: %u > %u\n",
                len, buf_size);
        return -1;
    }

    if (read_exact(ctx->fds[ch], buf, len) < 0)
        return -1;

    return (int)len;
}