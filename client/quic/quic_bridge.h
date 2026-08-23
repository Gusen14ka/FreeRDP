#pragma once

#include <stdint.h>
#include <stddef.h>

/* ================================================================
 * Wire format для Unix domain sockets:
 * [4B uint32_t length][length байт данных]
 *
 * length — размер RDP PDU в байтах
 * Это гарантирует целостность пакетов при параллельной записи
 * ================================================================ */

/* Типы каналов — каждый идёт в отдельный Unix сокет / QUIC стрим */
typedef enum {
    QUIC_CHANNEL_GRAPHICS  = 0,  /* fast-path графика, slow-path обновления */
    QUIC_CHANNEL_INPUT     = 1,  /* fast-path ввод (мышь, клавиатура)       */
    QUIC_CHANNEL_VCHANNEL  = 2,  /* виртуальные каналы (cliprdr, rdpdr...) */
    QUIC_CHANNEL_CONTROL   = 3,  /* служебные PDU (nego, MCS, license...)   */
    QUIC_CHANNEL_COUNT     = 4
} QuicChannel;

/* Контекст bridge — держит fd для каждого канала */
typedef struct {
    int fds[QUIC_CHANNEL_COUNT];  /* Unix socket fd, -1 если не подключён */
} QuicBridgeContext;

/* Директория для Unix сокетов */
#define QUIC_BRIDGE_SOCKET_DIR  "/tmp/rdp_quic_bridge"
#define QUIC_BRIDGE_SOCKET_FMT  QUIC_BRIDGE_SOCKET_DIR "/%s.sock"

/* Имена сокетов по каналу */
static const char* const QUIC_CHANNEL_NAMES[QUIC_CHANNEL_COUNT] = {
    "graphics",
    "input",
    "vchannel",
    "control",
};

/* ----------------------------------------------------------------
 * API
 * ---------------------------------------------------------------- */

/* Инициализация — создаёт директорию, обнуляет fd */
QuicBridgeContext* quic_bridge_new(void);
void               quic_bridge_free(QuicBridgeContext* ctx);

/* Подключиться к Go клиенту (клиентская сторона форка)
 * Go клиент должен уже слушать на Unix сокетах */
int quic_bridge_connect(QuicBridgeContext* ctx);

/* Слушать входящие подключения от Go сервера (серверная сторона форка)
 * Блокирует пока все каналы не подключатся */
int quic_bridge_listen(QuicBridgeContext* ctx);

/* Записать PDU в нужный канал (с wire format заголовком) */
int quic_bridge_write(QuicBridgeContext* ctx, QuicChannel ch,
                      const uint8_t* buf, uint32_t len);

/* Прочитать один PDU из канала (блокирующий)
 * Возвращает количество байт или -1 при ошибке
 * buf должен быть достаточно большим (рекомендуется 65536) */
int quic_bridge_read(QuicBridgeContext* ctx, QuicChannel ch,
                     uint8_t* buf, uint32_t buf_size);