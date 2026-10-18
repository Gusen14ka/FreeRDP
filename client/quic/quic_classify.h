#pragma once /* защита от повторного включения заголовка */

/* ================================================================
 * Классификация RDP PDU по каналам QUIC — единственный источник истины.
 *
 * PDU (Protocol Data Unit) — одно целое сообщение протокола RDP.
 * Форк раскладывает PDU по четырём потокам (QUIC-стримам):
 * graphics / input / vchannel / control. Решает, куда какое PDU,
 * только этот файл.
 *
 * Кто его использует:
 *   - клиент форка (quic_transport.c), направление клиент -> сервер;
 *   - модуль прокси quicmux, направление сервер -> клиент;
 *   - трассировщик (quic_trace.c), оба направления.
 * Так все три гарантированно делят поток одинаково.
 *
 * Всё header-only (функции static inline прямо в заголовке): файл можно
 * включать в любую цель сборки без конфликтов символов и без
 * зависимости от FreeRDP — поэтому он тестируется отдельно (tests/).
 *
 * Как устроено slow-path PDU (MS-RDPBCGR — спецификация RDP):
 *   TPKT(4) + X.224(3)                — транспортные заголовки, всегда 7 байт
 *   MCS Send Data: тип(1) initiator(2) channelId(2) priority(1) длина PER(1 или 2)
 *                                       MCS — слой, нумерующий каналы RDP
 *   [Security header, 4 байта: flags(2) flagsHi(2)] — есть НЕ всегда:
 *        при TLS/NLA и при уровне шифрования NONE у данных его нет,
 *        у лицензирования и служебных пакетов — есть
 *   Share Control: totalLength(2) pduType(2) pduSource(2)
 *   Share Data:    shareId(4) pad(1) streamId(1) uncompressedLength(2) pduType2(1) ...
 * Наличие security header определяется по данным: Share Control header
 * узнаётся по totalLength == оставшейся длине и корректному pduType.
 *
 * Fast-path PDU — укороченный формат без TPKT/MCS: первый байт с
 * младшими битами 00. Сервер шлёт так обновления экрана, клиент — ввод.
 * ================================================================ */

#include <stdint.h> /* uint8_t, uint16_t */
#include <stddef.h> /* size_t */

#include "quic_bridge.h" /* enum QuicChannel и имена каналов QUIC_CHANNEL_NAMES */

/* SEC_* флаги security header (MS-RDPBCGR 2.2.8.1.1.2.1). Сами константы
 * лежат во внутреннем rdp.h FreeRDP, поэтому продублированы здесь. */
#define QUIC_SEC_EXCHANGE_PKT    0x0001 /* обмен ключами шифрования */
#define QUIC_SEC_INFO_PKT        0x0040 /* Client Info (логин, настройки) */
#define QUIC_SEC_LICENSE_PKT     0x0080 /* лицензирование */
#define QUIC_SEC_AUTODETECT_REQ  0x1000 /* измерение сети: запрос */
#define QUIC_SEC_AUTODETECT_RSP  0x2000 /* измерение сети: ответ */
#define QUIC_SEC_HEARTBEAT       0x4000 /* «я жив» от сервера */
/* Любой из этих флагов означает служебный пакет -> поток control */
#define QUIC_SEC_CONTROL_FLAGS                                                    \
	(QUIC_SEC_EXCHANGE_PKT | QUIC_SEC_INFO_PKT | QUIC_SEC_LICENSE_PKT |          \
	 QUIC_SEC_AUTODETECT_REQ | QUIC_SEC_AUTODETECT_RSP | QUIC_SEC_HEARTBEAT)

/* Share Control pduType (младшие 4 бита) и версия (старшие биты = 0x10) */
#define QUIC_PDU_TYPE_DEMAND_ACTIVE  0x01 /* сервер: «вот мои возможности» */
#define QUIC_PDU_TYPE_CONFIRM_ACTIVE 0x03 /* клиент: «вот мои возможности» */
#define QUIC_PDU_TYPE_DEACTIVATE_ALL 0x06 /* сервер: сброс сессии */
#define QUIC_PDU_TYPE_DATA           0x07 /* обычные данные — смотрим pduType2 */
#define QUIC_PDU_TYPE_SERVER_REDIR   0x0A /* перенаправление на другой сервер */
#define QUIC_PDU_TYPE_VERSION        0x0010 /* поле версии, всегда 1 */

/* Share Data pduType2 — что именно за данные */
#define QUIC_DATA_PDU_INPUT      0x1C /* ввод (slow-path): мышь/клавиатура */
#define QUIC_DATA_PDU_UPDATE     0x02 /* обновление экрана */
#define QUIC_DATA_PDU_POINTER    0x1B /* курсор мыши */

#define QUIC_MCS_IO_CHANNEL 1003  /* основной канал RDP; остальные номера — виртуальные каналы */
#define QUIC_MCS_SDRQ       25    /* Send Data Request: клиент -> сервер */
#define QUIC_MCS_SDIN       26    /* Send Data Indication: сервер -> клиент */

#define QUIC_TPKT_X224_SIZE 7     /* TPKT(4) + X.224(3) */
#define QUIC_SEC_HDR_SIZE   4     /* flags(2) + flagsHi(2) */
#define QUIC_SHARE_CTRL_SIZE 6    /* totalLength(2) + pduType(2) + pduSource(2) */
#define QUIC_SHARE_DATA_PDUTYPE2_OFF 8 /* pduType2 от начала Share Data header */

/* Прочитать 16-битное число little-endian (младший байт первым) */
static inline uint16_t quic_le16(const uint8_t* p)
{
	return (uint16_t)(p[0] | (p[1] << 8)); /* младший байт | старший << 8 */
}

/* Номер MCS-канала slow-path PDU (Send Data Request/Indication),
 * или -1, если PDU fast-path / не MCS Send Data / слишком короткий.
 * Раскладка: TPKT(4) + X.224(3), затем MCS: [7] тип (старшие 6 бит),
 * [8..9] initiator, [10..11] channelId big-endian. */
static inline int quic_pdu_mcs_channel(const uint8_t* buf, size_t len)
{
	if (len < 12 || buf[0] != 0x03) /* короче заголовков или не TPKT (0x03) */
		return -1;
	const uint8_t mcs_type = buf[7] >> 2; /* тип MCS — старшие 6 бит байта 7 */
	if (mcs_type != QUIC_MCS_SDRQ && mcs_type != QUIC_MCS_SDIN)
		return -1; /* не Send Data (например, MCS Connect) — номера канала нет */
	return (int)(uint16_t)((buf[10] << 8) | buf[11]); /* channelId, big-endian */
}

/* Смещение полезной нагрузки MCS Send Data (после длины PER), или 0.
 * PER — способ кодирования длины в MCS: [12] priority/segmentation,
 * [13] длина: 1 байт, если старший бит 0, иначе 2 байта. */
static inline size_t quic_mcs_payload_offset(const uint8_t* buf, size_t len)
{
	if (quic_pdu_mcs_channel(buf, len) < 0 || len < 14)
		return 0; /* не MCS Send Data — нагрузки нет */
	const size_t off = (buf[13] & 0x80) ? 15 : 14; /* длина в 2 байта или в 1 */
	return off <= len ? off : 0; /* защита от выхода за конец буфера */
}

/* Похоже ли на Share Control header по смещению off: totalLength равен
 * остатку PDU и pduType — один из известных с версией 0x10.
 * Так отличаем «security header есть» от «security header нет». */
static inline int quic_is_share_ctrl(const uint8_t* buf, size_t len, size_t off)
{
	if (off + QUIC_SHARE_CTRL_SIZE > len)
		return 0; /* заголовок не помещается */
	if (quic_le16(buf + off) != len - off)
		return 0; /* totalLength должен ровно совпасть с остатком PDU */
	const uint16_t pt = quic_le16(buf + off + 2); /* pduType */
	if ((pt & 0xFFF0) != QUIC_PDU_TYPE_VERSION)
		return 0; /* версия всегда 0x10 */
	switch (pt & 0x0F) /* тип — младшие 4 бита */
	{
		case QUIC_PDU_TYPE_DEMAND_ACTIVE:
		case QUIC_PDU_TYPE_CONFIRM_ACTIVE:
		case QUIC_PDU_TYPE_DEACTIVATE_ALL:
		case QUIC_PDU_TYPE_DATA:
		case QUIC_PDU_TYPE_SERVER_REDIR:
			return 1; /* известный тип — это Share Control */
		default:
			return 0; /* иначе совпадение длины было случайным */
	}
}

/* Классификация PDU основного канала (1003) по Share Control/Data headers. */
static inline QuicChannel quic_classify_io_channel(const uint8_t* buf, size_t len)
{
	const size_t payload = quic_mcs_payload_offset(buf, len); /* начало данных после MCS */
	if (!payload)
		return QUIC_CHANNEL_CONTROL; /* не смогли найти данные — служебное */

	size_t sc = 0; /* смещение Share Control header; 0 = не найден */
	if (quic_is_share_ctrl(buf, len, payload))
		sc = payload; /* security header нет (TLS / шифрование NONE) */
	else if (payload + QUIC_SEC_HDR_SIZE <= len)
	{
		/* есть security header: служебные флаги — сразу control */
		if (quic_le16(buf + payload) & QUIC_SEC_CONTROL_FLAGS)
			return QUIC_CHANNEL_CONTROL;
		if (quic_is_share_ctrl(buf, len, payload + QUIC_SEC_HDR_SIZE))
			sc = payload + QUIC_SEC_HDR_SIZE; /* Share Control сразу за security header */
	}
	if (!sc)
		return QUIC_CHANNEL_CONTROL; /* не разобрали (напр. зашифровано) — служебный */

	if ((quic_le16(buf + sc + 2) & 0x0F) != QUIC_PDU_TYPE_DATA)
		return QUIC_CHANNEL_CONTROL; /* Demand/Confirm Active и т.п. — фаза подключения */

	/* pduType2 лежит после Share Control (6) и 8 байт Share Data header */
	const size_t type2_off = sc + QUIC_SHARE_CTRL_SIZE + QUIC_SHARE_DATA_PDUTYPE2_OFF;
	if (type2_off >= len)
		return QUIC_CHANNEL_CONTROL; /* PDU обрезано — служебное */

	switch (buf[type2_off]) /* что за данные */
	{
		case QUIC_DATA_PDU_INPUT:
			return QUIC_CHANNEL_INPUT; /* ввод */
		case QUIC_DATA_PDU_UPDATE:
		case QUIC_DATA_PDU_POINTER:
			return QUIC_CHANNEL_GRAPHICS; /* экран и курсор */
		default:
			return QUIC_CHANNEL_CONTROL; /* синхронизация, шрифты, Control и т.п. */
	}
}

/* Направление клиент -> сервер. */
static inline QuicChannel quic_classify_client_pdu(const uint8_t* buf, size_t len)
{
	if (len < 2)
		return QUIC_CHANNEL_CONTROL; /* слишком короткое, чтобы разбирать */

	/* Fast-path: биты 0-1 = 0x00. От клиента так идёт только ввод */
	if ((buf[0] & 0x03) == 0x00)
		return QUIC_CHANNEL_INPUT;

	/* Не TPKT (0x03) — служебное */
	if (buf[0] != 0x03)
		return QUIC_CHANNEL_CONTROL;

	const int chan = quic_pdu_mcs_channel(buf, len); /* номер MCS-канала или -1 */
	if (chan < 0)
		return QUIC_CHANNEL_CONTROL; /* X.224 nego, MCS connect/attach/join — фаза подключения */

	/* Всё, что не на основном канале, — виртуальный канал целиком,
	 * независимо от содержимого: иначе PDU одного канала разъедутся по
	 * разным стримам и потеряют порядок */
	if (chan != QUIC_MCS_IO_CHANNEL)
		return QUIC_CHANNEL_VCHANNEL;

	return quic_classify_io_channel(buf, len); /* основной канал — смотрим содержимое */
}

/* Направление сервер -> клиент. */
static inline QuicChannel quic_classify_server_pdu(const uint8_t* buf, size_t len)
{
	if (len < 1)
		return QUIC_CHANNEL_CONTROL; /* пустое — нечего разбирать */

	/* fast-path: сервер шлёт так только обновления экрана и курсора */
	if ((buf[0] & 0x03) == 0x00)
		return QUIC_CHANNEL_GRAPHICS;

	/* дальше разбор симметричен клиентскому (slow-path одинаков в обе стороны) */
	return quic_classify_client_pdu(buf, len);
}
