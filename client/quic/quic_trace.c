/* Трассировщик PDU: встраивается в транспорт FreeRDP и пишет каждое PDU
 * в CSV. Общая картина — в TRACE.md, формат файла — в quic_trace_writer.h. */

#include "quic_trace.h"        /* наш публичный интерфейс */
#include "quic_trace_writer.h" /* запись CSV */
#include "quic_classify.h"     /* та же классификация, что у форка */

#include <freerdp/channels/channels.h> /* freerdp_channels_get_id_by_name */
#include <freerdp/settings.h>          /* чтение настроек подключения */
#include <freerdp/transport_io.h>      /* rdpTransportIo: таблица ReadPdu/WritePdu */
#include <winpr/stream.h>              /* wStream: буфер с PDU */
#include <winpr/wtsapi.h>              /* CHANNEL_DEF: имя виртуального канала */

#include <stdio.h>  /* fprintf(stderr, ...) */
#include <stdlib.h> /* getenv */
#include <string.h>

/* Один клиент = одно соединение = одна трасса, поэтому состояние глобальное
 * (так же устроен quic_client.c). */
static QuicTraceWriter* g_trace = NULL; /* открытая трасса; NULL — трассировка выключена */
static rdpTransportIo g_orig_io; /* стандартные колбэки, которые мы оборачиваем */

/* Диагностика: сколько раз при записи Stream_Length != Stream_GetPosition.
 * Стандартный WritePdu FreeRDP считает длину PDU по позиции потока,
 * а quic_write_pdu форка — по Stream_Length; если они расходятся,
 * QUIC-режим отправлял бы PDU не того размера. */
static unsigned long long g_write_len_mismatch = 0;

/* ── Обёртки над ReadPdu / WritePdu ───────────────────────────── */

/* Чтение: сначала стандартная функция читает PDU из сети, потом мы его записываем */
static int trace_read_pdu(rdpTransport* transport, wStream* s)
{
	const int rc = g_orig_io.ReadPdu(transport, s); /* настоящее чтение (с расшифровкой TLS) */
	if (rc > 0 && g_trace) /* rc > 0 — прочитано целое PDU; 0 — данных пока нет */
	{
		/* Стандартный ReadPdu оставляет в s ровно одно целое PDU */
		const uint8_t* buf = Stream_Buffer(s); /* начало PDU */
		const size_t len = Stream_Length(s);   /* его длина */
		const uint64_t t = quic_trace_writer_now_us(g_trace); /* время прихода */
		quic_trace_writer_record(g_trace, t, 'd', /* 'd' — сервер -> клиент */
		                         QUIC_CHANNEL_NAMES[quic_classify_server_pdu(buf, len)],
		                         quic_pdu_mcs_channel(buf, len), (uint32_t)len);
	}
	return rc; /* результат возвращаем FreeRDP без изменений */
}

/* Запись: сначала записываем PDU в трассу, потом отдаём стандартной функции */
static int trace_write_pdu(rdpTransport* transport, wStream* s)
{
	if (g_trace && s)
	{
		/* Длину берём так же, как стандартный WritePdu, — по позиции */
		const size_t len = Stream_GetPosition(s);
		if (len > 0)
		{
			const uint8_t* buf = Stream_Buffer(s); /* начало PDU */
			const uint64_t t = quic_trace_writer_now_us(g_trace); /* время отправки */
			quic_trace_writer_record(g_trace, t, 'u', /* 'u' — клиент -> сервер */
			                         QUIC_CHANNEL_NAMES[quic_classify_client_pdu(buf, len)],
			                         quic_pdu_mcs_channel(buf, len), (uint32_t)len);
			if (Stream_Length(s) != len)
				g_write_len_mismatch++; /* см. комментарий у g_write_len_mismatch */
		}
	}
	return g_orig_io.WritePdu(transport, s); /* настоящая отправка (с шифрованием TLS) */
}

/* ── Публичные функции ────────────────────────────────────────── */

BOOL quic_trace_pre_connect(freerdp* instance)
{
	const char* path = getenv("RDP_TRACE"); /* куда писать трассу */
	if (!path || !*path || g_trace)
		return TRUE; /* трасса не запрошена (или уже открыта) — ничего не делаем */

	rdpContext* context = instance->context;
	const rdpTransportIo* defaults = freerdp_get_io_callbacks(context); /* текущие колбэки транспорта */
	if (!defaults || !defaults->ReadPdu || !defaults->WritePdu)
	{
		fprintf(stderr, "[trace] ОШИБКА: нет колбэков транспорта\n");
		return FALSE; /* FALSE из PreConnect прерывает подключение — ошибка видна сразу */
	}

	g_trace = quic_trace_writer_open(path); /* открыть файл, записать "# trace v1" */
	if (!g_trace)
	{
		fprintf(stderr, "[trace] ОШИБКА: не могу открыть %s\n", path);
		return FALSE;
	}

	/* Метаданные: всё, что влияет на объём трафика */
	const rdpSettings* st = context->settings; /* настройки из командной строки */
	quic_trace_writer_comment(g_trace, "host=%s:%u size=%ux%u bpp=%u",
	                          freerdp_settings_get_string(st, FreeRDP_ServerHostname), /* /v: */
	                          freerdp_settings_get_uint32(st, FreeRDP_ServerPort),
	                          freerdp_settings_get_uint32(st, FreeRDP_DesktopWidth),   /* /size: */
	                          freerdp_settings_get_uint32(st, FreeRDP_DesktopHeight),
	                          freerdp_settings_get_uint32(st, FreeRDP_ColorDepth));    /* /bpp: */
	const char* meta = getenv("RDP_TRACE_META"); /* метаданные от скрипта записи */
	if (meta && *meta)
		quic_trace_writer_comment(g_trace, "%s", meta);
	quic_trace_writer_columns(g_trace); /* t_us,dir,stream,mcs,len */

	/* Оборачиваем стандартные ReadPdu/WritePdu, остальное оставляем как есть */
	g_orig_io = *defaults;          /* запоминаем оригиналы — обёртки будут их вызывать */
	rdpTransportIo io = *defaults;  /* копия таблицы колбэков */
	io.ReadPdu = trace_read_pdu;    /* подменяем чтение */
	io.WritePdu = trace_write_pdu;  /* подменяем запись */
	if (!freerdp_set_io_callbacks(context, &io)) /* ставим таблицу в транспорт */
	{
		fprintf(stderr, "[trace] ОШИБКА: не удалось установить колбэки\n");
		quic_trace_writer_close(g_trace);
		g_trace = NULL;
		return FALSE;
	}
	/* FreeRDP хранит эту таблицу и переставляет её, если транспорт
	 * пересоздаётся (rdp.c), поэтому обёртки живут всю сессию */

	fprintf(stderr, "[trace] пишу трассу в %s\n", path);
	return TRUE;
}

void quic_trace_post_connect(freerdp* instance)
{
	if (!g_trace)
		return; /* трассировка выключена */

	/* Соответствие номеров MCS-каналов именам: номера назначает сервер
	 * при подключении, поэтому известны только после connect */
	quic_trace_writer_comment(g_trace, "mcs %d=io", QUIC_MCS_IO_CHANNEL); /* основной канал */
	const rdpSettings* st = instance->context->settings;
	const UINT32 n = freerdp_settings_get_uint32(st, FreeRDP_ChannelCount); /* сколько виртуальных каналов */
	for (UINT32 i = 0; i < n; i++)
	{
		const CHANNEL_DEF* def =
		    freerdp_settings_get_pointer_array(st, FreeRDP_ChannelDefArray, i); /* i-й канал */
		if (!def || !def->name[0])
			continue; /* пустая запись — пропускаем */
		const UINT16 id = freerdp_channels_get_id_by_name(instance, def->name); /* номер от сервера */
		if (id)
			quic_trace_writer_comment(g_trace, "mcs %u=%s", id, def->name); /* напр. "mcs 1005=rdpsnd" */
	}
}

void quic_trace_close(void)
{
	if (!g_trace)
		return; /* нечего закрывать */
	/* Итог в консоль — его видно в логе клиента */
	fprintf(stderr, "[trace] записано PDU: %llu", (unsigned long long)quic_trace_writer_count(g_trace));
	if (g_write_len_mismatch)
		fprintf(stderr, ", ВНИМАНИЕ: Stream_Length != позиции при записи %llu раз",
		        g_write_len_mismatch);
	fputc('\n', stderr);
	/* Строка "# end" — признак штатного закрытия: если её нет, хвост мог потеряться */
	quic_trace_writer_comment(g_trace, "end pdus=%llu write_len_mismatch=%llu",
	                          (unsigned long long)quic_trace_writer_count(g_trace),
	                          g_write_len_mismatch);
	quic_trace_writer_close(g_trace); /* сброс буфера и закрытие файла */
	g_trace = NULL;
}
