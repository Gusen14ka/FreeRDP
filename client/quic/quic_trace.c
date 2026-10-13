#include "quic_trace.h"
#include "quic_trace_writer.h"
#include "quic_classify.h"

#include <freerdp/channels/channels.h>
#include <freerdp/settings.h>
#include <freerdp/transport_io.h>
#include <winpr/stream.h>
#include <winpr/wtsapi.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Один клиент = одно соединение = одна трасса, поэтому состояние глобальное
 * (так же устроен quic_client.c). */
static QuicTraceWriter* g_trace = NULL;
static rdpTransportIo g_orig_io; /* стандартные колбэки, которые мы оборачиваем */

/* Диагностика: сколько раз при записи Stream_Length != Stream_GetPosition.
 * Стандартный WritePdu FreeRDP считает длину PDU по позиции потока,
 * а quic_write_pdu форка — по Stream_Length; если они расходятся,
 * QUIC-режим отправлял бы PDU не того размера. */
static unsigned long long g_write_len_mismatch = 0;

/* ── Обёртки над ReadPdu / WritePdu ───────────────────────────── */

static int trace_read_pdu(rdpTransport* transport, wStream* s)
{
	const int rc = g_orig_io.ReadPdu(transport, s);
	if (rc > 0 && g_trace)
	{
		/* Стандартный ReadPdu оставляет в s ровно одно целое PDU */
		const uint8_t* buf = Stream_Buffer(s);
		const size_t len = Stream_Length(s);
		const uint64_t t = quic_trace_writer_now_us(g_trace);
		quic_trace_writer_record(g_trace, t, 'd',
		                         QUIC_CHANNEL_NAMES[quic_classify_server_pdu(buf, len)],
		                         quic_pdu_mcs_channel(buf, len), (uint32_t)len);
	}
	return rc;
}

static int trace_write_pdu(rdpTransport* transport, wStream* s)
{
	if (g_trace && s)
	{
		/* Длину берём так же, как стандартный WritePdu, — по позиции */
		const size_t len = Stream_GetPosition(s);
		if (len > 0)
		{
			const uint8_t* buf = Stream_Buffer(s);
			const uint64_t t = quic_trace_writer_now_us(g_trace);
			quic_trace_writer_record(g_trace, t, 'u',
			                         QUIC_CHANNEL_NAMES[quic_classify_client_pdu(buf, len)],
			                         quic_pdu_mcs_channel(buf, len), (uint32_t)len);
			if (Stream_Length(s) != len)
				g_write_len_mismatch++;
		}
	}
	return g_orig_io.WritePdu(transport, s);
}

/* ── Публичные функции ────────────────────────────────────────── */

BOOL quic_trace_pre_connect(freerdp* instance)
{
	const char* path = getenv("RDP_TRACE");
	if (!path || !*path || g_trace)
		return TRUE; /* трасса не запрошена (или уже открыта) — ничего не делаем */

	rdpContext* context = instance->context;
	const rdpTransportIo* defaults = freerdp_get_io_callbacks(context);
	if (!defaults || !defaults->ReadPdu || !defaults->WritePdu)
	{
		fprintf(stderr, "[trace] ОШИБКА: нет колбэков транспорта\n");
		return FALSE;
	}

	g_trace = quic_trace_writer_open(path);
	if (!g_trace)
	{
		fprintf(stderr, "[trace] ОШИБКА: не могу открыть %s\n", path);
		return FALSE;
	}

	/* Метаданные: всё, что влияет на объём трафика */
	const rdpSettings* st = context->settings;
	quic_trace_writer_comment(g_trace, "host=%s:%u size=%ux%u bpp=%u",
	                          freerdp_settings_get_string(st, FreeRDP_ServerHostname),
	                          freerdp_settings_get_uint32(st, FreeRDP_ServerPort),
	                          freerdp_settings_get_uint32(st, FreeRDP_DesktopWidth),
	                          freerdp_settings_get_uint32(st, FreeRDP_DesktopHeight),
	                          freerdp_settings_get_uint32(st, FreeRDP_ColorDepth));
	const char* meta = getenv("RDP_TRACE_META");
	if (meta && *meta)
		quic_trace_writer_comment(g_trace, "%s", meta);
	quic_trace_writer_columns(g_trace);

	/* Оборачиваем стандартные ReadPdu/WritePdu, остальное оставляем как есть */
	g_orig_io = *defaults;
	rdpTransportIo io = *defaults;
	io.ReadPdu = trace_read_pdu;
	io.WritePdu = trace_write_pdu;
	if (!freerdp_set_io_callbacks(context, &io))
	{
		fprintf(stderr, "[trace] ОШИБКА: не удалось установить колбэки\n");
		quic_trace_writer_close(g_trace);
		g_trace = NULL;
		return FALSE;
	}

	fprintf(stderr, "[trace] пишу трассу в %s\n", path);
	return TRUE;
}

void quic_trace_post_connect(freerdp* instance)
{
	if (!g_trace)
		return;

	/* Соответствие номеров MCS-каналов именам: номера назначает сервер
	 * при подключении, поэтому известны только после connect */
	quic_trace_writer_comment(g_trace, "mcs %d=io", QUIC_MCS_IO_CHANNEL);
	const rdpSettings* st = instance->context->settings;
	const UINT32 n = freerdp_settings_get_uint32(st, FreeRDP_ChannelCount);
	for (UINT32 i = 0; i < n; i++)
	{
		const CHANNEL_DEF* def =
		    freerdp_settings_get_pointer_array(st, FreeRDP_ChannelDefArray, i);
		if (!def || !def->name[0])
			continue;
		const UINT16 id = freerdp_channels_get_id_by_name(instance, def->name);
		if (id)
			quic_trace_writer_comment(g_trace, "mcs %u=%s", id, def->name);
	}
}

void quic_trace_close(void)
{
	if (!g_trace)
		return;
	fprintf(stderr, "[trace] записано PDU: %llu", (unsigned long long)quic_trace_writer_count(g_trace));
	if (g_write_len_mismatch)
		fprintf(stderr, ", ВНИМАНИЕ: Stream_Length != позиции при записи %llu раз",
		        g_write_len_mismatch);
	fputc('\n', stderr);
	quic_trace_writer_comment(g_trace, "end pdus=%llu write_len_mismatch=%llu",
	                          (unsigned long long)quic_trace_writer_count(g_trace),
	                          g_write_len_mismatch);
	quic_trace_writer_close(g_trace);
	g_trace = NULL;
}
