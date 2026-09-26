#include <string.h>
#include <poll.h>
#include <freerdp/api.h>
#include <freerdp/freerdp.h>
#include <freerdp/input.h>
#include <freerdp/transport_io.h>
#include <freerdp/server/proxy/proxy_modules_api.h>
#include <freerdp/server/proxy/proxy_context.h>
#include <winpr/stream.h>
#include "quic_bridge.h"
#include "quic_transport.h"
#include <freerdp/peer.h>
#include <winpr/synch.h>


#define TAG MODULE_TAG("quicmux")

typedef struct
{
	proxyPluginsManager* mgr;
	QuicBridgeContext* bridge;
	HANDLE input_thread;
	BOOL running;
} quicmux_data;

static const char plugin_name[] = "quicmux";
static const char plugin_desc[] = "Transport-level RDP demux into unix-socket channels for QUIC bridge";

/* ===================== ps -> клиент: вся графика и служебные PDU ===================== */

static int quicmux_ps_write_pdu(rdpTransport* transport, wStream* s)
{
	rdpContext* context = transport_get_context(transport);
	QuicBridgeContext* bridge =
	    (QuicBridgeContext*)freerdp_get_io_callback_context(context);

	const uint8_t* buf = Stream_Buffer(s);
	size_t len = Stream_Length(s);
	if (len == 0)
		return 0;

	/* Направление ps->клиент зеркально клиентскому: fast-path здесь всегда
	 * графика (сервер по fast-path шлёт только обновления экрана/курсора) */
	QuicChannel ch;
	if ((buf[0] & 0x03) == 0x00)
		ch = QUIC_CHANNEL_GRAPHICS;
	else
		ch = quic_transport_classify_pdu(buf, len);

	if (quic_bridge_write(bridge, ch, buf, (uint32_t)len) < 0)
	{
		WLog_ERR(TAG, "не удалось записать исходящий PDU в мост (канал %s)",
		         QUIC_CHANNEL_NAMES[ch]);
		return -1;
	}

	return 1;
}

/* Хендлы unix-сокетов моста для событийного цикла ps.
 * Упрощение: одна активная сессия на процесс прокси. */
static HANDLE g_bridge_events[QUIC_CHANNEL_COUNT] = { 0 };
static DWORD (*g_orig_get_event_handles)(freerdp_peer*, HANDLE*, DWORD) = NULL;

static DWORD quicmux_get_event_handles(freerdp_peer* peer, HANDLE* events, DWORD count)
{
	DWORD n = g_orig_get_event_handles(peer, events, count);
	if (n == 0)
		return 0; /* оригинал сигнализирует об ошибке нулём — пробрасываем */

	for (int i = 0; i < QUIC_CHANNEL_COUNT && n < count; i++)
	{
		if (g_bridge_events[i])
			events[n++] = g_bridge_events[i];
	}
	return n;
}

static int quicmux_ps_read_pdu(rdpTransport* transport, wStream* s)
{
	rdpContext* context = transport_get_context(transport);
	QuicBridgeContext* bridge =
	    (QuicBridgeContext*)freerdp_get_io_callback_context(context);
	if (!bridge)
		return -1;

	/* Служебные каналы вперёд графики: фаза финализации чувствительна
	 * к порядку, а graphics может её обогнать */
	static const QuicChannel poll_order[QUIC_CHANNEL_COUNT] = {
		QUIC_CHANNEL_CONTROL, QUIC_CHANNEL_VCHANNEL,
		QUIC_CHANNEL_INPUT, QUIC_CHANNEL_GRAPHICS
	};

	struct pollfd fds[QUIC_CHANNEL_COUNT];
	for (int i = 0; i < QUIC_CHANNEL_COUNT; i++)
	{
		fds[i].fd = bridge->fds[poll_order[i]];
		fds[i].events = POLLIN;
		fds[i].revents = 0;
	}

	int ready = poll(fds, QUIC_CHANNEL_COUNT, 0);
	if (ready < 0)  return -1;
	if (ready == 0) return 0;

	for (int i = 0; i < QUIC_CHANNEL_COUNT; i++)
	{
		if (!(fds[i].revents & POLLIN)) continue;

		QuicChannel ch = poll_order[i];

		if (!Stream_EnsureCapacity(s, 64 * 1024))
			return -1;

		uint8_t* buf = Stream_Buffer(s);
		int n = quic_bridge_read(bridge, ch, buf, 64 * 1024);
		if (n < 0) return -1;
		if (n == 0) continue;

		Stream_SetPosition(s, n);
		Stream_SealLength(s);
		Stream_ResetPosition(s);

		WLog_DBG(TAG, "ps read: канал %s, %d байт", QUIC_CHANNEL_NAMES[ch], n);
		return n;
	}
	return 0;
}

static BOOL quicmux_server_post_connect(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	quicmux_data* data = (quicmux_data*)plugin->custom;
	pServerContext* ps = proxy_data_get_server_context(pdata);
	rdpContext* context = (rdpContext*)ps;

	freerdp_set_io_callback_context(context, data->bridge);

	const rdpTransportIo* defaults = freerdp_get_io_callbacks(context);
	if (!defaults)
	{
		WLog_ERR(TAG, "не удалось получить дефолтные io callbacks у ps");
		return FALSE;
	}

	rdpTransportIo io;
	memcpy(&io, defaults, sizeof(io));
	io.WritePdu = quicmux_ps_write_pdu;
	io.ReadPdu  = quicmux_ps_read_pdu;

	if (!freerdp_set_io_callbacks(context, &io))
	{
		WLog_ERR(TAG, "не удалось установить io callbacks на ps");
		return FALSE;
	}

	freerdp_peer* peer = (freerdp_peer*)custom;
	if (!peer)
	{
		WLog_ERR(TAG, "ServerPostConnect: нет freerdp_peer");
		return FALSE;
	}

	for (int i = 0; i < QUIC_CHANNEL_COUNT; i++)
	{
		g_bridge_events[i] = CreateFileDescriptorEvent(NULL, FALSE, FALSE,
							       data->bridge->fds[i], WINPR_FD_READ);
		if (!g_bridge_events[i])
		{
			WLog_ERR(TAG, "не удалось создать хендл для канала %s", QUIC_CHANNEL_NAMES[i]);
			return FALSE;
		}
	}

	g_orig_get_event_handles = peer->GetEventHandles;
	peer->GetEventHandles = quicmux_get_event_handles;

	WLog_INFO(TAG, "транспорт ps перехвачен — графика/служебные PDU идут в мост");
	return TRUE;
}

/* ===================== парсер Fast-Path Input PDU (MS-RDPBCGR 2.2.8.1.2) ===================== */

#define FASTPATH_INPUT_EVENT_SCANCODE 0x0
#define FASTPATH_INPUT_EVENT_MOUSE    0x1
#define FASTPATH_INPUT_EVENT_MOUSEX   0x2
#define FASTPATH_INPUT_EVENT_SYNC     0x3
#define FASTPATH_INPUT_EVENT_UNICODE  0x4
#define FASTPATH_INPUT_EVENT_QOE_TS   0x6

static void quicmux_dispatch_fastpath_input(rdpInput* input, const uint8_t* buf, size_t len)
{
	if (len < 1)
		return;

	uint8_t header0 = buf[0];
	size_t numEvents = (header0 >> 2) & 0x0F;
	size_t pos = 1;

	for (size_t i = 0; i < numEvents && pos < len; i++)
	{
		uint8_t eventHeader = buf[pos++];
		uint8_t eventCode = (eventHeader >> 5) & 0x07;

		switch (eventCode)
		{
			case FASTPATH_INPUT_EVENT_SCANCODE:
			{
				if (pos + 1 > len) return;
				uint8_t flags = eventHeader & 0x1F;
				uint8_t code = buf[pos++];
				UINT16 rdpFlags = 0;
				if (flags & 0x01) rdpFlags |= KBD_FLAGS_EXTENDED;
				if (flags & 0x02) rdpFlags |= KBD_FLAGS_RELEASE; else rdpFlags |= KBD_FLAGS_DOWN;
				freerdp_input_send_keyboard_event(input, rdpFlags, code);
				break;
			}
			case FASTPATH_INPUT_EVENT_MOUSE:
			{
				if (pos + 6 > len) return;
				UINT16 pflags = (UINT16)(buf[pos] | (buf[pos + 1] << 8)); pos += 2;
				UINT16 x = (UINT16)(buf[pos] | (buf[pos + 1] << 8)); pos += 2;
				UINT16 y = (UINT16)(buf[pos] | (buf[pos + 1] << 8)); pos += 2;
				freerdp_input_send_mouse_event(input, pflags, x, y);
				break;
			}
			case FASTPATH_INPUT_EVENT_MOUSEX:
			{
				if (pos + 6 > len) return;
				UINT16 pflags = (UINT16)(buf[pos] | (buf[pos + 1] << 8)); pos += 2;
				UINT16 x = (UINT16)(buf[pos] | (buf[pos + 1] << 8)); pos += 2;
				UINT16 y = (UINT16)(buf[pos] | (buf[pos + 1] << 8)); pos += 2;
				freerdp_input_send_extended_mouse_event(input, pflags, x, y);
				break;
			}
			case FASTPATH_INPUT_EVENT_UNICODE:
			{
				if (pos + 2 > len) return;
				UINT16 code = (UINT16)(buf[pos] | (buf[pos + 1] << 8)); pos += 2;
				freerdp_input_send_unicode_keyboard_event(input, 0, code);
				break;
			}
			case FASTPATH_INPUT_EVENT_SYNC:
			case FASTPATH_INPUT_EVENT_QOE_TS:
			default:
				break;
		}
	}
}

/* ===================== клиент -> pc: ввод ===================== */

static DWORD WINAPI quicmux_input_thread(LPVOID arg)
{
	proxyData* pdata = (proxyData*)arg;
	pClientContext* pc = proxy_data_get_client_context(pdata);
	rdpContext* context = (rdpContext*)pc;
	QuicBridgeContext* bridge =
	    (QuicBridgeContext*)freerdp_get_io_callback_context(context);

	rdpInput* input = context->input;

	uint8_t buf[64 * 1024];
	while (!proxy_data_shall_disconnect(pdata))
	{
		int n = quic_bridge_read(bridge, QUIC_CHANNEL_INPUT, buf, sizeof(buf));
		if (n < 0)
			break;
		if (n == 0)
			continue;

		quicmux_dispatch_fastpath_input(input, buf, (size_t)n);
	}

	return 0;
}

static BOOL quicmux_client_post_connect(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	quicmux_data* data = (quicmux_data*)plugin->custom;
	pClientContext* pc = proxy_data_get_client_context(pdata);
	rdpContext* context = (rdpContext*)pc;

	freerdp_set_io_callback_context(context, data->bridge);

	data->input_thread = CreateThread(NULL, 0, quicmux_input_thread, pdata, 0, NULL);
	if (!data->input_thread)
	{
		WLog_ERR(TAG, "не удалось запустить поток ввода");
		return FALSE;
	}

	WLog_INFO(TAG, "поток чтения input-канала запущен для pc");
	return TRUE;
}

/* ===================== жизненный цикл ===================== */

static BOOL quicmux_server_session_started(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	quicmux_data* data = (quicmux_data*)plugin->custom;

	data->bridge = quic_bridge_new();
	if (!data->bridge)
	{
		WLog_ERR(TAG, "не удалось создать контекст моста");
		return FALSE;
	}

	if (quic_bridge_connect(data->bridge) != 0)
	{
		WLog_ERR(TAG, "не удалось подключиться к unix-мосту");
		quic_bridge_free(data->bridge);
		data->bridge = NULL;
		return FALSE;
	}

	data->running = TRUE;
	WLog_INFO(TAG, "quic-мост подключен для новой сессии");
	return TRUE;
}

static BOOL quicmux_server_session_end(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	quicmux_data* data = (quicmux_data*)plugin->custom;

	data->running = FALSE;
	if (data->input_thread)
	{
		WaitForSingleObject(data->input_thread, 2000);
		CloseHandle(data->input_thread);
		data->input_thread = NULL;
	}
	if (data->bridge)
	{
		for (int i = 0; i < QUIC_CHANNEL_COUNT; i++)
		{
			if (g_bridge_events[i])
			{
				CloseHandle(g_bridge_events[i]);
				g_bridge_events[i] = NULL;
			}
		}
		g_orig_get_event_handles = NULL;

		quic_bridge_free(data->bridge);
		data->bridge = NULL;
	}
	return TRUE;
}

static BOOL quicmux_plugin_unload(proxyPlugin* plugin)
{
	if (plugin && plugin->custom)
		free(plugin->custom);
	return TRUE;
}

FREERDP_API BOOL proxy_module_entry_point(proxyPluginsManager* plugins_manager, void* userdata)
{
	proxyPlugin plugin = { 0 };
	quicmux_data* data = calloc(1, sizeof(quicmux_data));
	if (!data)
		return FALSE;

	data->mgr = plugins_manager;

	plugin.name = plugin_name;
	plugin.description = plugin_desc;
	plugin.PluginUnload = quicmux_plugin_unload;

	plugin.ServerSessionStarted = quicmux_server_session_started;
	plugin.ServerSessionEnd = quicmux_server_session_end;
	plugin.ServerPostConnect = quicmux_server_post_connect;
	//plugin.ClientPostConnect = quicmux_client_post_connect;

	plugin.custom = data;
	plugin.userdata = userdata;

	return plugins_manager->RegisterPlugin(plugins_manager, &plugin);
}

FREERDP_API BOOL quicmux_proxy_module_entry_point(proxyPluginsManager* plugins_manager,
                                                   void* userdata)
{
	return proxy_module_entry_point(plugins_manager, userdata);
}