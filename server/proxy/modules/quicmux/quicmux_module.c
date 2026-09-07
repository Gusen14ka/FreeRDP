#include <freerdp/api.h>
#include <freerdp/server/proxy/proxy_modules_api.h>
#include <freerdp/channels/rdpgfx.h>   /* RDPGFX_DVC_CHANNEL_NAME */
#include <winpr/stream.h>
#include "quic_bridge.h"   /* переиспользуем 1:1 из client/quic, без изменений */

#define TAG MODULE_TAG("quicmux")

typedef struct
{
    proxyPluginsManager* mgr;
    QuicBridgeContext* bridge;      /* тот же тип, что уже используется в quic_client.c */
} quicmux_data;

static const char plugin_name[] = "quicmux";
static const char plugin_desc[] = "Demultiplexes RDP traffic into unix-socket channels for QUIC bridge";

/* --- сериализация input-событий в канал "input" --- */

/* Формат на проводе внутри канала input:
 *   [1B type][варьируется по типу]
 * type: 0x01 = keyboard, 0x02 = unicode, 0x03 = mouse, 0x04 = mouse_ex
 * Выбрал так, а не "как есть share-data PDU", потому что данные
 * сюда приходят уже разобранными FreeRDP (flags/code напрямую),
 * ре-упаковывать их в фейковый RDP PDU не нужно — на другом конце
 * (xfreerdp-quic) мы всё равно не PDU ждём, а такой же явный ввод,
 * который потом сами же и восстановим в PDU через freerdp_input_send_*.
 */

static BOOL quicmux_keyboard_event(proxyPlugin* plugin, proxyData* pdata, void* param)
{
    const proxyKeyboardEventInfo* event = (const proxyKeyboardEventInfo*)param;
    quicmux_data* data = (quicmux_data*)plugin->custom;

    BYTE buf[4];
    buf[0] = 0x01;
    buf[1] = (BYTE)(event->flags & 0xFF);
    buf[2] = (BYTE)((event->flags >> 8) & 0xFF);
    buf[3] = event->rdp_scan_code;

    if (quic_bridge_write(data->bridge, QUIC_CHANNEL_INPUT, buf, sizeof(buf)) < 0)
    {
        WLog_ERR(TAG, "не удалось записать keyboard-событие в мост");
        /* fail-safe: пропускаем как обычно, чтобы сессия не встала колом */
        return TRUE;
    }

    return FALSE; /* поглощаем событие — родная пересылка в pc отключена */
}

static BOOL quicmux_mouse_event(proxyPlugin* plugin, proxyData* pdata, void* param)
{
    const proxyMouseEventInfo* event = (const proxyMouseEventInfo*)param;
    quicmux_data* data = (quicmux_data*)plugin->custom;

    BYTE buf[7];
    buf[0] = 0x03;
    buf[1] = (BYTE)(event->flags & 0xFF);
    buf[2] = (BYTE)((event->flags >> 8) & 0xFF);
    buf[3] = (BYTE)(event->x & 0xFF);
    buf[4] = (BYTE)((event->x >> 8) & 0xFF);
    buf[5] = (BYTE)(event->y & 0xFF);
    buf[6] = (BYTE)((event->y >> 8) & 0xFF);

    if (quic_bridge_write(data->bridge, QUIC_CHANNEL_INPUT, buf, sizeof(buf)) < 0)
        return TRUE;

    return FALSE;
}

/* ===================== GFX / графика (dynamic channel) ===================== */

static BOOL quicmux_dyn_channel_to_intercept(proxyPlugin* plugin, proxyData* pdata, void* arg)
{
    proxyChannelToInterceptData* data = (proxyChannelToInterceptData*)arg;

    /* помечаем GFX-канал на перехват; остальные dynamic-каналы (audio/video/camera
     * redirection и т.д.) не трогаем — они и так идут по обычному пути прокси,
     * можно будет добавить их сюда же в будущем при необходимости */
    if (strcmp(data->name, RDPGFX_DVC_CHANNEL_NAME) == 0)
        data->intercept = TRUE;

    return TRUE;
}

static BOOL quicmux_dyn_channel_intercept(proxyPlugin* plugin, proxyData* pdata, void* arg)
{
    proxyDynChannelInterceptData* event = (proxyDynChannelInterceptData*)arg;
    quicmux_data* data = (quicmux_data*)plugin->custom;

    if (strcmp(event->name, RDPGFX_DVC_CHANNEL_NAME) != 0)
    {
        event->result = PF_CHANNEL_RESULT_PASS;
        return TRUE;
    }

    const BYTE* buf = Stream_Buffer(event->data);
    size_t len = event->packetSize;

    /* GFX-канал двунаправленный (графика от таргета + ack/капабилити от клиента),
     * но обе стороны логически относятся к "графике" — пишем в один и тот же
     * unix-канал graphics независимо от event->isBackData */
    if (quic_bridge_write(data->bridge, QUIC_CHANNEL_GRAPHICS, buf, len) < 0)
    {
        WLog_ERR(TAG, "не удалось записать GFX-пакет в мост");
        event->result = PF_CHANNEL_RESULT_ERROR;
        return TRUE;
    }

    event->result = PF_CHANNEL_RESULT_DROP; /* поглощаем — родная пересылка отключена */
    return TRUE;
}

/* ===================== статические virtual channels (cliprdr/rdpdr/rdpsnd...) ===================== */

/* Формат в unix-канале vchannel: [2B channel_id LE][4B data_len LE][data...]
 * channel_id обязателен: в отличие от input/graphics, тут внутри ОДНОГО
 * unix-канала реально мультиплексируется НЕСКОЛЬКО разных RDP-каналов —
 * без id на другом конце нечем будет их различить при восстановлении. */
static BOOL quicmux_write_vchannel(quicmux_data* data, UINT16 channel_id,
                                    const BYTE* payload, size_t len)
{
    BYTE hdr[6];
    hdr[0] = (BYTE)(channel_id & 0xFF);
    hdr[1] = (BYTE)((channel_id >> 8) & 0xFF);
    hdr[2] = (BYTE)(len & 0xFF);
    hdr[3] = (BYTE)((len >> 8) & 0xFF);
    hdr[4] = (BYTE)((len >> 16) & 0xFF);
    hdr[5] = (BYTE)((len >> 24) & 0xFF);

    if (quic_bridge_write(data->bridge, QUIC_CHANNEL_VCHANNEL, hdr, sizeof(hdr)) < 0)
        return FALSE;
    if (len > 0 && quic_bridge_write(data->bridge, QUIC_CHANNEL_VCHANNEL, payload, len) < 0)
        return FALSE;
    return TRUE;
}

static BOOL quicmux_client_channel_data(proxyPlugin* plugin, proxyData* pdata, void* param)
{
    const proxyChannelDataEventInfo* channel = (const proxyChannelDataEventInfo*)param;
    quicmux_data* data = (quicmux_data*)plugin->custom;

    if (!quicmux_write_vchannel(data, channel->channel_id, channel->data, channel->data_len))
        return TRUE; /* fail-safe: пропускаем как обычно при сбое моста, не рвём сессию */

    return FALSE;
}

static BOOL quicmux_server_channel_data(proxyPlugin* plugin, proxyData* pdata, void* param)
{
    const proxyChannelDataEventInfo* channel = (const proxyChannelDataEventInfo*)param;
    quicmux_data* data = (quicmux_data*)plugin->custom;

    if (!quicmux_write_vchannel(data, channel->channel_id, channel->data, channel->data_len))
        return TRUE;

    return FALSE;
}

/* --- жизненный цикл: открываем/закрываем мост вместе с сессией --- */

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

    WLog_INFO(TAG, "quic-мост подключен для новой сессии");
    return TRUE;
}

static BOOL quicmux_server_session_end(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
    quicmux_data* data = (quicmux_data*)plugin->custom;
    if (data->bridge)
    {
        quic_bridge_free(data->bridge);   /* было: quic_bridge_close(...) */
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
    data->bridge = NULL;

    plugin.name = plugin_name;
    plugin.description = plugin_desc;
    plugin.PluginUnload = quicmux_plugin_unload;

    plugin.ServerSessionStarted = quicmux_server_session_started;
    plugin.ServerSessionEnd = quicmux_server_session_end;

    plugin.KeyboardEvent = quicmux_keyboard_event;
    plugin.MouseEvent = quicmux_mouse_event;
    /* UnicodeEvent/MouseExEvent — по аналогии, добавим при желании отдельно */

    plugin.DynChannelToIntercept = quicmux_dyn_channel_to_intercept;
    plugin.DynChannelIntercept   = quicmux_dyn_channel_intercept;
    plugin.ClientChannelData     = quicmux_client_channel_data;
    plugin.ServerChannelData     = quicmux_server_channel_data;

    plugin.custom = data;
    plugin.userdata = userdata;

    return plugins_manager->RegisterPlugin(plugins_manager, &plugin);
}

/* На случай, если модуль когда-нибудь статически слинкуют в сам freerdp-proxy —
 * именно эту версию имени ищет pf_modules_load_static_module. Не обязательно
 * для нашего текущего сценария (мы всегда грузимся как внешний .so), но
 * следуя тому же паттерну, что и demo/bitmap-filter/dyn-channel-dump модули. */
FREERDP_API BOOL quicmux_proxy_module_entry_point(proxyPluginsManager* plugins_manager,
                                                   void* userdata)
{
    return proxy_module_entry_point(plugins_manager, userdata);
}

