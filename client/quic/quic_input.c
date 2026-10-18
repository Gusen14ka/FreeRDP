/* Запись и воспроизведение ввода. Общая картина — TRACE.md,
 * формат файла — quic_input_script.h.
 *
 * Как устроено:
 *  - Ввод в FreeRDP идёт через таблицу функций rdpInput (KeyboardEvent,
 *    MouseEvent, ...). Её заполняет сама библиотека при обмене
 *    возможностями (Confirm Active) — ПОСЛЕ PostConnect — и заполняет
 *    заново при каждой реактивации сессии. Поэтому обёртки нельзя
 *    поставить один раз: их затрёт.
 *  - Решение: обёртка над WritePdu транспорта (она ставится в PreConnect и
 *    живёт всю сессию). Через неё проходит каждый исходящий PDU, в том числе
 *    первые служебные PDU сразу после регистрации ввода. На каждом вызове
 *    проверяем: если в таблице не наши функции — запоминаем новые
 *    оригиналы и ставим поверх свои. Так обёртки всегда на месте до
 *    первого нажатия пользователя.
 *  - Момент первой установки обёрток = активация сессии = ноль времени
 *    для записи и воспроизведения.
 *  - Воспроизведение — отдельный поток: спит до времени события и
 *    вызывает тот же freerdp_input_send_*(), что и обработчик клавиатуры
 *    xfreerdp. Отправка в транспорт в FreeRDP защищена блокировкой. */

#include "quic_input.h"
#include "quic_input_script.h"
#include "quic_arm.h" /* старт по SIGUSR1 (RDP_CAPTURE_ARM=signal) */

#include <freerdp/input.h>        /* rdpInput, freerdp_input_send_* */
#include <freerdp/settings.h>     /* размер экрана для шапки файла */
#include <freerdp/transport_io.h> /* rdpTransportIo: WritePdu */

#include <errno.h>
#include <pthread.h>  /* поток воспроизведения, мьютекс */
#include <stdatomic.h> /* флаг остановки потока */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>     /* clock_gettime, clock_nanosleep */

/* ── Состояние (один клиент = одна сессия) ────────────────────── */

static rdpContext* g_context = NULL;      /* контекст сессии */
static rdpTransportIo g_orig_io;           /* WritePdu, который мы оборачиваем */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER; /* защищает всё ниже */

static int g_active = 0;      /* 1 — сессия активирована, t0 задан */
static uint64_t g_t0_ns = 0;  /* момент активации по монотонным часам, нс */

/* Оригинальные функции ввода, которые мы оборачиваем */
static struct
{
	pSynchronizeEvent sync;
	pKeyboardEvent kbd;
	pUnicodeKeyboardEvent unicode;
	pMouseEvent mouse;
	pExtendedMouseEvent xmouse;
	pRelMouseEvent relmouse;
	pFocusInEvent focus;
	pKeyboardPauseEvent pause;
} g_orig;

/* Запись */
static FILE* g_rec = NULL;            /* файл RDP_INPUT_RECORD, NULL — запись выключена */
static unsigned long long g_rec_count = 0; /* сколько событий записано */

/* Воспроизведение */
static QuicInputEvent* g_script = NULL; /* события из RDP_INPUT_SCRIPT */
static size_t g_script_len = 0;         /* сколько их */
static pthread_t g_thread;              /* поток воспроизведения */
static int g_thread_started = 0;
static atomic_int g_stop = 0;           /* 1 — потоку пора завершаться */
static unsigned long long g_play_sent = 0, g_play_failed = 0; /* итог воспроизведения */

/* ── Время ────────────────────────────────────────────────────── */

static uint64_t mono_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts); /* монотонные часы — не прыгают при подводке времени */
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* Ноль времени для ввода: в режиме RDP_CAPTURE_ARM=signal — момент SIGUSR1,
 * иначе — активация сессии */
static uint64_t base_ns(void)
{
	return quic_arm_signal_mode() ? quic_arm_t0_ns() : g_t0_ns;
}

/* ── Запись одного события ────────────────────────────────────── */

static void record(QuicInputType type, uint32_t flags, int32_t a, int32_t b)
{
	pthread_mutex_lock(&g_lock); /* события идут из разных потоков */
	if (g_rec && g_active && quic_arm_is_armed()) /* до SIGUSR1 ввод не пишем */
	{
		const QuicInputEvent ev = { .t_us = (mono_ns() - base_ns()) / 1000u,
			                        .type = type, .flags = flags, .a = a, .b = b };
		char line[128];
		if (quic_input_format_line(&ev, line, sizeof line) > 0)
		{
			fputs(line, g_rec);
			g_rec_count++;
		}
	}
	pthread_mutex_unlock(&g_lock);
}

/* ── Обёртки функций ввода: записать и вызвать оригинал ─────────── */

static BOOL w_sync(rdpInput* in, UINT32 flags)
{
	record(QUIC_INPUT_SYNC, flags, 0, 0);
	return g_orig.sync ? g_orig.sync(in, flags) : TRUE;
}
static BOOL w_kbd(rdpInput* in, UINT16 flags, UINT8 code)
{
	record(QUIC_INPUT_KBD, flags, code, 0);
	return g_orig.kbd ? g_orig.kbd(in, flags, code) : TRUE;
}
static BOOL w_unicode(rdpInput* in, UINT16 flags, UINT16 code)
{
	record(QUIC_INPUT_UNICODE, flags, code, 0);
	return g_orig.unicode ? g_orig.unicode(in, flags, code) : TRUE;
}
static BOOL w_mouse(rdpInput* in, UINT16 flags, UINT16 x, UINT16 y)
{
	record(QUIC_INPUT_MOUSE, flags, x, y);
	return g_orig.mouse ? g_orig.mouse(in, flags, x, y) : TRUE;
}
static BOOL w_xmouse(rdpInput* in, UINT16 flags, UINT16 x, UINT16 y)
{
	record(QUIC_INPUT_XMOUSE, flags, x, y);
	return g_orig.xmouse ? g_orig.xmouse(in, flags, x, y) : TRUE;
}
static BOOL w_relmouse(rdpInput* in, UINT16 flags, INT16 dx, INT16 dy)
{
	record(QUIC_INPUT_RELMOUSE, flags, dx, dy);
	return g_orig.relmouse ? g_orig.relmouse(in, flags, dx, dy) : TRUE;
}
static BOOL w_focus(rdpInput* in, UINT16 toggle)
{
	record(QUIC_INPUT_FOCUS, toggle, 0, 0);
	return g_orig.focus ? g_orig.focus(in, toggle) : TRUE;
}
static BOOL w_pause(rdpInput* in)
{
	record(QUIC_INPUT_PAUSE, 0, 0, 0);
	return g_orig.pause ? g_orig.pause(in) : TRUE;
}

/* ── Воспроизведение ──────────────────────────────────────────── */

/* Отправить одно событие тем же API, что и обработчики xfreerdp */
static BOOL play_one(rdpInput* in, const QuicInputEvent* ev)
{
	switch (ev->type)
	{
		case QUIC_INPUT_KBD:
			return freerdp_input_send_keyboard_event(in, (UINT16)ev->flags, (UINT8)ev->a);
		case QUIC_INPUT_UNICODE:
			return freerdp_input_send_unicode_keyboard_event(in, (UINT16)ev->flags, (UINT16)ev->a);
		case QUIC_INPUT_MOUSE:
			return freerdp_input_send_mouse_event(in, (UINT16)ev->flags, (UINT16)ev->a,
			                                      (UINT16)ev->b);
		case QUIC_INPUT_XMOUSE:
			return freerdp_input_send_extended_mouse_event(in, (UINT16)ev->flags, (UINT16)ev->a,
			                                               (UINT16)ev->b);
		case QUIC_INPUT_RELMOUSE:
			return freerdp_input_send_rel_mouse_event(in, (UINT16)ev->flags, (INT16)ev->a,
			                                          (INT16)ev->b);
		case QUIC_INPUT_SYNC:
			return freerdp_input_send_synchronize_event(in, ev->flags);
		case QUIC_INPUT_FOCUS:
			return freerdp_input_send_focus_in_event(in, (UINT16)ev->flags);
		case QUIC_INPUT_PAUSE:
			return freerdp_input_send_keyboard_pause_event(in);
		default:
			return FALSE;
	}
}

/* Поток воспроизведения: события по абсолютному времени от t0 */
static void* play_thread(void* arg)
{
	(void)arg;
	rdpInput* in = g_context->input;
	/* В режиме RDP_CAPTURE_ARM=signal ждём SIGUSR1: повтор стартует из того же
	 * состояния экрана, что и запись (скрипт шлёт сигнал по готовности сессии) */
	while (!quic_arm_is_armed() && !atomic_load(&g_stop))
	{
		struct timespec ts = { .tv_sec = 0, .tv_nsec = 2000000 }; /* проверка каждые 2 мс */
		nanosleep(&ts, NULL);
	}
	const uint64_t base = base_ns(); /* ноль времени для повтора */
	for (size_t i = 0; i < g_script_len && !atomic_load(&g_stop); i++)
	{
		const uint64_t due_ns = base + g_script[i].t_us * 1000u; /* когда отправить */
		/* Спим кусками не длиннее 100 мс, чтобы быстро реагировать на остановку */
		for (;;)
		{
			const uint64_t now = mono_ns();
			if (now >= due_ns || atomic_load(&g_stop))
				break;
			const uint64_t left = due_ns - now;
			const uint64_t chunk = left > 100000000ull ? 100000000ull : left;
			struct timespec ts = { .tv_sec = (time_t)(chunk / 1000000000ull),
				                   .tv_nsec = (long)(chunk % 1000000000ull) };
			nanosleep(&ts, NULL);
		}
		if (atomic_load(&g_stop) || freerdp_shall_disconnect_context(g_context))
			break; /* сессия закрывается — дальше не шлём */
		if (play_one(in, &g_script[i]))
			g_play_sent++;
		else
			g_play_failed++;
	}
	return NULL;
}

/* ── Самовосстанавливающиеся обёртки ──────────────────────────── */

/* Если в таблице ввода не наши функции — запомнить их и поставить свои.
 * Вызывается под g_lock из обёртки WritePdu. */
static void ensure_wrapped(rdpInput* in)
{
	if (!in->KeyboardEvent)
		return; /* библиотека ещё не зарегистрировала ввод — рано */
	if (in->KeyboardEvent == w_kbd)
		return; /* уже наши */

	/* Новые оригиналы (первая активация или реактивация сессии) */
	g_orig.sync = in->SynchronizeEvent;
	g_orig.kbd = in->KeyboardEvent;
	g_orig.unicode = in->UnicodeKeyboardEvent;
	g_orig.mouse = in->MouseEvent;
	g_orig.xmouse = in->ExtendedMouseEvent;
	g_orig.relmouse = in->RelMouseEvent;
	g_orig.focus = in->FocusInEvent;
	g_orig.pause = in->KeyboardPauseEvent;

	/* Ставим свои поверх. Пустые слоты оставляем пустыми — как было */
	if (in->SynchronizeEvent) in->SynchronizeEvent = w_sync;
	in->KeyboardEvent = w_kbd;
	if (in->UnicodeKeyboardEvent) in->UnicodeKeyboardEvent = w_unicode;
	if (in->MouseEvent) in->MouseEvent = w_mouse;
	if (in->ExtendedMouseEvent) in->ExtendedMouseEvent = w_xmouse;
	if (in->RelMouseEvent) in->RelMouseEvent = w_relmouse;
	if (in->FocusInEvent) in->FocusInEvent = w_focus;
	if (in->KeyboardPauseEvent) in->KeyboardPauseEvent = w_pause;

	if (!g_active)
	{
		/* Первая активация: отсюда отсчитывается время */
		g_t0_ns = mono_ns();
		g_active = 1;
		fprintf(stderr, "[input] сессия активирована, отсчёт времени ввода начат\n");
		if (g_script_len && pthread_create(&g_thread, NULL, play_thread, NULL) == 0)
		{
			g_thread_started = 1;
			fprintf(stderr, "[input] воспроизвожу %zu событий\n", g_script_len);
		}
	}
	else
		fprintf(stderr, "[input] реактивация сессии: обёртки ввода переустановлены\n");
}

/* Обёртка WritePdu: проверить обёртки ввода и отправить PDU как обычно */
static int input_write_pdu(rdpTransport* transport, wStream* s)
{
	pthread_mutex_lock(&g_lock);
	if (g_context && g_context->input)
		ensure_wrapped(g_context->input);
	pthread_mutex_unlock(&g_lock);
	return g_orig_io.WritePdu(transport, s);
}

/* ── Загрузка файла для воспроизведения ───────────────────────── */

static BOOL load_script(const char* path)
{
	FILE* f = fopen(path, "r");
	if (!f)
	{
		fprintf(stderr, "[input] ОШИБКА: не могу открыть %s\n", path);
		return FALSE;
	}
	size_t cap = 1024;
	g_script = malloc(cap * sizeof(*g_script));
	char line[256];
	unsigned long lineno = 0;
	uint64_t last_t = 0;
	while (g_script && fgets(line, sizeof line, f))
	{
		lineno++;
		QuicInputEvent ev;
		const int rc = quic_input_parse_line(line, &ev);
		if (rc == 0)
			continue; /* комментарий / заголовок */
		if (rc < 0 || ev.t_us < last_t)
		{
			fprintf(stderr, "[input] ОШИБКА: %s, строка %lu: %s\n", path, lineno,
			        rc < 0 ? "не разобрать" : "время идёт назад");
			fclose(f);
			return FALSE;
		}
		last_t = ev.t_us;
		if (g_script_len == cap) /* массив заполнен — увеличиваем вдвое */
		{
			QuicInputEvent* bigger = realloc(g_script, 2 * cap * sizeof(*g_script));
			if (!bigger)
				break;
			g_script = bigger;
			cap *= 2;
		}
		g_script[g_script_len++] = ev;
	}
	fclose(f);
	if (!g_script)
		return FALSE;
	fprintf(stderr, "[input] загружено %zu событий из %s\n", g_script_len, path);
	return TRUE;
}

/* ── Публичные функции ────────────────────────────────────────── */

BOOL quic_input_pre_connect(freerdp* instance)
{
	const char* rec_path = getenv("RDP_INPUT_RECORD");
	const char* play_path = getenv("RDP_INPUT_SCRIPT");
	const BOOL want_rec = rec_path && *rec_path;
	const BOOL want_play = play_path && *play_path;
	if (!want_rec && !want_play)
		return TRUE; /* ничего не запрошено — клиент работает как обычно */

	quic_arm_init(); /* RDP_CAPTURE_ARM=signal — ждать SIGUSR1 перед записью/повтором */

	g_context = instance->context;

	if (want_play && !load_script(play_path))
		return FALSE; /* ошибка в файле — лучше не подключаться, чем играть мусор */

	if (want_rec)
	{
		g_rec = fopen(rec_path, "w");
		if (!g_rec)
		{
			fprintf(stderr, "[input] ОШИБКА: не могу открыть %s\n", rec_path);
			return FALSE;
		}
		setvbuf(g_rec, NULL, _IOLBF, 0); /* построчная буферизация: файл всегда цел */
		const rdpSettings* st = g_context->settings;
		/* Координаты мыши верны только для того же размера экрана — пишем его */
		fprintf(g_rec, "# input v1\n# size=%ux%u\n%s\n",
		        freerdp_settings_get_uint32(st, FreeRDP_DesktopWidth),
		        freerdp_settings_get_uint32(st, FreeRDP_DesktopHeight), QUIC_INPUT_COLUMNS);
		fprintf(stderr, "[input] записываю ввод в %s\n", rec_path);
	}

	/* Оборачиваем текущий WritePdu (это может быть уже обёртка трассировщика —
	 * тогда цепочка: наша -> трассировщик -> стандартная) */
	const rdpTransportIo* cur = freerdp_get_io_callbacks(g_context);
	if (!cur || !cur->WritePdu)
		return FALSE;
	g_orig_io = *cur;
	rdpTransportIo io = *cur;
	io.WritePdu = input_write_pdu;
	return freerdp_set_io_callbacks(g_context, &io);
}

void quic_input_close(void)
{
	if (!g_context)
		return; /* ничего не включали */
	atomic_store(&g_stop, 1); /* попросить поток воспроизведения остановиться */
	if (g_thread_started)
	{
		pthread_join(g_thread, NULL); /* дождаться его */
		g_thread_started = 0;
		fprintf(stderr, "[input] воспроизведено %llu из %zu событий%s\n", g_play_sent,
		        g_script_len, g_play_failed ? " (есть ошибки отправки)" : "");
	}
	pthread_mutex_lock(&g_lock);
	if (g_rec)
	{
		fprintf(g_rec, "# end events=%llu\n", g_rec_count); /* признак штатного закрытия */
		fclose(g_rec);
		g_rec = NULL;
		fprintf(stderr, "[input] записано событий: %llu\n", g_rec_count);
	}
	g_context = NULL;
	pthread_mutex_unlock(&g_lock);
	free(g_script);
	g_script = NULL;
	g_script_len = 0;
}
