#pragma once /* защита от повторного включения заголовка */

/* ================================================================
 * Формат файла ввода (запись и воспроизведение). Чистый C, без
 * зависимостей от FreeRDP — тестируется отдельно (tests/test_input_script.c).
 *
 * Одна строка — одно событие ввода, которое клиент отправил серверу:
 *   # комментарий                     — строки с '#' и пустые пропускаются
 *   t_us,type,flags,a,b               — заголовок столбцов
 *   1523000,kbd,0x0000,30,0           — клавиша нажата (скан-код 30 = 'A')
 *   1610000,kbd,0x8000,30,0           — клавиша отпущена (флаг RELEASE)
 *   2000000,mouse,0x0800,640,360      — движение мыши в точку (640, 360)
 *
 *   t_us  — микросекунды от активации сессии (момент, когда FreeRDP
 *           начинает отправлять ввод) — одинаковая точка отсчёта
 *           при записи и при воспроизведении
 *   type  — тип события (таблица QUIC_INPUT_TYPE_NAMES ниже)
 *   flags — флаги события как в протоколе RDP (шестнадцатеричные)
 *   a, b  — параметры: код клавиши / координаты / смещения (зависит от type)
 *
 * Значения записываются ровно в том виде, в каком их получает
 * freerdp_input_send_*(), поэтому воспроизведение повторяет
 * отправку байт в байт.
 * ================================================================ */

#include <stdint.h> /* uint16_t, uint64_t ... */
#include <stddef.h> /* size_t */

/* Тип события — какую функцию freerdp_input_send_*() звать */
typedef enum
{
	QUIC_INPUT_KBD = 0,  /* клавиша по скан-коду: flags, a = код */
	QUIC_INPUT_UNICODE,  /* символ Unicode: flags, a = код символа */
	QUIC_INPUT_MOUSE,    /* мышь: flags (кнопки/колесо/движение), a = x, b = y */
	QUIC_INPUT_XMOUSE,   /* доп. кнопки мыши (4-я, 5-я): flags, a = x, b = y */
	QUIC_INPUT_RELMOUSE, /* относительное движение: flags, a = dx, b = dy (со знаком) */
	QUIC_INPUT_SYNC,     /* синхронизация состояния Caps/Num/Scroll Lock: flags */
	QUIC_INPUT_FOCUS,    /* окно получило фокус: flags = состояние Lock-клавиш */
	QUIC_INPUT_PAUSE,    /* клавиша Pause (особая последовательность) */
	QUIC_INPUT_TYPE_COUNT
} QuicInputType;

/* Имена типов в файле — в том же порядке, что enum */
static const char* const QUIC_INPUT_TYPE_NAMES[QUIC_INPUT_TYPE_COUNT] = {
	"kbd", "unicode", "mouse", "xmouse", "relmouse", "sync", "focus", "pause",
};

/* Одно событие ввода */
typedef struct
{
	uint64_t t_us;      /* время от активации сессии, мкс */
	QuicInputType type; /* тип события */
	uint32_t flags;     /* флаги RDP (для sync — 32 бита, остальные 16) */
	int32_t a;          /* первый параметр (код / x / dx) */
	int32_t b;          /* второй параметр (y / dy), иначе 0 */
} QuicInputEvent;

/* Строка заголовка столбцов (без перевода строки) */
#define QUIC_INPUT_COLUMNS "t_us,type,flags,a,b"

/* Разобрать одну строку файла.
 * Возвращает 1 — событие разобрано в *ev; 0 — строку надо пропустить
 * (комментарий, пустая, заголовок); -1 — строка испорчена. */
int quic_input_parse_line(const char* line, QuicInputEvent* ev);

/* Записать событие строкой (с переводом строки) в buf размером size.
 * Возвращает длину строки или -1, если не поместилась. */
int quic_input_format_line(const QuicInputEvent* ev, char* buf, size_t size);
