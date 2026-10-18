/* Разбор и запись строк файла ввода. Формат — в quic_input_script.h. */

#include "quic_input_script.h"

#include <ctype.h>  /* isspace */
#include <errno.h>  /* errno — проверка ошибок strtoull/strtol */
#include <stdio.h>  /* snprintf */
#include <stdlib.h> /* strtoull, strtol, strtoul */
#include <string.h> /* strcmp, strncmp, strlen */

/* Найти тип по имени; -1, если такого нет */
static int type_from_name(const char* name, size_t len)
{
	for (int i = 0; i < QUIC_INPUT_TYPE_COUNT; i++)
	{
		/* имя должно совпасть целиком, а не только началом */
		if (strlen(QUIC_INPUT_TYPE_NAMES[i]) == len &&
		    strncmp(QUIC_INPUT_TYPE_NAMES[i], name, len) == 0)
			return i;
	}
	return -1;
}

int quic_input_parse_line(const char* line, QuicInputEvent* ev)
{
	const char* p = line;
	while (*p && isspace((unsigned char)*p))
		p++; /* пропустить пробелы в начале */
	if (*p == '\0' || *p == '#')
		return 0; /* пустая строка или комментарий */
	if (strncmp(p, QUIC_INPUT_COLUMNS, strlen(QUIC_INPUT_COLUMNS)) == 0)
		return 0; /* заголовок столбцов */

	char* end = NULL; /* сюда strto* кладёт место, где закончилось число */

	/* t_us */
	errno = 0;
	const unsigned long long t = strtoull(p, &end, 10);
	if (errno || end == p || *end != ',')
		return -1; /* не число или нет запятой после него */
	p = end + 1;

	/* type: до следующей запятой */
	const char* comma = strchr(p, ',');
	if (!comma)
		return -1;
	const int type = type_from_name(p, (size_t)(comma - p));
	if (type < 0)
		return -1; /* неизвестный тип события */
	p = comma + 1;

	/* flags: шестнадцатеричное с 0x или без (основание 0 — strtoul сам поймёт) */
	errno = 0;
	const unsigned long flags = strtoul(p, &end, 0);
	if (errno || end == p || *end != ',' || flags > 0xFFFFFFFFul)
		return -1;
	p = end + 1;

	/* a и b — целые со знаком (у relmouse смещения бывают отрицательными) */
	errno = 0;
	const long a = strtol(p, &end, 10);
	if (errno || end == p || *end != ',')
		return -1;
	p = end + 1;
	errno = 0;
	const long b = strtol(p, &end, 10);
	if (errno || end == p)
		return -1;
	while (*end && isspace((unsigned char)*end))
		end++; /* пропустить перевод строки и пробелы в конце */
	if (*end != '\0')
		return -1; /* лишнее после последнего числа */

	ev->t_us = (uint64_t)t;
	ev->type = (QuicInputType)type;
	ev->flags = (uint32_t)flags;
	ev->a = (int32_t)a;
	ev->b = (int32_t)b;
	return 1;
}

int quic_input_format_line(const QuicInputEvent* ev, char* buf, size_t size)
{
	if (ev->type >= QUIC_INPUT_TYPE_COUNT)
		return -1; /* защита от мусора в type */
	const int n = snprintf(buf, size, "%llu,%s,0x%04x,%d,%d\n", (unsigned long long)ev->t_us,
	                       QUIC_INPUT_TYPE_NAMES[ev->type], (unsigned)ev->flags, (int)ev->a,
	                       (int)ev->b);
	if (n < 0 || (size_t)n >= size)
		return -1; /* не поместилось в буфер */
	return n;
}
