/* Unit-тест формата файла ввода (quic_input_script.c):
 * разбор правильных и испорченных строк и обратимость «записал -> прочитал». */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "quic_input_script.h"

static int fails = 0;
#define CHECK(cond, name) do { if (cond) printf("ok   %s\n", name); \
                               else { printf("FAIL %s\n", name); fails++; } } while (0)

int main(void)
{
    QuicInputEvent e;

    /* Пропускаемые строки */
    CHECK(quic_input_parse_line("# комментарий\n", &e) == 0, "комментарий пропускается");
    CHECK(quic_input_parse_line("\n", &e) == 0, "пустая строка пропускается");
    CHECK(quic_input_parse_line("t_us,type,flags,a,b\n", &e) == 0, "заголовок пропускается");

    /* Правильные строки */
    CHECK(quic_input_parse_line("1523000,kbd,0x8000,30,0\n", &e) == 1 && e.t_us == 1523000 &&
          e.type == QUIC_INPUT_KBD && e.flags == 0x8000 && e.a == 30 && e.b == 0,
          "kbd: отпускание клавиши 30");
    CHECK(quic_input_parse_line("2000000,mouse,0x0800,640,360", &e) == 1 && e.type == QUIC_INPUT_MOUSE &&
          e.a == 640 && e.b == 360, "mouse без перевода строки");
    CHECK(quic_input_parse_line("5,relmouse,0x0800,-12,7\n", &e) == 1 && e.a == -12 && e.b == 7,
          "relmouse с отрицательным смещением");
    CHECK(quic_input_parse_line("7,sync,0x00000006,0,0\n", &e) == 1 && e.type == QUIC_INPUT_SYNC &&
          e.flags == 6, "sync");

    /* Испорченные строки */
    CHECK(quic_input_parse_line("abc,kbd,0,1,0\n", &e) == -1, "время не число");
    CHECK(quic_input_parse_line("1,keyboard,0,1,0\n", &e) == -1, "неизвестный тип");
    CHECK(quic_input_parse_line("1,kb,0,1,0\n", &e) == -1, "тип совпал только началом");
    CHECK(quic_input_parse_line("1,kbd,0,1\n", &e) == -1, "не хватает поля");
    CHECK(quic_input_parse_line("1,kbd,0,1,0,9\n", &e) == -1, "лишнее поле");
    CHECK(quic_input_parse_line("1,kbd,zz,1,0\n", &e) == -1, "флаги не число");

    /* Обратимость: случайные события -> строка -> событие, всё совпадает */
    srand(3);
    long bad = 0;
    char buf[128];
    for (int i = 0; i < 100000; i++)
    {
        QuicInputEvent in = {
            .t_us = ((uint64_t)rand() << 20) ^ (uint64_t)rand(),
            .type = (QuicInputType)(rand() % QUIC_INPUT_TYPE_COUNT),
            .flags = (uint32_t)rand() & 0xFFFF,
            .a = (rand() % 70000) - 35000,
            .b = (rand() % 70000) - 35000,
        }, out;
        if (quic_input_format_line(&in, buf, sizeof buf) < 0 ||
            quic_input_parse_line(buf, &out) != 1 || memcmp(&in, &out, sizeof in) != 0)
            bad++;
    }
    CHECK(bad == 0, "100 000 событий: запись -> чтение без потерь");
    CHECK(quic_input_format_line(&(QuicInputEvent){ .type = QUIC_INPUT_KBD }, buf, 5) == -1,
          "мало места в буфере -> ошибка");

    printf(fails ? "ИТОГ: ОШИБОК %d\n" : "ИТОГ: всё верно\n", fails);
    return fails != 0;
}
