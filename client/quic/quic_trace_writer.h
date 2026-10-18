#pragma once /* защита от повторного включения заголовка */

/* ================================================================
 * Запись трассы RDP в CSV. Чистый C + pthread, без зависимостей
 * от FreeRDP — поэтому тестируется отдельно (tests/test_trace_writer.c).
 *
 * Трасса — файл, где каждая строка описывает одно PDU сессии:
 * когда, в какую сторону, в какой поток форка и сколько байт.
 * Содержимое PDU не пишется (для воспроизведения нужен только размер).
 *
 * Формат файла (trace v1):
 *   # trace v1                      — комментарии/метаданные, строки с '#'
 *   # ...                             могут встречаться в любом месте
 *   t_us,dir,stream,mcs,len         — заголовок столбцов
 *   1023,d,graphics,1003,8192       — одна строка на PDU
 *
 *   t_us   — микросекунды от открытия трассы (CLOCK_MONOTONIC —
 *            часы, которые только идут вперёд и не прыгают при
 *            подводке системного времени)
 *   dir    — 'd' (down) сервер->клиент, 'u' (up) клиент->сервер
 *   stream — поток форка: graphics / input / vchannel / control
 *   mcs    — номер MCS-канала (slow-path), пусто для fast-path
 *   len    — размер PDU в байтах
 *
 * Читать: pandas.read_csv(path, comment='#')
 * ================================================================ */

#include <stdint.h> /* uint64_t, uint32_t */

/* Непрозрачный тип: поля спрятаны в .c, снаружи — только указатель */
typedef struct QuicTraceWriter QuicTraceWriter;

/* Открыть файл трассы и записать первые строки ("# trace v1", время старта).
 * NULL при ошибке. Отсчёт t_us начинается с этого момента. */
QuicTraceWriter* quic_trace_writer_open(const char* path);

/* Строка-комментарий "# <текст>" (как printf). Перевод строки добавляется сам.
 * __attribute__((format...)) — компилятор проверит аргументы как у printf. */
void quic_trace_writer_comment(QuicTraceWriter* w, const char* fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* Строка заголовка столбцов. Вызвать один раз после метаданных. */
void quic_trace_writer_columns(QuicTraceWriter* w);

/* Микросекунды от открытия трассы (монотонные часы). */
uint64_t quic_trace_writer_now_us(const QuicTraceWriter* w);

/* Одна запись. mcs < 0 — поле пустое. Потокобезопасно
 * (можно звать одновременно из разных потоков FreeRDP). */
void quic_trace_writer_record(QuicTraceWriter* w, uint64_t t_us, char dir,
                              const char* stream, int mcs, uint32_t len);

/* Сколько записей сделано. */
uint64_t quic_trace_writer_count(const QuicTraceWriter* w);

/* Сбросить буфер на диск и закрыть файл. w после вызова недействителен. */
void quic_trace_writer_close(QuicTraceWriter* w);
