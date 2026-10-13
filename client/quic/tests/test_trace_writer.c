#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include "quic_trace_writer.h"

#define THREADS 4
#define PER_THREAD 50000
static QuicTraceWriter* W;
static void* worker(void* arg) {
    long id = (long)arg;
    for (int i = 0; i < PER_THREAD; i++) {
        uint64_t t = quic_trace_writer_now_us(W);
        quic_trace_writer_record(W, t, id % 2 ? 'u' : 'd', id % 2 ? "input" : "graphics",
                                 i % 3 == 0 ? -1 : 1004, (uint32_t)(id * 1000000 + i));
    }
    return NULL;
}
int main(void) {
    const char* path = "/tmp/test_trace.csv";
    W = quic_trace_writer_open(path);
    if (!W) { puts("FAIL open"); return 1; }
    quic_trace_writer_comment(W, "scenario=%s size=%dx%d", "unit", 1280, 720);
    quic_trace_writer_columns(W);
    pthread_t th[THREADS];
    for (long i = 0; i < THREADS; i++) pthread_create(&th[i], NULL, worker, (void*)i);
    for (int i = 0; i < THREADS; i++) pthread_join(th[i], NULL);
    unsigned long long cnt = quic_trace_writer_count(W);
    quic_trace_writer_close(W);

    /* читаем обратно и проверяем каждую строку */
    FILE* f = fopen(path, "r"); char line[256];
    int comments = 0, header = 0, bad = 0; long rows = 0;
    static unsigned char seen[THREADS][PER_THREAD];
    unsigned long long last_t[THREADS] = {0}; int nonmono = 0;
    while (fgets(line, sizeof line, f)) {
        if (line[0] == '#') { comments++; continue; }
        if (!strcmp(line, "t_us,dir,stream,mcs,len\n")) { header++; continue; }
        unsigned long long t; char dir; char stream[32]; char mcs[16] = ""; unsigned len;
        /* разбор вручную: поле mcs может быть пустым */
        char* p = line; char* f1 = strsep(&p, ","); char* f2 = strsep(&p, ",");
        char* f3 = strsep(&p, ","); char* f4 = strsep(&p, ","); char* f5 = strsep(&p, "\n");
        if (!f1||!f2||!f3||!f4||!f5) { bad++; continue; }
        t = strtoull(f1, 0, 10); dir = f2[0]; snprintf(stream, sizeof stream, "%s", f3);
        snprintf(mcs, sizeof mcs, "%s", f4); len = (unsigned)strtoul(f5, 0, 10);
        long id = len / 1000000, i = len % 1000000;
        int want_mcs_empty = (i % 3 == 0);
        if (id >= THREADS || i >= PER_THREAD || seen[id][i] ||
            dir != (id % 2 ? 'u' : 'd') || strcmp(stream, id % 2 ? "input" : "graphics") ||
            (want_mcs_empty ? mcs[0] != 0 : strcmp(mcs, "1004"))) { bad++; continue; }
        seen[id][i] = 1; rows++;
        if (t < last_t[id]) nonmono++;   /* внутри одного потока время не убывает */
        last_t[id] = t;
    }
    fclose(f);
    printf("count()=%llu, строк данных=%ld (ожидалось %d), комментариев=%d, заголовков=%d, битых=%d, время назад=%d\n",
           cnt, rows, THREADS * PER_THREAD, comments, header, bad, nonmono);
    int ok = cnt == THREADS*PER_THREAD && rows == THREADS*PER_THREAD && comments == 3 && header == 1 && !bad && !nonmono;
    puts(ok ? "ИТОГ: OK" : "ИТОГ: ОШИБКА");
    return !ok;
}
