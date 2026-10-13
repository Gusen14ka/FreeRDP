#include "quic_trace_writer.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* Буфер stdio: строки копятся в памяти и уходят на диск пачками,
 * чтобы запись не тормозила клиент и не искажала t_us. */
#define QUIC_TRACE_BUF_SIZE (1u << 20) /* 1 МБ */

/* Принудительный сброс не реже раза в секунду: если клиент убьют
 * сигналом (kill в скриптах), потеряется не больше ~1 с трассы. */
#define QUIC_TRACE_FLUSH_US 1000000u

struct QuicTraceWriter
{
	FILE* f;
	char* buf;
	uint64_t t0_ns;
	uint64_t last_flush_us;
	uint64_t count;
	pthread_mutex_t lock; /* PDU пишут несколько потоков FreeRDP */
};

static uint64_t mono_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

QuicTraceWriter* quic_trace_writer_open(const char* path)
{
	QuicTraceWriter* w = calloc(1, sizeof(*w));
	if (!w)
		return NULL;

	w->f = fopen(path, "w");
	if (!w->f)
	{
		free(w);
		return NULL;
	}
	w->buf = malloc(QUIC_TRACE_BUF_SIZE);
	if (w->buf)
		setvbuf(w->f, w->buf, _IOFBF, QUIC_TRACE_BUF_SIZE);

	pthread_mutex_init(&w->lock, NULL);
	w->t0_ns = mono_ns();

	/* Реальное время старта — чтобы сопоставлять трассу с другими логами */
	struct timespec rt;
	clock_gettime(CLOCK_REALTIME, &rt);
	fprintf(w->f, "# trace v1\n# start_unix_ns=%llu\n",
	        (unsigned long long)rt.tv_sec * 1000000000ull + (unsigned long long)rt.tv_nsec);
	return w;
}

void quic_trace_writer_comment(QuicTraceWriter* w, const char* fmt, ...)
{
	if (!w)
		return;
	pthread_mutex_lock(&w->lock);
	fputs("# ", w->f);
	va_list ap;
	va_start(ap, fmt);
	vfprintf(w->f, fmt, ap);
	va_end(ap);
	fputc('\n', w->f);
	pthread_mutex_unlock(&w->lock);
}

void quic_trace_writer_columns(QuicTraceWriter* w)
{
	if (!w)
		return;
	pthread_mutex_lock(&w->lock);
	fputs("t_us,dir,stream,mcs,len\n", w->f);
	pthread_mutex_unlock(&w->lock);
}

uint64_t quic_trace_writer_now_us(const QuicTraceWriter* w)
{
	if (!w)
		return 0;
	return (mono_ns() - w->t0_ns) / 1000u;
}

void quic_trace_writer_record(QuicTraceWriter* w, uint64_t t_us, char dir,
                              const char* stream, int mcs, uint32_t len)
{
	if (!w)
		return;
	pthread_mutex_lock(&w->lock);
	if (mcs >= 0)
		fprintf(w->f, "%llu,%c,%s,%d,%u\n", (unsigned long long)t_us, dir, stream, mcs, len);
	else
		fprintf(w->f, "%llu,%c,%s,,%u\n", (unsigned long long)t_us, dir, stream, len);
	w->count++;
	if (t_us - w->last_flush_us >= QUIC_TRACE_FLUSH_US && t_us >= w->last_flush_us)
	{
		fflush(w->f);
		w->last_flush_us = t_us;
	}
	pthread_mutex_unlock(&w->lock);
}

uint64_t quic_trace_writer_count(const QuicTraceWriter* w)
{
	return w ? w->count : 0;
}

void quic_trace_writer_close(QuicTraceWriter* w)
{
	if (!w)
		return;
	pthread_mutex_lock(&w->lock);
	fclose(w->f); /* fclose сбрасывает буфер */
	pthread_mutex_unlock(&w->lock);
	pthread_mutex_destroy(&w->lock);
	free(w->buf); /* только после fclose: setvbuf-буфер должен жить до закрытия */
	free(w);
}
