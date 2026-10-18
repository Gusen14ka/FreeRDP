/* Реализация записи трассы. Описание формата — в quic_trace_writer.h,
 * общая картина — в TRACE.md. */

#include "quic_trace_writer.h"

#include <pthread.h> /* мьютекс: PDU пишут несколько потоков */
#include <stdarg.h>  /* va_list для comment() в стиле printf */
#include <stdio.h>   /* FILE, fprintf, setvbuf */
#include <stdlib.h>  /* malloc, calloc, free */
#include <time.h>    /* clock_gettime */

/* Буфер stdio: строки копятся в памяти и уходят на диск пачками,
 * чтобы запись не тормозила клиент и не искажала t_us.
 * Запись строки в буфер — копирование ~30 байт в память, без системного вызова. */
#define QUIC_TRACE_BUF_SIZE (1u << 20) /* 1 МБ */

/* Принудительный сброс не реже раза в секунду: если клиент убьют
 * сигналом (kill в скриптах), потеряется не больше ~1 с трассы. */
#define QUIC_TRACE_FLUSH_US 1000000u

/* Состояние открытой трассы */
struct QuicTraceWriter
{
	FILE* f;                 /* открытый файл трассы */
	char* buf;               /* наш буфер на 1 МБ, отданный stdio через setvbuf */
	uint64_t t0_ns;          /* момент открытия по монотонным часам, нс — ноль для t_us */
	uint64_t last_flush_us;  /* когда последний раз сбрасывали буфер на диск */
	uint64_t count;          /* сколько записей сделано */
	pthread_mutex_t lock;    /* PDU пишут несколько потоков FreeRDP — строки не должны перемешаться */
};

/* Текущее время по монотонным часам в наносекундах */
static uint64_t mono_ns(void)
{
	struct timespec ts;                  /* секунды + наносекунды */
	clock_gettime(CLOCK_MONOTONIC, &ts); /* монотонные часы: не прыгают при подводке времени */
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec; /* всё в наносекундах */
}

QuicTraceWriter* quic_trace_writer_open(const char* path)
{
	QuicTraceWriter* w = calloc(1, sizeof(*w)); /* calloc обнуляет все поля */
	if (!w)
		return NULL; /* не хватило памяти */

	w->f = fopen(path, "w"); /* "w" — создать или перезаписать файл */
	if (!w->f)
	{
		free(w); /* файл не открылся (нет папки, нет прав) — убираем за собой */
		return NULL;
	}
	w->buf = malloc(QUIC_TRACE_BUF_SIZE); /* свой буфер вместо стандартного (обычно 4 КБ) */
	if (w->buf)
		setvbuf(w->f, w->buf, _IOFBF, QUIC_TRACE_BUF_SIZE); /* _IOFBF — полная буферизация */
	/* если malloc не удался, работаем со стандартным буфером — медленнее, но корректно */

	pthread_mutex_init(&w->lock, NULL); /* мьютекс с настройками по умолчанию */
	w->t0_ns = mono_ns();               /* отсюда отсчитывается t_us */

	/* Реальное время старта — чтобы сопоставлять трассу с другими логами */
	struct timespec rt;
	clock_gettime(CLOCK_REALTIME, &rt); /* обычные «настенные» часы */
	fprintf(w->f, "# trace v1\n# start_unix_ns=%llu\n",
	        (unsigned long long)rt.tv_sec * 1000000000ull + (unsigned long long)rt.tv_nsec);
	return w;
}

void quic_trace_writer_comment(QuicTraceWriter* w, const char* fmt, ...)
{
	if (!w)
		return; /* трасса не открыта — ничего не делаем */
	pthread_mutex_lock(&w->lock); /* захватываем файл, чтобы строку не разорвал другой поток */
	fputs("# ", w->f);            /* признак комментария */
	va_list ap;                   /* список аргументов после fmt */
	va_start(ap, fmt);
	vfprintf(w->f, fmt, ap);      /* печать как printf */
	va_end(ap);
	fputc('\n', w->f);            /* конец строки */
	pthread_mutex_unlock(&w->lock);
}

void quic_trace_writer_columns(QuicTraceWriter* w)
{
	if (!w)
		return;
	pthread_mutex_lock(&w->lock);
	fputs("t_us,dir,stream,mcs,len\n", w->f); /* имена столбцов для pandas */
	pthread_mutex_unlock(&w->lock);
}

uint64_t quic_trace_writer_now_us(const QuicTraceWriter* w)
{
	if (!w)
		return 0;
	return (mono_ns() - w->t0_ns) / 1000u; /* сколько прошло с открытия, в микросекундах */
}

void quic_trace_writer_record(QuicTraceWriter* w, uint64_t t_us, char dir,
                              const char* stream, int mcs, uint32_t len)
{
	if (!w)
		return;
	pthread_mutex_lock(&w->lock); /* одна строка = одна атомарная запись */
	if (mcs >= 0) /* slow-path: номер канала есть */
		fprintf(w->f, "%llu,%c,%s,%d,%u\n", (unsigned long long)t_us, dir, stream, mcs, len);
	else /* fast-path: поле mcs пустое (два запятых подряд) */
		fprintf(w->f, "%llu,%c,%s,,%u\n", (unsigned long long)t_us, dir, stream, len);
	w->count++; /* счётчик для итоговой статистики */
	/* Раз в секунду принудительно сбрасываем буфер на диск. Вторая половина
	 * условия — защита от переполнения, если t_us вдруг меньше прошлого
	 * (записи из разных потоков могут прийти чуть не по порядку). */
	if (t_us - w->last_flush_us >= QUIC_TRACE_FLUSH_US && t_us >= w->last_flush_us)
	{
		fflush(w->f);            /* содержимое буфера — в файл */
		w->last_flush_us = t_us; /* запоминаем момент сброса */
	}
	pthread_mutex_unlock(&w->lock);
}

uint64_t quic_trace_writer_count(const QuicTraceWriter* w)
{
	return w ? w->count : 0; /* 0, если трасса не открыта */
}

void quic_trace_writer_close(QuicTraceWriter* w)
{
	if (!w)
		return;
	pthread_mutex_lock(&w->lock); /* дождаться, пока другие потоки допишут строки */
	fclose(w->f); /* fclose сбрасывает буфер на диск и закрывает файл */
	pthread_mutex_unlock(&w->lock);
	pthread_mutex_destroy(&w->lock);
	free(w->buf); /* только после fclose: setvbuf-буфер должен жить до закрытия */
	free(w);
}
