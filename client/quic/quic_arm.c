/* «Взвод» записи по SIGUSR1. Описание — quic_arm.h и TRACE.md. */

#include "quic_arm.h"

#include <signal.h>    /* sigaction, SIGUSR1 */
#include <stdatomic.h> /* атомарные флаги: их меняет обработчик сигнала */
#include <stdio.h>
#include <stdlib.h>    /* getenv */
#include <string.h>
#include <time.h>      /* clock_gettime */
#include <unistd.h>    /* write — безопасный вызов из обработчика сигнала */

static atomic_int g_inited = 0;    /* 1 — quic_arm_init уже отработал */
static atomic_int g_signal_mode = 0; /* 1 — ждём SIGUSR1 */
static atomic_int g_armed = 0;     /* 1 — сигнал пришёл */
static _Atomic uint64_t g_t0 = 0;  /* момент сигнала, нс */

uint64_t quic_arm_now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts); /* монотонные часы — не прыгают при подводке времени */
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* Обработчик SIGUSR1. В обработчике сигнала можно звать только
 * async-signal-safe функции: clock_gettime и write — из их числа,
 * printf — нет. Повторные сигналы игнорируются: старт один. */
static void on_sigusr1(int sig)
{
	(void)sig;
	int expected = 0;
	if (atomic_compare_exchange_strong(&g_armed, &expected, 1)) /* только первый сигнал */
	{
		atomic_store(&g_t0, quic_arm_now_ns());
		static const char msg[] = "[arm] получен SIGUSR1: запись начата\n";
		(void)!write(2, msg, sizeof msg - 1); /* 2 — stderr */
	}
}

void quic_arm_init(void)
{
	int expected = 0;
	if (!atomic_compare_exchange_strong(&g_inited, &expected, 1))
		return; /* уже инициализировано другим модулем */

	const char* mode = getenv("RDP_CAPTURE_ARM");
	if (!mode || strcmp(mode, "signal") != 0)
	{
		atomic_store(&g_armed, 1); /* обычный режим: «взведено» сразу */
		return;
	}

	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_sigusr1;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART; /* прерванные системные вызовы продолжатся сами */
	if (sigaction(SIGUSR1, &sa, NULL) != 0)
	{
		fprintf(stderr, "[arm] ОШИБКА: не удалось поставить обработчик SIGUSR1, пишу сразу\n");
		atomic_store(&g_armed, 1);
		return;
	}
	atomic_store(&g_signal_mode, 1);
	fprintf(stderr, "[arm] жду SIGUSR1, чтобы начать запись (kill -USR1 %d)\n", (int)getpid());
}

int quic_arm_signal_mode(void)
{
	return atomic_load(&g_signal_mode);
}

int quic_arm_is_armed(void)
{
	return atomic_load(&g_armed);
}

uint64_t quic_arm_t0_ns(void)
{
	return atomic_load(&g_t0);
}
