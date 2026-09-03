/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "timestamp.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>

// clock_gettime() is not implemented on older versions of OS X (< 10.12)
#if defined(__APPLE__) && !defined(CLOCK_MONOTONIC)
#include <sys/time.h>
#define CLOCK_MONOTONIC 0
int clock_gettime(int clk_id, struct timespec *t) {
	(void)clk_id;

	// gettimeofday() does not return monotonic time but it should be good enough.
	struct timeval now;
	if (gettimeofday(&now, NULL))
		return -1;

	t->tv_sec = now.tv_sec;
	t->tv_nsec = now.tv_usec * 1000;
	return 0;
}
#endif // defined(__APPLE__) && !defined(CLOCK_MONOTONIC)

static timestamp_t current_posix_timestamp(clockid_t clock_id) {
	struct timespec ts;
	if (clock_gettime(clock_id, &ts))
		return 0;
	return (timestamp_t)ts.tv_sec * 1000 + (timestamp_t)ts.tv_nsec / 1000000;
}
#endif

timestamp_t current_timestamp() {
#ifdef _WIN32
	return (timestamp_t)GetTickCount();
#else // POSIX
	/*
	 * Scheduling and TURN allocation deadlines must become overdue while a
	 * machine is suspended so they are processed immediately after resume.
	 */
#ifdef CLOCK_BOOTTIME
	return current_posix_timestamp(CLOCK_BOOTTIME);
#else
	return current_posix_timestamp(CLOCK_MONOTONIC);
#endif
#endif
}

timestamp_t current_consent_timestamp() {
#ifdef _WIN32
	return current_timestamp();
#else // POSIX
	/*
	 * Consent checks cannot run while the process is suspended. Measure their
	 * expiry in active runtime so resume first gets a chance to send the
	 * already-overdue check instead of destroying an unchanged candidate pair.
	 */
	return current_posix_timestamp(CLOCK_MONOTONIC);
#endif
}
