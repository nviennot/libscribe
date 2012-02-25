/*
 * scribe.c - Scribe API in user-space
 *
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <scribe.h>

#define __NR_get_scribe_flags	339
#define __NR_set_scribe_flags	340
#define __NR_scribe_send_event	341
#define __NR_scribe_recv_event	342

int get_scribe_flags(pid_t pid, unsigned long *flags)
{
	return syscall(__NR_get_scribe_flags, pid, flags);
}

int set_scribe_flags(pid_t pid, int flags, int duration)
{
	return syscall(__NR_set_scribe_flags, pid, flags, duration);
}

int scribe_send_event(const struct scribe_event *uevent)
{
	return syscall(__NR_scribe_send_event, uevent);
}

int scribe_recv_event(struct scribe_event *uevent, size_t size)
{
	return syscall(__NR_scribe_recv_event, uevent, size);
}

int scribe_is_recording(void)
{
	unsigned long flags;
	if (get_scribe_flags(0, &flags) < 0)
		return 0;
	return flags & SCRIBE_PS_RECORD;
}

int scribe_is_replaying(void)
{
	unsigned long flags;
	if (get_scribe_flags(0, &flags) < 0)
		return 0;
	return flags & SCRIBE_PS_REPLAY;
}

int scribe_disable(void)
{
	return set_scribe_flags(0, 0, SCRIBE_PERMANANT);
}

int scribe_enable(void)
{
	return set_scribe_flags(0, SCRIBE_PS_ENABLE_ALL, SCRIBE_PERMANANT);
}
