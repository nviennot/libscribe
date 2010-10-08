/*
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

#include <stdio.h>
#include <string.h>

#include <linux/types.h>
#include <scribe.h>

char *scribe_get_event_str(char *str, size_t size, struct scribe_event *event)
{

#define PRINT(t, fmt, ...)						\
	if (event->type == t) {						\
		struct_##t *e = (struct_##t *)event;			\
		snprintf(str, size, #t ": " fmt, __VA_ARGS__);		\
	}								\

	
	PRINT(SCRIBE_EVENT_PID, "pid=%d", e->pid);
	PRINT(SCRIBE_EVENT_SYSCALL, "syscall=%d, ret=%d", e->nr, e->ret);

#undef PRINT

	return str;
}
