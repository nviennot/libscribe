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

static int get_scribe_flags(void)
{
	return syscall(__NR_get_scribe_flags);
}

int set_scribe_flags(int flags)
{
	return syscall(__NR_set_scribe_flags, flags);
}

int scribe_is_recording(void)
{
	return get_scribe_flags() & SCRIBE_PS_RECORD;
}

int scribe_is_replaying(void)
{
	return get_scribe_flags() & SCRIBE_PS_REPLAY;
}

int scribe_disable(void)
{
	return set_scribe_flags(0) < 0 ? -1 : 0;
}

int scribe_enable(void)
{
	return set_scribe_flags(SCRIBE_PS_ENABLE_ALL) < 0 ? -1 : 0;
}
