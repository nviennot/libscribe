
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

#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <errno.h>
#include <scribe.h>
#include <fcntl.h>
#include <unistd.h>

#define SCRIBE_DEV_NAME "/dev/scribe"

int scribe_ctx_create(scribe_ctx_t *scribe_ctx)
{
	int dev;

	dev = open(SCRIBE_DEV_NAME, O_RDWR);
	if (dev < 0) {
		fprintf(stderr, "cannot open " SCRIBE_DEV_NAME "\n");
		return errno;
	}

	*scribe_ctx = dev;

	return 0;
}

int scribe_ctx_destroy(scribe_ctx_t scribe_ctx)
{
	if (close(scribe_ctx))
		return errno;
	return 0;
}

