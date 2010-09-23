/*
 * scribe.h - Scribe API in user-space
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

#ifndef _SCRIBE_H
#define _SCRIBE_H

typedef struct scribe_context {
	int dev;
} scribe_context_t;

/* Create a scribe context to use the record/replay features
 * On success, scribe_context_create() returns 0 and you can start using scribe
 * On error, it returns -1, and the contents of *ctx are undefined, and errno
 * is set appropriately.
 */
int scribe_context_create(scribe_context_t **pctx);

/* Destroy a scribe context */
int scribe_context_destroy(scribe_context_t *ctx);

/* Start the recording with a command line
 * Note that if the process cannot be executed, it will still report
 * a success, and your recording will contains a failed execve()
 */
int scribe_start_recording(scribe_context_t *ctx, char *const *argv);

/* Wait for things to happen */
int scribe_wait(scribe_context_t *ctx);

#endif /*_SCRIBE_H */
