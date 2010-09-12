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

typedef int scribe_ctx_t;

/* Create a scribe context to use the record/replay features
 * On success, scribe_ctx_create() returns 0 and you can start using scribe
 * On error, it returns an error number, and the contents of *scribe are
 * undefined.
 * Errors: EACCES, ENOENT: the scribe device couldn't be opened.
 */
int scribe_ctx_create(scribe_ctx_t *scribe_ctx);

/* Destroy a scribe context */
int scribe_ctx_destroy(scribe_ctx_t scribe_ctx);


#endif /*_SCRIBE_H */
