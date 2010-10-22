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

#include <linux/scribe_api.h>

struct scribe_context;
typedef struct scribe_context *scribe_context_t;

/*
 * Create a scribe context to use the record/replay features
 * On success, scribe_context_create() returns 0 and you can start using scribe
 * On error, it returns -1, and the contents of *ctx are undefined, and errno
 * is set appropriately.
 * Once the context is created, you may set your callbacks.
 */
int scribe_context_create(scribe_context_t *pctx);

/* Destroy a scribe context */
int scribe_context_destroy(scribe_context_t ctx);


struct scribe_operations {
	void (*on_idle) (scribe_context_t ctx, int error);
	void (*on_backtrace) (scribe_context_t ctx, loff_t *log_offset, int num);
	void (*on_diverge) (scribe_context_t ctx, struct scribe_event_diverge *event);
};

/*
 * Set callbacks for the context.
 * Must be set before starting record/replay
 */
int scribe_set_operations(scribe_context_t ctx, struct scribe_operations *ops);

/*
 * Start record/replay with a command line.
 * The function returns when the record/replay is over.
 */
#define CUSTOM_INIT_PROCESS	1
int scribe_record(scribe_context_t ctx, int flags, int log_fd, char *const *argv);
int scribe_replay(scribe_context_t ctx, int flags, int log_fd, int backtrace_len);

/*
 * Abort the record: It will stop the recording ASAP.
 * Abort the replay: It will go live when it can.
 */
int scribe_stop(scribe_context_t ctx);

/*
 * scribe_get_event_str() returns the string representation of an event
 */
char *scribe_get_event_str(char *str, size_t size, struct scribe_event *event);

#endif /*_SCRIBE_H */
