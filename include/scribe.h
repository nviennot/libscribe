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

struct scribe_operations {
	/*
	 * When starting record/replay, init_loader() will be called. This
	 * function is responsable to execve() the init process.
	 * Note: "scribe_init" will be prepended to argv.
	 * Note: during replay, you will be provided with the original
	 * parameters.
	 *
	 * If init_loader == NULL, the default one will be used.
	 */
	void (*init_loader) (void *private_data, char *const *argv, char *const *envp);

	/* Notifications during the replay */
	void (*on_backtrace) (void *private_data, loff_t *log_offset, int num);
	void (*on_diverge) (void *private_data, struct scribe_event_diverge *event);
};

/*
 * Create a scribe context to use the record/replay features
 * On success, scribe_context_create() returns 0 and you can start using scribe
 * On error, it returns -1, and the contents of *ctx are undefined, and errno
 * is set appropriately.
 */
int scribe_context_create(scribe_context_t *pctx, struct scribe_operations *ops,
			  void *private_data);

/* Destroy a scribe context */
int scribe_context_destroy(scribe_context_t ctx);

/*
 * Start record/replay with a command line. Returns the pid of the init
 * process.
 */
pid_t scribe_record(scribe_context_t ctx, int flags, int log_fd, char *const *argv, char *const *envp);
pid_t scribe_replay(scribe_context_t ctx, int flags, int log_fd, int backtrace_len);

/*
 * Wait for the record/replay to finish. It also allow your notifications to
 * get called.
 * returns -1 when the record/replay failed
 * returns -2 when pumping notification failed
 */
int scribe_wait(scribe_context_t ctx);

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
