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
	void (*on_diverge) (void *private_data, struct scribe_event_diverge *event,
			    struct scribe_event *mutations, size_t mutation_size);
	void (*on_bookmark) (void *private_data, int id, int npr);
	void (*on_attach) (void *private_data, pid_t real_pid, pid_t scribe_pid);
};

/* The default init_loader */
void scribe_default_init_loader(char *const *argv, char *const *envp);

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
 * when golive_bookmark_id != -1, the replay will golive on a specific
 * bookmark.
 * You may pass SCRIBE_DEFAULT or SCRIBE_ALL or a combination as @flags.
 * For replay @flags has no effect (the one used for the recording are used).
 */
#define SCRIBE_CUSTOM_INIT 0x01
#define SCRIBE_CLONE_NEWNET 0x02
pid_t scribe_record(scribe_context_t ctx, int flags, int log_fd,
		    char *const *argv, char *const *envp,
		    const char *cwd, const char *chroot);
pid_t scribe_replay(scribe_context_t ctx, int flags, int log_fd,
		    int backtrace_len);


/*
 * Wait for the record/replay to finish. It also allow your notifications to
 * get called.
 * returns -1 when the record/replay failed
 * returns -2 when pumping notification failed
 */
int scribe_wait(scribe_context_t ctx);

/*
 * Abort the record: It will stop the recording ASAP.
 * Abort the replay: It will go live when it can (right now, you may only use
 * it when called from on_bookmark()).
 */
int scribe_stop(scribe_context_t ctx);


/*
 * Continues execution when a notification got fired
 */
int scribe_resume(scribe_context_t ctx);

/*
 * Request a bookmark during the recording. All processes will sync together,
 * and a bookmark event will be written in the log file.
 */
int scribe_bookmark(scribe_context_t ctx);

/*
 * Check if a deadlock happened during the replay
 */
int scribe_check_deadlock(scribe_context_t ctx);

/*
 * scribe_get_event_str() returns the string representation of an event
 */
char *scribe_get_event_str(char *str, size_t size, struct scribe_event *event);


/* Scribed process specific */
int scribe_is_recording(void);
int scribe_is_replaying(void);
int scribe_disable(void);
int scribe_enable(void);
int scribe_send_event(const struct scribe_event *uevent);
int scribe_recv_event(struct scribe_event *uevent, size_t size);

static inline void clear_regs(void)
{
	__asm__ __volatile__ (
		"pushf\n"
		"pop %%eax\n"
		"and $0, %%ax\n"
		"push %%eax\n"
		"popf\n"
		"xor %%ebx, %%ebx\n"
		"xor %%ecx, %%ecx\n"
		"xor %%edx, %%edx\n"
		"xor %%esi, %%esi\n"
		"xor %%edi, %%edi\n"
		"xor %%eax, %%eax\n"
		: : : "ebx", "ecx", "edx", "esi", "edi", "eax"
	);
}

static inline void scribe_on_replay(void (*fn)(void *arg), void *arg)
{
	scribe_disable();
	if (scribe_is_replaying())
		fn(arg);
	clear_regs();
	scribe_enable();
}

#endif /*_SCRIBE_H */
