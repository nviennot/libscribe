
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <signal.h>

#include <scribe.h>
#include "eclone.h"

#define SCRIBE_DEV_NAME "/dev/scribe"

#define SCRIBE_IO_MAGIC			0xFF
#define SCRIBE_IO_START_RECORDING	_IOR(SCRIBE_IO_MAGIC,	1, int)
#define SCRIBE_IO_START_REPLAYING	_IOR(SCRIBE_IO_MAGIC,	2, int)
#define SCRIBE_IO_REQUEST_STOP		_IO(SCRIBE_IO_MAGIC,	3)

int scribe_context_create(scribe_context_t **pctx)
{
	scribe_context_t *ctx;

	ctx = malloc(sizeof(*ctx));
	if (!ctx)
		return -1;

	ctx->dev = open(SCRIBE_DEV_NAME, O_RDWR);
	if (ctx->dev < 0) {
		fprintf(stderr, "cannot open " SCRIBE_DEV_NAME "\n");
		free(ctx);
		return -1;
	}

	*pctx = ctx;
	return 0;
}

int scribe_context_destroy(scribe_context_t *ctx)
{
	if (close(ctx->dev))
		return -1;
	return 0;
}

struct child_args {
	scribe_context_t *ctx;
	char *const *argv;
};

#define STACK_SIZE 4*4096
#define CHILD_PID 2

static int child_loader(void *_fn_args)
{
	struct child_args *fn_args = _fn_args;
	kill(CHILD_PID, SIGSTOP);
	return execvp(fn_args->argv[0], fn_args->argv);
}

static int init_process(void *_fn_args)
{
	struct child_args *fn_args = _fn_args;
	scribe_context_t *ctx = fn_args->ctx;
	struct clone_args clone_args;
	pid_t child_pid;
	char *stack;
	int status = 0;

	stack = malloc(STACK_SIZE);
	if (!stack)
		return -1;

	/* FIXME remount all the 'proc' mounted file systems */

	memset(&clone_args, 0, sizeof(clone_args));
	child_pid = CHILD_PID;
	clone_args.nr_pids = 1;
	clone_args.child_stack = (unsigned long)stack;
	clone_args.child_stack_size = STACK_SIZE;
	child_pid = eclone(child_loader, _fn_args, 0, &clone_args, &child_pid);

	/* Wait for the child to be asleep */
	while (!WIFSTOPPED(status)) {
		if (waitpid(-1, &status, WUNTRACED | __WALL) < 0)
			return -1;
	}

	/* Now we start recording: when the child wakes up, it will
	 * be recorded and starting the execve()
	 */
	if (ioctl(ctx->dev, SCRIBE_IO_START_RECORDING, child_pid) < 0)
		return -1;
	kill(child_pid, SIGCONT);

	/* doing the init process in the new namespace */
	while (waitpid(-1, &status, __WALL) >= 0)
		;
	return 0;
}

int scribe_start_recording(scribe_context_t *ctx, char *const *argv)
{
	struct child_args fn_args = { .ctx = ctx, .argv = argv };
	pid_t init_pid;
	int status = 0;
	char *stack;

	stack = malloc(STACK_SIZE);
	if (!stack)
		return -1;
	init_pid = clone(init_process, stack + STACK_SIZE,
			CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNS | SIGCHLD, &fn_args);
	if (init_pid < 0)
		return -1;

	/* FIXME Need a way to wait for the recording to start.
	 * Upon reception of a SIGCHLD, we want to return an error,
	 * it means the init process failed
	 */

	return 0;
}

int scribe_wait(scribe_context_t *ctx)
{
	int status;
	while (waitpid(-1, &status, __WALL) >= 0);
	return 0;
}

