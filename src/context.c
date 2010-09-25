
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
#include <sys/mount.h>
#include <signal.h>
#include <limits.h>

#include <scribe.h>
#include "eclone.h"

#define SCRIBE_DEV_NAME "/dev/scribe"

#define SCRIBE_IDLE		0x00000000
#define SCRIBE_RECORD		0x00000001
#define SCRIBE_REPLAY		0x00000002
#define SCRIBE_STOP		0x00000004
#define SCRIBE_DEVICE_NAME		"scribe"
#define SCRIBE_IO_MAGIC			0xFF
#define SCRIBE_IO_SET_STATE		_IOR(SCRIBE_IO_MAGIC,	1, int)
#define SCRIBE_IO_ATTACH_ON_EXEC	_IOR(SCRIBE_IO_MAGIC,	2, int)

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
	free(ctx);
	return 0;
}

struct child_args {
	scribe_context_t *ctx;
	char *const *argv;
};


static int init_process(void *_fn_args)
{
	struct child_args *fn_args = _fn_args;
	int dev = fn_args->ctx->dev;

	/* mount a fresh new /proc */
	umount2("/proc", MNT_DETACH);
	mount("proc", "/proc", "proc", 0, NULL);

	if (ioctl(dev, SCRIBE_IO_ATTACH_ON_EXEC, 1))
		return 1;

	/* close the scribe device, so that it doesn't appear in the
	 * child's process space
	 */
	close(dev);

	execvp(fn_args->argv[0], fn_args->argv);
	return 1;
}

#define STACK_SIZE 4*4096

int scribe_start(scribe_context_t *ctx, int flags, char *const *argv)
{
	struct child_args fn_args = { .ctx = ctx, .argv = argv };
	char **new_argv = NULL;
	pid_t init_pid;
	int clone_flags;
	int ctx_state;
	char *stack;
	int argc, i;

	ctx_state = 0;
	ctx_state |= flags & RECORD ? SCRIBE_RECORD : 0;
	ctx_state |= flags & REPLAY ? SCRIBE_REPLAY : 0;
	if (!ctx_state) {
		errno = EINVAL;
		return -1;
	}

	if (!(flags & CUSTOM_INIT_PROCESS)) {
		/* We'll use the default init process for scribe
		 * which is scribe_init
		 */
		for (argc = 0; argv[argc]; argc++);
		argc++;
		new_argv = malloc(sizeof(*new_argv) * argc);
		if (!new_argv)
			return -1;
		new_argv[0] = "scribe_init";
		for (i = 1; i < argc; i++)
			new_argv[i] = argv[i-1];
		fn_args.argv = new_argv;
	}

	stack = malloc(STACK_SIZE);
	if (!stack) {
		free(new_argv);
		return -1;
	}
	if (ioctl(ctx->dev, SCRIBE_IO_SET_STATE, ctx_state)) {
		free(new_argv);
		free(stack);
		return 1;
	}
	clone_flags = CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNS | SIGCHLD;
	init_pid = clone(init_process, stack + STACK_SIZE, clone_flags, &fn_args);
	free(stack);
	free(new_argv);

	if (init_pid < 0) {
		ioctl(ctx->dev, SCRIBE_IO_SET_STATE, SCRIBE_IDLE);
		return -1;
	}

	return 0;
}

int scribe_wait(scribe_context_t *ctx)
{
	int status;
	while (waitpid(-1, &status, __WALL) >= 0);
	return 0;
}

