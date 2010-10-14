
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

#define SCRIBE_DEV_PATH "/dev/" SCRIBE_DEVICE_NAME

int scribe_context_create(scribe_context_t **pctx)
{
	scribe_context_t *ctx;

	ctx = malloc(sizeof(*ctx));
	if (!ctx)
		return -1;
	memset(ctx, 0, sizeof(*ctx));

	ctx->dev = open(SCRIBE_DEV_PATH, O_RDWR);
	if (ctx->dev < 0) {
		fprintf(stderr, "cannot open " SCRIBE_DEV_PATH "\n");
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

/* Direct kernel commands. They are not exported */
static int _cmd(scribe_context_t *ctx, void *event)
{
	size_t written, to_write;

	to_write = sizeof_event((struct scribe_event *)event);
	written = write(ctx->dev, event, to_write);

	if (written < 0)
		return -1;

	if (written != to_write) {
		errno = -EINVAL;
		return -1;
	}

	return 0;
}
static int cmd_record(scribe_context_t *ctx, int log_fd)
{
	struct scribe_event_record e =
		{.h = {.type = SCRIBE_EVENT_RECORD}, .log_fd = log_fd};
	return _cmd(ctx, &e);
}
static int cmd_replay(scribe_context_t *ctx, int log_fd)
{
	struct scribe_event_replay e =
		{.h = {.type = SCRIBE_EVENT_REPLAY}, .log_fd = log_fd};
	return _cmd(ctx, &e);
}
static int cmd_stop(scribe_context_t *ctx)
{
	struct scribe_event_stop e = {.h = {.type = SCRIBE_EVENT_STOP}};
	return _cmd(ctx, &e);
}
static int cmd_attach_on_execve(scribe_context_t *ctx, int enable)
{
	struct scribe_event_attach_on_execve e =
		{.h = {.type = SCRIBE_EVENT_ATTACH_ON_EXECVE},
			.enable = !!enable};
	return _cmd(ctx, &e);
}

/* The init process launcher */
struct child_args {
	scribe_context_t *ctx;
	char *const *argv;
};
static int init_process(void *_fn_args)
{
	struct child_args *fn_args = _fn_args;
	scribe_context_t *ctx = fn_args->ctx;

	/* mount a fresh new /proc */
	umount2("/proc", MNT_DETACH);
	mount("proc", "/proc", "proc", 0, NULL);

	if (cmd_attach_on_execve(ctx, 1))
		goto bad;

	/* close the scribe device, so that it doesn't appear in the
	 * child's process space
	 */
	close(ctx->dev);

	execvp(fn_args->argv[0], fn_args->argv);
bad:
	printf("Init failed. You probably want to ctrl+c\n");
	return 1;
}

static int notification_pump(scribe_context_t *ctx)
{
	char buffer[1024];
	struct scribe_event *e = (struct scribe_event *)buffer;

	for (;;) {
		/* Events arrive one by one */
		if (read(ctx->dev, buffer, sizeof(buffer)) < 0)
			return -1;

		if (e->type == SCRIBE_EVENT_CONTEXT_IDLE) {
			struct scribe_event_context_idle *idle = (void*)buffer;
			if (ctx->on_idle)
				ctx->on_idle(ctx, idle->error);
			return 0;
		}
	}

	return 0;
}

#define STACK_SIZE 4*4096

static int scribe_start(scribe_context_t *ctx, int action, int flags,
			int log_fd, char *const *argv)
{
	struct child_args fn_args = { .ctx = ctx, .argv = argv };
	char **new_argv = NULL;
	pid_t init_pid;
	int clone_flags;
	char *stack;
	int argc, i;
	int ret;

	if (!(flags & CUSTOM_INIT_PROCESS)) {
		/* We'll use the default init process for scribe
		 * which is scribe_init
		 */
		for (argc = 0; argv[argc]; argc++);
		argc++;
		new_argv = malloc(sizeof(*new_argv) * (argc+1));
		if (!new_argv)
			return -1;
		new_argv[0] = "scribe_init";
		for (i = 1; i < argc; i++)
			new_argv[i] = argv[i-1];
		new_argv[i] = NULL;
		fn_args.argv = new_argv;
	}

	stack = malloc(STACK_SIZE);
	if (!stack) {
		free(new_argv);
		return -1;
	}

	if (action == SCRIBE_RECORD)
		ret = cmd_record(ctx, log_fd);
	else
		ret = cmd_replay(ctx, log_fd);
	if (ret) {
		free(new_argv);
		free(stack);
		return -1;
	}

	clone_flags = CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNS | SIGCHLD;
	init_pid = clone(init_process, stack + STACK_SIZE, clone_flags, &fn_args);
	free(stack);
	free(new_argv);

	if (init_pid < 0) {
		scribe_stop(ctx);
		return -1;
	}

	return notification_pump(ctx);
}

int scribe_record(scribe_context_t *ctx, int flags, int log_fd, char *const *argv)
{
	return scribe_start(ctx, SCRIBE_RECORD, flags, log_fd, argv);
}

int scribe_replay(scribe_context_t *ctx, int flags, int log_fd, char *const *argv)
{
	return scribe_start(ctx, SCRIBE_REPLAY, flags, log_fd, argv);
}

int scribe_stop(scribe_context_t *ctx)
{
	return cmd_stop(ctx);
}

