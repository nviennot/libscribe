
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

struct scribe_context {
	int dev;
	struct scribe_operations ops;
	loff_t *backtrace;
};

#define SCRIBE_DEV_PATH "/dev/" SCRIBE_DEVICE_NAME

int scribe_context_create(scribe_context_t *pctx)
{
	scribe_context_t ctx;

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

int scribe_context_destroy(scribe_context_t ctx)
{
	if (ctx->backtrace)
		free(ctx->backtrace);
	if (close(ctx->dev))
		return -1;
	free(ctx);
	return 0;
}

int scribe_set_operations(scribe_context_t ctx, struct scribe_operations *ops)
{
	ctx->ops = *ops;
	return 0;
}

/* Direct kernel commands. They are not exported */
static int _cmd(scribe_context_t ctx, void *event)
{
	size_t written, to_write;

	to_write = sizeof_event((struct scribe_event *)event);
	written = write(ctx->dev, event, to_write);

	if (written < 0)
		return -1;

	if (written != to_write) {
		errno = EINVAL;
		return -1;
	}

	return 0;
}
static int cmd_record(scribe_context_t ctx, int log_fd)
{
	struct scribe_event_record e =
		{.h = {.type = SCRIBE_EVENT_RECORD}, .log_fd = log_fd};
	return _cmd(ctx, &e);
}
static int cmd_replay(scribe_context_t ctx, int log_fd, int backtrace_len)
{
	struct scribe_event_replay e =
		{.h = {.type = SCRIBE_EVENT_REPLAY},
			.log_fd = log_fd, .backtrace_len = backtrace_len };
	return _cmd(ctx, &e);
}
static int cmd_stop(scribe_context_t ctx)
{
	struct scribe_event_stop e = {.h = {.type = SCRIBE_EVENT_STOP}};
	return _cmd(ctx, &e);
}
static int cmd_attach_on_execve(scribe_context_t ctx, int enable)
{
	struct scribe_event_attach_on_execve e =
		{.h = {.type = SCRIBE_EVENT_ATTACH_ON_EXECVE},
			.enable = !!enable};
	return _cmd(ctx, &e);
}

/* The init process launcher */
struct child_args {
	scribe_context_t ctx;
	char *const *argv;
	char *const *envp;
};
static int init_process(void *_fn_args)
{
	struct child_args *fn_args = _fn_args;
	scribe_context_t ctx = fn_args->ctx;
	char *const *envp;

	/* mount a fresh new /proc */
	umount2("/proc", MNT_DETACH);
	mount("proc", "/proc", "proc", 0, NULL);

	if (cmd_attach_on_execve(ctx, 1))
		goto bad;

	envp = fn_args->envp;
	if (envp && envp != environ) {
		if (clearenv())
			goto bad;
		for (; *envp; envp++) {
			if (putenv((char *)*envp))
				goto bad;
		}
	}

	/*
	 * Close the scribe device, so that it doesn't appear in the
	 * child's process space.
	 */
	close(ctx->dev);

	execvp(fn_args->argv[0], fn_args->argv);
bad:
	printf("Init failed. You probably want to ctrl+c\n");
	return 1;
}

static int notification_pump(scribe_context_t ctx)
{
	int backtrace_len = 0;

	char buffer[1024];
	struct scribe_event *e = (struct scribe_event *)buffer;

	for (;;) {
		/* Events arrive one by one */
		if (read(ctx->dev, buffer, sizeof(buffer)) < 0)
			return -1;

		if (e->type == SCRIBE_EVENT_BACKTRACE) {
			struct scribe_event_backtrace *bt = (void*)buffer;
			ctx->backtrace[backtrace_len++] = bt->event_offset;
		} else if (backtrace_len) {
			if (ctx->ops.on_backtrace) {
				ctx->ops.on_backtrace(ctx, ctx->backtrace,
						      backtrace_len);
			}
			backtrace_len = 0;
		}

		if (is_diverge_type(e->type) && ctx->ops.on_diverge) {
			ctx->ops.on_diverge(ctx,
					    (struct scribe_event_diverge *)e);
		}

		if (e->type == SCRIBE_EVENT_CONTEXT_IDLE) {
			struct scribe_event_context_idle *idle = (void*)buffer;
			if (ctx->ops.on_idle)
				ctx->ops.on_idle(ctx, idle->error);
			return 0;
		}
	}

	return 0;
}

#define STACK_SIZE 4*4096

static int scribe_start(scribe_context_t ctx, int action, int flags,
			int log_fd, int backtrace_len,
			char *const *argv, char *const *envp)
{
	struct child_args fn_args = {
		.ctx = ctx,
		.argv = argv,
		.envp = envp,
	};
	pid_t init_pid;
	int clone_flags;
	char *stack;
	int ret;

	stack = malloc(STACK_SIZE);
	if (!stack)
		return -1;

	if (action == SCRIBE_RECORD)
		ret = cmd_record(ctx, log_fd);
	else
		ret = cmd_replay(ctx, log_fd, backtrace_len);
	if (ret) {
		free(stack);
		return -1;
	}

	clone_flags = CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNS | SIGCHLD;
	init_pid = clone(init_process, stack + STACK_SIZE, clone_flags, &fn_args);
	free(stack);

	if (init_pid < 0) {
		scribe_stop(ctx);
		return -1;
	}

	return notification_pump(ctx);
}

static ssize_t _read(int fd, void *buf, size_t count)
{
	ssize_t ret;
	size_t to_read = count;

	while (count > 0) {
		ret = read(fd, buf, count);
		if (ret < 0)
			return ret;
		buf = (char *)buf + ret;
		count -= ret;
	}
	return to_read;
}

static ssize_t _write(int fd, const void *buf, size_t count)
{
	ssize_t ret;
	size_t to_write = count;

	while (count > 0) {
		ret = write(fd, buf, count);
		if (ret < 0)
			return ret;
		buf = (char *)buf + ret;
		count -= ret;
	}
	return to_write;
}

static int save_init(int log_fd, char *const *argv, char *const *envp)
{
	struct scribe_event_init *e;
	int argc, envc;
	size_t size, total_size;
	int i;
	int ret;
	char *data;

	size = 0;
	for (argc = 0; argv[argc]; size += strlen(argv[argc])+1, argc++);
	for (envc = 0; envp[envc]; size += strlen(envp[envc])+1, envc++);

	total_size = size + sizeof_event_from_type(SCRIBE_EVENT_INIT);
	e = malloc(total_size);
	if (!e)
		return -1;

	e->h.h.type = SCRIBE_EVENT_INIT;
	e->h.size = size;
	e->argc = argc;
	e->envc = envc;
	data = (char *)e->data;
	for (i = 0; i < argc; i++) {
		strcpy(data, argv[i]);
		data += strlen(argv[i]) + 1;
	}
	for (i = 0; i < envc; i++) {
		strcpy(data, envp[i]);
		data += strlen(envp[i]) + 1;
	}

	ret = _write(log_fd, e, total_size);
	free(e);
	if (ret < 0)
		return -1;
	return 0;
}

static int restore_init(int log_fd, void **_data, char ***_argv, char ***_envp)
{
	struct scribe_event_init e;
	char *data = NULL;
	char **argv = NULL, **envp = NULL;
	int i;

	if (_read(log_fd, &e, sizeof(e)) < 0)
		return -1;

	data = malloc(e.h.size + (e.argc + e.envc + 2) * sizeof(char *));
	if (!data)
		return -1;

	argv = (char **)(data + e.h.size);
	envp = argv + e.argc + 1;

	*_data = data;
	*_argv = argv;
	*_envp = envp;

	if (_read(log_fd, data, e.h.size) < 0) {
		free(data);
		return -1;
	}

	for (i = 0; i < e.argc; i++) {
		argv[i] = data;
		data += strlen(data) + 1;
	}
	argv[i] = NULL;

	for (i = 0; i < e.envc; i++) {
		envp[i] = data;
		data += strlen(data) + 1;
	}
	envp[i] = NULL;

	return 0;
}

int scribe_record(scribe_context_t ctx, int flags, int log_fd, char *const *argv)
{
	char **new_argv = NULL;
	int argc, i;
	int ret;

	for (argc = 0; argv[argc]; argc++);

	if (!argc) {
		errno = EINVAL;
		return -1;
	}

	if (!(flags & CUSTOM_INIT_PROCESS)) {
		/* We'll use the default init process for scribe
		 * which is scribe_init
		 */
		argc++; /* that's for "scribe_init" */

		new_argv = malloc(sizeof(*new_argv) * (argc+1));
		if (!new_argv)
			return -1;

		new_argv[0] = "scribe_init";
		for (i = 1; i < argc; i++)
			new_argv[i] = argv[i-1];
		new_argv[i] = NULL;

		argv = new_argv;
	}

	if (save_init(log_fd, argv, environ) < 0) {
		free(new_argv);
		return -1;
	}

	ret = scribe_start(ctx, SCRIBE_RECORD, flags, log_fd,
			   0, argv, environ);

	free(new_argv);
	return ret;
}

int scribe_replay(scribe_context_t ctx, int flags, int log_fd, int backtrace_len)
{
	int ret;
	void *data;
	char **argv, **envp;

	if (restore_init(log_fd, &data, &argv, &envp) < 0)
		return -1;

	if (backtrace_len) {
		if (ctx->backtrace)
			free(ctx->backtrace);
		ctx->backtrace = malloc(sizeof(loff_t) * backtrace_len);
		if (!ctx->backtrace) {
			free(data);
			return -1;
		}
	}

	ret = scribe_start(ctx, SCRIBE_REPLAY, flags, log_fd,
			   backtrace_len, argv, envp);
	free(data);
	return ret;
}

int scribe_stop(scribe_context_t ctx)
{
	return cmd_stop(ctx);
}

