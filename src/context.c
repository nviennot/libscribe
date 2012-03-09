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
#include <linux/fs.h>
#include <signal.h>
#include <limits.h>
#include <scribe.h>

struct scribe_context {
	int dev;
	int mode;
	struct scribe_operations *ops;
	void *private_data;
	loff_t *backtrace;
};

#define SCRIBE_DEV_PATH "/dev/" SCRIBE_DEVICE_NAME

int scribe_context_create(scribe_context_t *pctx, struct scribe_operations *ops,
			  void *private_data)
{
	scribe_context_t ctx;

	ctx = malloc(sizeof(*ctx));
	if (!ctx)
		return -1;
	memset(ctx, 0, sizeof(*ctx));

	ctx->dev = open(SCRIBE_DEV_PATH, O_RDWR);
	if (ctx->dev < 0) {
		free(ctx);
		return -1;
	}

	ctx->mode = 0;
	ctx->ops = ops;
	ctx->private_data = private_data;

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

/* Direct kernel commands. They are not exported */
static int _cmd(scribe_context_t ctx, void *event)
{
	ssize_t written, to_write;

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
static int __scribe_record(scribe_context_t ctx, int flags, int log_fd)
{
	struct scribe_event_record e =
		{.h = {.type = SCRIBE_EVENT_RECORD},
			.flags = flags, .log_fd = log_fd};
	return _cmd(ctx, &e);
}
static int __scribe_replay(scribe_context_t ctx, int flags, int log_fd,
			   int backtrace_len)
{
	struct scribe_event_replay e =
		{.h = {.type = SCRIBE_EVENT_REPLAY},
			.flags = flags, .log_fd = log_fd,
			.backtrace_len = backtrace_len };
	return _cmd(ctx, &e);
}
int scribe_stop(scribe_context_t ctx)
{
	struct scribe_event_stop e = {.h = {.type = SCRIBE_EVENT_STOP}};
	return _cmd(ctx, &e);
}
static int scribe_attach_on_execve(scribe_context_t ctx, int enable)
{
	struct scribe_event_attach_on_execve e =
		{.h = {.type = SCRIBE_EVENT_ATTACH_ON_EXECVE},
			.enable = !!enable};
	return _cmd(ctx, &e);
}
int scribe_bookmark(scribe_context_t ctx)
{
	struct scribe_event_bookmark_request e =
		{.h = {.type = SCRIBE_EVENT_BOOKMARK_REQUEST}};
	return _cmd(ctx, &e);
}
int scribe_resume(scribe_context_t ctx)
{
	struct scribe_event_resume e =
		{.h = {.type = SCRIBE_EVENT_RESUME}};
	return _cmd(ctx, &e);
}

int scribe_check_deadlock(scribe_context_t ctx)
{
	struct scribe_event_check_deadlock e =
		{.h = {.type = SCRIBE_EVENT_CHECK_DEADLOCK}};
	return _cmd(ctx, &e);
}

void scribe_default_init_loader(char *const *argv, char *const *envp)
{
	if (envp && envp != environ) {
		if (clearenv())
			return;
		for (; *envp; envp++) {
			if (putenv((char *)*envp))
				return;
		}
	}

	execvp(argv[0], argv);
}


static int mount_new_proc(void)
{
	umount2("/proc", MNT_DETACH);
	if (mount("proc", "/proc", "proc", 0, NULL))
		return -1;
	return 0;
}

static int mount_new_devpts(void)
{
	/*
	 * TODO Instead of hardcoding the group and the mode, use the original
	 * ones.
	 */
	umount2("/dev/pts", MNT_DETACH);
	if (mount("devpts", "/dev/pts", "devpts",
		  MS_NOEXEC | MS_NOSUID | MS_RELATIME,
		  "newinstance,gid=5,mode=0620,ptmxmode=0666"))
		return -1;
	if (mount("/dev/pts/ptmx", "/dev/ptmx", NULL, MS_BIND, NULL))
		return -1;
	return 0;
}

/* The init process launcher */
struct child_args {
	scribe_context_t ctx;
	char *const *argv;
	char *const *envp;
	const char *cwd;
	const char *chroot;
};
static int init_process(void *_fn_args)
{
	struct child_args *fn_args = _fn_args;
	scribe_context_t ctx = fn_args->ctx;

	if (fn_args->chroot) {
		if (chroot(fn_args->chroot) < 0)
			goto bad;
	}

	if (chdir(fn_args->cwd) < 0)
		goto bad;

	if (mount_new_proc() < 0)
		goto bad;

	if (mount_new_devpts() < 0)
		goto bad;

	if (scribe_attach_on_execve(ctx, 1))
		goto bad;

	/*
	 * Close the scribe device, so that it doesn't appear in the
	 * child's process space.
	 */
	close(ctx->dev);

	if (ctx->ops && ctx->ops->init_loader)
		ctx->ops->init_loader(ctx->private_data,
				      fn_args->argv, fn_args->envp);
	else
		scribe_default_init_loader(fn_args->argv, fn_args->envp);

bad:
	/* TODO propagate the error through a pipe to the parent */
	perror("Init failed. You probably want to ctrl+c\n");
	return 1;
}

#define STACK_SIZE (4*4096)

#define SCRIBE_RECORD	1
#define SCRIBE_REPLAY	2

static pid_t scribe_start(scribe_context_t ctx, int action, int flags,
			  int log_fd, int backtrace_len,
			  char *const *argv, char *const *envp,
			  const char *cwd, const char *chroot)
{
	struct child_args fn_args = {
		.ctx = ctx,
		.argv = argv,
		.envp = envp,
		.cwd = cwd,
		.chroot = chroot
	};
	pid_t init_pid;
	int clone_flags;
	char *stack;
	int ret;

	stack = malloc(STACK_SIZE);
	if (!stack)
		return -1;

	if (action == SCRIBE_RECORD)
		ret = __scribe_record(ctx, flags, log_fd);
	else
		ret = __scribe_replay(ctx, flags, log_fd, backtrace_len);

	if (ret) {
		free(stack);
		return -1;
	}

	clone_flags = CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNS | SIGCHLD;
	if (flags & SCRIBE_CLONE_NEWNET)
		clone_flags |= CLONE_NEWNET;
	init_pid = clone(init_process, stack + STACK_SIZE, clone_flags, &fn_args);
	free(stack);

	if (init_pid < 0) {
		scribe_stop(ctx);
		return -1;
	}

	ctx->mode = action;
	return init_pid;
}

static ssize_t _read(int fd, void *buf, size_t count)
{
	ssize_t ret;
	size_t to_read = count;

	while (count > 0) {
		ret = read(fd, buf, count);
		if (ret == 0) {
			errno = ENODATA;
			return -1;
		}
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

static int save_init(int log_fd, int flags,
		     char *const *argv, char *const *envp,
		     const char *cwd, const char *chroot)
{
	struct scribe_event_init *e;
	int argc, envc;
	size_t size, total_size;
	int i;
	int ret;
	char *data;

	if (cwd == NULL)
		cwd = "";
	if (chroot == NULL)
		chroot = "";

	size = 0;
	for (argc = 0; argv[argc]; size += strlen(argv[argc])+1, argc++);
	for (envc = 0; envp[envc]; size += strlen(envp[envc])+1, envc++);
	size += strlen(cwd) + 1;
	size += strlen(chroot) + 1;

	total_size = size + sizeof_event_from_type(SCRIBE_EVENT_INIT);
	e = malloc(total_size);
	if (!e)
		return -1;

	e->h.h.type = SCRIBE_EVENT_INIT;
	e->h.size = size;
	e->flags = flags;
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

	strcpy(data, cwd);
	data += strlen(cwd) + 1;

	strcpy(data, chroot);
	data += strlen(chroot) + 1;

	ret = _write(log_fd, e, total_size);
	free(e);
	if (ret < 0)
		return -1;
	return 0;
}

static int restore_init(int log_fd, int *flags,
			void **_data, char ***_argv, char ***_envp,
			char **cwd, char **chroot)
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

	*flags = e.flags;
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

	*cwd = data;
	data += strlen(data) + 1;
	if (strlen(*cwd) == 0)
		*cwd = NULL;

	*chroot = data;
	data += strlen(data) + 1;
	if (strlen(*chroot) == 0)
		*chroot = NULL;

	return 0;
}

pid_t scribe_record(scribe_context_t ctx, int flags, int log_fd,
		    char *const *argv, char *const *envp,
		    const char *cwd, const char *chroot)
{
	char cwd_buffer[PATH_MAX];
	char **new_argv = NULL;
	int argc, i;
	pid_t ret;

	if (!cwd) {
		if (chroot)
			cwd = "/";
		else {
			cwd = getcwd(cwd_buffer, sizeof(cwd_buffer));
			if (!cwd)
				return -1;
		}
	}

	for (argc = 0; argv[argc]; argc++);

	if (!argc) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * We'll use the default init process for scribe
	 * which is scribe_init
	 */
	argc++; /* that's for "scribe_init" */

	new_argv = malloc(sizeof(*new_argv) * (argc+1));
	if (!new_argv)
		return -1;

	if (!(flags & SCRIBE_CUSTOM_INIT)) {
		new_argv[0] = "scribe_init";
		for (i = 1; i < argc; i++)
			new_argv[i] = argv[i-1];
		new_argv[i] = NULL;

		argv = new_argv;
	}

	if (!envp)
		envp = environ;

	if (save_init(log_fd, flags, argv, envp, cwd, chroot) < 0) {
		free(new_argv);
		return -1;
	}

	ret = scribe_start(ctx, SCRIBE_RECORD, flags, log_fd,
			   0, argv, envp, cwd, chroot);

	free(new_argv);
	return ret;
}

pid_t scribe_replay(scribe_context_t ctx, int flags, int log_fd,
		    int backtrace_len)
{
	pid_t ret;
	void *data;
	char **argv, **envp;
	char *cwd, *chroot;

	if (restore_init(log_fd, &flags, &data,
			 &argv, &envp, &cwd, &chroot) < 0)
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
			   backtrace_len, argv, envp, cwd, chroot);
	free(data);
	return ret;
}

int scribe_wait(scribe_context_t ctx)
{
	int backtrace_len = 0;

	char buffer[1024];
	struct scribe_event *e = (struct scribe_event *)buffer;
	int dev = ctx->dev;

	/*
	 * When we call a callback, we don't assume that ctx is valid anymore,
	 * hence the caching of dev, and we hope to return EBADF.
	 * XXX In some cases, the file descriptor can still be valid if the
	 * caller closed the context and opened something else...
	 */

	for (;;) {
		/* Events arrive one by one */
		if (read(dev, buffer, sizeof(buffer)) < 0)
			return -2;

		if (e->type == SCRIBE_EVENT_BACKTRACE) {
			struct scribe_event_backtrace *bt = (void*)buffer;
			ctx->backtrace[backtrace_len++] = bt->event_offset;
		} else if (backtrace_len) {
			if (ctx->ops && ctx->ops->on_backtrace) {
				ctx->ops->on_backtrace(ctx->private_data,
						       ctx->backtrace,
						       backtrace_len);
				backtrace_len = 0;
				continue;
			}
			backtrace_len = 0;
		}

		if (e->type == SCRIBE_EVENT_BOOKMARK_REACHED &&
		    ctx->ops && ctx->ops->on_bookmark) {
			struct scribe_event_bookmark_reached *bev = (void*)e;
			ctx->ops->on_bookmark(ctx->private_data,
					      bev->id, bev->npr);
			continue;
		}

		if (e->type == SCRIBE_EVENT_ON_ATTACH &&
		    ctx->ops && ctx->ops->on_attach) {
			struct scribe_event_on_attach *oaev = (void*)e;
			ctx->ops->on_attach(ctx->private_data,
					    oaev->real_pid, oaev->scribe_pid);
			continue;
		}

		if (is_diverge_type(e->type) && ctx->ops && ctx->ops->on_diverge) {
			ctx->ops->on_diverge(ctx->private_data,
					     (struct scribe_event_diverge *)e);
			continue;
		}

		if (e->type == SCRIBE_EVENT_CONTEXT_IDLE) {
			struct scribe_event_context_idle *idle = (void*)e;
			if (idle->error) {
				errno = -idle->error;
				return -1;
			}
			return 0;
		}
	}
	return 0;
}
