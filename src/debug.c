/*
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <ctype.h>

#include <linux/types.h>
#include <scribe.h>

#define PAGE_SIZE 4096

#define GET_STR(table, n) ({ 				\
	char *str;					\
	if ((unsigned int)n < sizeof(table##_str)/sizeof(char*))	\
		str = table##_str[(unsigned int)n];			\
	else str = NULL;				\
	str; })

static char *syscall_str[] = {
	"restart_syscall", "exit", "fork", "read", "write", "open", "close",
	"waitpid", "creat", "link", "unlink", "execve", "chdir", "time",
	"mknod", "chmod", "lchown16", "ni_syscall", "stat", "lseek", "getpid",
	"mount", "oldumount", "setuid16", "getuid16", "stime", "ptrace",
	"alarm", "fstat", "pause", "utime", "ni_syscall", "ni_syscall",
	"access", "nice", "ni_syscall", "sync", "kill", "rename", "mkdir",
	"rmdir", "dup", "pipe", "times", "ni_syscall", "brk", "setgid16",
	"getgid16", "signal", "geteuid16", "getegid16", "acct", "umount",
	"ni_syscall", "ioctl", "fcntl", "ni_syscall", "setpgid", "ni_syscall",
	"olduname", "umask", "chroot", "ustat", "dup2", "getppid", "getpgrp",
	"setsid", "sigaction", "sgetmask", "ssetmask", "setreuid16",
	"setregid16", "sigsuspend", "sigpending", "sethostname", "setrlimit",
	"old_getrlimit", "getrusage", "gettimeofday", "settimeofday",
	"getgroups16", "setgroups16", "old_select", "symlink", "lstat",
	"readlink", "uselib", "swapon", "reboot", "old_readdir", "old_mmap",
	"munmap", "truncate", "ftruncate", "fchmod", "fchown16",
	"getpriority", "setpriority", "ni_syscall", "statfs", "fstatfs",
	"ioperm", "socketcall", "syslog", "setitimer", "getitimer", "newstat",
	"newlstat", "newfstat", "uname", "iopl", "vhangup", "ni_syscall",
	"vm86old", "wait4", "swapoff", "sysinfo", "ipc", "fsync", "sigreturn",
	"clone", "setdomainname", "newuname", "modify_ldt", "adjtimex",
	"mprotect", "sigprocmask", "ni_syscall", "init_module",
	"delete_module", "ni_syscall", "quotactl", "getpgid", "fchdir",
	"bdflush", "sysfs", "personality", "ni_syscall", "setfsuid16",
	"setfsgid16", "llseek", "getdents", "select", "flock", "msync",
	"readv", "writev", "getsid", "fdatasync", "sysctl", "mlock",
	"munlock", "mlockall", "munlockall", "sched_setparam",
	"sched_getparam", "sched_setscheduler", "sched_getscheduler",
	"sched_yield", "sched_get_priority_max", "sched_get_priority_min",
	"sched_rr_get_interval", "nanosleep", "mremap", "setresuid16",
	"getresuid16", "vm86", "ni_syscall", "poll", "nfsservctl",
	"setresgid16", "getresgid16", "prctl", "rt_sigreturn", "rt_sigaction",
	"rt_sigprocmask", "rt_sigpending", "rt_sigtimedwait",
	"rt_sigqueueinfo", "rt_sigsuspend", "pread64", "pwrite64", "chown16",
	"getcwd", "capget", "capset", "sigaltstack", "sendfile", "ni_syscall",
	"ni_syscall", "vfork", "getrlimit", "mmap_pgoff", "truncate64",
	"ftruncate64", "stat64", "lstat64", "fstat64", "lchown", "getuid",
	"getgid", "geteuid", "getegid", "setreuid", "setregid", "getgroups",
	"setgroups", "fchown", "setresuid", "getresuid", "setresgid",
	"getresgid", "chown", "setuid", "setgid", "setfsuid", "setfsgid",
	"pivot_root", "mincore", "madvise", "getdents64", "fcntl64",
	"ni_syscall", "ni_syscall", "gettid", "readahead", "setxattr",
	"lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr",
	"listxattr", "llistxattr", "flistxattr", "removexattr",
	"lremovexattr", "fremovexattr", "tkill", "sendfile64", "futex",
	"sched_setaffinity", "sched_getaffinity", "set_thread_area",
	"get_thread_area", "io_setup", "io_destroy", "io_getevents",
	"io_submit", "io_cancel", "fadvise64", "ni_syscall", "exit_group",
	"lookup_dcookie", "epoll_create", "epoll_ctl", "epoll_wait",
	"remap_file_pages", "set_tid_address", "timer_create",
	"timer_settime", "timer_gettime", "timer_getoverrun", "timer_delete",
	"clock_settime", "clock_gettime", "clock_getres", "clock_nanosleep",
	"statfs64", "fstatfs64", "tgkill", "utimes", "fadvise64_64",
	"ni_syscall", "mbind", "get_mempolicy", "set_mempolicy", "mq_open",
	"mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify",
	"mq_getsetattr", "kexec_load", "waitid", "ni_syscall", "add_key",
	"request_key", "keyctl", "ioprio_set", "ioprio_get", "inotify_init",
	"inotify_add_watch", "inotify_rm_watch", "migrate_pages", "openat",
	"mkdirat", "mknodat", "fchownat", "futimesat", "fstatat64",
	"unlinkat", "renameat", "linkat", "symlinkat", "readlinkat",
	"fchmodat", "faccessat", "pselect6", "ppoll", "unshare",
	"set_robust_list", "get_robust_list", "splice", "sync_file_range",
	"tee", "vmsplice", "move_pages", "getcpu", "epoll_pwait", "utimensat",
	"signalfd", "timerfd_create", "eventfd", "fallocate",
	"timerfd_settime", "timerfd_gettime", "signalfd4", "eventfd2",
	"epoll_create1", "dup3", "pipe2", "inotify_init1", "preadv",
	"pwritev", "rt_tgsigqueueinfo", "perf_event_open", "recvmmsg",
	"eclone"
};

static char *syscall_socketcall_str[] = {
	"socket", "bind", "connect", "listen", "accept", "getsockname",
	"getpeername", "socketpair", "send", "recv", "sendto", "recvfrom",
	"shutdown", "setsockopt", "getsockopt", "sendmsg", "recvmsg",
	"accept4", "recvmmsg2"
};

static char *syscall_futex_str[] = {
	"futex_wait", "futex_wake", "futex_fd", "futex_requeue",
	"futex_cmp_requeue", "futex_wake_op", "futex_lock_pi",
	"futex_unlock_pi", "futex_trylock_pi", "futex_wait_bitset",
	"futex_wake_bitset", "futex_wait_requeue_pi", "futex_cmp_requeue_pi"
};

static char *get_syscall_str(char *buffer, unsigned int n)
{
	char *str;

	if ((str = GET_STR(syscall, n)))
		return str;
	if ((str = GET_STR(syscall_socketcall, n - SCRIBE_SOCKETCALL_BASE - 1)))
		return str;
	if ((str = GET_STR(syscall_futex, n - SCRIBE_FUTEX_BASE)))
		return str;

	sprintf(buffer, "syscall_%d", n);
	return buffer;
}

static char *get_syscall_args(char *buffer, unsigned long *args, int num_args)
{
	char *orig_buffer = buffer;
	const char *fmt;
	int i;

	buffer[0] = 0;
	for (i = 0; i < num_args; i++) {
		if (abs((int)args[i]) < PAGE_SIZE)
			fmt = "%ld";
		else if (!(args[i] & 0xfff00000))
			fmt = "%lx";
		else
			fmt = "%p";
		buffer += sprintf(buffer, fmt, args[i]);
		if (i != num_args-1)
			buffer += sprintf(buffer, ", ");
	}

	return orig_buffer;
}

static char *error_str[] = {
	"EPERM", "ENOENT", "ESRCH", "EINTR", "EIO", "ENXIO", "E2BIG",
	"ENOEXEC", "EBADF", "ECHILD", "EAGAIN", "ENOMEM", "EACCES", "EFAULT",
	"ENOTBLK", "EBUSY", "EEXIST", "EXDEV", "ENODEV", "ENOTDIR", "EISDIR",
	"EINVAL", "ENFILE", "EMFILE", "ENOTTY", "ETXTBSY", "EFBIG", "ENOSPC",
	"ESPIPE", "EROFS", "EMLINK", "EPIPE", "EDOM", "ERANGE", "EDEADLK",
	"ENAMETOOLONG", "ENOLCK", "ENOSYS", "ENOTEMPTY", "ELOOP", NULL,
	"ENOMSG", "EIDRM", "ECHRNG", "EL2NSYNC", "EL3HLT", "EL3RST", "ELNRNG",
	"EUNATCH", "ENOCSI", "EL2HLT", "EBADE", "EBADR", "EXFULL", "ENOANO",
	"EBADRQC", "EBADSLT", NULL, "EBFONT", "ENOSTR", "ENODATA", "ETIME",
	"ENOSR", "ENONET", "ENOPKG", "EREMOTE", "ENOLINK", "EADV", "ESRMNT",
	"ECOMM", "EPROTO", "EMULTIHOP", "EDOTDOT", "EBADMSG", "EOVERFLOW",
	"ENOTUNIQ", "EBADFD", "EREMCHG", "ELIBACC", "ELIBBAD", "ELIBSCN",
	"ELIBMAX", "ELIBEXEC", "EILSEQ", "ERESTART", "ESTRPIPE", "EUSERS",
	"ENOTSOCK", "EDESTADDRREQ", "EMSGSIZE", "EPROTOTYPE", "ENOPROTOOPT",
	"EPROTONOSUPPORT", "ESOCKTNOSUPPORT", "EOPNOTSUPP", "EPFNOSUPPORT",
	"EAFNOSUPPORT", "EADDRINUSE", "EADDRNOTAVAIL", "ENETDOWN",
	"ENETUNREACH", "ENETRESET", "ECONNABORTED", "ECONNRESET", "ENOBUFS",
	"EISCONN", "ENOTCONN", "ESHUTDOWN", "ETOOMANYREFS", "ETIMEDOUT",
	"ECONNREFUSED", "EHOSTDOWN", "EHOSTUNREACH", "EALREADY",
	"EINPROGRESS", "ESTALE", "EUCLEAN", "ENOTNAM", "ENAVAIL", "EISNAM",
	"EREMOTEIO", "EDQUOT", "ENOMEDIUM", "EMEDIUMTYPE", "ECANCELED",
	"ENOKEY", "EKEYEXPIRED", "EKEYREVOKED", "EKEYREJECTED", "EOWNERDEAD",
	"ENOTRECOVERABLE", "ERFKILL",
};

static char *error_512_str[] = {
	"ERESTARTSYS", "ERESTARTNOINTR", "ERESTARTNOHAND", "ENOIOCTLCMD",
	"ERESTART_RESTARTBLOCK", NULL, NULL, NULL, NULL, "EBADHANDLE",
	"ENOTSYNC", "EBADCOOKIE", "ENOTSUPP", "ETOOSMALL", "ESERVERFAULT",
	"EBADTYPE", "EJUKEBOX", "EIOCBQUEUED", "EIOCBRETRY"
};

#define MAX_ERRNO	4095
#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)
static char *get_ret_str(char *buffer, long ret)
{
	char *str;
	char perror_buf[512];
	if (IS_ERR_VALUE((unsigned long)ret)) {
		long err = -ret;
		if (err >= 512) {
			str = GET_STR(error_512, err-512);
			sprintf(buffer, "%ld %s", ret, str);
		} else {
			str = GET_STR(error, err-1);
			sprintf(buffer, "%ld %s (%s)", ret, str,
				strerror_r(err, perror_buf, sizeof(perror_buf)));
		}
	} else if ((unsigned long)ret < 0x100000) {
		sprintf(buffer, "%ld", ret);
	} else {
		sprintf(buffer, "%p", (void*)ret);
	}
	return buffer;
}

static char *signal_str[] = {
	"SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT",
	"SIGBUS", "SIGFPE", "SIGKILL", "SIGUSR1", "SIGSEGV", "SIGUSR2",
	"SIGPIPE", "SIGALRM", "SIGTERM", "SIGSTKFLT", "SIGCHLD", "SIGCONT",
	"SIGSTOP", "SIGTSTP", "SIGTTIN", "SIGTTOU", "SIGURG", "SIGXCPU",
	"SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH", "SIGIO", "SIGPWR",
	"SIGSYS"
};

static char *get_signal_str(char *buffer, int signr)
{
	char *str = GET_STR(signal, signr-1);
	if (str)
		return str;
	sprintf(buffer, "SIGRTMIN+%d", signr-32);
	return buffer;
}

static char *get_type_str(char *buffer, int type)
{
#define __SCRIBE_EVENT(name, ...)	\
	if (type == upper##name) return #name;
	#include <linux/scribe_events.h>

	sprintf(buffer, "unkown type: %d", type);
	return buffer;
}

static char *escape_str(char *buf, ssize_t buf_size,
			const void* _data, size_t data_size)
{
	const char *data = _data;
	char *orig_buf = buf;
	ssize_t orig_buf_size = buf_size;
	char c;
	long l;
	int i, s;
	int hex_count = 0;

#define PRINT(fmt, ...) s = snprintf(buf, buf_size, fmt, ##__VA_ARGS__)
	PRINT("\"");
	buf += s;
	buf_size -= s;
	for (i = 0;
	     i < data_size && buf_size > 0;
	     i++, buf += s, buf_size -= s) {
		c = data[i];
		switch (c) {
		case '\n': PRINT("\\n"); break;
		case '\t': PRINT("\\t"); break;
		case '\0': PRINT("\\0"); hex_count++; break;
		case '\\': PRINT("\\\\"); break;
		default:
			if (isgraph(c) || c == ' ')
				PRINT("%c", c);
			else {
				PRINT("\\x%02x", (unsigned char)c);
				hex_count++;
			}
			break;
		}
	}

	if (buf_size <= 0)
		strcpy(buf-5+buf_size, "...\"");
	else
		strcpy(buf, "\"");

	if (hex_count <= i/4)
		return orig_buf;

	for (i = 0, buf_size = orig_buf_size, buf = orig_buf;
	     i < data_size && buf_size > 0;
	     buf += s, buf_size -= s) {
		if ((data_size % sizeof(long)) == 0) {
			l = *((long *)&data[i]);
			if (sizeof(long) == 8)
				PRINT("%s%016lx", i == 0 ? "" : " ", l);
			else
				PRINT("%s%08lx", i == 0 ? "" : " ", l);
			i += sizeof(long);
		} else {
			c = data[i];
			PRINT("%02x", (unsigned char)c);
			i++;
		}
	}
	if (buf_size <= 0)
		strcpy(buf-4+buf_size, "...");
#undef PRINT

	return orig_buf;
}

static char *__get_data_type_str(char *buf, int type)
{
	switch(type) {
		case 0: return "output";
		case SCRIBE_DATA_INPUT: return "input";
		case SCRIBE_DATA_INPUT | SCRIBE_DATA_STRING: return "input string";
		case SCRIBE_DATA_NON_DETERMINISTIC: return "non-det output";
		case SCRIBE_DATA_INTERNAL: return "internal";
		case SCRIBE_DATA_ZERO | SCRIBE_DATA_NON_DETERMINISTIC:
		case SCRIBE_DATA_ZERO: return "zero output";
		default:
			sprintf(buf, "unknown (%02x)", type);
			return buf;
	}
}

static char *get_data_type_str(char *buf, int type)
{
	char tmp[100];

	sprintf(buf, "%s%s",
		__get_data_type_str(tmp, type & ~SCRIBE_DATA_NEED_INFO),
		(type & SCRIBE_DATA_NEED_INFO) ? " (need_info)" : "");

	return buf;
}

static char *get_diverge_data_str(char *buf, ssize_t buf_size, int offset,
				  const char *data, size_t data_size)
{
	char dbuf[offset + data_size];
	char tmp[buf_size];
	int i;

	if (offset > buf_size/2)
		return escape_str(buf, buf_size, data, data_size);

	if (data_size > 2*sizeof(long))
		data_size -= (offset + data_size) % sizeof(long);

	memcpy(dbuf+offset, data, data_size);

	memset(dbuf, 0xCC, offset);
	escape_str(tmp, buf_size, dbuf, offset+data_size);
	memset(dbuf, 0xDD, offset);
	escape_str(buf, buf_size, dbuf, offset+data_size);

	for (i = 0; i < buf_size; i++) {
		if (buf[i] != tmp[i])
			buf[i] = '?';
	}
	return buf;
}

static char *get_strv_str(char *buf, ssize_t buf_size,
			  const char *data, int offset, int len)
{
	int s;
	char *orig_buf = buf;

	while (offset--)
		data += strlen(data) + 1;

	while (len-- && buf_size > 0) {
		s = snprintf(buf, buf_size, "%s%s", data, len ? " " : "");
		buf += s;
		buf_size -= s;
		data += strlen(data) + 1;
	}

	if (buf_size <= 0)
		strcpy(buf-4+buf_size, "...");

	return orig_buf;
}

static const char *get_res_type_str(char *buf, size_t buf_size, int type)
{
	switch (type) {
		case SCRIBE_RES_TYPE_INODE: return "inode";
		case SCRIBE_RES_TYPE_FILE: return "file";
		case SCRIBE_RES_TYPE_FILES_STRUCT: return "files_struct";
		case SCRIBE_RES_TYPE_PID: return "pid";
		case SCRIBE_RES_TYPE_FUTEX: return "futex";
		case SCRIBE_RES_TYPE_IPC: return "ipc";
		case SCRIBE_RES_TYPE_MMAP: return "mmap";
		case SCRIBE_RES_TYPE_PPID: return "ppid";
		case SCRIBE_RES_TYPE_SUNADDR: return "unix addr";
		default:
			snprintf(buf, buf_size, "unknown type %d", type);
			return buf;
	}
}

static char *get_bookmark_type_str(char *buf, size_t buf_size, int type)
{
	switch (type) {
		case SCRIBE_BOOKMARK_PRE_SYSCALL: return "pre-syscall";
		case SCRIBE_BOOKMARK_POST_SYSCALL: return "post-syscall";
		default:
			snprintf(buf, buf_size, "unknown type %d", type);
			return buf;
	}
}

static char *get_regs_str(char *buf, size_t buf_size, struct pt_regs *regs)
{
	snprintf(buf, buf_size,
		 "eip: %04x:%08lx, eflags: %08lx, "
		 "eax: %08lx, ebx: %08lx, ecx: %08lx, edx: %08lx "
		 "esi: %08lx, edi: %08lx, ebp: %08lx, esp: %08lx "
		 "ds: %04x, es: %04x, fs: %04x, gs: %04x, ss: %04x",
		 regs->xcs, regs->eip, regs->eflags,
		 regs->eax, regs->ebx, regs->ecx, regs->edx,
		 regs->esi, regs->edi, regs->ebp, regs->esp,
		 regs->xds, regs->xes, regs->xfs, regs->xgs, regs->xss);
	return buf;
}

static char *get_res_desc(char *buf, size_t buf_size,
			  const void *desc, size_t desc_size)
{
	if (buf_size - 1 < desc_size)
		desc_size = buf_size - 1;
	memcpy(buf, desc, desc_size);
	buf[desc_size] = '\0';
	return buf;
}

static char *get_duration_str(int duration)
{
	if (duration == SCRIBE_UNTIL_NEXT_SYSCALL)
		return "until next syscall";
	return "permanently";
}

static char *get_set_flags_str(char *buf, size_t buf_size, int flags,
			       int duration, struct scribe_event *extra)
{
	char *orig_buf = buf;
	int s;

	if (flags == 0 && duration == SCRIBE_UNTIL_NEXT_SYSCALL) {
		if (extra)
			s = snprintf(buf, buf_size, "%s", "new: ");
		else
			s = snprintf(buf, buf_size, "%s", "ignore syscall");
	} else {
		s = snprintf(buf, buf_size, "set flags = %08x, duration = %s",
			     flags, get_duration_str(duration));
	}
	buf += s;
	buf_size -= s;

	if (extra)
		scribe_get_event_str(buf, buf_size, extra);
	return orig_buf;
}


char *scribe_get_event_str(char *str, size_t size, struct scribe_event *event)
{
	char buffer1[4096];
	char buffer2[4096];
	char buffer3[4096];

#define DECL_EVENT(t) struct##t *e __attribute__((__unused__)) = \
	(struct##t *)event

#define __TYPE(t, fmt, ...)					\
	if (event->type == t) {					\
		DECL_EVENT(t);					\
		snprintf(str, size, fmt, ##__VA_ARGS__);	\
		return str;					\
	}
	__TYPE(SCRIBE_EVENT_INIT,
	       "init: flags = %08x, cwd = \"%s\", chroot = \"%s\", argv = \"%s\", envp = \"%s\"",
	       e->flags,
	       get_strv_str(buffer1    , 100, (char *)e->data, e->argc+e->envc, 1),
	       get_strv_str(buffer1+100, 100, (char *)e->data, e->argc+e->envc+1, 1),
	       get_strv_str(buffer1+200, 100, (char *)e->data, 0, e->argc),
	       get_strv_str(buffer1+300, 30, (char *)e->data, e->argc, e->envc));
	__TYPE(SCRIBE_EVENT_PID, "pid=%d", e->pid);
	__TYPE(SCRIBE_EVENT_DATA_INFO, "data info: %s, ptr = %p, size = %u",
	       get_data_type_str(buffer1, e->data_type),
	       (void *)e->user_ptr, e->size);
	__TYPE(SCRIBE_EVENT_DATA, "data: size = %u, %s",
	       e->h.size, escape_str(buffer1, 100, e->data, e->h.size));
	__TYPE(SCRIBE_EVENT_DATA_EXTRA, "data: %s, ptr = %p, size = %u, %s",
	       get_data_type_str(buffer1, e->data_type),
	       (void *)e->user_ptr, e->h.size,
	       escape_str(buffer2, 100, e->data, e->h.size));
	__TYPE(SCRIBE_EVENT_SYSCALL, "syscall() = %s",
	       get_ret_str(buffer2, e->ret));
	__TYPE(SCRIBE_EVENT_SYSCALL_EXTRA, "%s(%s) = %s",
	       get_syscall_str(buffer1, e->nr),
	       get_syscall_args(buffer2, (unsigned long *)e->args,
				e->h.size/sizeof(unsigned long)),
	       get_ret_str(buffer3, e->ret));
	__TYPE(SCRIBE_EVENT_SYSCALL_END, "syscall ended");
	__TYPE(SCRIBE_EVENT_QUEUE_EOF, "queue EOF");
	__TYPE(SCRIBE_EVENT_RESOURCE_LOCK,
	       "resource lock, serial = %u", e->serial);
	__TYPE(SCRIBE_EVENT_RESOURCE_LOCK_INTR, "resource lock interrupted");
	__TYPE(SCRIBE_EVENT_RESOURCE_LOCK_EXTRA,
	       "resource lock, type = %s, access = %s, id = %u, "
	       "serial = %u, desc = %s",
	       get_res_type_str(buffer1, sizeof(buffer1), e->type),
	       e->write_access ? "write" : "read", e->id, e->serial,
	       get_res_desc(buffer2, sizeof(buffer2), e->desc, e->h.size));
	__TYPE(SCRIBE_EVENT_RESOURCE_UNLOCK,
	       "resource unlock, id = %u", e->id);
	__TYPE(SCRIBE_EVENT_RDTSC, "rdtsc = %016llx", e->tsc);
	__TYPE(SCRIBE_EVENT_SIGNAL, "signal: %s, deferred = %s, info = %s",
	       get_signal_str(buffer1, e->nr),
	       e->deferred ? "true" : "false",
	       escape_str(buffer2, 100, e->info, e->h.size));
	__TYPE(SCRIBE_EVENT_FENCE, "--fence(%u)--", e->serial);
	__TYPE(SCRIBE_EVENT_MEM_OWNED_READ,
	       "mem owned read-only, serial = %u", e->serial);
	__TYPE(SCRIBE_EVENT_MEM_OWNED_WRITE,
	       "mem owned, serial = %u", e->serial);
	__TYPE(SCRIBE_EVENT_MEM_OWNED_READ_EXTRA,
	       "mem owned read-only, id = %u, page = %08x, serial = %u",
	       e->id, e->address, e->serial);
	__TYPE(SCRIBE_EVENT_MEM_OWNED_WRITE_EXTRA,
	       "mem owned, id = %u, page = %08x, serial = %u",
	       e->id, e->address, e->serial);
	__TYPE(SCRIBE_EVENT_MEM_PUBLIC_READ,
	       "mem public read-only, page = %08x", e->address);
	__TYPE(SCRIBE_EVENT_MEM_PUBLIC_WRITE,
	       "mem public, page = %08x", e->address);
	__TYPE(SCRIBE_EVENT_MEM_ALONE, "mem alone");
	__TYPE(SCRIBE_EVENT_REGS, "regs: %s",
	       get_regs_str(buffer1, sizeof(buffer1), &e->regs));
	__TYPE(SCRIBE_EVENT_BOOKMARK,
	       "bookmark, type = %s, id = %u, npr = %u",
	       get_bookmark_type_str(buffer1, sizeof(buffer1), e->type),
	       e->id, e->npr);
	__TYPE(SCRIBE_EVENT_SIG_SEND_COOKIE,
	       "signal send, cookie = %u", e->cookie);
	__TYPE(SCRIBE_EVENT_SIG_RECV_COOKIE,
	       "signal recv, cookie = %u", e->cookie);
	__TYPE(SCRIBE_EVENT_SIG_HANDLED_COOKIE,
	       "signal handled, cookie = %u", e->cookie);
	__TYPE(SCRIBE_EVENT_SIG_HANDLED,
	       "signal handled, signal = %s", get_signal_str(buffer1, e->nr));
	__TYPE(SCRIBE_EVENT_SET_FLAGS, "%s",
	       get_set_flags_str(buffer1, sizeof(buffer1), e->flags, e->duration,
				 e->h.size ? (struct scribe_event *)e->extra : NULL));


	__TYPE(SCRIBE_EVENT_ATTACH_ON_EXECVE,
	       "attach_on_execve: %d", e->enable);
	__TYPE(SCRIBE_EVENT_RECORD,
	       "start recording, logfd = %d", e->log_fd);
	__TYPE(SCRIBE_EVENT_REPLAY,
	       "start replaying, logfd = %d, backtrace_len = %d",
	       e->log_fd, e->backtrace_len);
	__TYPE(SCRIBE_EVENT_STOP, "stop request");
	__TYPE(SCRIBE_EVENT_BOOKMARK_REQUEST, "bookmark request");
	__TYPE(SCRIBE_EVENT_CHECK_DEADLOCK, "check deadlock");
	__TYPE(SCRIBE_EVENT_RESUME, "resume");


	__TYPE(SCRIBE_EVENT_BACKTRACE,
	       "backtrace: offset = %lld", e->event_offset);
	__TYPE(SCRIBE_EVENT_CONTEXT_IDLE,
	       "context idle: error = %d", e->error);
	__TYPE(SCRIBE_EVENT_BOOKMARK_REACHED,
	       "bookmark reached, id = %d, npr = %d", e->id, e->npr);


	__TYPE(SCRIBE_EVENT_DIVERGE_EVENT_TYPE,
	       "event type = %s",
	       get_type_str(buffer1, e->type));
	__TYPE(SCRIBE_EVENT_DIVERGE_EVENT_SIZE,
	       "event size = %d", e->size);
	__TYPE(SCRIBE_EVENT_DIVERGE_DATA_TYPE,
	       "data type = %s",
	       get_data_type_str(buffer1, e->type));
	__TYPE(SCRIBE_EVENT_DIVERGE_DATA_PTR,
	       "data user ptr = %p",
	       (void *)e->user_ptr);
	__TYPE(SCRIBE_EVENT_DIVERGE_DATA_CONTENT,
	       "data content, offset = %d, %s", e->offset,
	       get_diverge_data_str(buffer1, 100, e->offset,
				    (char *)e->data, e->size));
	__TYPE(SCRIBE_EVENT_DIVERGE_RESOURCE_TYPE,
	       "resource type = %s",
	       get_res_type_str(buffer1, sizeof(buffer1), e->type));
	__TYPE(SCRIBE_EVENT_DIVERGE_SYSCALL,
	       "%s(%s)", get_syscall_str(buffer1, e->nr),
	       get_syscall_args(buffer2, (unsigned long *)e->args, e->num_args));

	__TYPE(SCRIBE_EVENT_DIVERGE_SYSCALL_RET,
	       "syscall return value = %s",
	       get_ret_str(buffer1, e->ret));
	__TYPE(SCRIBE_EVENT_DIVERGE_FENCE_SERIAL,
	       "fence serial = %u", e->serial);
	__TYPE(SCRIBE_EVENT_DIVERGE_MEM_OWNED,
	       "memory access, trying to %s page = %08x",
	       e->write_access ? "write to" : "read", e->address);
	__TYPE(SCRIBE_EVENT_DIVERGE_MEM_NOT_OWNED,
	       "memory address, page not owned");
	__TYPE(SCRIBE_EVENT_DIVERGE_REGS, "regs: %s",
	       get_regs_str(buffer1, sizeof(buffer1), &e->regs));
	__TYPE(SCRIBE_EVENT_DIVERGE_QUEUE_NOT_EMPTY,
	       "queue not empty");
#undef __TYPE

	snprintf(str, size, "unkown event %d", event->type);
	return str;
}
