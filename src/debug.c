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

#include <stdio.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <ctype.h>

#include <linux/types.h>
#include <scribe.h>

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

static char *error_str[] = {
	"EPERM", "ENOENT", "ESRCH", "EINTR", "EIO", "ENXIO", "E2BIG",
	"ENOEXEC", "EBADF", "ECHILD", "EAGAIN", "ENOMEM", "EACCES", "EFAULT",
	"ENOTBLK", "EBUSY", "EEXIST", "EXDEV", "ENODEV", "ENOTDIR", "EISDIR",
	"EINVAL", "ENFILE", "EMFILE", "ENOTTY", "ETXTBSY", "EFBIG", "ENOSPC",
	"ESPIPE", "EROFS", "EMLINK", "EPIPE", "EDOM", "ERANGE", "EAGAIN",
	"EINPROGRESS", "EALREADY", "ENOTSOCK", "EDESTADDRREQ", "EMSGSIZE",
	"EPROTOTYPE", "ENOPROTOOPT", "EPROTONOSUPPORT", "ESOCKTNOSUPPORT",
	"EOPNOTSUPP", "EPFNOSUPPORT", "EAFNOSUPPORT", "EADDRINUSE",
	"EADDRNOTAVAIL", "ENETDOWN", "ENETUNREACH", "ENETRESET",
	"ECONNABORTED", "ECONNRESET", "ENOBUFS", "EISCONN", "ENOTCONN",
	"ESHUTDOWN", "ETOOMANYREFS", "ETIMEDOUT", "ECONNREFUSED", "ELOOP",
	"ENAMETOOLONG", "EHOSTDOWN", "EHOSTUNREACH", "ENOTEMPTY", NULL,
	"EUSERS", "EDQUOT", "ESTALE", "EREMOTE", NULL, NULL, NULL, NULL, NULL,
	"ENOLCK", "ENOSYS", NULL, "ENOMSG", "EIDRM", "ENOSR", "ETIME",
	"EBADMSG", "EPROTO", "ENODATA", "ENOSTR", "ECHRNG", "EL2NSYNC",
	"EL3HLT", "EL3RST", "ENOPKG", "ELNRNG", "EUNATCH", "ENOCSI", "EL2HLT",
	"EBADE", "EBADR", "EXFULL", "ENOANO", "EBADRQC", "EBADSLT", NULL,
	"EBFONT", "ENONET", "ENOLINK", "EADV", "ESRMNT", "ECOMM", "EMULTIHOP",
	"EDOTDOT", "EOVERFLOW", "ENOTUNIQ", "EBADFD", "EREMCHG", "EILSEQ",
	"EUCLEAN", "ENOTNAM", "ENAVAIL", "EISNAM", "EREMOTEIO", "ELIBACC",
	"ELIBBAD", "ELIBSCN", "ELIBMAX", "ELIBEXEC", "ERESTART", "ESTRPIPE",
	"ENOMEDIUM", "EMEDIUMTYPE", "ECANCELED", "ENOKEY", "EKEYEXPIRED",
	"EKEYREVOKED", "EKEYREJECTED", "EOWNERDEAD", "ENOTRECOVERABLE",
	"ERFKILL"
};

static char *error_512_str[] = {
	"ERESTARTSYS", "ERESTARTNOINTR", "ERESTARTNOHAND", "ENOIOCTLCMD",
	"ERESTART_RESTARTBLOCK", NULL, NULL, NULL, NULL, "EBADHANDLE",
	"ENOTSYNC", "EBADCOOKIE", "ENOTSUPP", "ETOOSMALL", "ESERVERFAULT",
	"EBADTYPE", "EJUKEBOX", "EIOCBQUEUED", "EIOCBRETRY"
};

#define GET_STR(table, n) ({ 				\
	char *str;					\
	if (n < sizeof(table##_str)/sizeof(char*))	\
		str = table##_str[n];			\
	else str = NULL;				\
	str; })

static char *get_syscall_str(char *buffer, unsigned int n)
{
	char *str = GET_STR(syscall, n);
	if (str)
		return str;
	sprintf(buffer, "syscall_%d", n);
	return buffer;

}

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

static char *get_data_type_str(int type)
{
	switch(type) {
		case 0: return "output";
		case SCRIBE_DATA_INPUT: return "input";
		case SCRIBE_DATA_INPUT | SCRIBE_DATA_STRING: return "input string";
		case SCRIBE_DATA_NON_DETERMINISTIC: return "non-det output";
		default: return "unkown";
	}
}

char *scribe_get_event_str(char *str, size_t size, struct scribe_event *event)
{
	char buffer1[4096];
	char buffer2[4096];

#define DECL_EVENT(t) struct_##t *e = (struct_##t *)event
#define GENERIC_EVENT(t, fmt, ...)					\
	if (event->type == t) {						\
		DECL_EVENT(t);						\
		snprintf(str, size, fmt, ##__VA_ARGS__);		\
		return str;						\
	}
	GENERIC_EVENT(SCRIBE_EVENT_SYSCALL, "%s() = %s",
		      get_syscall_str(buffer1, e->nr),
		      get_ret_str(buffer2, e->ret));
	GENERIC_EVENT(SCRIBE_EVENT_SYSCALL_END, "syscall ended");
	GENERIC_EVENT(SCRIBE_EVENT_DATA, "data: %s, ptr = %p, size = %u, %s",
		      get_data_type_str(e->data_type),
		      (void *)e->user_ptr,
		      e->size,
		      escape_str(buffer1, 100, e->data, e->size));
	GENERIC_EVENT(SCRIBE_EVENT_PID, "pid=%d", e->pid);
#undef GENERIC_EVENT

	snprintf(str, size, "unkown event %d", event->type);
	return str;
}
