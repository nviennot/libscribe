/*
 *  Scribe, the record/replay mechanism
 *
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

/*
 * This is the include file that gets shared with userspace.
 * It describes the events that are used in two places:
 * - The logfile, which is the output of a scribe recording
 * - The protocol of the scribe device (through read() and write()).
 */

#ifndef _LINUX_SCRIBE_API_H
#define _LINUX_SCRIBE_API_H

#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/net.h>
#include <linux/futex.h>
#include <linux/scribe_defines.h>
#include <linux/scribe_resource.h>

#include <sys/types.h>
#ifndef __always_inline
#define __always_inline inline
#endif

/*
 * FIXME This file contain architecture dependent code, such as EDIVERGE,
 * the 32/64bits values, the pt_regs struct...
 */
#define EDIVERGE			200	/* Replay diverged */

#define SCRIBE_DEVICE_NAME		"scribe"


/*
 * These flags are used in the context flags, they are passed along with the
 * record/replay command
 */

#define SCRIBE_SYSCALL_RET		0x00000100
#define SCRIBE_SYSCALL_EXTRA		0x00000200
#define SCRIBE_SIG_EXTRA		0x00000400
#define SCRIBE_SIG_COOKIE		0x00000800
#define SCRIBE_RES_EXTRA		0x00001000
#define SCRIBE_MEM_EXTRA		0x00002000
#define SCRIBE_DATA_EXTRA		0x00004000
#define SCRIBE_DATA_STRING_ALWAYS	0x00008000
#define SCRIBE_DATA_ALWAYS		0x00010000
#define SCRIBE_RES_ALWAYS		0x00020000
#define SCRIBE_FENCE_ALWAYS		0x00040000
#define SCRIBE_REGS			0x00080000
#define SCRIBE_ALL			0x00ffff00
#define SCRIBE_DEFAULT			(SCRIBE_SYSCALL_EXTRA)

#define SCRIBE_DISABLE_MM		0x01000000
#define SCRIBE_DISABLE_FUTEX_HASH	0x02000000
#define SCRIBE_FLAGS_MASK		0xffffff00

/*
 * These flags are used for the scribe syscalls such as sys_set_scribe_flags().
 */
#define SCRIBE_PS_RECORD		0x00000001
#define SCRIBE_PS_REPLAY		0x00000002
#define SCRIBE_PS_ATTACH_ON_EXEC	0x00000004
#define SCRIBE_PS_DETACHING		0x00000008
#define SCRIBE_PS_MUTATING		0x00000010
#define SCRIBE_PS_ENABLE_SYSCALL	0x00000100
#define SCRIBE_PS_ENABLE_DATA		0x00000200
#define SCRIBE_PS_ENABLE_RESOURCE	0x00000400
#define SCRIBE_PS_ENABLE_SIGNAL		0x00000800
#define SCRIBE_PS_ENABLE_TSC		0x00001000
#define SCRIBE_PS_ENABLE_MM		0x00002000
#define SCRIBE_PS_RET_CHECK		0x00004000
#define SCRIBE_PS_STRICT_REPLAY		0x00008000
#define SCRIBE_PS_FIXED_IO		0x00010000
#define SCRIBE_PS_ENABLE_ALL		0x00ffff00

/*
 * These flags are used as a data type
 * They are also defined in scribe_uaccess.h
 */
#define SCRIBE_DATA_INPUT		0x01
#define SCRIBE_DATA_STRING		0x02
#define SCRIBE_DATA_NON_DETERMINISTIC	0x04
#define SCRIBE_DATA_INTERNAL		0x08
#define SCRIBE_DATA_ZERO		0x10
#define SCRIBE_DATA_NEED_INFO		0x20

/*
 * Bookmark types
 */
#define SCRIBE_BOOKMARK_PRE_SYSCALL	0x00
#define SCRIBE_BOOKMARK_POST_SYSCALL	0x01


/*
 * Duration arguments
 */
#define SCRIBE_PERMANANT		0x00
#define SCRIBE_UNTIL_NEXT_SYSCALL	0x01

/*
 * Syscalls offsets for scribe syscalls and multiplexed ones
 */

#define __NR_get_scribe_flags		501
#define __NR_set_scribe_flags		502
#define __NR_scribe_send_event		503
#define __NR_scribe_recv_event		504
#define __NR_scribe_filter_syscall	505

enum scribe_multiplexed_syscalls {
	SCRIBE_SYSCALL_BASE = 550,

#define SCRIBE_SOCKETCALL_FIRST __NR_SOCKET_RESERVED
	__NR_SOCKET_RESERVED,
	__NR_socket,
	__NR_bind,
	__NR_connect,
	__NR_listen,
	__NR_accept,
	__NR_getsockname,
	__NR_getpeername,
	__NR_socketpair,
	__NR_send,
	__NR_recv,
	__NR_sendto,
	__NR_recvfrom,
	__NR_shutdown,
	__NR_setsockopt,
	__NR_getsockopt,
	__NR_sendmsg,
	__NR_recvmsg,
	__NR_accept4,
	__NR_recvmmsg2,
#define SCRIBE_SOCKETCALL_LAST __NR_recvmmsg2

#define SCRIBE_FUTEX_FIRST  __NR_futex_wait
	__NR_futex_wait,
	__NR_futex_wake,
	__NR_futex_fd,
	__NR_futex_requeue,
	__NR_futex_cmp_requeue,
	__NR_futex_wake_op,
	__NR_futex_lock_pi,
	__NR_futex_unlock_pi,
	__NR_futex_trylock_pi,
	__NR_futex_wait_bitset,
	__NR_futex_wake_bitset,
	__NR_futex_wait_requeue_pi,
	__NR_futex_cmp_requeue_pi,
#define SCRIBE_FUTEX_LAST  __NR_futex_cmp_requeue_pi

	NR_scribe_syscalls,
};

enum scribe_event_type {
	SCRIBE_EVENT_DUMMY1 = 0, /* skip the type 0 for safety */

#define __SCRIBE_EVENT(name, ...) upper##name,
#define SCRIBE_START_COMMAND_DECL \
	SCRIBE_EVENT_DUMMY2 = 127, /*
				    * Start all device events at 128, it helps
				    * for backward compatibility.
				    */
	#include <linux/scribe_events.h>
};

struct scribe_event {
	__u8 type;
} __attribute__((packed));

struct scribe_event_sized {
	struct scribe_event h;
	__u16 size;
} __attribute__((packed));

struct scribe_event_diverge {
	struct scribe_event h;
	__u32 pid;
	__u32 fatal;
	__u32 num_ev_consumed;
	__u64 last_event_offset;
} __attribute__((packed));

#define __SCRIBE_EVENT(name, ...)	\
	struct name {			\
		__VA_ARGS__		\
	} __attribute__((packed));
#define __header_regular	struct scribe_event h;
#define __header_sized		struct scribe_event_sized h;
#define __header_diverge	struct scribe_event_diverge h;
#define __field(type, name)	type name;
#include <linux/scribe_events.h>

static inline int is_diverge_type(int type)
{
#define __SCRIBE_EVENT(...)
#define __SCRIBE_EVENT_SIZED(...)
#define __SCRIBE_EVENT_DIVERGE(name, ...) type == upper##name ||
	return
		#include <linux/scribe_events.h>
		0;
}

static __always_inline int is_sized_type(int type)
{
#define __SCRIBE_EVENT(...)
#define __SCRIBE_EVENT_SIZED(name, ...) type == upper##name ||
#define __SCRIBE_EVENT_DIVERGE(...)
	return
		#include <linux/scribe_events.h>
		0;
}

void you_are_using_an_unknown_scribe_type(void);
/*
 * XXX The additional payload of sized event is NOT accounted here.
 */
static __always_inline size_t sizeof_event_from_type(__u8 type)
{
#define __SCRIBE_EVENT(name, ...)	\
	if (type == upper##name) return sizeof(struct name);
	#include <linux/scribe_events.h>

	if (__builtin_constant_p(type))
		you_are_using_an_unknown_scribe_type();

	return (size_t)-1;
}

static inline size_t sizeof_event(struct scribe_event *event)
{
	size_t sz = sizeof_event_from_type(event->type);
	if (is_sized_type(event->type))
		sz += ((struct scribe_event_sized *)event)->size;
	return sz;
}


#endif /* _LINUX_SCRIBE_API_H_ */
