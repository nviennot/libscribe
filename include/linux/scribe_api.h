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

#define SCRIBE_REGS			0x00000100
#define SCRIBE_DATA_DET			0x00000200
#define SCRIBE_DATA_EXTRA		0x00000400
#define SCRIBE_RES_EXTRA		0x00000800
#define SCRIBE_SIG_COOKIE		0x00001000
#define SCRIBE_ALL			0x0000ff00

/*
 * These flags are used for the scribe syscalls such as sys_set_scribe_flags().
 */
#define SCRIBE_PS_RECORD		0x00000001
#define SCRIBE_PS_REPLAY		0x00000002
#define SCRIBE_PS_ATTACH_ON_EXEC	0x00000004
#define SCRIBE_PS_DETACHING		0x00000008
#define SCRIBE_PS_ENABLE_SYSCALL	0x00000100
#define SCRIBE_PS_ENABLE_DATA		0x00000200
#define SCRIBE_PS_ENABLE_RESOURCE	0x00000400
#define SCRIBE_PS_ENABLE_SIGNAL		0x00000800
#define SCRIBE_PS_ENABLE_TSC		0x00001000
#define SCRIBE_PS_ENABLE_MM		0x00002000
#define SCRIBE_PS_ENABLE_ALL		0x0000ff00

/*
 * These flags are used as a data type
 * They are also defined in scribe_uaccess.h
 */
#define SCRIBE_DATA_INPUT		0x01
#define SCRIBE_DATA_STRING		0x02
#define SCRIBE_DATA_NON_DETERMINISTIC	0x04
#define SCRIBE_DATA_INTERNAL		0x08
#define SCRIBE_DATA_ZERO		0x10

/*
 * These flags are used as a resource type
 * They are also defined in scribe_resource.h
 */
#define SCRIBE_RES_TYPE_RESERVED	0
#define SCRIBE_RES_TYPE_INODE		1
#define SCRIBE_RES_TYPE_FILE		2
#define SCRIBE_RES_TYPE_FILES_STRUCT	3
#define SCRIBE_RES_TYPE_TASK		4
#define SCRIBE_RES_TYPE_FUTEX		5
#define SCRIBE_RES_TYPE_SPINLOCK	0x40
#define SCRIBE_RES_TYPE_REGISTRATION	0x80


enum scribe_event_type {
	SCRIBE_EVENT_DUMMY1 = 0, /* skip the type 0 for safety */

#define __SCRIBE_EVENT(uname, lname, ...) uname,
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
	__u64 last_event_offset;
} __attribute__((packed));

#define __SCRIBE_EVENT(uname, lname, ...)	\
	struct lname {				\
		__VA_ARGS__			\
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
#define __SCRIBE_EVENT_DIVERGE(uname, lname, ...) type == uname ||
	return
		#include <linux/scribe_events.h>
		0;
}

static __always_inline int is_sized_type(int type)
{
#define __SCRIBE_EVENT(...)
#define __SCRIBE_EVENT_SIZED(uname, lname, ...) type == uname ||
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
#define __SCRIBE_EVENT(uname, lname, ...)	\
	if (type == uname) return sizeof(struct lname);
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



/*
 * FIXME Find a way to do that with the scribe_events.h file
 */
#define struct_SCRIBE_EVENT_INIT \
	struct scribe_event_init
#define struct_SCRIBE_EVENT_PID \
	struct scribe_event_pid
#define struct_SCRIBE_EVENT_DATA \
	struct scribe_event_data
#define struct_SCRIBE_EVENT_DATA_EXTRA \
	struct scribe_event_data_extra
#define struct_SCRIBE_EVENT_SYSCALL \
	struct scribe_event_syscall
#define struct_SCRIBE_EVENT_SYSCALL_END \
	struct scribe_event_syscall_end
#define struct_SCRIBE_EVENT_QUEUE_EOF \
	struct scribe_event_queue_eof
#define struct_SCRIBE_EVENT_RESOURCE_LOCK \
	struct scribe_event_resource_lock
#define struct_SCRIBE_EVENT_RESOURCE_LOCK_EXTRA \
	struct scribe_event_resource_lock_extra
#define struct_SCRIBE_EVENT_RESOURCE_UNLOCK \
	struct scribe_event_resource_unlock
#define struct_SCRIBE_EVENT_RDTSC \
	struct scribe_event_rdtsc
#define struct_SCRIBE_EVENT_SIGNAL \
	struct scribe_event_signal
#define struct_SCRIBE_EVENT_FENCE \
	struct scribe_event_fence
#define struct_SCRIBE_EVENT_MEM_OWNED_READ \
	struct scribe_event_mem_owned_read
#define struct_SCRIBE_EVENT_MEM_OWNED_WRITE \
	struct scribe_event_mem_owned_write
#define struct_SCRIBE_EVENT_MEM_PUBLIC_READ \
	struct scribe_event_mem_public_read
#define struct_SCRIBE_EVENT_MEM_PUBLIC_WRITE \
	struct scribe_event_mem_public_write
#define struct_SCRIBE_EVENT_MEM_ALONE \
	struct scribe_event_mem_alone
#define struct_SCRIBE_EVENT_REGS \
	struct scribe_event_regs
#define struct_SCRIBE_EVENT_BOOKMARK \
	struct scribe_event_bookmark
#define struct_SCRIBE_EVENT_SIG_SEND_COOKIE \
	struct scribe_event_sig_send_cookie
#define struct_SCRIBE_EVENT_SIG_RECV_COOKIE \
	struct scribe_event_sig_recv_cookie
#define struct_SCRIBE_EVENT_ATTACH_ON_EXECVE \
	struct scribe_event_attach_on_execve
#define struct_SCRIBE_EVENT_RECORD \
	struct scribe_event_record
#define struct_SCRIBE_EVENT_REPLAY \
	struct scribe_event_replay
#define struct_SCRIBE_EVENT_STOP \
	struct scribe_event_stop
#define struct_SCRIBE_EVENT_BOOKMARK_REQUEST \
	struct scribe_event_bookmark_request
#define struct_SCRIBE_EVENT_GOLIVE_ON_NEXT_BOOKMARK \
	struct scribe_event_golive_on_next_bookmark
#define struct_SCRIBE_EVENT_GOLIVE_ON_BOOKMARK_ID \
	struct scribe_event_golive_on_bookmark_id
#define struct_SCRIBE_EVENT_BACKTRACE \
	struct scribe_event_backtrace
#define struct_SCRIBE_EVENT_CONTEXT_IDLE \
	struct scribe_event_context_idle
#define struct_SCRIBE_EVENT_DIVERGE_EVENT_TYPE \
	struct scribe_event_diverge_event_type
#define struct_SCRIBE_EVENT_DIVERGE_EVENT_SIZE \
	struct scribe_event_diverge_event_size
#define struct_SCRIBE_EVENT_DIVERGE_DATA_TYPE \
	struct scribe_event_diverge_data_type
#define struct_SCRIBE_EVENT_DIVERGE_DATA_PTR \
	struct scribe_event_diverge_data_ptr
#define struct_SCRIBE_EVENT_DIVERGE_DATA_CONTENT \
	struct scribe_event_diverge_data_content
#define struct_SCRIBE_EVENT_DIVERGE_RESOURCE_TYPE \
	struct scribe_event_diverge_resource_type
#define struct_SCRIBE_EVENT_DIVERGE_SYSCALL \
	struct scribe_event_diverge_syscall
#define struct_SCRIBE_EVENT_DIVERGE_SYSCALL_RET \
	struct scribe_event_diverge_syscall_ret
#define struct_SCRIBE_EVENT_DIVERGE_FENCE_SERIAL \
	struct scribe_event_diverge_fence_serial
#define struct_SCRIBE_EVENT_DIVERGE_MEM_OWNED \
	struct scribe_event_diverge_mem_owned
#define struct_SCRIBE_EVENT_DIVERGE_MEM_NOT_OWNED \
	struct scribe_event_diverge_mem_not_owned
#define struct_SCRIBE_EVENT_DIVERGE_REGS \
	struct scribe_event_diverge_regs

#endif /* _LINUX_SCRIBE_API_H_ */
