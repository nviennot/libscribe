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

#ifndef _LINUX_SCRIBE_API_H
#define _LINUX_SCRIBE_API_H


#include <linux/types.h>
#ifdef __KERNEL__
#include <linux/list.h>
#else
#ifndef __always_inline
#define __always_inline inline
#endif

#endif /* __KERNEL__ */


/* FIXME This has to go in <asm/errno.h> */
#define EDIVERGE	200	/* Replay diverged */

#define SCRIBE_DEVICE_NAME	"scribe"
#define SCRIBE_IDLE		0x00000000
#define SCRIBE_RECORD		0x00000001
#define SCRIBE_REPLAY		0x00000002
#define SCRIBE_STOP		0x00000004

#define SCRIBE_PS_RECORD		0x00000001
#define SCRIBE_PS_REPLAY		0x00000002
#define SCRIBE_PS_ATTACH_ON_EXEC	0x00000004
#define SCRIBE_PS_ENABLE_SYSCALL	0x00000100
#define SCRIBE_PS_ENABLE_DATA		0x00000200
#define SCRIBE_PS_ENABLE_RESOURCE	0x00000400
#define SCRIBE_PS_ENABLE_SIGNAL		0x00000800
#define SCRIBE_PS_ENABLE_TSC		0x00001000
#define SCRIBE_PS_ENABLE_MM		0x00002000
#define SCRIBE_PS_ENABLE_ALL		0x0000ff00

enum scribe_event_type {
	/* log file events */
	SCRIBE_EVENT_INIT = 1,
	SCRIBE_EVENT_PID,
	SCRIBE_EVENT_DATA,
	SCRIBE_EVENT_SYSCALL,
	SCRIBE_EVENT_SYSCALL_END,
	SCRIBE_EVENT_QUEUE_EOF,
	SCRIBE_EVENT_RESOURCE_LOCK,
	SCRIBE_EVENT_RESOURCE_UNLOCK,
	SCRIBE_EVENT_RDTSC,
	SCRIBE_EVENT_SIGNAL,
	SCRIBE_EVENT_FENCE,
	SCRIBE_EVENT_MEM_OWNED_READ,
	SCRIBE_EVENT_MEM_OWNED_WRITE,
	SCRIBE_EVENT_MEM_PUBLIC_READ,
	SCRIBE_EVENT_MEM_PUBLIC_WRITE,
	SCRIBE_EVENT_MEM_ALONE,

	/* userspace -> kernel commands */
	SCRIBE_EVENT_ATTACH_ON_EXECVE = 128,
	SCRIBE_EVENT_RECORD,
	SCRIBE_EVENT_REPLAY,
	SCRIBE_EVENT_STOP,

	/* kernel -> userspace notifications */
	SCRIBE_EVENT_BACKTRACE,
	SCRIBE_EVENT_CONTEXT_IDLE,
	SCRIBE_EVENT_DIVERGE_EVENT_TYPE,
	SCRIBE_EVENT_DIVERGE_EVENT_SIZE,
	SCRIBE_EVENT_DIVERGE_DATA_TYPE,
	SCRIBE_EVENT_DIVERGE_DATA_PTR,
	SCRIBE_EVENT_DIVERGE_DATA_CONTENT,
	SCRIBE_EVENT_DIVERGE_RESOURCE_TYPE,
	SCRIBE_EVENT_DIVERGE_SYSCALL_RET,
	SCRIBE_EVENT_DIVERGE_FENCE_SERIAL,
	SCRIBE_EVENT_DIVERGE_MEM_OWNED,
	SCRIBE_EVENT_DIVERGE_MEM_NOT_OWNED,
};

struct scribe_event {
#ifdef __KERNEL__
	struct list_head node;
	loff_t log_offset; /* Only used during replay for back traces */
	__u8 __align__[3];
	char payload_offset[0];
	/*
	 * type must directly follow payload_offset,
	 * serialization routines depend on it.
	 */
#endif
	__u8 type;
} __attribute__((packed));

struct scribe_event_sized {
	struct scribe_event h;
	__u16 size;
} __attribute__((packed));

struct scribe_event_diverge {
	struct scribe_event h;
	__u32 pid;
} __attribute__((packed));

/* Log file */
#define struct_SCRIBE_EVENT_INIT struct scribe_event_init
struct scribe_event_init {
	struct scribe_event_sized h;
	__u16 argc;
	__u16 envc;
	__u8 data[0];
} __attribute__((packed));

#define struct_SCRIBE_EVENT_PID struct scribe_event_pid
struct scribe_event_pid {
	struct scribe_event h;
	__u32 pid;
} __attribute__((packed));

#define SCRIBE_DATA_INPUT		0x01
#define SCRIBE_DATA_STRING		0x02
#define SCRIBE_DATA_NON_DETERMINISTIC	0x04
#define SCRIBE_DATA_INTERNAL		0x08
#define SCRIBE_DATA_ZERO		0x10

#define struct_SCRIBE_EVENT_DATA struct scribe_event_data
struct scribe_event_data {
	struct scribe_event_sized h;
	__u32 user_ptr; /* FIXME 64 bit support ? */
	__u8 data_type;
	__u8 data[0];
	__u32 ldata[0];
} __attribute__((packed));

#define struct_SCRIBE_EVENT_SYSCALL struct scribe_event_syscall
struct scribe_event_syscall {
	struct scribe_event h;
	__u32 ret; /* FIXME 64 bit support ? */
	__u16 nr;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_SYSCALL_END struct scribe_event_syscall_end
struct scribe_event_syscall_end {
	struct scribe_event h;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_QUEUE_EOF struct scribe_event_queue_eof
struct scribe_event_queue_eof {
	struct scribe_event h;
} __attribute__((packed));


/* Also defined in scribe_resource.h */
#define SCRIBE_RES_TYPE_RESERVED	0
#define SCRIBE_RES_TYPE_INODE		1
#define SCRIBE_RES_TYPE_FILE		2
#define SCRIBE_RES_TYPE_FILES_STRUCT	3
#define SCRIBE_RES_TYPE_TASK		4
#define SCRIBE_RES_TYPE_FUTEX		5
#define SCRIBE_RES_TYPE_SPINLOCK	0x40
#define SCRIBE_RES_TYPE_REGISTRATION	0x80

#define struct_SCRIBE_EVENT_RESOURCE_LOCK struct scribe_event_resource_lock
struct scribe_event_resource_lock {
	struct scribe_event h;
	__u8 type;
	__u32 serial;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_RESOURCE_UNLOCK struct scribe_event_resource_unlock
struct scribe_event_resource_unlock {
	struct scribe_event h;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_RDTSC struct scribe_event_rdtsc
struct scribe_event_rdtsc {
	struct scribe_event h;
	__u64 tsc;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_SIGNAL struct scribe_event_signal
struct scribe_event_signal {
	struct scribe_event_sized h;
	__u8 nr;
	__u8 info[0];
} __attribute__((packed));

#define struct_SCRIBE_EVENT_FENCE struct scribe_event_fence
struct scribe_event_fence {
	struct scribe_event h;
	__u32 serial;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_MEM_OWNED_READ struct scribe_event_mem_owned_read
struct scribe_event_mem_owned_read {
	struct scribe_event h;
	__u32 address;
	__u32 serial;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_MEM_OWNED_WRITE struct scribe_event_mem_owned_write
struct scribe_event_mem_owned_write {
	struct scribe_event h;
	__u32 address;
	__u32 serial;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_MEM_PUBLIC_READ struct scribe_event_mem_public_read
struct scribe_event_mem_public_read {
	struct scribe_event h;
	__u32 address;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_MEM_PUBLIC_WRITE struct scribe_event_mem_public_write
struct scribe_event_mem_public_write {
	struct scribe_event h;
	__u32 address;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_MEM_ALONE struct scribe_event_mem_alone
struct scribe_event_mem_alone {
	struct scribe_event h;
} __attribute__((packed));

/* Commands */

#define struct_SCRIBE_EVENT_ATTACH_ON_EXECVE \
	struct scribe_event_attach_on_execve
struct scribe_event_attach_on_execve {
	struct scribe_event h;
	__u8 enable;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_RECORD struct scribe_event_record
struct scribe_event_record {
	struct scribe_event h;
	__u32 log_fd;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_REPLAY struct scribe_event_replay
struct scribe_event_replay {
	struct scribe_event h;
	__u32 log_fd;
	__s32 backtrace_len;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_STOP struct scribe_event_stop
struct scribe_event_stop {
	struct scribe_event h;
} __attribute__((packed));


/* Notifications */

#define struct_SCRIBE_EVENT_BACKTRACE struct scribe_event_backtrace
struct scribe_event_backtrace {
	struct scribe_event h;
	__u64 event_offset;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_CONTEXT_IDLE struct scribe_event_context_idle
struct scribe_event_context_idle {
	struct scribe_event h;
	__s32 error;
} __attribute__((packed));

/* Diverge Notifications */

#define struct_SCRIBE_EVENT_DIVERGE_EVENT_TYPE \
	struct scribe_event_diverge_event_type
struct scribe_event_diverge_event_type {
	struct scribe_event_diverge h;
	__u8 type;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_DIVERGE_EVENT_SIZE \
	struct scribe_event_diverge_event_size
struct scribe_event_diverge_event_size {
	struct scribe_event_diverge h;
	__u16 size;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_DIVERGE_DATA_TYPE \
	struct scribe_event_diverge_data_type
struct scribe_event_diverge_data_type {
	struct scribe_event_diverge h;
	__u8 type;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_DIVERGE_DATA_PTR \
	struct scribe_event_diverge_data_ptr
struct scribe_event_diverge_data_ptr {
	struct scribe_event_diverge h;
	__u32 user_ptr;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_DIVERGE_DATA_CONTENT \
	struct scribe_event_diverge_data_content
struct scribe_event_diverge_data_content {
	struct scribe_event_diverge h;
	__u16 offset;
	__u8 size;
	__u8 data[128];
} __attribute__((packed));

#define struct_SCRIBE_EVENT_DIVERGE_RESOURCE_TYPE \
	struct scribe_event_diverge_resource_type
struct scribe_event_diverge_resource_type {
	struct scribe_event_diverge h;
	__u8 type;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_DIVERGE_SYSCALL_RET \
	struct scribe_event_diverge_syscall_ret
struct scribe_event_diverge_syscall_ret {
	struct scribe_event_diverge h;
	__u32 ret;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_DIVERGE_FENCE_SERIAL \
	struct scribe_event_diverge_fence_serial
struct scribe_event_diverge_fence_serial {
	struct scribe_event_diverge h;
	__u32 serial;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_DIVERGE_MEM_OWNED \
	struct scribe_event_diverge_mem_owned
struct scribe_event_diverge_mem_owned {
	struct scribe_event_diverge h;
	__u32 address;
	__u8 write_access;
} __attribute__((packed));

#define struct_SCRIBE_EVENT_DIVERGE_MEM_NOT_OWNED \
	struct scribe_event_diverge_mem_not_owned
struct scribe_event_diverge_mem_not_owned {
	struct scribe_event_diverge h;
} __attribute__((packed));


static __always_inline int is_sized_type(int type)
{
	return  type == SCRIBE_EVENT_INIT ||
		type == SCRIBE_EVENT_DATA ||
		type == SCRIBE_EVENT_SIGNAL;
}

static __always_inline int is_diverge_type(int type)
{
	return  type == SCRIBE_EVENT_DIVERGE_EVENT_TYPE ||
		type == SCRIBE_EVENT_DIVERGE_EVENT_SIZE ||
		type == SCRIBE_EVENT_DIVERGE_DATA_TYPE ||
		type == SCRIBE_EVENT_DIVERGE_DATA_PTR ||
		type == SCRIBE_EVENT_DIVERGE_DATA_CONTENT ||
		type == SCRIBE_EVENT_DIVERGE_RESOURCE_TYPE ||
		type == SCRIBE_EVENT_DIVERGE_SYSCALL_RET ||
		type == SCRIBE_EVENT_DIVERGE_FENCE_SERIAL ||
		type == SCRIBE_EVENT_DIVERGE_MEM_OWNED ||
		type == SCRIBE_EVENT_DIVERGE_MEM_NOT_OWNED;
}

void __you_are_using_an_unknown_scribe_type(void);
/*
 * XXX The additional payload of sized event is NOT accounted here.
 */
static __always_inline size_t sizeof_event_from_type(__u8 type)
{
#define __TYPE(t) if (type == t) return sizeof(struct_##t);
	__TYPE(SCRIBE_EVENT_INIT);
	__TYPE(SCRIBE_EVENT_PID);
	__TYPE(SCRIBE_EVENT_DATA);
	__TYPE(SCRIBE_EVENT_SYSCALL);
	__TYPE(SCRIBE_EVENT_SYSCALL_END);
	__TYPE(SCRIBE_EVENT_QUEUE_EOF);
	__TYPE(SCRIBE_EVENT_RESOURCE_LOCK);
	__TYPE(SCRIBE_EVENT_RESOURCE_UNLOCK);
	__TYPE(SCRIBE_EVENT_RDTSC);
	__TYPE(SCRIBE_EVENT_SIGNAL);
	__TYPE(SCRIBE_EVENT_FENCE);
	__TYPE(SCRIBE_EVENT_MEM_OWNED_READ);
	__TYPE(SCRIBE_EVENT_MEM_OWNED_WRITE);
	__TYPE(SCRIBE_EVENT_MEM_PUBLIC_READ);
	__TYPE(SCRIBE_EVENT_MEM_PUBLIC_WRITE);
	__TYPE(SCRIBE_EVENT_MEM_ALONE);

	__TYPE(SCRIBE_EVENT_ATTACH_ON_EXECVE);
	__TYPE(SCRIBE_EVENT_RECORD);
	__TYPE(SCRIBE_EVENT_REPLAY);
	__TYPE(SCRIBE_EVENT_STOP);

	__TYPE(SCRIBE_EVENT_BACKTRACE);
	__TYPE(SCRIBE_EVENT_CONTEXT_IDLE);

	__TYPE(SCRIBE_EVENT_DIVERGE_EVENT_TYPE);
	__TYPE(SCRIBE_EVENT_DIVERGE_EVENT_SIZE);
	__TYPE(SCRIBE_EVENT_DIVERGE_DATA_TYPE);
	__TYPE(SCRIBE_EVENT_DIVERGE_DATA_PTR);
	__TYPE(SCRIBE_EVENT_DIVERGE_DATA_CONTENT);
	__TYPE(SCRIBE_EVENT_DIVERGE_RESOURCE_TYPE);
	__TYPE(SCRIBE_EVENT_DIVERGE_SYSCALL_RET);
	__TYPE(SCRIBE_EVENT_DIVERGE_FENCE_SERIAL);
	__TYPE(SCRIBE_EVENT_DIVERGE_MEM_OWNED);
	__TYPE(SCRIBE_EVENT_DIVERGE_MEM_NOT_OWNED);
#undef  __TYPE

	if (__builtin_constant_p(type))
		__you_are_using_an_unknown_scribe_type();

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
