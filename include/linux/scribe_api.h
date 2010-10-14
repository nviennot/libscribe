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


#define SCRIBE_IDLE		0x00000000
#define SCRIBE_RECORD		0x00000001
#define SCRIBE_REPLAY		0x00000002
#define SCRIBE_STOP		0x00000004

#define SCRIBE_DEVICE_NAME		"scribe"

enum scribe_event_type {
	/* log file events */
	SCRIBE_EVENT_PID = 1,
	SCRIBE_EVENT_DATA,
	SCRIBE_EVENT_SYSCALL,
	SCRIBE_EVENT_SYSCALL_END,

	/* userspace -> kernel commands */
	SCRIBE_EVENT_ATTACH_ON_EXECVE,
	SCRIBE_EVENT_RECORD,
	SCRIBE_EVENT_REPLAY,
	SCRIBE_EVENT_STOP,

	/* kernel -> userspace notifications */
	SCRIBE_EVENT_CONTEXT_IDLE
};

struct scribe_event {
#ifdef __KERNEL__
	struct list_head node;
	char payload_offset[0];
	/*
	 * type must directly follow payload_offset,
	 * dev_write() relies on it.
	 */
#endif
	__u8 type;
} __attribute__((packed));

/* Log file */

#define struct_SCRIBE_EVENT_PID struct scribe_event_pid
struct scribe_event_pid {
	struct scribe_event h;
	__u32 pid;
} __attribute__((packed));

#define SCRIBE_DATA_INPUT		1
#define SCRIBE_DATA_STRING		2
#define SCRIBE_DATA_NON_DETERMINISTIC	4

#define struct_SCRIBE_EVENT_DATA struct scribe_event_data
struct scribe_event_data {
	struct scribe_event h;
	__u32 size;
	__u8 data_type;
	__u32 user_ptr; /* FIXME 64 bit support ? */
	__u8 data[0];
	__u32 ldata[0];
} __attribute__((packed));

#define struct_SCRIBE_EVENT_SYSCALL struct scribe_event_syscall
struct scribe_event_syscall {
	struct scribe_event h;
	__u16 nr;
	__u32 ret; /* FIXME 64 bit support ? */
} __attribute__((packed));

#define struct_SCRIBE_EVENT_SYSCALL_END struct scribe_event_syscall_end
struct scribe_event_syscall_end {
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
} __attribute__((packed));

#define struct_SCRIBE_EVENT_STOP struct scribe_event_stop
struct scribe_event_stop {
	struct scribe_event h;
} __attribute__((packed));


/* Notifications */

#define struct_SCRIBE_EVENT_CONTEXT_IDLE struct scribe_event_context_idle
struct scribe_event_context_idle {
	struct scribe_event h;
	__s32 error;
} __attribute__((packed));


void __you_are_using_an_unknown_scribe_type(void);
/*
 * XXX Data events have a variable size. This additional payload
 * is NOT accounted here.
 */
static __always_inline size_t sizeof_event_from_type(__u8 type)
{
#define __TYPE(t) if (type == t) return sizeof(struct_##t);
	__TYPE(SCRIBE_EVENT_PID);
	__TYPE(SCRIBE_EVENT_DATA);
	__TYPE(SCRIBE_EVENT_SYSCALL);
	__TYPE(SCRIBE_EVENT_SYSCALL_END);

	__TYPE(SCRIBE_EVENT_ATTACH_ON_EXECVE);
	__TYPE(SCRIBE_EVENT_RECORD);
	__TYPE(SCRIBE_EVENT_REPLAY);
	__TYPE(SCRIBE_EVENT_STOP);

	__TYPE(SCRIBE_EVENT_CONTEXT_IDLE);

#undef  __TYPE

	if (__builtin_constant_p(type))
		__you_are_using_an_unknown_scribe_type();

	return (size_t)-1;
}

static inline size_t sizeof_event(struct scribe_event *event)
{
	size_t sz = sizeof_event_from_type(event->type);
	if (event->type == SCRIBE_EVENT_DATA)
		sz += ((struct scribe_event_data *)event)->size;
	return sz;
}

#endif /* _LINUX_SCRIBE_API_H_ */
