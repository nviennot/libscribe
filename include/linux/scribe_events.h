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
 * This file contains event definitions, it should not be included directly
 */

#ifndef __SCRIBE_EVENT
#error "Do not include this file directly, use <linux/scribe_api.h>"
#endif

/* Default settings */
#ifndef __header_regular
#define __header_regular
#endif

#ifndef __header_sized
#define __header_sized
#endif

#ifndef __header_diverge
#define __header_diverge
#endif

#ifndef SCRIBE_EVENT
#define SCRIBE_EVENT(uname, lname, ...)		\
	__SCRIBE_EVENT(SCRIBE_EVENT_##uname,	\
		       scribe_event_##lname,	\
		       __header_regular __VA_ARGS__)
#endif

#ifndef __SCRIBE_EVENT_SIZED
#define __SCRIBE_EVENT_SIZED __SCRIBE_EVENT
#endif

#ifndef SCRIBE_EVENT_SIZED
#define SCRIBE_EVENT_SIZED(uname, lname, ...)		\
	__SCRIBE_EVENT_SIZED(SCRIBE_EVENT_##uname,	\
			     scribe_event_##lname,	\
			     __header_sized __VA_ARGS__)
#endif

#ifndef __SCRIBE_EVENT_DIVERGE
#define __SCRIBE_EVENT_DIVERGE __SCRIBE_EVENT
#endif


#ifndef SCRIBE_EVENT_DIVERGE
#define SCRIBE_EVENT_DIVERGE(uname, lname, ...)			\
	__SCRIBE_EVENT_DIVERGE(SCRIBE_EVENT_DIVERGE_##uname,	\
			       scribe_event_diverge_##lname,	\
			       __header_diverge __VA_ARGS__)
#endif

#ifndef SCRIBE_START_LOG_FILE_DECL
#define SCRIBE_START_LOG_FILE_DECL
#endif

#ifndef SCRIBE_START_COMMAND_DECL
#define SCRIBE_START_COMMAND_DECL
#endif

#ifndef SCRIBE_START_NOTIFICATION_DECL
#define SCRIBE_START_NOTIFICATION_DECL
#endif

#ifndef SCRIBE_START_DIVERGE_NOTIFICATION_DECL
#define SCRIBE_START_DIVERGE_NOTIFICATION_DECL
#endif

/* The declarations begin here */

/* Log file events */
SCRIBE_START_LOG_FILE_DECL

SCRIBE_EVENT_SIZED(INIT, init,
	__field(__u32, flags)
	__field(__u16, argc)
	__field(__u16, envc)
	__field(__u8, data[0])
)

SCRIBE_EVENT(PID, pid,
	__field(__u32, pid)
)

SCRIBE_EVENT_SIZED(DATA, data,
	__field(__u8, data[0])
	__field(__u32, ldata[0])
)

SCRIBE_EVENT_SIZED(DATA_EXTRA, data_extra,
	__field(__u32, user_ptr) /* FIXME 64 bit support ? */
	__field(__u8, data_type)
	__field(__u8, data[0])
	__field(__u32, ldata[0])
)

SCRIBE_EVENT(SYSCALL, syscall,
	__field(__u32, ret) /* FIXME 64 bit support ? */
	__field(__u16, nr)
)

SCRIBE_EVENT(SYSCALL_END, syscall_end)

SCRIBE_EVENT(QUEUE_EOF, queue_eof)

SCRIBE_EVENT(RESOURCE_LOCK, resource_lock,
	__field(__u32, serial)
)

SCRIBE_EVENT(RESOURCE_LOCK_EXTRA, resource_lock_extra,
	__field(__u8, type)
	__field(__u32, object)
	__field(__u32, serial)
)

SCRIBE_EVENT(RESOURCE_UNLOCK, resource_unlock,
	__field(__u32, object)
)

SCRIBE_EVENT(RDTSC, rdtsc,
	__field(__u64, tsc)
)

SCRIBE_EVENT_SIZED(SIGNAL, signal,
	__field(__u8, nr)
	__field(__u8, deferred)
	__field(__u8, info[0])
)

SCRIBE_EVENT(FENCE, fence,
	__field(__u32, serial)
)

SCRIBE_EVENT(MEM_OWNED_READ, mem_owned_read,
	__field(__u32, address)
	__field(__u32, serial)
)

SCRIBE_EVENT(MEM_OWNED_WRITE, mem_owned_write,
	__field(__u32, address)
	__field(__u32, serial)
)

SCRIBE_EVENT(MEM_PUBLIC_READ, mem_public_read,
	__field(__u32, address)
)

SCRIBE_EVENT(MEM_PUBLIC_WRITE, mem_public_write,
	__field(__u32, address)
)

SCRIBE_EVENT(MEM_ALONE, mem_alone)

SCRIBE_EVENT(REGS, regs,
	__field(struct pt_regs, regs)
)

SCRIBE_EVENT(BOOKMARK, bookmark,
	__field(__u32, id)
	__field(__u32, npr)
)

SCRIBE_EVENT(SIG_SEND_COOKIE, sig_send_cookie,
	__field(__u32, cookie)
)

SCRIBE_EVENT(SIG_RECV_COOKIE, sig_recv_cookie,
	__field(__u32, cookie)
)

/* Command events */
SCRIBE_START_COMMAND_DECL

SCRIBE_EVENT(ATTACH_ON_EXECVE, attach_on_execve,
	__field(__u8, enable)
)

SCRIBE_EVENT(RECORD, record,
	__field(__u32, flags)
	__field(__u32, log_fd)
)

SCRIBE_EVENT(REPLAY, replay,
	__field(__u32, flags)
	__field(__u32, log_fd)
	__field(__s32, backtrace_len)
)

SCRIBE_EVENT(STOP, stop)

SCRIBE_EVENT(BOOKMARK_REQUEST, bookmark_request)

SCRIBE_EVENT(GOLIVE_ON_NEXT_BOOKMARK, golive_on_next_bookmark)

SCRIBE_EVENT(GOLIVE_ON_BOOKMARK_ID, golive_on_bookmark_id,
	__field(__u32, id)
)

/* Notification events */
SCRIBE_START_NOTIFICATION_DECL

SCRIBE_EVENT(BACKTRACE, backtrace,
	__field(__u64, event_offset)
)

SCRIBE_EVENT(CONTEXT_IDLE, context_idle,
	__field(__s32, error)
)

/* Diverge Notification events */
SCRIBE_START_DIVERGE_NOTIFICATION_DECL

SCRIBE_EVENT_DIVERGE(EVENT_TYPE, event_type,
	__field(__u8, type)
)

SCRIBE_EVENT_DIVERGE(EVENT_SIZE, event_size,
	__field(__u16, size)
)

SCRIBE_EVENT_DIVERGE(DATA_TYPE, data_type,
	__field(__u8, type)
)

SCRIBE_EVENT_DIVERGE(DATA_PTR, data_ptr,
	__field(__u32, user_ptr)
)

SCRIBE_EVENT_DIVERGE(DATA_CONTENT, data_content,
	__field(__u16, offset)
	__field(__u8, size)
	__field(__u8, data[128])
)

SCRIBE_EVENT_DIVERGE(RESOURCE_TYPE, resource_type,
	__field(__u8, type)
)

SCRIBE_EVENT_DIVERGE(SYSCALL, syscall,
	__field(__u16, nr)
)

SCRIBE_EVENT_DIVERGE(SYSCALL_RET, syscall_ret,
	__field(__u32, ret)
)

SCRIBE_EVENT_DIVERGE(FENCE_SERIAL, fence_serial,
	__field(__u32, serial)
)

SCRIBE_EVENT_DIVERGE(MEM_OWNED, mem_owned,
	__field(__u32, address)
	__field(__u8, write_access)
)

SCRIBE_EVENT_DIVERGE(MEM_NOT_OWNED, mem_not_owned)

SCRIBE_EVENT_DIVERGE(REGS, regs,
	__field(struct pt_regs, regs)
)

#undef __header_regular
#undef __header_sized
#undef __header_diverge
#undef __SCRIBE_EVENT
#undef SCRIBE_EVENT
#undef __SCRIBE_EVENT_SIZED
#undef SCRIBE_EVENT_SIZED
#undef __SCRIBE_EVENT_DIVERGE
#undef SCRIBE_EVENT_DIVERGE
#undef SCRIBE_START_LOG_FILE_DECL
#undef SCRIBE_START_COMMAND_DECL
#undef SCRIBE_START_NOTIFICATION_DECL
#undef SCRIBE_START_DIVERGE_NOTIFICATION_DECL
