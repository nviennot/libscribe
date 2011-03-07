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

#ifndef _LINUX_SCRIBE_RESOURCE_H_
#define _LINUX_SCRIBE_RESOURCE_H_



enum scribe_resource_type {
	SCRIBE_RES_TYPE_INODE,
	SCRIBE_RES_TYPE_FILE,
	SCRIBE_RES_TYPE_FILES_STRUCT,
	SCRIBE_RES_TYPE_PID,
	SCRIBE_RES_TYPE_FUTEX,
	SCRIBE_RES_TYPE_IPC,
	SCRIBE_RES_TYPE_PTRACE,
};
#define SCRIBE_RES_TYPE_MASK		0x0f
#define SCRIBE_RES_SPINLOCK		0x80


#endif /* _LINUX_SCRIBE_RESOURCE_H_ */
