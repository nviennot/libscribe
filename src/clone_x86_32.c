/*
 *  clone_x86_32.c: support for eclone() on x86_32
 *
 *  Copyright (C) Oren Laadan <orenl@cs.columbia.edu>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#define _GNU_SOURCE

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <asm/unistd.h>

/*
 * libc doesn't support eclone() yet...
 * below is arch-dependent code to use the syscall
 */

#include "eclone.h"

#ifndef __NR_eclone
#define __NR_eclone 338
#endif

int eclone(int (*fn)(void *), void *fn_arg, int clone_flags_low,
	   struct clone_args *clone_args, pid_t *pids)
{
	struct clone_args my_args;
	long retval;
	void **newstack;

	if (clone_args->child_stack) {
		/*
		 * Set up the stack for child:
		 *  - fn_arg will be the argument for the child function
		 *  - the fn pointer will be loaded into edx after the clone
		 */
		newstack = (void **)(unsigned long)(clone_args->child_stack +
					    clone_args->child_stack_size);
		*--newstack = fn_arg;
		*--newstack = fn;
	} else
		newstack = (void **)0;

	my_args = *clone_args;
	my_args.child_stack = (unsigned long)newstack;
	my_args.child_stack_size = 0;

	__asm__ __volatile__(
		"pushl %%ebx\n\t"      /* ebx needs to be saved for -fPIC code */
		"movl %3,%%ebx\n\t"
		"int $0x80\n\t"	       /* Linux/i386 system call */
		"testl %0,%0\n\t"      /* check return value */
		"jne 1f\n\t"	       /* jump if parent */
		"popl %%edx\n\t"       /* get subthread function */
		"call *%%edx\n\t"      /* start subthread function */
		"movl %2,%0\n\t"
		"int $0x80\n"	       /* exit system call: exit subthread */
		"1:\n\t"
		"popl %%ebx\n\t"
		:"=a" (retval)
		:"0" (__NR_eclone), "i" (__NR_exit),
		 "r" (clone_flags_low),	/* flags -> 1st (ebx) */
		 "c" (&my_args),	/* clone_args -> 2nd (ecx) */
		 "d" (sizeof(my_args)),	/* args_size -> 3rd (edx) */
		 "S" (pids)		/* pids -> 4th (esi) */
		 : "memory"
		);

	if (retval < 0) {
		errno = -retval;
		retval = -1;
	}
	return retval;
}
