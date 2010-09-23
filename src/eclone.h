#ifndef _ECLONE_H_
#define _ECLONE_H_

#include <stdint.h>

struct clone_args {
	uint64_t clone_flags_high;
	uint64_t child_stack;
	uint64_t child_stack_size;
	uint64_t parent_tid_ptr;
	uint64_t child_tid_ptr;
	uint32_t nr_pids;
	uint32_t reserved0;
};


/*
 * Arch-dependent code implements this interface; This is slightly
 * different than the syscall prototype - the arch-dependent code
 * fills in the args_size.
 */
extern int eclone(int (*fn)(void *), void *fn_arg,
		  int clone_flags_low,
		  struct clone_args *clone_args,
		  pid_t *pids);

#endif
