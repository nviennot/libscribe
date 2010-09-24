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

/* This is the default init process for scribe.
 * It is required because init will be recorded, and thus we cannot
 * inherit the monitor's address space
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int status;

	if (argc < 2) {
		fprintf(stderr, "This is used internally by libscribe");
		return 1;
	}

	pid_t pid = fork();
	if (pid < 0)
		return 1;

	if (!pid) {
		execvp(argv[1], argv+1);
		perror("Cannot fork()");
		return 1;
	}

	/* child reaper */
	while (waitpid(-1, &status, __WALL) >= 0);

	return 0;
}
