#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/mman.h>
#include <error.h>
#include <linux/types.h>
#include <scribe.h>

#define LIBERROR(msg, args...) { error( 0, errno, msg, ##args ); return -1; }
#define ERROR(msg, args...) { error( 0, 0, msg, ##args ); return -1; }

void usage()
{
	printf("scribe_profiler <log_file>\n");
}

int dump_events(const char *buf, size_t len)
{
	size_t off;
	char buffer[2000];
	pid_t pid = 0;
	int in_syscall = 0;
	for(off = 0; off < len; off += sizeof_event((struct scribe_event *)(buf+off))) {
		struct scribe_event *event = (struct scribe_event *)(buf+off);
		if (event->type == SCRIBE_EVENT_PID)
			pid = ((struct scribe_event_pid *)event)->pid;
		else if (event->type == SCRIBE_EVENT_SYSCALL_END)
			in_syscall = 0;
		else {
			scribe_get_event_str(buffer, sizeof(buffer), event);
			printf("[%02d] %s%s\n", pid, in_syscall ? "    " : "", buffer);

			if (event->type == SCRIBE_EVENT_SYSCALL)
				in_syscall = 1;
		}
	}

	if (off != len)
		ERROR("invalid log file %d %d", off, len);
	return 0;
}

int dump_log(const char *filename)
{
	int fd = open(filename, O_RDONLY);

	if (fd < 0)
		LIBERROR("cannot open %s", filename);

	size_t len = lseek(fd, 0, SEEK_END);
	char *buffer = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);

	if (buffer == MAP_FAILED) {
		close(fd);
		LIBERROR("cannot mmap %s", filename);
	}

	int ret = dump_events(buffer, len);

	munmap(buffer, len);
	close(fd);
	return ret;
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		usage();
		return -1;
	}

	return dump_log(argv[1]) < 0 ? 1 : 0;
}
