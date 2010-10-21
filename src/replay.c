#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <scribe.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#define LIBERROR(msg, args...) do { error( 0, errno, msg, ##args ); return -1; } while(0)
#define ERROR(msg, args...) do { error( 0, 0, msg, ##args ); return -1; } while(0)

int logfile;

int has_diverged;

static void on_idle(scribe_context_t ctx, int error)
{
	if (error < 0)
		printf("On Idle: error=%d %s\n", -error, strerror(-error));
	else if (error > 0 && !has_diverged)
		printf("On Idle: error=%d\n", error);
	else
		printf("Done\n");
}

static void on_backtrace(scribe_context_t ctx, loff_t *log_offset, int num)
{
	struct scribe_event *event;
	char *log_buffer;
	char str_buf[2000];
	size_t len;
	int i;

	len = lseek(logfile, 0, SEEK_END);
	log_buffer = mmap(NULL, len, PROT_READ, MAP_PRIVATE, logfile, 0);
	if (!log_buffer)
		return;

	printf("Backtrace:\n");
	for (i = 0; i < num; i++) {
		event = (struct scribe_event *)(log_buffer+log_offset[i]);
		scribe_get_event_str(str_buf, sizeof(str_buf), event);
		printf("    %s\n", str_buf);
	}
}

static void on_diverge(scribe_context_t ctx, struct scribe_event_diverge *e)
{
	char buffer[2000];
	scribe_get_event_str(buffer, sizeof(buffer), (struct scribe_event *)e);
	printf("Diverged:\n");
	printf("    [%02d] %s\n", e->pid, buffer);

	has_diverged = 1;
}

static struct scribe_operations scribe_ops = {
	.on_idle = on_idle,
	.on_backtrace = on_backtrace,
	.on_diverge = on_diverge
};

int main(int argc, char **argv)
{
	scribe_context_t ctx;

	logfile = open("log", O_RDONLY);
	if (logfile < 0)
		LIBERROR("cannot open logfile");

	scribe_context_create(&ctx);
	scribe_set_operations(ctx, &scribe_ops);

	if (scribe_replay(ctx, 0, logfile, 100, argv+1) < 0)
		LIBERROR("can't record");

	return 0;
}
