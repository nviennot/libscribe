#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <scribe.h>

#define LIBERROR(msg, args...) do { error( 0, errno, msg, ##args ); return -1; } while(0)
#define ERROR(msg, args...) do { error( 0, 0, msg, ##args ); return -1; } while(0)

static void on_idle(scribe_context_t ctx, int error)
{
	if (error < 0)
		printf("On Idle: error=%d %s\n", -error, strerror(-error));
	else
		printf("All done :)\n");
}

static struct scribe_operations scribe_ops = {
	.on_idle = on_idle
};

int main(int argc, char **argv)
{
	int logfile;
	scribe_context_t ctx;

	logfile = open("log", O_CREAT | O_RDWR | O_TRUNC, 0600);
	if (logfile < 0)
		LIBERROR("cannot open logfile");

	scribe_context_create(&ctx);
	scribe_set_operations(ctx, &scribe_ops);

	if (scribe_record(ctx, 0, logfile, argv+1) < 0)
		LIBERROR("can't record");

	return 0;
}
