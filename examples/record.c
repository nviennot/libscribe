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

int main(int argc, char **argv)
{
	int logfile;
	scribe_context_t ctx;

	logfile = open("log", O_CREAT | O_RDWR | O_TRUNC, 0600);
	if (logfile < 0)
		LIBERROR("cannot open logfile");

	scribe_context_create(&ctx, NULL, NULL);

	if (scribe_record(ctx, 0, logfile, argv+1, NULL, NULL, NULL) < 0)
		LIBERROR("can't record");

	if (scribe_wait(ctx) < 0)
		LIBERROR("can't record");

	return 0;
}
