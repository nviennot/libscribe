#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <error.h>
#include <string.h>
#include <linux/types.h>
#include <scribe.h>

#define LIBERROR(msg, args...) { error( 0, errno, msg, ##args ); return -1; }
#define ERROR(msg, args...) { error( 0, 0, msg, ##args ); return -1; }

#define BUF_SIZE 1024

void handle_event_string(const char *str)
{
	struct scribe_event_data *event;

	if (scribe_is_recording()) {
		event = malloc(sizeof(*event) + strlen(str) + 1);
		event->h.h.type = SCRIBE_EVENT_DATA;
		event->h.size = strlen(str) + 1;

		strcpy(event->data, str);

		scribe_send_event((void *) event);
	}

	if (scribe_is_replaying()) {
		event = malloc(BUF_SIZE);
		scribe_recv_event((void *) event, BUF_SIZE);
		printf("%s\n", event->data);
	}
}

int main(int argc, const char *argv[])
{
	if (argc > 1)
		handle_event_string(argv[1]);

	if (argc > 2)
		handle_event_string(argv[2]);

	return 0;
}


