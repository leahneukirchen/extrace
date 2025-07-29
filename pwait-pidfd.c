/* pwait - wait for processes to terminate
 *
 * Requires Linux 6.15+ with PIDFD_INFO_EXIT.
 *
 * Usage: pwait [-v] [-c] [-t TIMEOUT] PID...
 *  -v  Print the exit status when each process terminates.
 *  -c  Check for PIDs to exit successfully, else return 111.
 *  -t  Timeout after TIMEOUT seconds.
 *
 * To the extent possible under law, Leah Neukirchen <leah@vuxu.org>
 * has waived all copyright and related or neighboring rights to this work.
 * http://creativecommons.org/publicdomain/zero/1.0/
 */

#define _GNU_SOURCE

#include <linux/pidfd.h>

#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int
pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

int
main(int argc, char *argv[])
{
	struct pollfd *fds;
	nfds_t i, nfds;
	int verbose = 0;
	int check = 0;
	long timeout = -1;
	int alive = 1;
	long count = -1;
	int rc = 0;

	int opt;
	while ((opt = getopt(argc, argv, "+cvt:n:")) != -1)
		switch (opt) {
		case 'c': check = 1; break;
		case 'v': verbose = 1; break;
		case 'n': {
			errno = 0;
			char *rest = 0;
			count = strtol(optarg, &rest, 10);
			if (count <= 0 || *rest || errno != 0) {
				fprintf(stderr, "pwait: invalid count\n");
				exit(-1);
			}
			break;
		}
		case 't': {
			errno = 0;
			char *rest = 0;
			timeout = strtol(optarg, &rest, 10);
			if (timeout <= 0 || *rest || errno != 0) {
				fprintf(stderr, "pwait: invalid timeout\n");
				exit(-1);
			}
			break;
		}
		default: goto usage;
		}

	argc -= optind;
	argv += optind;

	if (argc == 0) {
usage:
		fprintf(stderr, "Usage: pwait [-v] [-c] [-t TIMEOUT] [-n COUNT] PID...\n");
		exit(-1);
	}

	fds = calloc(argc + 1, sizeof (struct pollfd));
	if (!fds) {
		perror("pwait: calloc");
		exit(-1);
	}

	for (i = 0, nfds = 1; i < (nfds_t)argc; i++) {
		char *end;
		errno = 0;
		pid_t pid = strtol(argv[i], &end, 10);
		if (pid <= 0 || *end || errno != 0) {
			fprintf(stderr, "pwait: %s: invalid process id\n",
			    argv[i]);
			continue;
		}

		int pidfd = pidfd_open(pid, 0);
		if (pidfd < 0) {
			if (errno == ESRCH) {
				fprintf(stderr, "pwait: %d: no such process\n", pid);
			} else {
				perror("pwait: pidfd_open");
				exit(-1);
			}
			continue;
		}

		fds[nfds].fd = pidfd;
		fds[nfds].events = (check || verbose) ? POLLHUP : POLLIN;
		nfds++;
	}

	if (nfds == 1)
		exit(1);

	if (timeout > 0) {
		int timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
		if (timerfd < 0) {
			perror("timerfd_create");
			exit(-1);
		}
		timerfd_settime(timerfd, 0,
		    &(struct itimerspec) { .it_value = { .tv_sec = timeout } },
		    0);
		fds[0].fd = timerfd;
		fds[0].events = POLLIN;
	} else {
		fds[0].fd = -1;
	}

	if (count < 0)
		count = argc;

	alive = argc;
	while (alive > argc - count) {
		if (poll(fds, nfds, -1) < 0) {
			perror("pwait: poll");
			exit(-1);
		}

		if (fds[0].revents & POLLIN) {
			if (verbose)
				printf("pwait: timeout.");
			exit(3);
		}

		alive = 0;
		for (i = 1; i < nfds; i++) {
			if (fds[i].revents & POLLIN) {
				close(fds[i].fd);
				fds[i].fd = -1;
			} else if (fds[i].revents & POLLHUP) {
				struct pidfd_info info = { .mask = PIDFD_INFO_EXIT };
				int r = ioctl(fds[i].fd, PIDFD_GET_INFO, &info);
				if (r < 0) {
					perror("ioctl");
					exit(-1);
				}

				int status = info.exit_code;
				if (verbose) {
					if (WIFEXITED(status))
						printf("%s: exited with status %d.\n",
						    argv[i-1],
						    WEXITSTATUS(status));
					else if (WIFSIGNALED(status))
						printf("%s: killed by signal %d.\n",
						    argv[i-1],
						    WTERMSIG(status));
					else
						printf("%s: terminated.\n", argv[i-1]);
				}

				if (check && (WTERMSIG(status) || !WEXITSTATUS(status)))
					rc = 111;

				close(fds[i].fd);
				fds[i].fd = -1;
                        } else if (fds[i].fd >= 0) {
				alive++;
			}
		}
	}

	exit(rc);
}
