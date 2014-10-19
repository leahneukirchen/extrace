/* pwait - wait for processes to terminate
 *
 * Requires CONFIG_CONNECTOR=y and CONFIG_PROC_EVENTS=y.
 * Requires root or "setcap cap_net_admin+ep pwait".
 *
 * Usage: pwait [-v] PID...
 * -v  Print the exit status when each process terminates.
 *
 * Copyright (C) 2014 Christian Neukirchen <chneukirchen@gmail.com>
 *
 * hacked from sources of:
 */
/* FreeBSD: head/bin/pwait/pwait.c 245506 2013-01-16 18:15:25Z delphij */
/*-
 * Copyright (c) 2004-2009, Jilles Tjoelker
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with
 * or without modification, are permitted provided that the
 * following conditions are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the
 *    following disclaimer.
 * 2. Redistributions in binary form must reproduce the
 *    above copyright notice, this list of conditions and
 *    the following disclaimer in the documentation and/or
 *    other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */
/* exec-notify, so you can watch your acrobat reader or vim executing "bash -c"
 * commands ;-)
 * Requires some 2.6.x Linux kernel with proc connector enabled.
 *
 * $  cc -Wall -ansi -pedantic -std=c99 exec-notify.c
 *
 * (C) 2007-2010 Sebastian Krahmer <krahmer@suse.de> original netlink handling
 * stolen from an proc-connector example, copyright folows:
 */
/* Copyright (C) Matt Helsley, IBM Corp. 2005
 * Derived from fcctl.c by Guillaume Thouvenin
 * Original copyright notice follows:
 *
 * Copyright (C) 2005 BULL SA.
 * Written by Guillaume Thouvenin <guillaume.thouvenin@bull.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#define _XOPEN_SOURCE 700

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <linux/connector.h>
#include <linux/netlink.h>
#include <linux/cn_proc.h>

#define max(x,y) ((y)<(x)?(x):(y))
#define min(x,y) ((y)>(x)?(x):(y))

#define SEND_MESSAGE_LEN (NLMSG_LENGTH(sizeof (struct cn_msg) + \
				       sizeof (enum proc_cn_mcast_op)))
#define RECV_MESSAGE_LEN (NLMSG_LENGTH(sizeof (struct cn_msg) + \
				       sizeof (struct proc_event)))

#define SEND_MESSAGE_SIZE    (NLMSG_SPACE(SEND_MESSAGE_LEN))
#define RECV_MESSAGE_SIZE    (NLMSG_SPACE(RECV_MESSAGE_LEN))

#define BUFF_SIZE (max(max(SEND_MESSAGE_SIZE, RECV_MESSAGE_SIZE), 1024))
#define MIN_RECV_SIZE (min(SEND_MESSAGE_SIZE, RECV_MESSAGE_SIZE))

sig_atomic_t quit = 0;

static void
sigint(int sig)
{
	quit = 1;
}

static void
display(pid_t pid, int status)
{
	if (WIFEXITED(status))
		printf("%ld: exited with status %d.\n",
		    (long)pid,
		    WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		printf("%ld: killed by signal %d.\n",
		    (long)pid,
		    WTERMSIG(status));
	else
		printf("%ld: terminated.\n",
		    (long)pid);
}

int
main(int argc, char *argv[])
{
	int sk_nl;
	struct sockaddr_nl my_nla, kern_nla, from_nla;
	socklen_t from_nla_len;
	char buff[BUFF_SIZE];
	struct nlmsghdr *nl_hdr, *nlh;
	struct cn_msg *cn_hdr;
	struct proc_event *ev;
	enum proc_cn_mcast_op *mcop_msg;
	size_t recv_len = 0;
	int opt;
	int n;
	pid_t *pids;
	pid_t pid;
	char *end;
	int verbose = 0;
	int seen = 0;
	int rc = -1;

	while ((opt = getopt(argc, argv, "+v")) != -1)
		switch (opt) {
		case 'v': verbose = 1; break;
		default: goto usage;
		}
	
	argc -= optind;
	argv += optind;

	if (argc == 0) {
usage:
		fprintf(stderr, "Usage: pwait [-v] PID...\n");
		exit(1);
	}

	pids = calloc(argc, sizeof (pid_t));
	if (!pids) {
		perror("calloc");
		exit(1);
	}

	for (n = 0; n < argc; n++) {
		errno = 0;
		pid = strtol(argv[n], &end, 10);
		if (pid < 0 || *end != '\0' || errno != 0) {
			fprintf(stderr, "%s: bad process id\n", argv[n]);
			continue;
		}
		pids[n] = pid;
	}

	sk_nl = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
	if (sk_nl == -1) {
		perror("socket sk_nl error");
		exit(1);
	}

	my_nla.nl_family = AF_NETLINK;
	my_nla.nl_groups = CN_IDX_PROC;
	my_nla.nl_pid = getpid();

	kern_nla.nl_family = AF_NETLINK;
	kern_nla.nl_groups = CN_IDX_PROC;
	kern_nla.nl_pid = 1;

	if (bind(sk_nl, (struct sockaddr *)&my_nla, sizeof my_nla) == -1) {
		perror("binding sk_nl error");
		goto close_and_exit;
	}
	nl_hdr = (struct nlmsghdr *)buff;
	cn_hdr = (struct cn_msg *)NLMSG_DATA(nl_hdr);
	mcop_msg = (enum proc_cn_mcast_op*)&cn_hdr->data[0];

	memset(buff, 0, sizeof buff);
	*mcop_msg = PROC_CN_MCAST_LISTEN;

	nl_hdr->nlmsg_len = SEND_MESSAGE_LEN;
	nl_hdr->nlmsg_type = NLMSG_DONE;
	nl_hdr->nlmsg_flags = 0;
	nl_hdr->nlmsg_seq = 0;
	nl_hdr->nlmsg_pid = getpid();

	cn_hdr->id.idx = CN_IDX_PROC;
	cn_hdr->id.val = CN_VAL_PROC;
	cn_hdr->seq = 0;
	cn_hdr->ack = 0;
	cn_hdr->len = sizeof (enum proc_cn_mcast_op);

	if (send(sk_nl, nl_hdr, nl_hdr->nlmsg_len, 0) != nl_hdr->nlmsg_len) {
		fprintf(stderr, "failed to send proc connector mcast ctl op!\n");
		goto close_and_exit;
	}

	if (*mcop_msg == PROC_CN_MCAST_IGNORE)
		goto close_and_exit;

	signal(SIGINT, sigint);

	rc = 0;
	while (!quit) {
		memset(buff, 0, sizeof buff);

		from_nla_len = sizeof from_nla;
		nlh = (struct nlmsghdr *)buff;
		memcpy(&from_nla, &kern_nla, sizeof from_nla);
		recv_len = recvfrom(sk_nl, buff, BUFF_SIZE, 0,
		    (struct sockaddr *)&from_nla, &from_nla_len);
		if (from_nla.nl_pid != 0 || recv_len < 1)
			continue;

		while (NLMSG_OK(nlh, recv_len)) {
			if (nlh->nlmsg_type == NLMSG_NOOP)
				continue;
			if (nlh->nlmsg_type == NLMSG_ERROR ||
			    nlh->nlmsg_type == NLMSG_OVERRUN)
				break;
			
			ev = (struct proc_event *)
			    ((struct cn_msg *) NLMSG_DATA(nlh))->data;
			
			if (ev->what == PROC_EVENT_EXIT) {
				int status = ev->event_data.exit.exit_code;
				pid_t pid = ev->event_data.exit.process_pid;
				
				seen = 0;
				for (n = 0; n < argc; n++)
					if (pids[n] == pid) {
						if (verbose && !seen)
							display(pid, status);
						pids[n] = 0;
						seen = 1;
					}
			}
			
			if (nlh->nlmsg_type == NLMSG_DONE)
				break;
			nlh = NLMSG_NEXT(nlh, recv_len);
		}
		
		quit = 1;
		for (n = 0; n < argc; n++)
			if (pids[n] != 0)
				quit = 0;
	}

close_and_exit:
	close(sk_nl);
	return rc;
}
