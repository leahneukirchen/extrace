/* extrace - trace exec() calls system-wide
 *
 * Requires CONFIG_CONNECTOR=y and CONFIG_PROC_EVENTS=y.
 * Requires root or "setcap cap_net_admin+ep extrace".
 *
 * Usage: extrace [-deflqQtu] [-o FILE] [-p PID|CMD...]
 * default: show all exec(), globally
 * -p PID   only show exec() descendant of PID
 * CMD...   run CMD... and only show exec() descendant of it
 * -o FILE  log to FILE instead of standard output
 * -d       print cwd of process
 * -e       print environment of process
 * -f       flat output: no indentation
 * -l       print full path of argv[0]
 * -q       don't print exec() arguments
 * -Q       don't print error messages
 * -u       print user of process
 *
 * Copyright (C) 2014-2019 Leah Neukirchen <leah@vuxu.org>
 *
 * hacked from sources of:
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

#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define max(x, y) ((y) < (x) ? (x) : (y))
#define min(x, y) ((y) > (x) ? (x) : (y))

#define SEND_MESSAGE_LEN (NLMSG_LENGTH(sizeof (struct cn_msg) + \
                                       sizeof (enum proc_cn_mcast_op)))
#define RECV_MESSAGE_LEN (NLMSG_LENGTH(sizeof (struct cn_msg) + \
                                       sizeof (struct proc_event)))

#define SEND_MESSAGE_SIZE (NLMSG_SPACE(SEND_MESSAGE_LEN))
#define RECV_MESSAGE_SIZE (NLMSG_SPACE(RECV_MESSAGE_LEN))

#define BUFF_SIZE (max(max(SEND_MESSAGE_SIZE, RECV_MESSAGE_SIZE), 1024))
#define MIN_RECV_SIZE (min(SEND_MESSAGE_SIZE, RECV_MESSAGE_SIZE))

#define CMDLINE_MAX 32768
#define CMDLINE_DB_MAX 32
pid_t parent = 1;
int flat = 0;
int run = 0;
int full_path = 0;
int show_args = 1;
int show_errors = 1;
int show_cwd = 0;
int show_env = 0;
int show_exit = 0;
int show_user = 0;
FILE *output;
sig_atomic_t quit = 0;
#define CPU_MAX 4096
uint32_t last_seq[CPU_MAX];

#define PID_DB_SIZE 1024
struct {
	pid_t pid;
	int depth;
	uint64_t start;
	char cmdline[CMDLINE_DB_MAX];
} pid_db[PID_DB_SIZE];

static void
print_runtime_error(const char* fmt, ...) {
	va_list ap;
	if (show_errors) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
	}
}

static int
open_proc_dir(pid_t pid) {
	char name[48];
	snprintf(name, sizeof name, "/proc/%d", pid);
	return open(name, O_DIRECTORY);
}

static int
pid_depth(pid_t pid)
{
	pid_t ppid = 0;
	char name[PATH_MAX];
	char buf[2048];
	char *s;
	int fd, d, i;

	snprintf(name, sizeof name, "/proc/%d/stat", pid);

	if ((fd = open(name, O_RDONLY)) < 0)
		return 0;
	if (read(fd, buf, sizeof buf) <= 0)
		return 0;
	close(fd);

	s = strrchr(buf, ')');  /* find end of COMM (recommended way) */
	if (!s)
		return 0;
	while (*++s == ' ')
		;
	/* skip over STATE */
	while (*++s == ' ')
		;
	errno = 0;
	ppid = strtol(s, 0, 10);  /* parse PPID */
	if (errno != 0)
		return 0;

	if (ppid == parent)
		return 0;

	if (ppid == 0)
		return -1;  /* a parent we are not interested in */

	for (i = 0; i < PID_DB_SIZE - 1; i++)
		if (pid_db[i].pid == ppid)
			d = pid_db[i].depth;
	if (i == PID_DB_SIZE - 1)
		d = pid_depth(ppid);  /* we need to recurse */

	if (d == -1)
		return -1;

	return d + 1;
}

static const char *
sig2name(int sig)
{
	switch (sig) {
#define X(s) case s: return #s;
		/* signals defined in POSIX.1-1990 */
		X(SIGHUP)
		X(SIGINT)
		X(SIGQUIT)
		X(SIGILL)
		X(SIGABRT)
		X(SIGFPE)
		X(SIGKILL)
		X(SIGSEGV)
		X(SIGUSR1)
		X(SIGUSR2)
		X(SIGPIPE)
		X(SIGALRM)
		X(SIGTERM)
		X(SIGCHLD)
		X(SIGCONT)
		X(SIGSTOP)
		X(SIGTSTP)
		X(SIGTTIN)
		X(SIGTTOU)

		/* signals defined in POSIX.1-2001 */
		X(SIGBUS)
		X(SIGPOLL)
		X(SIGPROF)
		X(SIGSYS)
		X(SIGTRAP)
		X(SIGURG)
		X(SIGVTALRM)
		X(SIGXCPU)
		X(SIGXFSZ)

		/* other signals */
#ifdef SIGSTKFLT
		X(SIGSTKFLT)  /* Stack fault on coprocessor (unused) */
#endif
#ifdef SIGWINCH
		X(SIGWINCH)   /* Window resize signal (4.3BSD) */
#endif
#ifdef SIGPWR
		X(SIGPWR)     /* Power failure (System V) */
#endif

#undef X
	default: {
		static char buf[8];
		snprintf(buf, sizeof buf, "SIG%d", sig);
		return buf;
	}
	}
}

static void
sigchld(int sig)
{
	(void)sig;
	while (waitpid(-1, NULL, WNOHANG) > 0)
		;
	quit = 1;
}

static void
print_shquoted(const char *s)
{
	if (*s && !strpbrk(s,
	    "\001\002\003\004\005\006\007\010"
	    "\011\012\013\014\015\016\017\020"
	    "\021\022\023\024\025\026\027\030"
	    "\031\032\033\034\035\036\037\040"
	    "`^#*[]=|\\?${}()'\"<>&;\177")) {
		fprintf(output, "%s", s);
		return;
	}

	putc('\'', output);
	for (; *s; s++)
		if (*s == '\'')
			fprintf(output, "'\\''");
		else if (*s == '\n')
			fprintf(output, "'$'\\n''");
		else
			putc(*s, output);
	putc('\'', output);
}

static void
print_env(int proc_dir_fd)
{
	int fd;
	FILE *env;

	fprintf(output, "  ");
	fd = openat(proc_dir_fd, "environ", O_RDONLY);
	if (fd >= 0 && (env = fdopen(fd, "r"))) {
		char *line = 0, *eq = 0;
		size_t linelen = 0;
		while (getdelim(&line, &linelen, '\0', env) >= 0) {
			putc(' ', output);
			if ((eq = strchr(line, '='))) {
				/* print split so = doesn't trigger escaping.  */
				*eq = 0;
				print_shquoted(line);
				putc('=', output);
				print_shquoted(eq+1);
			} else {
				/* weird env entry without equal sign.  */
				print_shquoted(line);
			}
		}
		free(line);
		fclose(env);
	} else {
		fprintf(output, " -");
	}
}

static void
handle_msg(struct cn_msg *cn_hdr)
{
	char cmdline[CMDLINE_MAX];
	char exe[PATH_MAX];
	char cwd[PATH_MAX];
	char *argvrest;

	int r = 0, r2 = 0, r3 = 0, fd, d;
	struct proc_event *ev = (struct proc_event *)cn_hdr->data;

	if (ev->what == PROC_EVENT_EXEC) {
		pid_t pid = ev->event_data.exec.process_pid;
		int i = 0;
		int proc_dir_fd = open_proc_dir(pid);
		if (proc_dir_fd < 0) {
			print_runtime_error(
			    "extrace: process vanished before notification: pid %d\n",
			    pid);
			return;
		}

		memset(&cmdline, 0, sizeof cmdline);
		fd = openat(proc_dir_fd, "cmdline", O_RDONLY);
		if (fd >= 0) {
			r = read(fd, cmdline, sizeof cmdline);
			close(fd);

			if (r > 0)
				cmdline[r] = 0;

			if (full_path) {
				r2 = readlinkat(proc_dir_fd, "exe", exe, sizeof exe);
				if (r2 > 0)
					exe[r2] = 0;
			}

			argvrest = strchr(cmdline, 0) + 1;
		}

		d = pid_depth(pid);
		if (d < 0) {
			if (*cmdline) {
				print_runtime_error(
				    "extrace: process vanished before we found its parent: pid %d: %s\n",
				    pid, cmdline);
			} else {
				print_runtime_error(
				    "extrace: process vanished without a name: pid %d\n",
				    pid);
			}
			close(proc_dir_fd);
			return;
		}

		if (show_exit || !flat) {
			for (i = 0; i < PID_DB_SIZE - 1; i++)
				if (pid_db[i].pid == 0)
					break;
			if (i == PID_DB_SIZE - 1)
				print_runtime_error("extrace: warning: pid_db of "
				    "size %d overflowed\n", PID_DB_SIZE);

			pid_db[i].pid = pid;
			pid_db[i].depth = d;
			pid_db[i].start = ev->timestamp_ns;
		}

		if (show_cwd) {
			r3 = readlinkat(proc_dir_fd, "cwd", cwd, sizeof cwd);
			if (r3 > 0)
				cwd[r3] = 0;
		}

		if (!flat)
			fprintf(output, "%*s", 2*d, "");
		fprintf(output, "%d", pid);
		if (show_exit) {
			putc('+', output);
			snprintf(pid_db[i].cmdline, CMDLINE_DB_MAX,
			    "%s", cmdline);
		}
		if (show_user) {
			struct stat st;
			struct passwd *p;

			if (fstat(proc_dir_fd, &st) < 0)
				st.st_uid = -1;
			if ((p = getpwuid(st.st_uid)))
				fprintf(output," <%s>", p->pw_name);
			else
				fprintf(output," <%d>", st.st_uid);
		}
		putc(' ', output);
		if (show_cwd) {
			print_shquoted(cwd);
			fprintf(output, " %% ");
		}

		if (full_path)
			print_shquoted(exe);
		else
			print_shquoted(cmdline);

		if (show_args && r > 0) {
			while (argvrest - cmdline < r) {
				putc(' ', output);
				print_shquoted(argvrest);
				argvrest = strchr(argvrest, 0)+1;
			}
		}

		if (r == sizeof cmdline)
			fprintf(output, "... <truncated>");

		if (show_env)
			print_env(proc_dir_fd);

		close(proc_dir_fd);

		fprintf(output, "\n");
		fflush(output);
	} else if ((show_exit || !flat) && ev->what == PROC_EVENT_EXIT) {
		pid_t pid = ev->event_data.exit.process_pid;
		int i;

		for (i = 0; i < PID_DB_SIZE; i++)
			if (pid_db[i].pid == pid)
				break;
		if (i == PID_DB_SIZE)
			return;

		pid_db[i].pid = 0;

		if (!show_exit)
			return;

		if (!flat)
			fprintf(output, "%*s",
			    2*pid_db[i].depth, "");

		fprintf(output, "%d- ", pid);
		print_shquoted(pid_db[i].cmdline);

		if (!WIFEXITED(ev->event_data.exit.exit_code))
			fprintf(output, " exited signal=%s",
			    sig2name(WTERMSIG(ev->event_data.exit.exit_code)));
		else
			fprintf(output, " exited status=%d",
			    WEXITSTATUS(ev->event_data.exit.exit_code));
		fprintf(output, " time=%.3fs\n",
		    (ev->timestamp_ns - pid_db[i].start) / 1e9);
		fflush(output);
	}
}

static pid_t
parse_pid(char *s)
{
	pid_t pid;
	char *end;

	errno = 0;
	pid = strtol(s, &end, 10);
	if (pid <= 0 || *end || errno != 0) {
		fprintf(stderr, "extrace: %s: invalid process id\n", s);
		exit(1);
	}

	errno = 0;
	kill(pid, 0);
	if (errno == ESRCH) {
		fprintf(stderr, "extrace: %s: no such process\n", s);
		exit(1);
	}

	return pid;
}

int
main(int argc, char *argv[])
{
	int sk_nl;
	struct sockaddr_nl my_nla, kern_nla, from_nla;
	socklen_t from_nla_len;
	char buff[BUFF_SIZE];
	struct nlmsghdr *nl_hdr, *nlh;
	struct cn_msg *cn_hdr, *cmsg;
	struct proc_event *cproc;
	enum proc_cn_mcast_op *mcop_msg;
	size_t recv_len = 0;
	int rc = -1, opt;

	output = stdout;

	while ((opt = getopt(argc, argv, "+deflo:p:qQtwu")) != -1)
		switch (opt) {
		case 'd': show_cwd = 1; break;
		case 'e': show_env = 1; break;
		case 'f': flat = 1; break;
		case 'l': full_path = 1; break;
		case 'p': parent = parse_pid(optarg); break;
		case 'q': show_args = 0; break;
		case 'Q': show_errors = 0; break;
		case 't': show_exit = 1; break;
		case 'o':
			output = fopen(optarg, "w");
			if (!output) {
				perror("fopen");
				exit(1);
			}
			break;
		case 'w': /* obsoleted, ignore */; break;
		case 'u': show_user = 1; break;
		default: goto usage;
		}

	if (parent != 1 && optind != argc) {
usage:
		fprintf(stderr, "Usage: extrace [-deflqQtu] [-o FILE] [-p PID|CMD...]\n");
		exit(1);
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
	mcop_msg = (enum proc_cn_mcast_op *)&cn_hdr->data[0];

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
		printf("failed to send proc connector mcast ctl op!\n");
		goto close_and_exit;
	}

	if (*mcop_msg == PROC_CN_MCAST_IGNORE) {
		rc = 0;
		goto close_and_exit;
	}

	if (optind != argc) {
		pid_t child;

		parent = getpid();
		signal(SIGCHLD, sigchld);

		child = fork();
		if (child == -1) {
			perror("fork");
			goto close_and_exit;
		}
		if (child == 0) {
			execvp(argv[optind], argv+optind);
			perror("execvp");
			goto close_and_exit;
		}
	}

	rc = 0;
	while (!quit) {
		cmsg = (struct cn_msg *)(buff + sizeof (struct nlmsghdr));
		cproc = (struct proc_event *)(buff + sizeof (struct nlmsghdr) + sizeof (struct cn_msg));

		memset(buff, 0, sizeof buff);
		from_nla_len = sizeof from_nla;
		nlh = (struct nlmsghdr *)buff;
		memcpy(&from_nla, &kern_nla, sizeof from_nla);
		recv_len = recvfrom(sk_nl, buff, BUFF_SIZE, 0,
		    (struct sockaddr *)&from_nla, &from_nla_len);
		if (from_nla.nl_pid != 0 || recv_len < 1)
			continue;

		if (cproc->what == PROC_EVENT_NONE)
			continue;
	
		if (last_seq[cproc->cpu] &&
		    cmsg->seq != last_seq[cproc->cpu] + 1)
			print_runtime_error(
			    "extrace: out of order message on cpu %d\n",
			    cproc->cpu);
		last_seq[cproc->cpu] = cmsg->seq;

		while (NLMSG_OK(nlh, recv_len)) {
			if (nlh->nlmsg_type == NLMSG_NOOP)
				continue;
			if (nlh->nlmsg_type == NLMSG_ERROR ||
			    nlh->nlmsg_type == NLMSG_OVERRUN)
				break;

			handle_msg(NLMSG_DATA(nlh));

			if (nlh->nlmsg_type == NLMSG_DONE)
				break;
			nlh = NLMSG_NEXT(nlh, recv_len);
		}
	}

close_and_exit:
	close(sk_nl);
	return rc;
}
