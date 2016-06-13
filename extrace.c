/* extrace - trace exec() calls system-wide
 *
 * Requires CONFIG_CONNECTOR=y and CONFIG_PROC_EVENTS=y.
 * Requires root or "setcap cap_net_admin+ep extrace".
 *
 * Usage: extrace [-d] [-f] [-o FILE] [-p PID|CMD...]
 * default: show all exec(), globally
 * -p PID   only show exec() descendant of PID
 * CMD...   run CMD... and only show exec() descendant of it
 * -o FILE  log to FILE instead of standard output
 * -f       flat output: no indentation
 * -l       print full path of argv[0]
 * -d       print cwd of process
 * -q       don't print exec() arguments
 *
 * Copyright (C) 2014-2016 Christian Neukirchen <chneukirchen@gmail.com>
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

#define CMDLINE_MAX 32768
pid_t parent = 1;
int flat = 0;
int run = 0;
int full_path = 0;
int show_args = 1;
int show_cwd = 0;
FILE *output;
sig_atomic_t quit = 0;

static int
pid_depth(pid_t pid)
{
  pid_t ppid = 0;
  FILE *f;
  char name[PATH_MAX];
  int d;

  snprintf(name, sizeof name, "/proc/%d/stat", pid);

  if ((f = fopen(name, "r"))) {
    fscanf(f, "%*d (%*[^)]) %*c %d", &ppid);
    fclose(f);
  }

  if (ppid == parent)
    return 0;

  if (ppid == 0)
    return -1;  /* a parent we are not interested in */

  d = pid_depth(ppid);
  if (d == -1)
    return -1;

  return d+1;
}

static void
sigint(int sig)
{
  (void)sig;
  quit = 1;
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
handle_msg(struct cn_msg *cn_hdr)
{
  char cmdline[CMDLINE_MAX], name[PATH_MAX];
  char exe[PATH_MAX];
  char cwd[PATH_MAX];
  char *argvrest;

  int r = 0, r2 = 0, r3 = 0, fd, d;
  struct proc_event *ev = (struct proc_event *)cn_hdr->data;

  if (ev->what == PROC_EVENT_EXEC) {
    d = pid_depth(ev->event_data.exec.process_pid);
    if (d < 0)
      return;

    snprintf(name, sizeof name, "/proc/%d/cmdline",
             ev->event_data.exec.process_pid);

    memset(&cmdline, 0, sizeof cmdline);
    fd = open(name, O_RDONLY);
    if (fd > 0) {
      r = read(fd, cmdline, sizeof cmdline);
      close(fd);

      if (r > 0)
        cmdline[r] = 0;

      if (full_path) {
        snprintf(name, sizeof name, "/proc/%d/exe",
                 ev->event_data.exec.process_pid);
        r2 = readlink(name, exe, sizeof exe);
        if (r2 > 0)
          exe[r2] = 0;
      }

      argvrest = strchr(cmdline, 0) + 1;
    }

    if (show_cwd) {
      snprintf(name, sizeof name, "/proc/%d/cwd",
               ev->event_data.exec.process_pid);
      r3 = readlink(name, cwd, sizeof cwd);
      if (r3 > 0)
        cwd[r3] = 0;
    }

    if (!flat)
      fprintf(output, "%*s", 2*d, "");
    fprintf(output, "%d ", ev->event_data.exec.process_pid);
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

    fprintf(output, "\n");
    fflush(output);
  }
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
  enum proc_cn_mcast_op *mcop_msg;
  size_t recv_len = 0;
  int rc = -1, opt;

  output = stdout;

  while ((opt = getopt(argc, argv, "+dflo:p:qw")) != -1)
    switch (opt) {
    case 'd': show_cwd = 1; break;
    case 'f': flat = 1; break;
    case 'l': full_path = 1; break;
    case 'p': parent = atoi(optarg); break;
    case 'q': show_args = 0; break;
    case 'o':
      output = fopen(optarg, "w");
      if (!output) {
        perror("fopen");
        exit(1);
      }
      break;
    case 'w': /* obsoleted, ignore */; break;
    default: goto usage;
    }

  if (parent != 1 && optind != argc) {
usage:
    fprintf(stderr, "Usage: extrace [-dflwq] [-o FILE] [-p PID|CMD...]\n");
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
      if (nlh->nlmsg_type == NLMSG_ERROR || nlh->nlmsg_type == NLMSG_OVERRUN)
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
