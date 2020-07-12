/* auth-shadow.c -- shadow authentification routine for vlock,
 *                  the VT locking program for linux
 *
 * This program is copyright (C) 2007 Frank Benkstein, and is free
 * software which is freely distributable under the terms of the
 * GNU General Public License version 2, included as the file COPYING in this
 * distribution.  It is NOT public domain software, and any
 * redistribution not permitted by the GNU General Public License is
 * expressly forbidden without prior written permission from
 * the author.
 *
 */

/* for crypt() */
#define _XOPEN_SOURCE

#ifndef __FreeBSD__
/* for asprintf() */
#define _GNU_SOURCE
#endif

#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

#include <sys/mman.h>

#include <shadow.h>

#include "auth.h"
#include "prompt.h"

bool auth(const char *user, struct timespec *timeout)
{
  char *pwd;
  char *cryptpw;
  char *msg;
  struct spwd *spw;
  int result = false;
  char *username = (char *)user;

  if (NULL == user) {
    username = prompt("Login: ", timeout);
    if (NULL == username) {
      goto out_pwd;
    }
    printf("%s\n",username); /* workaround */
  }
  /* format the prompt */
  if (asprintf(&msg, "%s's Password: ", username) < 0)
    return false;

  if ((pwd = prompt_echo_off(msg, timeout)) == NULL) {
    log_session_access(username,0);
    goto out_pwd;
  }

  /* get the shadow password */
  if ((spw = getspnam(username)) == NULL) {
    const int error = errno;
    if (EACCES == error) {
      fprintf(stderr,"Installation error: vlock running account must be part of the shadow group !\n");
    } else {
      perror("vlock: getspnam()");
    }

    goto out_shadow;
  }

  /* hash the password */
  if ((cryptpw = crypt(pwd, spw->sp_pwdp)) == NULL) {
    perror("vlock: crypt()");
    goto out_shadow;
  }

  result = (strcmp(cryptpw, spw->sp_pwdp) == 0);

  log_session_access(username,result);

  if (!result) {
    sleep(1);
    fprintf(stderr, "vlock: Authentication error\n");
  }

out_shadow:
  /* deallocate shadow resources */
  endspent();

  /* free the password */
  free(pwd);

out_pwd:
  /* free the prompt */
  free(msg);

  /* free allocated username in multiusers mode */
  if (!user)
    free(username);

  return result;
}
