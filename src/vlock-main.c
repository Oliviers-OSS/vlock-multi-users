/* vlock-main.c -- main routine for vlock,
 *                    the VT locking program for linux
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <pwd.h>

#include <termios.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>
#include <syslog.h>

#include "prompt.h"
#include "auth.h"
#include "console_switch.h"
#include "util.h"
#include "cmdline_parameters.h"

#ifdef USE_PLUGINS
#include "plugins.h"
#endif

int vlock_debug = 0;
static cmndline_parameters parameters = {
		.modes = 0,
		.timeout = TIMEOUT_NOT_SET
};

#define ensure_atexit(func) \
  do { \
    if (atexit(func) != 0) \
      fatal_perror("vlock: atexit() failed"); \
  } while (0)

static char *get_username(void)
{
  uid_t uid = getuid();
  char *username = NULL;

  /* Get the user name from the environment if started as root. */
  if (uid == 0)
    username = getenv("USER");

  if (username == NULL) {
    struct passwd *pw;

    /* Get the password entry. */
    pw = getpwuid(uid);

    if (pw == NULL)
      return NULL;

    username = pw->pw_name;
  }

  return strdup(username);
}

int log_session_access(const char *newuser,bool success)
{
  int error = EXIT_SUCCESS;
  uid_t uid = getuid();
  char *username = NULL;
  char buffer[100];

  /* Get the user name from the environment if started as root. */
  if (uid == 0)
	username = getenv("USER");

  if (username == NULL) {
	struct passwd *pw;

	/* Get the password entry. */
	pw = getpwuid(uid);

	if (pw != NULL) {
		username = pw->pw_name;
	} else {
		error = ENOENT;
		sprintf(buffer,"(%u)",uid);
		username = buffer;
	}
  }

  if (success) {
	  if (!newuser) {
		  newuser = "???";
	  }
	  syslog(LOG_NOTICE,"user %s entering into %s's session",newuser,username);
  } else {
	  syslog(LOG_ERR,"user %s authentication has failed",username);
  }

  return error;
}

static inline void log_session_lock() {
	  uid_t uid = getuid();
	  char *username = NULL;
	  char buffer[16];

	  /* Get the user name from the environment if started as root. */
	  if (uid == 0)
		username = getenv("USER");

	  if (username == NULL) {
		struct passwd *pw;

		/* Get the password entry. */
		pw = getpwuid(uid);

		if (pw != NULL) {
			username = pw->pw_name;
		} else {
			sprintf(buffer,"(%u)",uid);
			username = buffer;
		}
	  }

	const char *mode = "mono-user";
#ifdef NO_ROOT_PASS
	const char *root_mode = "";
#else /* NO_ROOT_PASS */
	const char *root_mode = ",root";
#endif /* NO_ROOT_PASS */

	if ((parameters.modes & e_MultiUsers) == e_MultiUsers) {
		mode = "multi-users";
	}
	syslog(LOG_NOTICE,"User %s's session is now locked (%s%s)",username,mode,root_mode);
}

static void terminate(int signum)
{
  fprintf(stderr, "vlock: Terminated!\n");
  /* Call exit here to ensure atexit handlers are called. */
  exit(1);
}

static void block_signals(void)
{
  struct sigaction sa;

  /* Ignore some signals. */
  /* These signals shouldn't be delivered anyway, because terminal signals are
   * disabled below. */
  (void) sigemptyset(&(sa.sa_mask));
  sa.sa_flags = SA_RESTART;
  sa.sa_handler = SIG_IGN;
  (void) sigaction(SIGINT, &sa, NULL);
  (void) sigaction(SIGQUIT, &sa, NULL);
  (void) sigaction(SIGTSTP, &sa, NULL);

  /* Install special handler for SIGTERM. */
  sa.sa_flags = SA_RESETHAND;
  sa.sa_handler = terminate;
  (void) sigaction(SIGTERM, &sa, NULL);
}

static struct termios term;
static tcflag_t lflag;

static void secure_terminal(void)
{
  /* Disable terminal echoing and signals. */
  (void) tcgetattr(STDIN_FILENO, &term);
  lflag = term.c_lflag;
  term.c_lflag &= ~(ECHO | ISIG);
  (void) tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

static void restore_terminal(void)
{
  /* Restore the terminal. */
  term.c_lflag = lflag;
  (void) tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

static int auth_tries;

static void auth_loop(const char *username)
{
  struct timespec *prompt_timeout;
  struct timespec *wait_timeout;
  char *vlock_message;

  /* Get the vlock message from the environment. */
  vlock_message = getenv("VLOCK_MESSAGE");
  if (vlock_message == NULL) {
    if (console_switch_locked)
      vlock_message = getenv("VLOCK_ALL_MESSAGE");
    else
      vlock_message = getenv("VLOCK_CURRENT_MESSAGE");
  }

  /* Get the timeouts from the environment. */
  prompt_timeout = parse_seconds(getenv("VLOCK_PROMPT_TIMEOUT"));
#ifdef USE_PLUGINS
  wait_timeout = parse_seconds(getenv("VLOCK_TIMEOUT"));
#else
  wait_timeout = NULL;
#endif

  log_session_lock();
  for (;;) {
    char c;

    /* Print vlock message if there is one. */
    if (vlock_message && *vlock_message) {
      if ((parameters.modes & e_KeepScreen) != e_KeepScreen) {
    	  const char *cls = "\033[H\033[J";
    	  fputs(cls, stderr);
      }
      fprintf(stderr,"%s\n",vlock_message);
    }

    /* Wait for enter or escape to be pressed. */
    c = wait_for_character("\n\033", wait_timeout);

    /* Escape was pressed or the timeout occurred. */
    if (c == '\033' || c == 0) {
#ifdef USE_PLUGINS
      plugin_hook("vlock_save");
      /* Wait for any key to be pressed. */
      c = wait_for_character(NULL, NULL);
      plugin_hook("vlock_save_abort");

      /* Do not require enter to be pressed twice. */
      if (c != '\n')
        continue;
#else
      continue;
#endif
    }

    /* Try authentication as user. */
    if (auth(username, prompt_timeout))
      break;
    else
      sleep(1);

#ifndef NO_ROOT_PASS
    if (strcmp(username, "root") != 0) {
      /* Try authentication as root. */
      if (auth("root", prompt_timeout))
        break;
      else
        sleep(1);
    }
#endif

    auth_tries++;
  }

  /* Free timeouts memory. */
  free(wait_timeout);
  free(prompt_timeout);
}

void display_auth_tries(void)
{
  if (auth_tries > 0)
    fprintf(stderr, "%d failed authentication %s.\n", auth_tries, auth_tries > 1 ? "tries" : "try");
}

void log_program_end(void) {
	syslog(LOG_NOTICE,"vlock ended");
	closelog();
}

#ifdef USE_PLUGINS
static void call_end_hook(void)
{
  (void) plugin_hook("vlock_end");
}
#endif


static inline void printVersion(void)
{
        //printf(PACKAGE_STRING EOL);
}

static const struct option longopts[] =
{
#define NEED_ARG        required_argument
#define NO_ARG          no_argument
#define OPT_ARG         optional_argument
#define X(l,s,t,o)      { TO_STRING(l),o,NULL,TO_STRING(s)[0] },
                CMDLINE_OPTS_TABLE
#undef X
#undef NEED_ARG
#undef NO_ARG
#undef OPT_ARG
                { NULL, 0, NULL, 0 }
};

static inline void printHelp(const char *errorMsg)
{
#define X(l,s,t,o) "-" TO_STRING(s) ", --" TO_STRING(l) t EOL

#define USAGE "Usage: " TO_STRING(PROGNAME) " [OPTIONS]" EOL

   if (errorMsg != NULL) {
      fprintf(stderr, "Error %s" EOL USAGE CMDLINE_OPTS_TABLE, errorMsg);
   } else {
      fprintf(stdout, USAGE CMDLINE_OPTS_TABLE);
   }
#undef X
#undef USAGE
}

static int parse_cmdLine(int argc,char *const argv[])
{
#define NEED_ARG        ":"
#define NO_ARG          ""
#define OPT_ARG         "::"
#define X(l,s,t,o) TO_STRING(s) o

   int error = EXIT_SUCCESS;
   int optc;

      while (((optc = getopt_long(argc, argv, CMDLINE_OPTS_TABLE, longopts, NULL)) != -1)
            && (EXIT_SUCCESS == error)) {
         switch (optc) {
            case 'c':
               parameters.modes &= ~e_All;
               break;
            case 'a':
               parameters.modes |= e_All;
               break;
            case 'u':
               parameters.modes |= e_MultiUsers;
               break;
            case 'k':
              parameters.modes |= e_KeepScreen;
              break;
#ifdef USE_PLUGINS
		   case 'n':
			  parameters.modes |= e_NewVirtualConsole;
			  break;
		   case 's':
			  parameters.modes |= e_SysReq;
			  break;
#endif /* USE_PLUGINS */
           case 'h':
              printHelp(NULL);
              exit(EXIT_SUCCESS);
              break;
		   case 'v':
              printVersion();
              exit(EXIT_SUCCESS);
              break;
		   case '?':
              error = EINVAL;
              printHelp("");
              break;
           default:
              error = EINVAL;
              printHelp("invalid parameter");
              break;
         } /* switch */
      } /*while(((optc = getopt_long(argc,argv,"cln:phv",longopts,NULL))!= -1) && (EXIT_SUCCESS == error))*/
#undef X
#undef NEED_ARG
#undef NO_ARG
#undef OPT_ARG
      return error;
}

/* Lock the current terminal until proper authentication is received. */
int main(int argc, char *const argv[])
{
	int error = EXIT_SUCCESS;
  char *username = NULL;

  vlock_debug = (getenv("VLOCK_DEBUG") != NULL);

  error = parse_cmdLine(argc,argv);
  if (error != EXIT_SUCCESS) {
	  errno = error;
	  perror("vlock: invalid arguments\n");
	  exit(EXIT_FAILURE);
  }

  openlog("vlock",LOG_CONS|LOG_PID,LOG_AUTH);

  block_signals();

  if ((parameters.modes & e_MultiUsers) != e_MultiUsers) {
	  username = get_username();
	  if (username == NULL)
	      fatal_perror("vlock: could not get username");
  }

  ensure_atexit(log_program_end);
  ensure_atexit(display_auth_tries);

#ifdef USE_PLUGINS
  for (int i = 1; i < argc; i++) {
	  if (argv[i][0] != '-') {
	  		if (!load_plugin(argv[i]))
	  		      fatal_error("vlock: loading plugin '%s' failed: %s", argv[i], STRERROR);
	  	}
  }

  ensure_atexit(unload_plugins);

  if (!resolve_dependencies()) {
    if (errno == 0)
      exit(EXIT_FAILURE);
    else
      fatal_error("vlock: error resolving plugin dependencies: %s", STRERROR);
  }

  plugin_hook("vlock_start");
  ensure_atexit(call_end_hook);
#else /* !USE_PLUGINS */
  /* Emulate pseudo plugin "all". */
  if ((parameters.modes & e_All) != e_All) {
    if (!lock_console_switch()) {
      if (errno)
        perror("vlock: could not disable console switching");

      exit(EXIT_FAILURE);
    }

    ensure_atexit((void (*)(void))unlock_console_switch);
  } else if (argc > 1) {
    fatal_error("vlock: plugin support disabled");
  }
#endif /* !USE_PLUGINS */

  if (!isatty(STDIN_FILENO))
    fatal_error("vlock: stdin is not a terminal");

  secure_terminal();
  ensure_atexit(restore_terminal);

  auth_loop(username);

  free(username);

  return error;
}
