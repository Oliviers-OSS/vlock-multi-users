/*
 * cmdline_parameters.h
 *
 *  Created on: 11 juil. 2020
 *      Author: oc
 */
#define GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)

#if (GCC_VERSION > 40000) /* GCC 4.0.0 */
#pragma once
#endif /* GCC 4.0.0 */

#ifndef _CMDLINE_PARAMETERS_H_
#define _CMDLINE_PARAMETERS_H_

#include <getopt.h>

#define TIMEOUT_NOT_SET	(unsigned int)(-1)

#ifndef PROGNAME
#define PROGNAME "vlock"
#endif /* PROGNAME */

#ifndef TO_STRING
#define STRING(x) #x
#define TO_STRING(x) STRING(x)
#endif /* STRING */

#define MODE(m)  X(m)
#define MODE_TABLE \
		MODE(All) \
		MODE(MultiUsers) \
		MODE(NewVirtualConsole) \
		MODE(SysReq) \
		MODE(KeepScreen)

#define X(m)    ev_##m,
typedef enum ModeBitValue_ {
  MODE_TABLE
} ModeBitValue;
#undef X

#define X(m)    e_##m = 1<<ev_##m,
typedef enum ModeValue_ {
  MODE_TABLE
} ModeValue;
#undef X

#define EOL "\n"
#define NLT "\t"

#define O(l,s,t,o)      X(l,s,t,o)

#define CMDLINE_CMN_OPTS_TABLE \
                O(current,c," :lock only this virtual console, allowing user to" EOL NLT "switch to other virtual consoles.",NO_ARG) \
                O(all,a," :lock all virtual consoles by preventing other users" EOL NLT "from switching virtual consoles.",NO_ARG) \
                O(multi-user,u," :ask user name before password to allow unlock" EOL NLT "accountability on a generic user session",NO_ARG) \
                O(keep-screen,k," :don't clear the screen at startup",NO_ARG)


#ifdef USE_PLUGINS
#define CMDLINE_PLUGINS_OPTS_TABLE \
		O(new,n," allocate a new virtual console before locking," EOL NLT "implies --all.",NO_ARG) \
		O(disable-sysrq,s," disable SysRq while consoles are locked to" EOL NLT "prevent killing vlock with SAK.",NO_ARG) \
		O(timeout,t,"<seconds>: run screen saver plugins" EOL NLT "after the given amount of time.",NO_ARG)
#else /* USE_PLUGINS */
#define CMDLINE_PLUGINS_OPTS_TABLE
#endif /* USE_PLUGINS */

#define CMDLINE_OPTS_TABLE \
		CMDLINE_CMN_OPTS_TABLE \
		CMDLINE_PLUGINS_OPTS_TABLE \
		O(help,h,": Print this help message and exit.",NO_ARG) \
        O(version,v,": Print the version number of vlock and exit.",NEED_ARG)

typedef struct cmndline_parameters_ {
  unsigned int modes;
  unsigned int timeout;
} cmndline_parameters;


#endif /* _CMDLINE_PARAMETERS_H_ */
