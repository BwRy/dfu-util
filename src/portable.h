
#ifndef PORTABLE_H
#define PORTABLE_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#else
# define PACKAGE "dfu-util"
# define PACKAGE_VERSION "0.7-msvc"
# define PACKAGE_STRING "dfu-util 0.7-msvc"
# define PACKAGE_BUGREPORT "dfu-util@lists.gnumonks.org"
#endif

#ifdef HAVE_FTRUNCATE
# include <unistd.h>
#else
# include <io.h>
#endif /* HAVE_FTRUNCATE */

#ifdef HAVE_USLEEP
# include <unistd.h>
# define milli_sleep(msec) usleep(1000 * (msec))
#elif defined HAVE_WINDOWS_H
# define milli_sleep(msec) Sleep(msec)
#else
# error "Can't get no sleep! Please report"
#endif /* HAVE_USLEEP */

#endif /* PORTABLE_H */
