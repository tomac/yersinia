dnl
dnl Process this file with autoconf to produce a configure script.
dnl

AC_INIT(yersinia, 0.8.2, yersinia@yersinia.net)

AC_CONFIG_SRCDIR([src/yersinia.c])

AM_CONFIG_HEADER(src/config.h)

AC_CANONICAL_TARGET([])

AM_INIT_AUTOMAKE

AC_PROG_CC

if test -n "$GCC"; then
    CFLAGS="-Wall -Winvalid-source-encoding"
    supports_invalid_encoding=no

    AC_LANG_PUSH([C])
    AC_SUBST(CFLAGS)
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[int i=0;]])],
                                       [supports_invalid_encoding=yes],
                                       [supports_invalid_encoding=no] )
    AC_LANG_POP([C])

    if test $supports_invalid_encoding = yes; then
        CFLAGS="-O3 -Wall -g -D_DEFAULT_SOURCE -Wno-conversion -Wno-invalid-source-encoding"
    else
        CFLAGS="-O3 -Wall -g -D_DEFAULT_SOURCE"
    fi
else
     AC_MSG_WARN(Ouch!! Only gcc variants are supported...)
     AC_MSG_ERROR(...you're on your own.)
fi

AC_HEADER_STDC([])

AC_SUBST(CFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)

AC_PROG_INSTALL
AC_PATH_PROG(MAKEDEPEND, makedepend)

AC_LBL_UNALIGNED_ACCESS

dnl
dnl Check for libraries
dnl
AC_CHECK_LIB(socket,main)
AC_CHECK_LIB(resolv,main)
AC_CHECK_LIB(nsl,main)
AC_CHECK_LIB(rt,main)

dnl
dnl libpcap must be at least 0.8.x
dnl
AC_MSG_CHECKING(for a complete set of pcap headers)

possible_dirs="`eval echo -n ${includedir}` \
	       /usr/include /usr/include/pcap \
               /usr/local/include /usr/local/include/pcap \
               /usr/share/include /usr/share/include/pcap"

AC_ARG_WITH(pcap-includes,
[  --with-pcap-includes    specify the pcap include directory],
[PCAP_DIR=$withval],
[PCAP_DIR=$possible_dirs])

pcap_dir=""
for dir in $PCAP_DIR ; do 
    if test -d $dir -a -r "$dir/pcap-bpf.h" ; then 
       if test -n "$pcap_dir" -a "$pcap_dir" != "$dir"; then
          echo 
          echo; echo more than one set found in:
          echo  $pcap_dir 
          echo  $dir
          echo; echo please wipe out all unused pcap installations
          exit
       else 
          pcap_dir="$dir"
       fi
    fi
done

if test -z "$pcap_dir" ; then
   echo no; echo !!! couldn\'t find a complete set of pcap headers
   exit
else
   echo found $pcap_dir

   PCAP_INCLUDE="-I$pcap_dir"
   PCAP_LINK="-L`dirname $pcap_dir`/lib"

   AC_SUBST(PCAP_INCLUDE)
   AC_SUBST(PCAP_LINK)
  
fi

if test "$PCAP_LINK" != "-L/usr/lib" ; then
  LIBS="$LIBS $PCAP_LINK"
fi
if test "$PCAP_INCLUDE" !=  "-I/usr/include" ; then
  CFLAGS="$CFLAGS $PCAP_INCLUDE"
fi

AC_CHECK_LIB(pcap, pcap_lib_version, have_libpcap=yes, have_libpcap=no)

if test $have_libpcap = no; then
  AC_MSG_WARN(Ouch!! Libpcap (at least 0.8.x) library is needed in order to compile Yersinia!!...)
  AC_MSG_ERROR(...i'm sure you'll take the right decision.)
fi

AH_TEMPLATE([HAVE_PCAP_DUMP_FLUSH], [pcap_dump_flush])
AC_CHECK_LIB(pcap, pcap_dump_flush,AC_DEFINE(HAVE_PCAP_DUMP_FLUSH))
           
dnl Check for BSD's BPF
disable_bpf=no
have_bpf=no
AC_MSG_CHECKING(for BPF device sending support)
AC_TRY_RUN([
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>

int 
main(int argc, char *argv[]) {
	int fd;
	
	fd = open("/dev/bpf0", O_RDONLY, 0);
	
	/* if we opened it, we're good */
	if (fd > 1)
		exit(0);
		
	/* if we got EBUSY or permission denied it exists, so we're good */
	if (fd < 0 && (errno == EBUSY || errno == 13))
		exit(0);
		
	/* else suck, no good */
    exit(-1);
}],
	[
	if test $disable_bpf = no ; then
	    AC_DEFINE([HAVE_BPF], [1], 
	              [Do we have BPF device support?])
		AC_MSG_RESULT(yes)
		have_bpf=yes
	else
		AC_MSG_RESULT(no)
	fi
	])

dnl
dnl
dnl libnet must be at least 1.1.2
dnl
dnl
AC_MSG_CHECKING(for a complete set of libnet headers)

possible_dirs="`eval echo -n ${includedir}` \
	       /usr/include /usr/include/libnet \
               /usr/local/include /usr/local/include/libnet \
               /usr/share/include /usr/share/include/libnet"

possible_libnet_config_dirs="/usr /usr/local /opt"

AC_ARG_WITH(libnet-includes,
[  --with-libnet-includes  specify the libnet include directory],
[LIBNET_DIR=$withval LIBNET_CONFIG_DIR=$withval],
[LIBNET_DIR=$possible_dirs LIBNET_CONFIG_DIR=$possible_libnet_config_dirs])

libnet_dir=""
for dir in $LIBNET_DIR ; do 
    if test -d $dir -a -r "$dir/libnet.h" ; then 
       if test -n "$libnet_dir" -a "$libnet_dir" != "$dir"; then
          echo 
          echo; echo more than one set found in:
          echo  $libnet_dir 
          echo  $dir
          echo; echo please wipe out all unused libnet installations
          exit
       else 
          libnet_dir="$dir"
       fi
    fi
done

for dir in $LIBNET_CONFIG_DIR ; do
    if test -d $dir -a -r "$dir/bin/libnet-config" ; then
       libnet_config_dir="$dir/bin"
    fi
done

if test -z "$libnet_dir" ; then
   echo no; echo !!! couldn\'t find a complete set of libnet headers
   exit
else
   echo found $libnet_dir

dnl libnet headers are usually in /usr/include/libnet, so we need a ..
   LIBNET_INCLUDE="-I$libnet_dir"
   LIBNET_LINK="-L`dirname $libnet_dir`/lib"
   LIBNET_CONFIG="$libnet_config_dir/libnet-config"

   AC_SUBST(LIBNET_INCLUDE)
   AC_SUBST(LIBNET_LINK)
   AC_SUBST(LIBNET_CONFIG)
  
fi

if test "$LIBNET_LINK" != "-L/usr/lib" ; then
  LIBS="$LIBS $LIBNET_LINK"
fi
if test "$LIBNET_INCLUDE" !=  "-I/usr/include" ; then
  CFLAGS="$CFLAGS $LIBNET_INCLUDE"
fi

AC_CHECK_LIB(net, libnet_build_stp_conf, have_libnet=yes, have_libnet=no)
if test $have_libnet = no; then
  AC_MSG_WARN(Ouch!! Libnet library 1.1.2 is needed in order to compile Yersinia!!...)
  AC_MSG_ERROR(...i'm sure you'll take the right decision.)
fi

dnl AC_CHECK_HEADERS(libnet.h, have_libnet=yes,have_libnet=no)
dnl if test $have_libnet = no; then
dnl   AC_MSG_WARN(Ouch!! You need to install the libnet.h file in order to compile Yersinia!!...)
dnl   AC_MSG_ERROR(...i'm sure you'll take the right decision.)
dnl fi

AC_MSG_CHECKING(if libnet is at least version 1.1.2)
AC_TRY_RUN([
#include <stdlib.h>
#include <stdio.h>
#include <libnet.h>
#define HOPE_MAJOR  1
#define HOPE_MEDIUM 1
#define HOPE_MINOR  2
int main(void)
{
  unsigned int major,medium,minor,current, desired;
  desired = HOPE_MAJOR*10000 + HOPE_MEDIUM*100 + HOPE_MINOR;
  sscanf( LIBNET_VERSION, "%d.%d.%d", &major, &medium, &minor);
  current = major*10000 + medium*100 + minor;
  if ( current >= desired )
     exit(0);
  exit(1);
}],
[AC_MSG_RESULT(yes); have_libnet=yes],
[AC_MSG_RESULT(no); have_libnet=no],
[AC_MSG_RESULT(no); have_libnet=no])

if test $have_libnet = no; then
  AC_MSG_WARN(Ouch!! At least Libnet library version 1.1.2 is needed in order to compile Yersinia!!...)
  AC_MSG_ERROR(...i'm sure you'll take the right decision.)
fi



dnl
dnl Check headers
dnl
AC_CHECK_HEADERS(sys/sockio.h sys/ioctl.h net/if.h,,,
[[
#if HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
]])
AC_CHECK_HEADERS(bstring.h sys/time.h sys/param.h netinet/in_systm.h inttypes.h)
AC_CHECK_HEADERS(netinet/in_system.h sys/wait.h)

AC_HEADER_TIME

AC_C_BIGENDIAN


dnl
dnl sockaddr sa_len?
dnl
AH_TEMPLATE([HAVE_SOCKADDR_SA_LEN], [have sockaddr_sa_len])
AC_MSG_CHECKING([if struct sockaddr has sa_len field])
AC_TRY_COMPILE([#include <sys/types.h>
		#include <sys/socket.h>],
	        [struct sockaddr sa; sa.sa_len;],
        	[AC_MSG_RESULT(yes); AC_DEFINE(HAVE_SOCKADDR_SA_LEN)],
                [AC_MSG_RESULT(no);]
)


AH_TEMPLATE([PTHREAD_NEED_TESTCANCEL], [pthread need testcancel])
AH_TEMPLATE([STRANGE_BSD_BYTE], [strange bsd byte])
AH_TEMPLATE([HPUX], [HP-UX System])
AH_TEMPLATE([DARWIN], [Darwin System])
AH_TEMPLATE([OPENBSD], [OpenBSD System])
AH_TEMPLATE([NETBSD], [NetBSD System])
AH_TEMPLATE([FREEBSD], [FreeBSD System])
AH_TEMPLATE([SOLARIS_251], [Solaris 2.51 System])
AH_TEMPLATE([SOLARIS_26], [Solaris 2.6 System])
AH_TEMPLATE([SOLARIS_27], [Solaris 2.7 System])
AH_TEMPLATE([SOLARIS_28], [Solaris 2.8 System])
AH_TEMPLATE([SOLARIS_29], [Solaris 2.9 System])
AH_TEMPLATE([SOLARIS], [Solaris System])
AH_TEMPLATE([LINUX], [Linux System])
AH_TEMPLATE([LINUX_20], [Linux 2.0 System])
AH_TEMPLATE([LINUX_21], [Linux 2.1 System])
AH_TEMPLATE([LINUX_22], [Linux 2.2 System])
AH_TEMPLATE([LINUX_23], [Linux 2.3 System])
AH_TEMPLATE([LINUX_24], [Linux 2.4 System])
AH_TEMPLATE([LINUX_25], [Linux 2.5 System])
AH_TEMPLATE([LINUX_26], [Linux 2.6 System])
AH_TEMPLATE([NEED_USLEEP], [System need DoS timeout])
case "$target_os" in

   *linux*)
           AC_DEFINE(LINUX)
           AC_DEFINE(PTHREAD_NEED_TESTCANCEL)
           case "`uname -r`" in
                2.6*)
                   AC_DEFINE(LINUX_26)
                ;;
                2.5*)
                   AC_DEFINE(LINUX_25)
                ;;
                2.4*)
                   AC_DEFINE(LINUX_24)
                ;;
                2.3*)
                   AC_DEFINE(LINUX_23)
                ;;
                2.2*)
                   AC_DEFINE(LINUX_22)
                ;;
                2.1*)
                   AC_DEFINE(LINUX_21)
                ;;
                2.0*)
                   AC_DEFINE(LINUX_20)
                ;;
           esac
           ;;

   *solaris*)
           AC_DEFINE(SOLARIS)
           case "`uname -r`" in
                5.5.1)
                   AC_DEFINE(SOLARIS_251)
                ;;
                5.6*)
                   AC_DEFINE(SOLARIS_26)
                ;;
                5.7*)
                   AC_DEFINE(SOLARIS_27)
                ;;
                5.8*)
                   AC_DEFINE(SOLARIS_27)
                ;;
                5.9*)
                   AC_DEFINE(SOLARIS_27)
                ;;
           esac
           ;;

   *freebsd*)
           AC_DEFINE(FREEBSD)
           AC_DEFINE(STRANGE_BSD_BYTE)
           AC_DEFINE(NEED_USLEEP)
           ;;

   *netbsd*)
           AC_DEFINE(NETBSD)
           AC_DEFINE(STRANGE_BSD_BYTE)
           AC_DEFINE(NEED_USLEEP)
           ;;

   *openbsd*)
           AC_DEFINE(OPENBSD)
           AC_DEFINE(NEED_USLEEP)
           case "`uname -r`" in
                1.*)
                   AC_DEFINE(STRANGE_BSD_BYTE)
                ;;
                2.0*)
                   AC_DEFINE(STRANGE_BSD_BYTE)
                ;;
                2.*)

                ;;
                *)
                  AC_DEFINE(STRANGE_BSD_BYTE)
                ;;
           esac
           ;;
   
   *hpux*)
           AC_DEFINE(HPUX)
           ;;           
   *darwin*)
           AC_DEFINE(DARWIN)
           ;;

   *)
       AC_MSG_WARN(it seems that your OS is not supported)
       AC_MSG_WARN(and this may cause troubles)
       AC_MSG_WARN(please send bugs and diffs to yersinia@iwasnot.org)
    ;;

esac


dnl
dnl Check for library functions
dnl
AC_CHECK_FUNCS(memcpy memset pthread_setconcurrency strerror strtok_r rand_r)
AC_CHECK_FUNCS(calloc_r malloc_r free_r ctime_r nanosleep)
AC_CHECK_FUNCS(strerror_r, have_strerror_r=yes,have_strerror_r=no)

if test $have_strerror_r = yes; then
AC_MSG_CHECKING(if strerror_r is on glibc version >= 2.0)
AC_TRY_RUN([
#include <stdlib.h>
#include <features.h>
int main(void)
{
#if defined(__GLIBC__) && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 0
   exit(0);
#else
   exit(1);
#endif
}],
[AC_MSG_RESULT(yes); have_glibc=yes],
[AC_MSG_RESULT(no); have_glibc=no],
[AC_MSG_RESULT(no); have_glibc=no])

AH_TEMPLATE([HAVE_GLIBC_STRERROR_R], [have glibc strerror_r])
if test $have_glibc = yes; then
  AC_DEFINE(HAVE_GLIBC_STRERROR_R)
fi

fi

dnl
dnl Check for pthreads
dnl

AC_CHECK_HEADERS(semaphore.h)
AC_CHECK_HEADERS(sched.h sys/sched.h)
AC_CHECK_HEADERS(pthread.h)

AC_CHECK_LIB(pthread, pthread_create, , [
   AC_CHECK_LIB(pthreads, pthread_create, , [
      AC_CHECK_LIB(c_r, pthread_create)
   ])
])

AC_MSG_CHECKING([for pthreads support])
   if test ".${ac_cv_header_pthread_h}"             != ".yes" ||
      (test ".${ac_cv_lib_pthread_pthread_create}"  != ".yes" &&
       test ".${ac_cv_lib_pthreads_pthread_create}" != ".yes" &&
       test ".${ac_cv_lib_c_r_pthread_create}"      != ".yes"); then
       AC_MSG_RESULT(error)
       AC_MSG_WARN(error)
       AC_MSG_WARN(***********************************************)
       AC_MSG_WARN(* PTHREADS is NOT available on your system !! *)
       AC_MSG_WARN(***********************************************)
   else
       AC_MSG_RESULT(ok)
   fi



dnl
dnl Check for remote admin
dnl
AC_ARG_ENABLE(admin, [  --disable-admin         disable remote admin interface],,enable_admin=true)
AH_TEMPLATE([HAVE_REMOTE_ADMIN], [remote admin support])
AM_CONDITIONAL(HAVE_REMOTE_ADMIN, test $enable_admin = true)

if test "$enable_admin" = "true"; then
     AC_DEFINE(HAVE_REMOTE_ADMIN)
fi


dnl Curses detection: Munged from Midnight Commander's configure.in
dnl
dnl What it does:
dnl =============
dnl
dnl - Determine which version of curses is installed on your system
dnl   and set the -I/-L/-l compiler entries and add a few preprocessor
dnl   symbols 
dnl - Do an AC_SUBST on the CURSES_INCLUDEDIR and CURSES_LIBS so that
dnl   @CURSES_INCLUDEDIR@ and @CURSES_LIBS@ will be available in
dnl   Makefile.in's
dnl - Modify the following configure variables (these are the only
dnl   curses.m4 variables you can access from within configure.in)
dnl   CURSES_INCLUDEDIR - contains -I's and possibly -DRENAMED_CURSES if
dnl                       an ncurses.h that's been renamed to curses.h
dnl                       is found.
dnl   CURSES_LIBS       - sets -L and -l's appropriately
dnl   CFLAGS            - if --with-sco, add -D_SVID3 
dnl   has_curses        - exports result of tests to rest of configure
dnl
dnl Usage:
dnl ======
dnl 1) Add lines indicated below to acconfig.h
dnl 2) call AC_CHECK_CURSES after AC_PROG_CC in your configure.in
dnl 3) Instead of #include <curses.h> you should use the following to
dnl    properly locate ncurses or curses header file
dnl
dnl    #if defined(USE_NCURSES) && !defined(RENAMED_NCURSES)
dnl    #include <ncurses.h>
dnl    #else
dnl    #include <curses.h>
dnl    #endif
dnl
dnl 4) Make sure to add @CURSES_INCLUDEDIR@ to your preprocessor flags
dnl 5) Make sure to add @CURSES_LIBS@ to your linker flags or LIBS
dnl
dnl Notes with automake:
dnl - call AM_CONDITIONAL(HAS_CURSES, test "$has_curses" = true) from
dnl   configure.in
dnl - your Makefile.am can look something like this
dnl   -----------------------------------------------
dnl   INCLUDES= blah blah blah $(CURSES_INCLUDEDIR) 
dnl   if HAS_CURSES
dnl   CURSES_TARGETS=name_of_curses_prog
dnl   endif
dnl   bin_PROGRAMS = other_programs $(CURSES_TARGETS)
dnl   other_programs_SOURCES = blah blah blah
dnl   name_of_curses_prog_SOURCES = blah blah blah
dnl   other_programs_LDADD = blah
dnl   name_of_curses_prog_LDADD = blah $(CURSES_LIBS)
dnl   -----------------------------------------------
dnl
dnl
dnl The following lines should be added to acconfig.h:
dnl ==================================================
dnl
dnl /*=== Curses version detection defines ===*/
dnl /* Found some version of curses that we're going to use */
dnl #undef HAS_CURSES
dnl    
dnl /* Use SunOS SysV curses? */
dnl #undef USE_SUNOS_CURSES
dnl 
dnl /* Use old BSD curses - not used right now */
dnl #undef USE_BSD_CURSES
dnl 
dnl /* Use SystemV curses? */
dnl #undef USE_SYSV_CURSES
dnl 
dnl /* Use Ncurses? */
dnl #undef USE_NCURSES
dnl 
dnl /* If you Curses does not have color define this one */
dnl #undef NO_COLOR_CURSES
dnl 
dnl /* Define if you want to turn on SCO-specific code */
dnl #undef SCO_FLAVOR
dnl 
dnl /* Set to reflect version of ncurses *
dnl  *   0 = version 1.*
dnl  *   1 = version 1.9.9g
dnl  *   2 = version 4.0/4.1 */
dnl #undef NCURSES_970530
dnl
dnl /*=== End new stuff for acconfig.h ===*/
dnl 

AH_TEMPLATE([HAS_CURSES], [curses supported])
AH_TEMPLATE([USE_SUNOS_CURSES], [SunOS curses])
AH_TEMPLATE([USE_BSD_CURSES], [BSD curses])
AH_TEMPLATE([USE_SYSV_CURSES], [SysV curses])
AH_TEMPLATE([USE_NCURSES], [ncurses])
AH_TEMPLATE([NO_COLOR_CURSES], [no color supported])
AH_TEMPLATE([SCO_FLAVOR], [SCO code])
AH_TEMPLATE([NCURSES_970530], [ncurses version])

AC_DEFUN([AC_CHECK_CURSES],[
	search_ncurses=true
	screen_manager=""
	has_curses=false

	CFLAGS=${CFLAGS--O}

	AC_SUBST(CURSES_LIBS)
	AC_SUBST(CURSES_INCLUDEDIR)

	AC_ARG_WITH(sco,
	  [  --with-sco              Use this to turn on SCO-specific code],[
	  if test x$withval = xyes; then
		AC_DEFINE(SCO_FLAVOR)
		CFLAGS="$CFLAGS -D_SVID3"
	  fi
	])

	AC_ARG_WITH(sunos-curses,
	  [  --with-sunos-curses     Used to force SunOS 4.x curses],[
	  if test x$withval = xyes; then
		AC_USE_SUNOS_CURSES
	  fi
	])

	AC_ARG_WITH(osf1-curses,
	  [  --with-osf1-curses      Used to force OSF/1 curses],[
	  if test x$withval = xyes; then
		AC_USE_OSF1_CURSES
	  fi
	])

	AC_ARG_WITH(vcurses,
	  [  --with-vcurses[=incdir]   Used to force SysV curses],
	  if test x$withval != xyes; then
		CURSES_INCLUDEDIR="-I$withval"
	  fi
	  AC_USE_SYSV_CURSES
	)

	AC_ARG_WITH(ncurses,
	  [  --with-ncurses[=dir]      Compile with ncurses/locate base dir],
	  if test x$withval = xno ; then
		search_ncurses=false
	  elif test x$withval != xyes ; then
		CURSES_LIBS="$LIBS -L$withval/lib -lncurses"
		CURSES_INCLUDEDIR="-I$withval/include"
		search_ncurses=false
		screen_manager="ncurses"
		AC_DEFINE(USE_NCURSES)
		AC_DEFINE(HAS_CURSES)
		has_curses=true
	  fi
	)

	if $search_ncurses
	then
		AC_SEARCH_NCURSES()
	fi


])


AC_DEFUN([AC_USE_SUNOS_CURSES], [
	search_ncurses=false
	screen_manager="SunOS 4.x /usr/5include curses"
	AC_MSG_RESULT(Using SunOS 4.x /usr/5include curses)
	AC_DEFINE(USE_SUNOS_CURSES)
	AC_DEFINE(HAS_CURSES)
	has_curses=true
	AC_DEFINE(NO_COLOR_CURSES)
	AC_DEFINE(USE_SYSV_CURSES)
	CURSES_INCLUDEDIR="-I/usr/5include"
	CURSES_LIBS="/usr/5lib/libcurses.a /usr/5lib/libtermcap.a"
	AC_MSG_RESULT(Please note that some screen refreshs may fail)
])

AC_DEFUN([AC_USE_OSF1_CURSES], [
       AC_MSG_RESULT(Using OSF1 curses)
       search_ncurses=false
       screen_manager="OSF1 curses"
       AC_DEFINE(HAS_CURSES)
       has_curses=true
       AC_DEFINE(NO_COLOR_CURSES)
       AC_DEFINE(USE_SYSV_CURSES)
       CURSES_LIBS="-lcurses"
])

AC_DEFUN([AC_USE_SYSV_CURSES], [
	AC_MSG_RESULT(Using SysV curses)
	AC_DEFINE(HAS_CURSES)
	has_curses=true
	AC_DEFINE(USE_SYSV_CURSES)
	search_ncurses=false
	screen_manager="SysV/curses"
	CURSES_LIBS="-lcurses"
])

dnl AC_ARG_WITH(bsd-curses,
dnl [--with-bsd-curses         Used to compile with bsd curses, not very fancy],
dnl 	search_ncurses=false
dnl	screen_manager="Ultrix/cursesX"
dnl	if test $system = ULTRIX
dnl	then
dnl	    THIS_CURSES=cursesX
dnl        else
dnl	    THIS_CURSES=curses
dnl	fi
dnl
dnl	CURSES_LIBS="-l$THIS_CURSES -ltermcap"
dnl	AC_DEFINE(HAS_CURSES)
dnl	has_curses=true
dnl	AC_DEFINE(USE_BSD_CURSES)
dnl	AC_MSG_RESULT(Please note that some screen refreshs may fail)
dnl	AC_WARN(Use of the bsdcurses extension has some)
dnl	AC_WARN(display/input problems.)
dnl	AC_WARN(Reconsider using xcurses)
dnl)

	
dnl
dnl Parameters: directory filename cureses_LIBS curses_INCLUDEDIR nicename
dnl
AC_DEFUN([AC_NCURSES], [
    if $search_ncurses
    then
        if test -f $1/$2
	then
	    AC_MSG_RESULT(Found ncurses on $1/$2)
 	    CURSES_LIBS="$3"
	    CURSES_INCLUDEDIR="$4"
	    search_ncurses=false
	    screen_manager=$5
            AC_DEFINE(HAS_CURSES)
            has_curses=true
	    AC_DEFINE(USE_NCURSES)
	fi
    fi
])

AC_DEFUN([AC_SEARCH_NCURSES], [
    AC_CHECKING("location of ncurses.h file")

    AC_NCURSES(/usr/include, ncurses.h, -lncurses,, "ncurses on /usr/include")
    AC_NCURSES(/usr/include/ncurses, ncurses.h, -lncurses, -I/usr/include/ncurses, "ncurses on /usr/include/ncurses")
    AC_NCURSES(/usr/local/include, ncurses.h, -L/usr/local/lib -lncurses, -I/usr/local/include, "ncurses on /usr/local")
    AC_NCURSES(/usr/local/include/ncurses, ncurses.h, -L/usr/local/lib -L/usr/local/lib/ncurses -lncurses, -I/usr/local/include/ncurses, "ncurses on /usr/local/include/ncurses")

    AC_NCURSES(/usr/local/include/ncurses, curses.h, -L/usr/local/lib -lncurses, -I/usr/local/include/ncurses -DRENAMED_NCURSES, "renamed ncurses on /usr/local/.../ncurses")

    AC_NCURSES(/usr/include/ncurses, curses.h, -lncurses, -I/usr/include/ncurses -DRENAMED_NCURSES, "renamed ncurses on /usr/include/ncurses")

    dnl
    dnl We couldn't find ncurses, try SysV curses
    dnl
    if $search_ncurses 
    then
        AC_EGREP_HEADER(init_color, /usr/include/curses.h,
	    AC_USE_SYSV_CURSES)
	AC_EGREP_CPP(USE_NCURSES,[
#include <curses.h>
#ifdef __NCURSES_H
#undef USE_NCURSES
USE_NCURSES
#endif
],[
	CURSES_INCLUDEDIR="$CURSES_INCLUDEDIR -DRENAMED_NCURSES"
        AC_DEFINE(HAS_CURSES)
	has_curses=true
        AC_DEFINE(USE_NCURSES)
        search_ncurses=false
        screen_manager="ncurses installed as curses"
])
    fi

    dnl
    dnl Try SunOS 4.x /usr/5{lib,include} ncurses
    dnl The flags USE_SUNOS_CURSES, USE_BSD_CURSES and BUGGY_CURSES
    dnl should be replaced by a more fine grained selection routine
    dnl
    if $search_ncurses
    then
	if test -f /usr/5include/curses.h
	then
	    AC_USE_SUNOS_CURSES
        fi
    else
        # check for ncurses version, to properly ifdef mouse-fix
	AC_MSG_CHECKING(for ncurses version)
	ncurses_version=unknown
cat > conftest.$ac_ext <<EOF
[#]line __oline__ "configure"
#include "confdefs.h"
#ifdef RENAMED_NCURSES
#include <curses.h>
#else
#include <ncurses.h>
#endif
#undef VERSION
VERSION:NCURSES_VERSION
EOF
        if (eval "$ac_cpp conftest.$ac_ext") 2>&AC_FD_CC |
  egrep "VERSION:" >conftest.out 2>&1; then
changequote(,)dnl
            ncurses_version=`cat conftest.out|sed -e 's/^[^"]*"//' -e 's/".*//'`
changequote([,])dnl
	fi
	rm -rf conftest*
        AC_MSG_RESULT($ncurses_version)
	case "$ncurses_version" in
changequote(,)dnl
	4.[01])
changequote([,])dnl
            AC_DEFINE(NCURSES_970530,2)
            ;;
	1.9.9g)
            AC_DEFINE(NCURSES_970530,1)
            ;;
	1*)
            AC_DEFINE(NCURSES_970530,0)
            ;;
	esac
    fi
])


AC_CHECK_CURSES
AM_CONDITIONAL(HAS_CURSES, test "$has_curses" = true)

if test "$has_curses" = "true"; then
    AC_CHECK_HEADERS(panel.h)
    AC_CHECK_LIB(ncurses, use_default_colors, [AC_DEFINE(HAVE_NCURSES_USE_DEFAULTS_COLORS,1,[Define to 1 if have use_default_colors])])
    AC_CHECK_LIB(ncurses, resize_term, [AC_DEFINE(HAVE_NCURSES_RESIZETERM,1,[Define to 1 if have resizeterm])])
    AC_CHECK_LIB(ncurses, wresize, [AC_DEFINE(HAVE_NCURSES_WRESIZE,1,[Define to 1 if have wresize])])
fi

dnl
dnl GTK Interface checks
dnl

dnl AC_ARG_ENABLE(gtk, [  --without-gtk              disable gtk 2.0 interface],,enable_gtk=true)
dnl AH_TEMPLATE([HAVE_GTK], [gtk interface support])
dnl AM_CONDITIONAL(HAVE_GTK, test "$enable_gtk" = true)


AC_ARG_ENABLE(gtk, AC_HELP_STRING([--disable-gtk], [Disable gtk 2.0 interface]), [use_gtk=$enableval], [use_gtk=yes])

AH_TEMPLATE([HAVE_GTK], [gtk interface support])
AM_CONDITIONAL(HAVE_GTK, test $use_gtk = yes)

if test $use_gtk = yes; then
     AC_DEFINE(HAVE_GTK)
     pkg_modules="gtk+-2.0 >= 2.6.0"
     PKG_CHECK_MODULES(PACKAGE, [$pkg_modules])
     AC_SUBST(PACKAGE_CFLAGS)
     AC_SUBST(PACKAGE_LIBS)
     GETTEXT_PACKAGE=yersinia
     AC_SUBST(GETTEXT_PACKAGE)
     AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE", [Gettext package.])
dnl Add the languages which your application supports here.
     ALL_LINGUAS=""
     AM_GLIB_GNU_GETTEXT
fi

AH_TEMPLATE([INFO_KERN], "Kernel name")
AH_TEMPLATE([INFO_KERN_VER], "Kernel version")
AH_TEMPLATE([INFO_PLATFORM], "Platform architecture")
AH_TEMPLATE([INFO_DATE], "Building date")

info_date="`date '+%a %d-%b-%Y %H:%M'`"
info_kern="`uname -s`"
info_kern_ver="`uname -r`"
info_platform="`uname -m`"

AC_DEFINE_UNQUOTED(INFO_KERN, "$info_kern")
AC_DEFINE_UNQUOTED(INFO_KERN_VER, "$info_kern_ver")
AC_DEFINE_UNQUOTED(INFO_PLATFORM, "$info_platform")
AC_DEFINE_UNQUOTED(INFO_DATE, "$info_date")

dnl
dnl Build Makefile.
dnl
dnl AC_CONFIG_FILES([Makefile])
AC_OUTPUT(Makefile src/Makefile)

echo ""
echo " Yersinia, our beloved one, has been configured with the following options."
echo "                         Remote admin : $enable_admin"
echo "                          Use ncurses : $has_curses"
echo "                              Use gtk : $use_gtk"
echo ""
