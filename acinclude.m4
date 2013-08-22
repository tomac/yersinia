dnl
dnl Copyright (c) 1995, 1996, 1997, 1998
dnl The Regents of the University of California.  All rights reserved.
dnl
dnl Redistribution and use in source and binary forms, with or without
dnl modification, are permitted provided that: (1) source code distributions
dnl retain the above copyright notice and this paragraph in its entirety, (2)
dnl distributions including binary code include the above copyright notice and
dnl this paragraph in its entirety in the documentation or other materials
dnl provided with the distribution, and (3) all advertising materials mentioning
dnl features or use of this software display the following acknowledgement:
dnl ``This product includes software developed by the University of California,
dnl Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
dnl the University nor the names of its contributors may be used to endorse
dnl or promote products derived from this software without specific prior
dnl written permission.
dnl THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
dnl WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
dnl MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
dnl
dnl LBL autoconf macros
dnl

dnl
dnl Checks to see if unaligned memory accesses fail
dnl
dnl usage:
dnl
dnl AC_LBL_UNALIGNED_ACCESS
dnl
dnl results:
dnl
dnl LBL_ALIGN (DEFINED)
dnl

AC_DEFUN([AC_LBL_UNALIGNED_ACCESS],
    [AC_MSG_CHECKING(if unaligned accesses fail)
    AC_CACHE_VAL(ac_cv_lbl_unaligned_fail,
    [case "$host_cpu" in

    #
    # These are CPU types where:
    #
    #   the CPU faults on an unaligned access, but at least some
    #   OSes that support that CPU catch the fault and simulate
    #   the unaligned access (e.g., Alpha/{Digital,Tru64} UNIX) -
    #   the simulation is slow, so we don't want to use it;
    #
    #   the CPU, I infer (from the old
    #
    # XXX: should also check that they don't do weird things (like on arm)
    #
    #   comment) doesn't fault on unaligned accesses, but doesn't
    #   do a normal unaligned fetch, either (e.g., presumably, ARM);
    #
    #   for whatever reason, the test program doesn't work
    #   (this has been claimed to be the case for several of those
    #   CPUs - I don't know what the problem is; the problem
    #   was reported as "the test program dumps core" for SuperH,
    #   but that's what the test program is *supposed* to do -
    #   it dumps core before it writes anything, so the test
    #   for an empty output file should find an empty output
    #   file and conclude that unaligned accesses don't work).
    #
    # This run-time test won't work if you're cross-compiling, so
    # in order to support cross-compiling for a particular CPU,
    # we have to wire in the list of CPU types anyway, as far as
    # I know, so perhaps we should just have a set of CPUs on
    # which we know it doesn't work, a set of CPUs on which we
    # know it does work, and have the script just fail on other
    # cpu types and update it when such a failure occurs.
    #
    alpha*|arm*|bfin*|hp*|mips*|sh*|sparc*|ia64|nv1)
        ac_cv_lbl_unaligned_fail=yes
        ;;

    *)
        cat >conftest.c <<EOF
#       include <sys/types.h>
#       include <sys/wait.h>
#       include <stdio.h>
        unsigned char a[[5]] = { 1, 2, 3, 4, 5 };
        main() {
        unsigned int i;
        pid_t pid;
        int status;
        /* avoid "core dumped" message */
        pid = fork();
        if (pid <  0)
            exit(2);
        if (pid > 0) {
            /* parent */
            pid = waitpid(pid, &status, 0);
            if (pid < 0)
                exit(3);
            exit(!WIFEXITED(status));
        }
        /* child */
        i = *(unsigned int *)&a[[1]];
        printf("%d\n", i);
        exit(0);
        }
EOF
        ${CC-cc} -o conftest $CFLAGS $CPPFLAGS $LDFLAGS \
            conftest.c $LIBS >/dev/null 2>&1
        if test ! -x conftest ; then
            dnl failed to compile for some reason
            ac_cv_lbl_unaligned_fail=yes
        else
            ./conftest >conftest.out
            if test ! -s conftest.out ; then
                ac_cv_lbl_unaligned_fail=yes
            else
                ac_cv_lbl_unaligned_fail=no
            fi
        fi
        rm -f -r conftest* core core.conftest
        ;;
    esac])
    AC_MSG_RESULT($ac_cv_lbl_unaligned_fail)
    if test $ac_cv_lbl_unaligned_fail = yes ; then
        AC_DEFINE(LBL_ALIGN,1,[if unaligned access fails])
    fi])

