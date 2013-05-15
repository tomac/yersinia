# generated automatically by aclocal 1.7.9 -*- Autoconf -*-

# Copyright (C) 1996, 1997, 1998, 1999, 2000, 2001, 2002
# Free Software Foundation, Inc.
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.

# Like AC_CONFIG_HEADER, but automatically create stamp file. -*- Autoconf -*-

# Copyright 1996, 1997, 2000, 2001 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

AC_PREREQ([2.52])

# serial 6

# AM_CONFIG_HEADER is obsolete.  It has been replaced by AC_CONFIG_HEADERS.
AU_DEFUN([AM_CONFIG_HEADER], [AC_CONFIG_HEADERS($@)])

# Do all the work for Automake.                            -*- Autoconf -*-

# This macro actually does too much some checks are only needed if
# your package does certain things.  But this isn't really a big deal.

# Copyright (C) 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003
# Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 10

AC_PREREQ([2.54])

# Autoconf 2.50 wants to disallow AM_ names.  We explicitly allow
# the ones we care about.
m4_pattern_allow([^AM_[A-Z]+FLAGS$])dnl

# AM_INIT_AUTOMAKE(PACKAGE, VERSION, [NO-DEFINE])
# AM_INIT_AUTOMAKE([OPTIONS])
# -----------------------------------------------
# The call with PACKAGE and VERSION arguments is the old style
# call (pre autoconf-2.50), which is being phased out.  PACKAGE
# and VERSION should now be passed to AC_INIT and removed from
# the call to AM_INIT_AUTOMAKE.
# We support both call styles for the transition.  After
# the next Automake release, Autoconf can make the AC_INIT
# arguments mandatory, and then we can depend on a new Autoconf
# release and drop the old call support.
AC_DEFUN([AM_INIT_AUTOMAKE],
[AC_REQUIRE([AM_SET_CURRENT_AUTOMAKE_VERSION])dnl
 AC_REQUIRE([AC_PROG_INSTALL])dnl
# test to see if srcdir already configured
if test "`cd $srcdir && pwd`" != "`pwd`" &&
   test -f $srcdir/config.status; then
  AC_MSG_ERROR([source directory already configured; run "make distclean" there first])
fi

# test whether we have cygpath
if test -z "$CYGPATH_W"; then
  if (cygpath --version) >/dev/null 2>/dev/null; then
    CYGPATH_W='cygpath -w'
  else
    CYGPATH_W=echo
  fi
fi
AC_SUBST([CYGPATH_W])

# Define the identity of the package.
dnl Distinguish between old-style and new-style calls.
m4_ifval([$2],
[m4_ifval([$3], [_AM_SET_OPTION([no-define])])dnl
 AC_SUBST([PACKAGE], [$1])dnl
 AC_SUBST([VERSION], [$2])],
[_AM_SET_OPTIONS([$1])dnl
 AC_SUBST([PACKAGE], ['AC_PACKAGE_TARNAME'])dnl
 AC_SUBST([VERSION], ['AC_PACKAGE_VERSION'])])dnl

_AM_IF_OPTION([no-define],,
[AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of package])
 AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version number of package])])dnl

# Some tools Automake needs.
AC_REQUIRE([AM_SANITY_CHECK])dnl
AC_REQUIRE([AC_ARG_PROGRAM])dnl
AM_MISSING_PROG(ACLOCAL, aclocal-${am__api_version})
AM_MISSING_PROG(AUTOCONF, autoconf)
AM_MISSING_PROG(AUTOMAKE, automake-${am__api_version})
AM_MISSING_PROG(AUTOHEADER, autoheader)
AM_MISSING_PROG(MAKEINFO, makeinfo)
AM_MISSING_PROG(AMTAR, tar)
AM_PROG_INSTALL_SH
AM_PROG_INSTALL_STRIP
# We need awk for the "check" target.  The system "awk" is bad on
# some platforms.
AC_REQUIRE([AC_PROG_AWK])dnl
AC_REQUIRE([AC_PROG_MAKE_SET])dnl
AC_REQUIRE([AM_SET_LEADING_DOT])dnl

_AM_IF_OPTION([no-dependencies],,
[AC_PROVIDE_IFELSE([AC_PROG_CC],
                  [_AM_DEPENDENCIES(CC)],
                  [define([AC_PROG_CC],
                          defn([AC_PROG_CC])[_AM_DEPENDENCIES(CC)])])dnl
AC_PROVIDE_IFELSE([AC_PROG_CXX],
                  [_AM_DEPENDENCIES(CXX)],
                  [define([AC_PROG_CXX],
                          defn([AC_PROG_CXX])[_AM_DEPENDENCIES(CXX)])])dnl
])
])


# When config.status generates a header, we must update the stamp-h file.
# This file resides in the same directory as the config header
# that is generated.  The stamp files are numbered to have different names.

# Autoconf calls _AC_AM_CONFIG_HEADER_HOOK (when defined) in the
# loop where config.status creates the headers, so we can generate
# our stamp files there.
AC_DEFUN([_AC_AM_CONFIG_HEADER_HOOK],
[# Compute $1's index in $config_headers.
_am_stamp_count=1
for _am_header in $config_headers :; do
  case $_am_header in
    $1 | $1:* )
      break ;;
    * )
      _am_stamp_count=`expr $_am_stamp_count + 1` ;;
  esac
done
echo "timestamp for $1" >`AS_DIRNAME([$1])`/stamp-h[]$_am_stamp_count])

# Copyright 2002  Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA

# AM_AUTOMAKE_VERSION(VERSION)
# ----------------------------
# Automake X.Y traces this macro to ensure aclocal.m4 has been
# generated from the m4 files accompanying Automake X.Y.
AC_DEFUN([AM_AUTOMAKE_VERSION],[am__api_version="1.7"])

# AM_SET_CURRENT_AUTOMAKE_VERSION
# -------------------------------
# Call AM_AUTOMAKE_VERSION so it can be traced.
# This function is AC_REQUIREd by AC_INIT_AUTOMAKE.
AC_DEFUN([AM_SET_CURRENT_AUTOMAKE_VERSION],
	 [AM_AUTOMAKE_VERSION([1.7.9])])

# Helper functions for option handling.                    -*- Autoconf -*-

# Copyright 2001, 2002  Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 2

# _AM_MANGLE_OPTION(NAME)
# -----------------------
AC_DEFUN([_AM_MANGLE_OPTION],
[[_AM_OPTION_]m4_bpatsubst($1, [[^a-zA-Z0-9_]], [_])])

# _AM_SET_OPTION(NAME)
# ------------------------------
# Set option NAME.  Presently that only means defining a flag for this option.
AC_DEFUN([_AM_SET_OPTION],
[m4_define(_AM_MANGLE_OPTION([$1]), 1)])

# _AM_SET_OPTIONS(OPTIONS)
# ----------------------------------
# OPTIONS is a space-separated list of Automake options.
AC_DEFUN([_AM_SET_OPTIONS],
[AC_FOREACH([_AM_Option], [$1], [_AM_SET_OPTION(_AM_Option)])])

# _AM_IF_OPTION(OPTION, IF-SET, [IF-NOT-SET])
# -------------------------------------------
# Execute IF-SET if OPTION is set, IF-NOT-SET otherwise.
AC_DEFUN([_AM_IF_OPTION],
[m4_ifset(_AM_MANGLE_OPTION([$1]), [$2], [$3])])

#
# Check to make sure that the build environment is sane.
#

# Copyright 1996, 1997, 2000, 2001 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 3

# AM_SANITY_CHECK
# ---------------
AC_DEFUN([AM_SANITY_CHECK],
[AC_MSG_CHECKING([whether build environment is sane])
# Just in case
sleep 1
echo timestamp > conftest.file
# Do `set' in a subshell so we don't clobber the current shell's
# arguments.  Must try -L first in case configure is actually a
# symlink; some systems play weird games with the mod time of symlinks
# (eg FreeBSD returns the mod time of the symlink's containing
# directory).
if (
   set X `ls -Lt $srcdir/configure conftest.file 2> /dev/null`
   if test "$[*]" = "X"; then
      # -L didn't work.
      set X `ls -t $srcdir/configure conftest.file`
   fi
   rm -f conftest.file
   if test "$[*]" != "X $srcdir/configure conftest.file" \
      && test "$[*]" != "X conftest.file $srcdir/configure"; then

      # If neither matched, then we have a broken ls.  This can happen
      # if, for instance, CONFIG_SHELL is bash and it inherits a
      # broken ls alias from the environment.  This has actually
      # happened.  Such a system could not be considered "sane".
      AC_MSG_ERROR([ls -t appears to fail.  Make sure there is not a broken
alias in your environment])
   fi

   test "$[2]" = conftest.file
   )
then
   # Ok.
   :
else
   AC_MSG_ERROR([newly created file is older than distributed files!
Check your system clock])
fi
AC_MSG_RESULT(yes)])

#  -*- Autoconf -*-


# Copyright 1997, 1999, 2000, 2001 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 3

# AM_MISSING_PROG(NAME, PROGRAM)
# ------------------------------
AC_DEFUN([AM_MISSING_PROG],
[AC_REQUIRE([AM_MISSING_HAS_RUN])
$1=${$1-"${am_missing_run}$2"}
AC_SUBST($1)])


# AM_MISSING_HAS_RUN
# ------------------
# Define MISSING if not defined so far and test if it supports --run.
# If it does, set am_missing_run to use it, otherwise, to nothing.
AC_DEFUN([AM_MISSING_HAS_RUN],
[AC_REQUIRE([AM_AUX_DIR_EXPAND])dnl
test x"${MISSING+set}" = xset || MISSING="\${SHELL} $am_aux_dir/missing"
# Use eval to expand $SHELL
if eval "$MISSING --run true"; then
  am_missing_run="$MISSING --run "
else
  am_missing_run=
  AC_MSG_WARN([`missing' script is too old or missing])
fi
])

# AM_AUX_DIR_EXPAND

# Copyright 2001 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# For projects using AC_CONFIG_AUX_DIR([foo]), Autoconf sets
# $ac_aux_dir to `$srcdir/foo'.  In other projects, it is set to
# `$srcdir', `$srcdir/..', or `$srcdir/../..'.
#
# Of course, Automake must honor this variable whenever it calls a
# tool from the auxiliary directory.  The problem is that $srcdir (and
# therefore $ac_aux_dir as well) can be either absolute or relative,
# depending on how configure is run.  This is pretty annoying, since
# it makes $ac_aux_dir quite unusable in subdirectories: in the top
# source directory, any form will work fine, but in subdirectories a
# relative path needs to be adjusted first.
#
# $ac_aux_dir/missing
#    fails when called from a subdirectory if $ac_aux_dir is relative
# $top_srcdir/$ac_aux_dir/missing
#    fails if $ac_aux_dir is absolute,
#    fails when called from a subdirectory in a VPATH build with
#          a relative $ac_aux_dir
#
# The reason of the latter failure is that $top_srcdir and $ac_aux_dir
# are both prefixed by $srcdir.  In an in-source build this is usually
# harmless because $srcdir is `.', but things will broke when you
# start a VPATH build or use an absolute $srcdir.
#
# So we could use something similar to $top_srcdir/$ac_aux_dir/missing,
# iff we strip the leading $srcdir from $ac_aux_dir.  That would be:
#   am_aux_dir='\$(top_srcdir)/'`expr "$ac_aux_dir" : "$srcdir//*\(.*\)"`
# and then we would define $MISSING as
#   MISSING="\${SHELL} $am_aux_dir/missing"
# This will work as long as MISSING is not called from configure, because
# unfortunately $(top_srcdir) has no meaning in configure.
# However there are other variables, like CC, which are often used in
# configure, and could therefore not use this "fixed" $ac_aux_dir.
#
# Another solution, used here, is to always expand $ac_aux_dir to an
# absolute PATH.  The drawback is that using absolute paths prevent a
# configured tree to be moved without reconfiguration.

# Rely on autoconf to set up CDPATH properly.
AC_PREREQ([2.50])

AC_DEFUN([AM_AUX_DIR_EXPAND], [
# expand $ac_aux_dir to an absolute path
am_aux_dir=`cd $ac_aux_dir && pwd`
])

# AM_PROG_INSTALL_SH
# ------------------
# Define $install_sh.

# Copyright 2001 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

AC_DEFUN([AM_PROG_INSTALL_SH],
[AC_REQUIRE([AM_AUX_DIR_EXPAND])dnl
install_sh=${install_sh-"$am_aux_dir/install-sh"}
AC_SUBST(install_sh)])

# AM_PROG_INSTALL_STRIP

# Copyright 2001 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# One issue with vendor `install' (even GNU) is that you can't
# specify the program used to strip binaries.  This is especially
# annoying in cross-compiling environments, where the build's strip
# is unlikely to handle the host's binaries.
# Fortunately install-sh will honor a STRIPPROG variable, so we
# always use install-sh in `make install-strip', and initialize
# STRIPPROG with the value of the STRIP variable (set by the user).
AC_DEFUN([AM_PROG_INSTALL_STRIP],
[AC_REQUIRE([AM_PROG_INSTALL_SH])dnl
# Installed binaries are usually stripped using `strip' when the user
# run `make install-strip'.  However `strip' might not be the right
# tool to use in cross-compilation environments, therefore Automake
# will honor the `STRIP' environment variable to overrule this program.
dnl Don't test for $cross_compiling = yes, because it might be `maybe'.
if test "$cross_compiling" != no; then
  AC_CHECK_TOOL([STRIP], [strip], :)
fi
INSTALL_STRIP_PROGRAM="\${SHELL} \$(install_sh) -c -s"
AC_SUBST([INSTALL_STRIP_PROGRAM])])

#                                                          -*- Autoconf -*-
# Copyright (C) 2003  Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 1

# Check whether the underlying file-system supports filenames
# with a leading dot.  For instance MS-DOS doesn't.
AC_DEFUN([AM_SET_LEADING_DOT],
[rm -rf .tst 2>/dev/null
mkdir .tst 2>/dev/null
if test -d .tst; then
  am__leading_dot=.
else
  am__leading_dot=_
fi
rmdir .tst 2>/dev/null
AC_SUBST([am__leading_dot])])

# serial 5						-*- Autoconf -*-

# Copyright (C) 1999, 2000, 2001, 2002, 2003  Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.


# There are a few dirty hacks below to avoid letting `AC_PROG_CC' be
# written in clear, in which case automake, when reading aclocal.m4,
# will think it sees a *use*, and therefore will trigger all it's
# C support machinery.  Also note that it means that autoscan, seeing
# CC etc. in the Makefile, will ask for an AC_PROG_CC use...



# _AM_DEPENDENCIES(NAME)
# ----------------------
# See how the compiler implements dependency checking.
# NAME is "CC", "CXX", "GCJ", or "OBJC".
# We try a few techniques and use that to set a single cache variable.
#
# We don't AC_REQUIRE the corresponding AC_PROG_CC since the latter was
# modified to invoke _AM_DEPENDENCIES(CC); we would have a circular
# dependency, and given that the user is not expected to run this macro,
# just rely on AC_PROG_CC.
AC_DEFUN([_AM_DEPENDENCIES],
[AC_REQUIRE([AM_SET_DEPDIR])dnl
AC_REQUIRE([AM_OUTPUT_DEPENDENCY_COMMANDS])dnl
AC_REQUIRE([AM_MAKE_INCLUDE])dnl
AC_REQUIRE([AM_DEP_TRACK])dnl

ifelse([$1], CC,   [depcc="$CC"   am_compiler_list=],
       [$1], CXX,  [depcc="$CXX"  am_compiler_list=],
       [$1], OBJC, [depcc="$OBJC" am_compiler_list='gcc3 gcc'],
       [$1], GCJ,  [depcc="$GCJ"  am_compiler_list='gcc3 gcc'],
                   [depcc="$$1"   am_compiler_list=])

AC_CACHE_CHECK([dependency style of $depcc],
               [am_cv_$1_dependencies_compiler_type],
[if test -z "$AMDEP_TRUE" && test -f "$am_depcomp"; then
  # We make a subdir and do the tests there.  Otherwise we can end up
  # making bogus files that we don't know about and never remove.  For
  # instance it was reported that on HP-UX the gcc test will end up
  # making a dummy file named `D' -- because `-MD' means `put the output
  # in D'.
  mkdir conftest.dir
  # Copy depcomp to subdir because otherwise we won't find it if we're
  # using a relative directory.
  cp "$am_depcomp" conftest.dir
  cd conftest.dir
  # We will build objects and dependencies in a subdirectory because
  # it helps to detect inapplicable dependency modes.  For instance
  # both Tru64's cc and ICC support -MD to output dependencies as a
  # side effect of compilation, but ICC will put the dependencies in
  # the current directory while Tru64 will put them in the object
  # directory.
  mkdir sub

  am_cv_$1_dependencies_compiler_type=none
  if test "$am_compiler_list" = ""; then
     am_compiler_list=`sed -n ['s/^#*\([a-zA-Z0-9]*\))$/\1/p'] < ./depcomp`
  fi
  for depmode in $am_compiler_list; do
    # Setup a source with many dependencies, because some compilers
    # like to wrap large dependency lists on column 80 (with \), and
    # we should not choose a depcomp mode which is confused by this.
    #
    # We need to recreate these files for each test, as the compiler may
    # overwrite some of them when testing with obscure command lines.
    # This happens at least with the AIX C compiler.
    : > sub/conftest.c
    for i in 1 2 3 4 5 6; do
      echo '#include "conftst'$i'.h"' >> sub/conftest.c
      : > sub/conftst$i.h
    done
    echo "${am__include} ${am__quote}sub/conftest.Po${am__quote}" > confmf

    case $depmode in
    nosideeffect)
      # after this tag, mechanisms are not by side-effect, so they'll
      # only be used when explicitly requested
      if test "x$enable_dependency_tracking" = xyes; then
	continue
      else
	break
      fi
      ;;
    none) break ;;
    esac
    # We check with `-c' and `-o' for the sake of the "dashmstdout"
    # mode.  It turns out that the SunPro C++ compiler does not properly
    # handle `-M -o', and we need to detect this.
    if depmode=$depmode \
       source=sub/conftest.c object=sub/conftest.${OBJEXT-o} \
       depfile=sub/conftest.Po tmpdepfile=sub/conftest.TPo \
       $SHELL ./depcomp $depcc -c -o sub/conftest.${OBJEXT-o} sub/conftest.c \
         >/dev/null 2>conftest.err &&
       grep sub/conftst6.h sub/conftest.Po > /dev/null 2>&1 &&
       grep sub/conftest.${OBJEXT-o} sub/conftest.Po > /dev/null 2>&1 &&
       ${MAKE-make} -s -f confmf > /dev/null 2>&1; then
      # icc doesn't choke on unknown options, it will just issue warnings
      # (even with -Werror).  So we grep stderr for any message
      # that says an option was ignored.
      if grep 'ignoring option' conftest.err >/dev/null 2>&1; then :; else
        am_cv_$1_dependencies_compiler_type=$depmode
        break
      fi
    fi
  done

  cd ..
  rm -rf conftest.dir
else
  am_cv_$1_dependencies_compiler_type=none
fi
])
AC_SUBST([$1DEPMODE], [depmode=$am_cv_$1_dependencies_compiler_type])
AM_CONDITIONAL([am__fastdep$1], [
  test "x$enable_dependency_tracking" != xno \
  && test "$am_cv_$1_dependencies_compiler_type" = gcc3])
])


# AM_SET_DEPDIR
# -------------
# Choose a directory name for dependency files.
# This macro is AC_REQUIREd in _AM_DEPENDENCIES
AC_DEFUN([AM_SET_DEPDIR],
[AC_REQUIRE([AM_SET_LEADING_DOT])dnl
AC_SUBST([DEPDIR], ["${am__leading_dot}deps"])dnl
])


# AM_DEP_TRACK
# ------------
AC_DEFUN([AM_DEP_TRACK],
[AC_ARG_ENABLE(dependency-tracking,
[  --disable-dependency-tracking Speeds up one-time builds
  --enable-dependency-tracking  Do not reject slow dependency extractors])
if test "x$enable_dependency_tracking" != xno; then
  am_depcomp="$ac_aux_dir/depcomp"
  AMDEPBACKSLASH='\'
fi
AM_CONDITIONAL([AMDEP], [test "x$enable_dependency_tracking" != xno])
AC_SUBST([AMDEPBACKSLASH])
])

# Generate code to set up dependency tracking.   -*- Autoconf -*-

# Copyright 1999, 2000, 2001, 2002 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

#serial 2

# _AM_OUTPUT_DEPENDENCY_COMMANDS
# ------------------------------
AC_DEFUN([_AM_OUTPUT_DEPENDENCY_COMMANDS],
[for mf in $CONFIG_FILES; do
  # Strip MF so we end up with the name of the file.
  mf=`echo "$mf" | sed -e 's/:.*$//'`
  # Check whether this is an Automake generated Makefile or not.
  # We used to match only the files named `Makefile.in', but
  # some people rename them; so instead we look at the file content.
  # Grep'ing the first line is not enough: some people post-process
  # each Makefile.in and add a new line on top of each file to say so.
  # So let's grep whole file.
  if grep '^#.*generated by automake' $mf > /dev/null 2>&1; then
    dirpart=`AS_DIRNAME("$mf")`
  else
    continue
  fi
  grep '^DEP_FILES *= *[[^ @%:@]]' < "$mf" > /dev/null || continue
  # Extract the definition of DEP_FILES from the Makefile without
  # running `make'.
  DEPDIR=`sed -n -e '/^DEPDIR = / s///p' < "$mf"`
  test -z "$DEPDIR" && continue
  # When using ansi2knr, U may be empty or an underscore; expand it
  U=`sed -n -e '/^U = / s///p' < "$mf"`
  test -d "$dirpart/$DEPDIR" || mkdir "$dirpart/$DEPDIR"
  # We invoke sed twice because it is the simplest approach to
  # changing $(DEPDIR) to its actual value in the expansion.
  for file in `sed -n -e '
    /^DEP_FILES = .*\\\\$/ {
      s/^DEP_FILES = //
      :loop
	s/\\\\$//
	p
	n
	/\\\\$/ b loop
      p
    }
    /^DEP_FILES = / s/^DEP_FILES = //p' < "$mf" | \
       sed -e 's/\$(DEPDIR)/'"$DEPDIR"'/g' -e 's/\$U/'"$U"'/g'`; do
    # Make sure the directory exists.
    test -f "$dirpart/$file" && continue
    fdir=`AS_DIRNAME(["$file"])`
    AS_MKDIR_P([$dirpart/$fdir])
    # echo "creating $dirpart/$file"
    echo '# dummy' > "$dirpart/$file"
  done
done
])# _AM_OUTPUT_DEPENDENCY_COMMANDS


# AM_OUTPUT_DEPENDENCY_COMMANDS
# -----------------------------
# This macro should only be invoked once -- use via AC_REQUIRE.
#
# This code is only required when automatic dependency tracking
# is enabled.  FIXME.  This creates each `.P' file that we will
# need in order to bootstrap the dependency handling code.
AC_DEFUN([AM_OUTPUT_DEPENDENCY_COMMANDS],
[AC_CONFIG_COMMANDS([depfiles],
     [test x"$AMDEP_TRUE" != x"" || _AM_OUTPUT_DEPENDENCY_COMMANDS],
     [AMDEP_TRUE="$AMDEP_TRUE" ac_aux_dir="$ac_aux_dir"])
])

# Check to see how 'make' treats includes.	-*- Autoconf -*-

# Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 2

# AM_MAKE_INCLUDE()
# -----------------
# Check to see how make treats includes.
AC_DEFUN([AM_MAKE_INCLUDE],
[am_make=${MAKE-make}
cat > confinc << 'END'
am__doit:
	@echo done
.PHONY: am__doit
END
# If we don't find an include directive, just comment out the code.
AC_MSG_CHECKING([for style of include used by $am_make])
am__include="#"
am__quote=
_am_result=none
# First try GNU make style include.
echo "include confinc" > confmf
# We grep out `Entering directory' and `Leaving directory'
# messages which can occur if `w' ends up in MAKEFLAGS.
# In particular we don't look at `^make:' because GNU make might
# be invoked under some other name (usually "gmake"), in which
# case it prints its new name instead of `make'.
if test "`$am_make -s -f confmf 2> /dev/null | grep -v 'ing directory'`" = "done"; then
   am__include=include
   am__quote=
   _am_result=GNU
fi
# Now try BSD make style include.
if test "$am__include" = "#"; then
   echo '.include "confinc"' > confmf
   if test "`$am_make -s -f confmf 2> /dev/null`" = "done"; then
      am__include=.include
      am__quote="\""
      _am_result=BSD
   fi
fi
AC_SUBST([am__include])
AC_SUBST([am__quote])
AC_MSG_RESULT([$_am_result])
rm -f confinc confmf
])

# AM_CONDITIONAL                                              -*- Autoconf -*-

# Copyright 1997, 2000, 2001 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 5

AC_PREREQ(2.52)

# AM_CONDITIONAL(NAME, SHELL-CONDITION)
# -------------------------------------
# Define a conditional.
AC_DEFUN([AM_CONDITIONAL],
[ifelse([$1], [TRUE],  [AC_FATAL([$0: invalid condition: $1])],
        [$1], [FALSE], [AC_FATAL([$0: invalid condition: $1])])dnl
AC_SUBST([$1_TRUE])
AC_SUBST([$1_FALSE])
if $2; then
  $1_TRUE=
  $1_FALSE='#'
else
  $1_TRUE='#'
  $1_FALSE=
fi
AC_CONFIG_COMMANDS_PRE(
[if test -z "${$1_TRUE}" && test -z "${$1_FALSE}"; then
  AC_MSG_ERROR([conditional "$1" was never defined.
Usually this means the macro was only invoked conditionally.])
fi])])

dnl @(#) $Header: /tcpdump/master/libpcap/aclocal.m4,v 1.83 2003/11/16 09:45:31 guy Exp $ (LBL)
dnl
dnl Copyright (c) 1995, 1996, 1997, 1998
dnl	The Regents of the University of California.  All rights reserved.
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
dnl Determine which compiler we're using (cc or gcc)
dnl If using gcc, determine the version number
dnl If using cc, require that it support ansi prototypes
dnl If using gcc, use -O2 (otherwise use -O)
dnl If using cc, explicitly specify /usr/local/include
dnl
dnl usage:
dnl
dnl	AC_LBL_C_INIT(copt, incls)
dnl
dnl results:
dnl
dnl	$1 (copt set)
dnl	$2 (incls set)
dnl	CC
dnl	LDFLAGS
dnl	ac_cv_lbl_gcc_vers
dnl	LBL_CFLAGS
dnl
AC_DEFUN(AC_LBL_C_INIT,
    [AC_PREREQ(2.12)
    AC_BEFORE([$0], [AC_PROG_CC])
    AC_BEFORE([$0], [AC_LBL_FIXINCLUDES])
    AC_BEFORE([$0], [AC_LBL_DEVEL])
    AC_ARG_WITH(gcc, [  --without-gcc           don't use gcc])
    $1="-O"
    $2=""
    if test "${srcdir}" != "." ; then
	    $2="-I\$(srcdir)"
    fi
    if test "${CFLAGS+set}" = set; then
	    LBL_CFLAGS="$CFLAGS"
    fi
    if test -z "$CC" ; then
	    case "$target_os" in

	    bsdi*)
		    AC_CHECK_PROG(SHLICC2, shlicc2, yes, no)
		    if test $SHLICC2 = yes ; then
			    CC=shlicc2
			    export CC
		    fi
		    ;;
	    esac
    fi
    if test -z "$CC" -a "$with_gcc" = no ; then
	    CC=cc
	    export CC
    fi
    AC_PROG_CC
    if test "$GCC" = yes ; then
	    if test "$SHLICC2" = yes ; then
		    ac_cv_lbl_gcc_vers=2
		    $1="-O2"
	    else
		    AC_MSG_CHECKING(gcc version)
		    AC_CACHE_VAL(ac_cv_lbl_gcc_vers,
			ac_cv_lbl_gcc_vers=`$CC -v 2>&1 | \
			    sed -e '/^gcc version /!d' \
				-e 's/^gcc version //' \
				-e 's/ .*//' -e 's/^[[[^0-9]]]*//' \
				-e 's/\..*//'`)
		    AC_MSG_RESULT($ac_cv_lbl_gcc_vers)
		    if test $ac_cv_lbl_gcc_vers -gt 1 ; then
			    $1="-O2"
		    fi
	    fi
    else
	    AC_MSG_CHECKING(that $CC handles ansi prototypes)
	    AC_CACHE_VAL(ac_cv_lbl_cc_ansi_prototypes,
		AC_TRY_COMPILE(
		    [#include <sys/types.h>],
		    [int frob(int, char *)],
		    ac_cv_lbl_cc_ansi_prototypes=yes,
		    ac_cv_lbl_cc_ansi_prototypes=no))
	    AC_MSG_RESULT($ac_cv_lbl_cc_ansi_prototypes)
	    if test $ac_cv_lbl_cc_ansi_prototypes = no ; then
		    case "$target_os" in

		    hpux*)
			    AC_MSG_CHECKING(for HP-UX ansi compiler ($CC -Aa -D_HPUX_SOURCE))
			    savedcflags="$CFLAGS"
			    CFLAGS="-Aa -D_HPUX_SOURCE $CFLAGS"
			    AC_CACHE_VAL(ac_cv_lbl_cc_hpux_cc_aa,
				AC_TRY_COMPILE(
				    [#include <sys/types.h>],
				    [int frob(int, char *)],
				    ac_cv_lbl_cc_hpux_cc_aa=yes,
				    ac_cv_lbl_cc_hpux_cc_aa=no))
			    AC_MSG_RESULT($ac_cv_lbl_cc_hpux_cc_aa)
			    if test $ac_cv_lbl_cc_hpux_cc_aa = no ; then
				    AC_MSG_ERROR(see the INSTALL doc for more info)
			    fi
			    CFLAGS="$savedcflags"
			    V_CCOPT="-Aa $V_CCOPT"
			    AC_DEFINE(_HPUX_SOURCE,1,[needed on HP-UX])
			    ;;

		    *)
			    AC_MSG_ERROR(see the INSTALL doc for more info)
			    ;;
		    esac
	    fi
	    $2="$$2 -I/usr/local/include"
	    LDFLAGS="$LDFLAGS -L/usr/local/lib"

	    case "$target_os" in

	    irix*)
		    V_CCOPT="$V_CCOPT -xansi -signed -g3"
		    ;;

	    osf*)
		    V_CCOPT="$V_CCOPT -std1 -g3"
		    ;;

	    ultrix*)
		    AC_MSG_CHECKING(that Ultrix $CC hacks const in prototypes)
		    AC_CACHE_VAL(ac_cv_lbl_cc_const_proto,
			AC_TRY_COMPILE(
			    [#include <sys/types.h>],
			    [struct a { int b; };
			    void c(const struct a *)],
			    ac_cv_lbl_cc_const_proto=yes,
			    ac_cv_lbl_cc_const_proto=no))
		    AC_MSG_RESULT($ac_cv_lbl_cc_const_proto)
		    if test $ac_cv_lbl_cc_const_proto = no ; then
			    AC_DEFINE(const,)
		    fi
		    ;;
	    esac
    fi
])

#
# Try compiling a sample of the type of code that appears in
# gencode.c with "inline", "__inline__", and "__inline".
#
# Autoconf's AC_C_INLINE, at least in autoconf 2.13, isn't good enough,
# as it just tests whether a function returning "int" can be inlined;
# at least some versions of HP's C compiler can inline that, but can't
# inline a function that returns a struct pointer.
#
AC_DEFUN(AC_LBL_C_INLINE,
    [AC_MSG_CHECKING(for inline)
    AC_CACHE_VAL(ac_cv_lbl_inline, [
	ac_cv_lbl_inline=""
	ac_lbl_cc_inline=no
	for ac_lbl_inline in inline __inline__ __inline
	do
	    AC_TRY_COMPILE(
		[#define inline $ac_lbl_inline
		static inline struct iltest *foo(void);
		struct iltest {
		    int iltest1;
		    int iltest2;
		};

		static inline struct iltest *
		foo()
		{
		    static struct iltest xxx;

		    return &xxx;
		}],,ac_lbl_cc_inline=yes,)
	    if test "$ac_lbl_cc_inline" = yes ; then
		break;
	    fi
	done
	if test "$ac_lbl_cc_inline" = yes ; then
	    ac_cv_lbl_inline=$ac_lbl_inline
	fi])
    if test ! -z "$ac_cv_lbl_inline" ; then
	AC_MSG_RESULT($ac_cv_lbl_inline)
    else
	AC_MSG_RESULT(no)
    fi
    AC_DEFINE_UNQUOTED(inline, $ac_cv_lbl_inline, [Define as token for inline if inlining supported])])

dnl
dnl Use pfopen.c if available and pfopen() not in standard libraries
dnl Require libpcap
dnl Look for libpcap in ..
dnl Use the installed libpcap if there is no local version
dnl
dnl usage:
dnl
dnl	AC_LBL_LIBPCAP(pcapdep, incls)
dnl
dnl results:
dnl
dnl	$1 (pcapdep set)
dnl	$2 (incls appended)
dnl	LIBS
dnl	LBL_LIBS
dnl
AC_DEFUN(AC_LBL_LIBPCAP,
    [AC_REQUIRE([AC_LBL_LIBRARY_NET])
    dnl
    dnl save a copy before locating libpcap.a
    dnl
    LBL_LIBS="$LIBS"
    pfopen=/usr/examples/packetfilter/pfopen.c
    if test -f $pfopen ; then
	    AC_CHECK_FUNCS(pfopen)
	    if test $ac_cv_func_pfopen = "no" ; then
		    AC_MSG_RESULT(Using $pfopen)
		    LIBS="$LIBS $pfopen"
	    fi
    fi
    AC_MSG_CHECKING(for local pcap library)
    libpcap=FAIL
    lastdir=FAIL
    places=`ls .. | sed -e 's,/$,,' -e 's,^,../,' | \
	egrep '/libpcap-[[0-9]]*\.[[0-9]]*(\.[[0-9]]*)?([[ab]][[0-9]]*)?$'`
    for dir in $places ../libpcap libpcap ; do
	    basedir=`echo $dir | sed -e 's/[[ab]][[0-9]]*$//'`
	    if test $lastdir = $basedir ; then
		    dnl skip alphas when an actual release is present
		    continue;
	    fi
	    lastdir=$dir
	    if test -r $dir/pcap.c ; then
		    libpcap=$dir/libpcap.a
		    d=$dir
		    dnl continue and select the last one that exists
	    fi
    done
    if test $libpcap = FAIL ; then
	    AC_MSG_RESULT(not found)
	    AC_CHECK_LIB(pcap, main, libpcap="-lpcap")
	    if test $libpcap = FAIL ; then
		    AC_MSG_ERROR(see the INSTALL doc for more info)
	    fi
    else
	    $1=$libpcap
	    $2="-I$d $$2"
	    AC_MSG_RESULT($libpcap)
    fi
    LIBS="$libpcap $LIBS"
    case "$target_os" in

    aix*)
	    pseexe="/lib/pse.exp"
	    AC_MSG_CHECKING(for $pseexe)
	    if test -f $pseexe ; then
		    AC_MSG_RESULT(yes)
		    LIBS="$LIBS -I:$pseexe"
	    fi
	    ;;
    esac])

dnl
dnl Define RETSIGTYPE and RETSIGVAL
dnl
dnl usage:
dnl
dnl	AC_LBL_TYPE_SIGNAL
dnl
dnl results:
dnl
dnl	RETSIGTYPE (defined)
dnl	RETSIGVAL (defined)
dnl
AC_DEFUN(AC_LBL_TYPE_SIGNAL,
    [AC_BEFORE([$0], [AC_LBL_LIBPCAP])
    AC_TYPE_SIGNAL
    if test "$ac_cv_type_signal" = void ; then
	    AC_DEFINE(RETSIGVAL,[],[return value of signal handlers])
    else
	    AC_DEFINE(RETSIGVAL,(0),[return value of signal handlers])
    fi
    case "$target_os" in

    irix*)
	    AC_DEFINE(_BSD_SIGNALS,1,[get BSD semantics on Irix])
	    ;;

    *)
	    dnl prefer sigset() to sigaction()
	    AC_CHECK_FUNCS(sigset)
	    if test $ac_cv_func_sigset = no ; then
		    AC_CHECK_FUNCS(sigaction)
	    fi
	    ;;
    esac])

dnl
dnl If using gcc, make sure we have ANSI ioctl definitions
dnl
dnl usage:
dnl
dnl	AC_LBL_FIXINCLUDES
dnl
AC_DEFUN(AC_LBL_FIXINCLUDES,
    [if test "$GCC" = yes ; then
	    AC_MSG_CHECKING(for ANSI ioctl definitions)
	    AC_CACHE_VAL(ac_cv_lbl_gcc_fixincludes,
		AC_TRY_COMPILE(
		    [/*
		     * This generates a "duplicate case value" when fixincludes
		     * has not be run.
		     */
#		include <sys/types.h>
#		include <sys/time.h>
#		include <sys/ioctl.h>
#		ifdef HAVE_SYS_IOCCOM_H
#		include <sys/ioccom.h>
#		endif],
		    [switch (0) {
		    case _IO('A', 1):;
		    case _IO('B', 1):;
		    }],
		    ac_cv_lbl_gcc_fixincludes=yes,
		    ac_cv_lbl_gcc_fixincludes=no))
	    AC_MSG_RESULT($ac_cv_lbl_gcc_fixincludes)
	    if test $ac_cv_lbl_gcc_fixincludes = no ; then
		    # Don't cache failure
		    unset ac_cv_lbl_gcc_fixincludes
		    AC_MSG_ERROR(see the INSTALL for more info)
	    fi
    fi])

dnl
dnl Check for flex, default to lex
dnl Require flex 2.4 or higher
dnl Check for bison, default to yacc
dnl Default to lex/yacc if both flex and bison are not available
dnl Define the yy prefix string if using flex and bison
dnl
dnl usage:
dnl
dnl	AC_LBL_LEX_AND_YACC(lex, yacc, yyprefix)
dnl
dnl results:
dnl
dnl	$1 (lex set)
dnl	$2 (yacc appended)
dnl	$3 (optional flex and bison -P prefix)
dnl
AC_DEFUN(AC_LBL_LEX_AND_YACC,
    [AC_ARG_WITH(flex, [  --without-flex          don't use flex])
    AC_ARG_WITH(bison, [  --without-bison         don't use bison])
    if test "$with_flex" = no ; then
	    $1=lex
    else
	    AC_CHECK_PROGS($1, flex, lex)
    fi
    if test "$$1" = flex ; then
	    # The -V flag was added in 2.4
	    AC_MSG_CHECKING(for flex 2.4 or higher)
	    AC_CACHE_VAL(ac_cv_lbl_flex_v24,
		if flex -V >/dev/null 2>&1; then
			ac_cv_lbl_flex_v24=yes
		else
			ac_cv_lbl_flex_v24=no
		fi)
	    AC_MSG_RESULT($ac_cv_lbl_flex_v24)
	    if test $ac_cv_lbl_flex_v24 = no ; then
		    s="2.4 or higher required"
		    AC_MSG_WARN(ignoring obsolete flex executable ($s))
		    $1=lex
	    fi
    fi
    if test "$with_bison" = no ; then
	    $2=yacc
    else
	    AC_CHECK_PROGS($2, bison, yacc)
    fi
    if test "$$2" = bison ; then
	    $2="$$2 -y"
    fi
    if test "$$1" != lex -a "$$2" = yacc -o "$$1" = lex -a "$$2" != yacc ; then
	    AC_MSG_WARN(don't have both flex and bison; reverting to lex/yacc)
	    $1=lex
	    $2=yacc
    fi
    if test "$$1" = flex -a -n "$3" ; then
	    $1="$$1 -P$3"
	    $2="$$2 -p $3"
    fi])

dnl
dnl Checks to see if union wait is used with WEXITSTATUS()
dnl
dnl usage:
dnl
dnl	AC_LBL_UNION_WAIT
dnl
dnl results:
dnl
dnl	DECLWAITSTATUS (defined)
dnl
AC_DEFUN(AC_LBL_UNION_WAIT,
    [AC_MSG_CHECKING(if union wait is used)
    AC_CACHE_VAL(ac_cv_lbl_union_wait,
	AC_TRY_COMPILE([
#	include <sys/types.h>
#	include <sys/wait.h>],
	    [int status;
	    u_int i = WEXITSTATUS(status);
	    u_int j = waitpid(0, &status, 0);],
	    ac_cv_lbl_union_wait=no,
	    ac_cv_lbl_union_wait=yes))
    AC_MSG_RESULT($ac_cv_lbl_union_wait)
    if test $ac_cv_lbl_union_wait = yes ; then
	    AC_DEFINE(DECLWAITSTATUS,union wait,[type for wait])
    else
	    AC_DEFINE(DECLWAITSTATUS,int,[type for wait])
    fi])

dnl
dnl Checks to see if the sockaddr struct has the 4.4 BSD sa_len member
dnl
dnl usage:
dnl
dnl	AC_LBL_SOCKADDR_SA_LEN
dnl
dnl results:
dnl
dnl	HAVE_SOCKADDR_SA_LEN (defined)
dnl
AC_DEFUN(AC_LBL_SOCKADDR_SA_LEN,
    [AC_MSG_CHECKING(if sockaddr struct has sa_len member)
    AC_CACHE_VAL(ac_cv_lbl_sockaddr_has_sa_len,
	AC_TRY_COMPILE([
#	include <sys/types.h>
#	include <sys/socket.h>],
	[u_int i = sizeof(((struct sockaddr *)0)->sa_len)],
	ac_cv_lbl_sockaddr_has_sa_len=yes,
	ac_cv_lbl_sockaddr_has_sa_len=no))
    AC_MSG_RESULT($ac_cv_lbl_sockaddr_has_sa_len)
    if test $ac_cv_lbl_sockaddr_has_sa_len = yes ; then
	    AC_DEFINE(HAVE_SOCKADDR_SA_LEN,1,[if struct sockaddr has sa_len])
    fi])

dnl
dnl Checks to see if there's a sockaddr_storage structure
dnl
dnl usage:
dnl
dnl	AC_LBL_SOCKADDR_STORAGE
dnl
dnl results:
dnl
dnl	HAVE_SOCKADDR_STORAGE (defined)
dnl
AC_DEFUN(AC_LBL_SOCKADDR_STORAGE,
    [AC_MSG_CHECKING(if sockaddr_storage struct exists)
    AC_CACHE_VAL(ac_cv_lbl_has_sockaddr_storage,
	AC_TRY_COMPILE([
#	include <sys/types.h>
#	include <sys/socket.h>],
	[u_int i = sizeof (struct sockaddr_storage)],
	ac_cv_lbl_has_sockaddr_storage=yes,
	ac_cv_lbl_has_sockaddr_storage=no))
    AC_MSG_RESULT($ac_cv_lbl_has_sockaddr_storage)
    if test $ac_cv_lbl_has_sockaddr_storage = yes ; then
	    AC_DEFINE(HAVE_SOCKADDR_STORAGE,1,[if struct sockaddr_storage exists])
    fi])

dnl
dnl Checks to see if the dl_hp_ppa_info_t struct has the HP-UX 11.00
dnl dl_module_id_1 member
dnl
dnl usage:
dnl
dnl	AC_LBL_HP_PPA_INFO_T_DL_MODULE_ID_1
dnl
dnl results:
dnl
dnl	HAVE_HP_PPA_INFO_T_DL_MODULE_ID_1 (defined)
dnl
dnl NOTE: any compile failure means we conclude that it doesn't have
dnl that member, so if we don't have DLPI, don't have a <sys/dlpi_ext.h>
dnl header, or have one that doesn't declare a dl_hp_ppa_info_t type,
dnl we conclude it doesn't have that member (which is OK, as either we
dnl won't be using code that would use that member, or we wouldn't
dnl compile in any case).
dnl
AC_DEFUN(AC_LBL_HP_PPA_INFO_T_DL_MODULE_ID_1,
    [AC_MSG_CHECKING(if dl_hp_ppa_info_t struct has dl_module_id_1 member)
    AC_CACHE_VAL(ac_cv_lbl_dl_hp_ppa_info_t_has_dl_module_id_1,
	AC_TRY_COMPILE([
#	include <sys/types.h>
#	include <sys/dlpi.h>
#	include <sys/dlpi_ext.h>],
	[u_int i = sizeof(((dl_hp_ppa_info_t *)0)->dl_module_id_1)],
	ac_cv_lbl_dl_hp_ppa_info_t_has_dl_module_id_1=yes,
	ac_cv_lbl_dl_hp_ppa_info_t_has_dl_module_id_1=no))
    AC_MSG_RESULT($ac_cv_lbl_dl_hp_ppa_info_t_has_dl_module_id_1)
    if test $ac_cv_lbl_dl_hp_ppa_info_t_has_dl_module_id_1 = yes ; then
	    AC_DEFINE(HAVE_HP_PPA_INFO_T_DL_MODULE_ID_1,1,[if ppa_info_t_dl_module_id exists])
    fi])

dnl
dnl Checks to see if -R is used
dnl
dnl usage:
dnl
dnl	AC_LBL_HAVE_RUN_PATH
dnl
dnl results:
dnl
dnl	ac_cv_lbl_have_run_path (yes or no)
dnl
AC_DEFUN(AC_LBL_HAVE_RUN_PATH,
    [AC_MSG_CHECKING(for ${CC-cc} -R)
    AC_CACHE_VAL(ac_cv_lbl_have_run_path,
	[echo 'main(){}' > conftest.c
	${CC-cc} -o conftest conftest.c -R/a1/b2/c3 >conftest.out 2>&1
	if test ! -s conftest.out ; then
		ac_cv_lbl_have_run_path=yes
	else
		ac_cv_lbl_have_run_path=no
	fi
	rm -f conftest*])
    AC_MSG_RESULT($ac_cv_lbl_have_run_path)
    ])

dnl
dnl Due to the stupid way it's implemented, AC_CHECK_TYPE is nearly useless.
dnl
dnl usage:
dnl
dnl	AC_LBL_CHECK_TYPE
dnl
dnl results:
dnl
dnl	int32_t (defined)
dnl	u_int32_t (defined)
dnl
AC_DEFUN(AC_LBL_CHECK_TYPE,
    [AC_MSG_CHECKING(for $1 using $CC)
    AC_CACHE_VAL(ac_cv_lbl_have_$1,
	AC_TRY_COMPILE([
#	include "confdefs.h"
#	include <sys/types.h>
#	if STDC_HEADERS
#	include <stdlib.h>
#	include <stddef.h>
#	endif],
	[$1 i],
	ac_cv_lbl_have_$1=yes,
	ac_cv_lbl_have_$1=no))
    AC_MSG_RESULT($ac_cv_lbl_have_$1)
    if test $ac_cv_lbl_have_$1 = no ; then
	    AC_DEFINE($1, $2, [if we have $1])
    fi])

dnl
dnl Checks to see if unaligned memory accesses fail
dnl
dnl usage:
dnl
dnl	AC_LBL_UNALIGNED_ACCESS
dnl
dnl results:
dnl
dnl	LBL_ALIGN (DEFINED)
dnl
AC_DEFUN(AC_LBL_UNALIGNED_ACCESS,
    [AC_MSG_CHECKING(if unaligned accesses fail)
    AC_CACHE_VAL(ac_cv_lbl_unaligned_fail,
	[case "$host_cpu" in

	#
	# These are CPU types where:
	#
	#	the CPU faults on an unaligned access, but at least some
	#	OSes that support that CPU catch the fault and simulate
	#	the unaligned access (e.g., Alpha/{Digital,Tru64} UNIX) -
	#	the simulation is slow, so we don't want to use it;
	#
	#	the CPU, I infer (from the old
	#
	# XXX: should also check that they don't do weird things (like on arm)
	#
	#	comment) doesn't fault on unaligned accesses, but doesn't
	#	do a normal unaligned fetch, either (e.g., presumably, ARM);
	#
	#	for whatever reason, the test program doesn't work
	#	(this has been claimed to be the case for several of those
	#	CPUs - I don't know what the problem is; the problem
	#	was reported as "the test program dumps core" for SuperH,
	#	but that's what the test program is *supposed* to do -
	#	it dumps core before it writes anything, so the test
	#	for an empty output file should find an empty output
	#	file and conclude that unaligned accesses don't work).
	#
	# This run-time test won't work if you're cross-compiling, so
	# in order to support cross-compiling for a particular CPU,
	# we have to wire in the list of CPU types anyway, as far as
	# I know, so perhaps we should just have a set of CPUs on
	# which we know it doesn't work, a set of CPUs on which we
	# know it does work, and have the script just fail on other
	# cpu types and update it when such a failure occurs.
	#
	alpha*|arm*|hp*|mips*|sh*|sparc*|ia64|nv1)
		ac_cv_lbl_unaligned_fail=yes
		;;

	*)
		cat >conftest.c <<EOF
#		include <sys/types.h>
#		include <sys/wait.h>
#		include <stdio.h>
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
		rm -f conftest* core core.conftest
		;;
	esac])
    AC_MSG_RESULT($ac_cv_lbl_unaligned_fail)
    if test $ac_cv_lbl_unaligned_fail = yes ; then
	    AC_DEFINE(LBL_ALIGN,1,[if unaligned access fails])
    fi])

dnl
dnl If using gcc and the file .devel exists:
dnl	Compile with -g (if supported) and -Wall
dnl	If using gcc 2, do extra prototype checking
dnl	If an os prototype include exists, symlink os-proto.h to it
dnl
dnl usage:
dnl
dnl	AC_LBL_DEVEL(copt)
dnl
dnl results:
dnl
dnl	$1 (copt appended)
dnl	HAVE_OS_PROTO_H (defined)
dnl	os-proto.h (symlinked)
dnl
AC_DEFUN(AC_LBL_DEVEL,
    [rm -f os-proto.h
    if test "${LBL_CFLAGS+set}" = set; then
	    $1="$$1 ${LBL_CFLAGS}"
    fi
    if test -f .devel ; then
	    if test "$GCC" = yes ; then
		    if test "${LBL_CFLAGS+set}" != set; then
			    if test "$ac_cv_prog_cc_g" = yes ; then
				    $1="-g $$1"
			    fi
			    $1="$$1 -Wall"
			    if test $ac_cv_lbl_gcc_vers -gt 1 ; then
				    $1="$$1 -Wmissing-prototypes -Wstrict-prototypes"
			    fi
		    fi
	    else
		    case "$target_os" in

		    irix6*)
			    V_CCOPT="$V_CCOPT -n32"
			    ;;

		    *)
			    ;;
		    esac
	    fi
	    os=`echo $target_os | sed -e 's/\([[0-9]][[0-9]]*\)[[^0-9]].*$/\1/'`
	    name="lbl/os-$os.h"
	    if test -f $name ; then
		    ln -s $name os-proto.h
		    AC_DEFINE(HAVE_OS_PROTO_H,1,[if there's an os_proto.h])
	    else
		    AC_MSG_WARN(can't find $name)
	    fi
    fi])

dnl
dnl Improved version of AC_CHECK_LIB
dnl
dnl Thanks to John Hawkinson (jhawk@mit.edu)
dnl
dnl usage:
dnl
dnl	AC_LBL_CHECK_LIB(LIBRARY, FUNCTION [, ACTION-IF-FOUND [,
dnl	    ACTION-IF-NOT-FOUND [, OTHER-LIBRARIES]]])
dnl
dnl results:
dnl
dnl	LIBS
dnl

define(AC_LBL_CHECK_LIB,
[AC_MSG_CHECKING([for $2 in -l$1])
dnl Use a cache variable name containing both the library and function name,
dnl because the test really is for library $1 defining function $2, not
dnl just for library $1.  Separate tests with the same $1 and different $2's
dnl may have different results.
ac_lib_var=`echo $1['_']$2['_']$5 | sed 'y%./+- %__p__%'`
AC_CACHE_VAL(ac_cv_lbl_lib_$ac_lib_var,
[ac_save_LIBS="$LIBS"
LIBS="-l$1 $5 $LIBS"
AC_TRY_LINK(dnl
ifelse([$2], [main], , dnl Avoid conflicting decl of main.
[/* Override any gcc2 internal prototype to avoid an error.  */
]ifelse(AC_LANG, CPLUSPLUS, [#ifdef __cplusplus
extern "C"
#endif
])dnl
[/* We use char because int might match the return type of a gcc2
    builtin and then its argument prototype would still apply.  */
char $2();
]),
	    [$2()],
	    eval "ac_cv_lbl_lib_$ac_lib_var=yes",
	    eval "ac_cv_lbl_lib_$ac_lib_var=no")
LIBS="$ac_save_LIBS"
])dnl
if eval "test \"`echo '$ac_cv_lbl_lib_'$ac_lib_var`\" = yes"; then
  AC_MSG_RESULT(yes)
  ifelse([$3], ,
[changequote(, )dnl
  ac_tr_lib=HAVE_LIB`echo $1 | sed -e 's/[^a-zA-Z0-9_]/_/g' \
    -e 'y/abcdefghijklmnopqrstuvwxyz/ABCDEFGHIJKLMNOPQRSTUVWXYZ/'`
changequote([, ])dnl
  AC_DEFINE_UNQUOTED($ac_tr_lib)
  LIBS="-l$1 $LIBS"
], [$3])
else
  AC_MSG_RESULT(no)
ifelse([$4], , , [$4
])dnl
fi
])

dnl
dnl AC_LBL_LIBRARY_NET
dnl
dnl This test is for network applications that need socket() and
dnl gethostbyname() -ish functions.  Under Solaris, those applications
dnl need to link with "-lsocket -lnsl".  Under IRIX, they need to link
dnl with "-lnsl" but should *not* link with "-lsocket" because
dnl libsocket.a breaks a number of things (for instance:
dnl gethostbyname() under IRIX 5.2, and snoop sockets under most
dnl versions of IRIX).
dnl
dnl Unfortunately, many application developers are not aware of this,
dnl and mistakenly write tests that cause -lsocket to be used under
dnl IRIX.  It is also easy to write tests that cause -lnsl to be used
dnl under operating systems where neither are necessary (or useful),
dnl such as SunOS 4.1.4, which uses -lnsl for TLI.
dnl
dnl This test exists so that every application developer does not test
dnl this in a different, and subtly broken fashion.

dnl It has been argued that this test should be broken up into two
dnl seperate tests, one for the resolver libraries, and one for the
dnl libraries necessary for using Sockets API. Unfortunately, the two
dnl are carefully intertwined and allowing the autoconf user to use
dnl them independantly potentially results in unfortunate ordering
dnl dependancies -- as such, such component macros would have to
dnl carefully use indirection and be aware if the other components were
dnl executed. Since other autoconf macros do not go to this trouble,
dnl and almost no applications use sockets without the resolver, this
dnl complexity has not been implemented.
dnl
dnl The check for libresolv is in case you are attempting to link
dnl statically and happen to have a libresolv.a lying around (and no
dnl libnsl.a).
dnl
AC_DEFUN(AC_LBL_LIBRARY_NET, [
    # Most operating systems have gethostbyname() in the default searched
    # libraries (i.e. libc):
    AC_CHECK_FUNC(gethostbyname, ,
	# Some OSes (eg. Solaris) place it in libnsl:
	AC_LBL_CHECK_LIB(nsl, gethostbyname, , 
	    # Some strange OSes (SINIX) have it in libsocket:
	    AC_LBL_CHECK_LIB(socket, gethostbyname, ,
		# Unfortunately libsocket sometimes depends on libnsl.
		# AC_CHECK_LIB's API is essentially broken so the
		# following ugliness is necessary:
		AC_LBL_CHECK_LIB(socket, gethostbyname,
		    LIBS="-lsocket -lnsl $LIBS",
		    AC_CHECK_LIB(resolv, gethostbyname),
		    -lnsl))))
    AC_CHECK_FUNC(socket, , AC_CHECK_LIB(socket, socket, ,
	AC_LBL_CHECK_LIB(socket, socket, LIBS="-lsocket -lnsl $LIBS", ,
	    -lnsl)))
    # DLPI needs putmsg under HPUX so test for -lstr while we're at it
    AC_CHECK_LIB(str, putmsg)
    ])

dnl
dnl Test for __attribute__
dnl

AC_DEFUN(AC_C___ATTRIBUTE__, [
AC_MSG_CHECKING(for __attribute__)
AC_CACHE_VAL(ac_cv___attribute__, [
AC_TRY_COMPILE([
#include <stdlib.h>
],
[
static void foo(void) __attribute__ ((noreturn));

static void
foo(void)
{
  exit(1);
}
],
ac_cv___attribute__=yes,
ac_cv___attribute__=no)])
if test "$ac_cv___attribute__" = "yes"; then
  AC_DEFINE(HAVE___ATTRIBUTE__, 1, [define if your compiler has __attribute__])
  V_DEFS="$V_DEFS -D_U_=\"__attribute__((unused))\""
else
  V_DEFS="$V_DEFS -D_U_=\"\""
fi
AC_MSG_RESULT($ac_cv___attribute__)
])

dnl
dnl Checks to see if tpacket_stats is defined in linux/if_packet.h
dnl If so then pcap-linux.c can use this to report proper statistics.
dnl
dnl -Scott Barron
dnl
AC_DEFUN(AC_LBL_TPACKET_STATS,
   [AC_MSG_CHECKING(if if_packet.h has tpacket_stats defined)
   AC_CACHE_VAL(ac_cv_lbl_tpacket_stats,
   AC_TRY_COMPILE([
#  include <linux/if_packet.h>],
   [struct tpacket_stats stats],
   ac_cv_lbl_tpacket_stats=yes,
   ac_cv_lbl_tpacket_stats=no))
   AC_MSG_RESULT($ac_cv_lbl_tpacket_stats)
   if test $ac_cv_lbl_tpacket_stats = yes; then
       AC_DEFINE(HAVE_TPACKET_STATS,1,[if if_packet.h has tpacket_stats defined])
   fi])

# pkg.m4 - Macros to locate and utilise pkg-config.            -*- Autoconf -*-
# 
# Copyright © 2004 Scott James Remnant <scott@netsplit.com>.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
# As a special exception to the GNU General Public License, if you
# distribute this file as part of a program that contains a
# configuration script generated by Autoconf, you may include it under
# the same distribution terms that you use for the rest of that program.

# PKG_PROG_PKG_CONFIG([MIN-VERSION])
# ----------------------------------
AC_DEFUN([PKG_PROG_PKG_CONFIG],
[m4_pattern_forbid([^_?PKG_[A-Z_]+$])
m4_pattern_allow([^PKG_CONFIG(_PATH)?$])
AC_ARG_VAR([PKG_CONFIG], [path to pkg-config utility])dnl
if test "x$ac_cv_env_PKG_CONFIG_set" != "xset"; then
	AC_PATH_TOOL([PKG_CONFIG], [pkg-config])
fi
if test -n "$PKG_CONFIG"; then
	_pkg_min_version=m4_default([$1], [0.9.0])
	AC_MSG_CHECKING([pkg-config is at least version $_pkg_min_version])
	if $PKG_CONFIG --atleast-pkgconfig-version $_pkg_min_version; then
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
		PKG_CONFIG=""
	fi
		
fi[]dnl
])# PKG_PROG_PKG_CONFIG

# PKG_CHECK_EXISTS(MODULES, [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
#
# Check to see whether a particular set of modules exists.  Similar
# to PKG_CHECK_MODULES(), but does not set variables or print errors.
#
#
# Similar to PKG_CHECK_MODULES, make sure that the first instance of
# this or PKG_CHECK_MODULES is called, or make sure to call
# PKG_CHECK_EXISTS manually
# --------------------------------------------------------------
AC_DEFUN([PKG_CHECK_EXISTS],
[AC_REQUIRE([PKG_PROG_PKG_CONFIG])dnl
if test -n "$PKG_CONFIG" && \
    AC_RUN_LOG([$PKG_CONFIG --exists --print-errors "$1"]); then
  m4_ifval([$2], [$2], [:])
m4_ifvaln([$3], [else
  $3])dnl
fi])


# _PKG_CONFIG([VARIABLE], [COMMAND], [MODULES])
# ---------------------------------------------
m4_define([_PKG_CONFIG],
[if test -n "$PKG_CONFIG"; then
    if test -n "$$1"; then
        pkg_cv_[]$1="$$1"
    else
        PKG_CHECK_EXISTS([$3],
                         [pkg_cv_[]$1=`$PKG_CONFIG --[]$2 "$3" 2>/dev/null`],
			 [pkg_failed=yes])
    fi
else
	pkg_failed=untried
fi[]dnl
])# _PKG_CONFIG

# _PKG_SHORT_ERRORS_SUPPORTED
# -----------------------------
AC_DEFUN([_PKG_SHORT_ERRORS_SUPPORTED],
[AC_REQUIRE([PKG_PROG_PKG_CONFIG])
if $PKG_CONFIG --atleast-pkgconfig-version 0.20; then
        _pkg_short_errors_supported=yes
else
        _pkg_short_errors_supported=no
fi[]dnl
])# _PKG_SHORT_ERRORS_SUPPORTED


# PKG_CHECK_MODULES(VARIABLE-PREFIX, MODULES, [ACTION-IF-FOUND],
# [ACTION-IF-NOT-FOUND])
#
#
# Note that if there is a possibility the first call to
# PKG_CHECK_MODULES might not happen, you should be sure to include an
# explicit call to PKG_PROG_PKG_CONFIG in your configure.ac
#
#
# --------------------------------------------------------------
AC_DEFUN([PKG_CHECK_MODULES],
[AC_REQUIRE([PKG_PROG_PKG_CONFIG])dnl
AC_ARG_VAR([$1][_CFLAGS], [C compiler flags for $1, overriding pkg-config])dnl
AC_ARG_VAR([$1][_LIBS], [linker flags for $1, overriding pkg-config])dnl

pkg_failed=no
AC_MSG_CHECKING([for $1])

_PKG_CONFIG([$1][_CFLAGS], [cflags], [$2])
_PKG_CONFIG([$1][_LIBS], [libs], [$2])

m4_define([_PKG_TEXT], [Alternatively, you may set the environment variables $1[]_CFLAGS
and $1[]_LIBS to avoid the need to call pkg-config.
See the pkg-config man page for more details.])

if test $pkg_failed = yes; then
        _PKG_SHORT_ERRORS_SUPPORTED
        if test $_pkg_short_errors_supported = yes; then
	        $1[]_PKG_ERRORS=`$PKG_CONFIG --short-errors --errors-to-stdout --print-errors "$2"`
        else 
	        $1[]_PKG_ERRORS=`$PKG_CONFIG --errors-to-stdout --print-errors "$2"`
        fi
	# Put the nasty error message in config.log where it belongs
	echo "$$1[]_PKG_ERRORS" >&AS_MESSAGE_LOG_FD

	ifelse([$4], , [AC_MSG_ERROR(dnl
[Package requirements ($2) were not met:

$$1_PKG_ERRORS

Consider adjusting the PKG_CONFIG_PATH environment variable if you
installed software in a non-standard prefix.

_PKG_TEXT
])],
		[AC_MSG_RESULT([no])
                $4])
elif test $pkg_failed = untried; then
	ifelse([$4], , [AC_MSG_FAILURE(dnl
[The pkg-config script could not be found or is too old.  Make sure it
is in your PATH or set the PKG_CONFIG environment variable to the full
path to pkg-config.

_PKG_TEXT

To get pkg-config, see <http://www.freedesktop.org/software/pkgconfig>.])],
		[$4])
else
	$1[]_CFLAGS=$pkg_cv_[]$1[]_CFLAGS
	$1[]_LIBS=$pkg_cv_[]$1[]_LIBS
        AC_MSG_RESULT([yes])
	ifelse([$3], , :, [$3])
fi[]dnl
])# PKG_CHECK_MODULES

# Copyright (C) 1995-2002 Free Software Foundation, Inc.
# Copyright (C) 2001-2003,2004 Red Hat, Inc.
#
# This file is free software, distributed under the terms of the GNU
# General Public License.  As a special exception to the GNU General
# Public License, this file may be distributed as part of a program
# that contains a configuration script generated by Autoconf, under
# the same distribution terms as the rest of that program.
#
# This file can be copied and used freely without restrictions.  It can
# be used in projects which are not available under the GNU Public License
# but which still want to provide support for the GNU gettext functionality.
#
# Macro to add for using GNU gettext.
# Ulrich Drepper <drepper@cygnus.com>, 1995, 1996
#
# Modified to never use included libintl. 
# Owen Taylor <otaylor@redhat.com>, 12/15/1998
#
# Major rework to remove unused code
# Owen Taylor <otaylor@redhat.com>, 12/11/2002
#
# Added better handling of ALL_LINGUAS from GNU gettext version 
# written by Bruno Haible, Owen Taylor <otaylor.redhat.com> 5/30/3002
#
# Modified to require ngettext
# Matthias Clasen <mclasen@redhat.com> 08/06/2004
#
# We need this here as well, since someone might use autoconf-2.5x
# to configure GLib then an older version to configure a package
# using AM_GLIB_GNU_GETTEXT
AC_PREREQ(2.53)

dnl
dnl We go to great lengths to make sure that aclocal won't 
dnl try to pull in the installed version of these macros
dnl when running aclocal in the glib directory.
dnl
m4_copy([AC_DEFUN],[glib_DEFUN])
m4_copy([AC_REQUIRE],[glib_REQUIRE])
dnl
dnl At the end, if we're not within glib, we'll define the public
dnl definitions in terms of our private definitions.
dnl

# GLIB_LC_MESSAGES
#--------------------
glib_DEFUN([GLIB_LC_MESSAGES],
  [AC_CHECK_HEADERS([locale.h])
    if test $ac_cv_header_locale_h = yes; then
    AC_CACHE_CHECK([for LC_MESSAGES], am_cv_val_LC_MESSAGES,
      [AC_TRY_LINK([#include <locale.h>], [return LC_MESSAGES],
       am_cv_val_LC_MESSAGES=yes, am_cv_val_LC_MESSAGES=no)])
    if test $am_cv_val_LC_MESSAGES = yes; then
      AC_DEFINE(HAVE_LC_MESSAGES, 1,
        [Define if your <locale.h> file defines LC_MESSAGES.])
    fi
  fi])

# GLIB_PATH_PROG_WITH_TEST
#----------------------------
dnl GLIB_PATH_PROG_WITH_TEST(VARIABLE, PROG-TO-CHECK-FOR,
dnl   TEST-PERFORMED-ON-FOUND_PROGRAM [, VALUE-IF-NOT-FOUND [, PATH]])
glib_DEFUN([GLIB_PATH_PROG_WITH_TEST],
[# Extract the first word of "$2", so it can be a program name with args.
set dummy $2; ac_word=[$]2
AC_MSG_CHECKING([for $ac_word])
AC_CACHE_VAL(ac_cv_path_$1,
[case "[$]$1" in
  /*)
  ac_cv_path_$1="[$]$1" # Let the user override the test with a path.
  ;;
  *)
  IFS="${IFS= 	}"; ac_save_ifs="$IFS"; IFS="${IFS}:"
  for ac_dir in ifelse([$5], , $PATH, [$5]); do
    test -z "$ac_dir" && ac_dir=.
    if test -f $ac_dir/$ac_word; then
      if [$3]; then
	ac_cv_path_$1="$ac_dir/$ac_word"
	break
      fi
    fi
  done
  IFS="$ac_save_ifs"
dnl If no 4th arg is given, leave the cache variable unset,
dnl so AC_PATH_PROGS will keep looking.
ifelse([$4], , , [  test -z "[$]ac_cv_path_$1" && ac_cv_path_$1="$4"
])dnl
  ;;
esac])dnl
$1="$ac_cv_path_$1"
if test ifelse([$4], , [-n "[$]$1"], ["[$]$1" != "$4"]); then
  AC_MSG_RESULT([$]$1)
else
  AC_MSG_RESULT(no)
fi
AC_SUBST($1)dnl
])

# GLIB_WITH_NLS
#-----------------
glib_DEFUN([GLIB_WITH_NLS],
  dnl NLS is obligatory
  [AC_REQUIRE([AC_CANONICAL_HOST])dnl
    USE_NLS=yes
    AC_SUBST(USE_NLS)

    gt_cv_have_gettext=no

    CATOBJEXT=NONE
    XGETTEXT=:
    INTLLIBS=

    AC_CHECK_HEADER(libintl.h,
     [gt_cv_func_dgettext_libintl="no"
      libintl_extra_libs=""

      #
      # First check in libc
      #
      AC_CACHE_CHECK([for ngettext in libc], gt_cv_func_ngettext_libc,
        [AC_TRY_LINK([
#include <libintl.h>
],
         [return !ngettext ("","", 1)],
	  gt_cv_func_ngettext_libc=yes,
          gt_cv_func_ngettext_libc=no)
        ])
  
      if test "$gt_cv_func_ngettext_libc" = "yes" ; then
	      AC_CACHE_CHECK([for dgettext in libc], gt_cv_func_dgettext_libc,
        	[AC_TRY_LINK([
#include <libintl.h>
],
	          [return !dgettext ("","")],
		  gt_cv_func_dgettext_libc=yes,
	          gt_cv_func_dgettext_libc=no)
        	])
      fi
  
      if test "$gt_cv_func_ngettext_libc" = "yes" ; then
        AC_CHECK_FUNCS(bind_textdomain_codeset)
      fi

      #
      # If we don't have everything we want, check in libintl
      #
      if test "$gt_cv_func_dgettext_libc" != "yes" \
	 || test "$gt_cv_func_ngettext_libc" != "yes" \
         || test "$ac_cv_func_bind_textdomain_codeset" != "yes" ; then
        
        AC_CHECK_LIB(intl, bindtextdomain,
	    [AC_CHECK_LIB(intl, ngettext,
		    [AC_CHECK_LIB(intl, dgettext,
			          gt_cv_func_dgettext_libintl=yes)])])

	if test "$gt_cv_func_dgettext_libintl" != "yes" ; then
	  AC_MSG_CHECKING([if -liconv is needed to use gettext])
	  AC_MSG_RESULT([])
  	  AC_CHECK_LIB(intl, ngettext,
          	[AC_CHECK_LIB(intl, dcgettext,
		       [gt_cv_func_dgettext_libintl=yes
			libintl_extra_libs=-liconv],
			:,-liconv)],
		:,-liconv)
        fi

        #
        # If we found libintl, then check in it for bind_textdomain_codeset();
        # we'll prefer libc if neither have bind_textdomain_codeset(),
        # and both have dgettext and ngettext
        #
        if test "$gt_cv_func_dgettext_libintl" = "yes" ; then
          glib_save_LIBS="$LIBS"
          LIBS="$LIBS -lintl $libintl_extra_libs"
          unset ac_cv_func_bind_textdomain_codeset
          AC_CHECK_FUNCS(bind_textdomain_codeset)
          LIBS="$glib_save_LIBS"

          if test "$ac_cv_func_bind_textdomain_codeset" = "yes" ; then
            gt_cv_func_dgettext_libc=no
          else
            if test "$gt_cv_func_dgettext_libc" = "yes" \
		&& test "$gt_cv_func_ngettext_libc" = "yes"; then
              gt_cv_func_dgettext_libintl=no
            fi
          fi
        fi
      fi

      if test "$gt_cv_func_dgettext_libc" = "yes" \
	|| test "$gt_cv_func_dgettext_libintl" = "yes"; then
        gt_cv_have_gettext=yes
      fi
  
      if test "$gt_cv_func_dgettext_libintl" = "yes"; then
        INTLLIBS="-lintl $libintl_extra_libs"
      fi
  
      if test "$gt_cv_have_gettext" = "yes"; then
	AC_DEFINE(HAVE_GETTEXT,1,
	  [Define if the GNU gettext() function is already present or preinstalled.])
	GLIB_PATH_PROG_WITH_TEST(MSGFMT, msgfmt,
	  [test -z "`$ac_dir/$ac_word -h 2>&1 | grep 'dv '`"], no)dnl
	if test "$MSGFMT" != "no"; then
          glib_save_LIBS="$LIBS"
          LIBS="$LIBS $INTLLIBS"
	  AC_CHECK_FUNCS(dcgettext)
	  MSGFMT_OPTS=
	  AC_MSG_CHECKING([if msgfmt accepts -c])
	  GLIB_RUN_PROG([msgfmt -c -o /dev/null],[
msgid ""
msgstr ""
"Content-Type: text/plain; charset=UTF-8\n"
"Project-Id-Version: test 1.0\n"
"PO-Revision-Date: 2007-02-15 12:01+0100\n"
"Last-Translator: test <foo@bar.xx>\n"
"Language-Team: C <LL@li.org>\n"
"MIME-Version: 1.0\n"
"Content-Transfer-Encoding: 8bit\n"
], [MSGFMT_OPTS=-c; AC_MSG_RESULT([yes])], [AC_MSG_RESULT([no])])
	  AC_SUBST(MSGFMT_OPTS)
	  AC_PATH_PROG(GMSGFMT, gmsgfmt, $MSGFMT)
	  GLIB_PATH_PROG_WITH_TEST(XGETTEXT, xgettext,
	    [test -z "`$ac_dir/$ac_word -h 2>&1 | grep '(HELP)'`"], :)
	  AC_TRY_LINK(, [extern int _nl_msg_cat_cntr;
			 return _nl_msg_cat_cntr],
	    [CATOBJEXT=.gmo 
             DATADIRNAME=share],
	    [case $host in
	    *-*-solaris*)
	    dnl On Solaris, if bind_textdomain_codeset is in libc,
	    dnl GNU format message catalog is always supported,
            dnl since both are added to the libc all together.
	    dnl Hence, we'd like to go with DATADIRNAME=share and
	    dnl and CATOBJEXT=.gmo in this case.
            AC_CHECK_FUNC(bind_textdomain_codeset,
	      [CATOBJEXT=.gmo 
               DATADIRNAME=share],
	      [CATOBJEXT=.mo
               DATADIRNAME=lib])
	    ;;
	    *)
	    CATOBJEXT=.mo
            DATADIRNAME=lib
	    ;;
	    esac])
          LIBS="$glib_save_LIBS"
	  INSTOBJEXT=.mo
	else
	  gt_cv_have_gettext=no
	fi
      fi
    ])

    if test "$gt_cv_have_gettext" = "yes" ; then
      AC_DEFINE(ENABLE_NLS, 1,
        [always defined to indicate that i18n is enabled])
    fi

    dnl Test whether we really found GNU xgettext.
    if test "$XGETTEXT" != ":"; then
      dnl If it is not GNU xgettext we define it as : so that the
      dnl Makefiles still can work.
      if $XGETTEXT --omit-header /dev/null 2> /dev/null; then
        : ;
      else
        AC_MSG_RESULT(
	  [found xgettext program is not GNU xgettext; ignore it])
        XGETTEXT=":"
      fi
    fi

    # We need to process the po/ directory.
    POSUB=po

    AC_OUTPUT_COMMANDS(
      [case "$CONFIG_FILES" in *po/Makefile.in*)
        sed -e "/POTFILES =/r po/POTFILES" po/Makefile.in > po/Makefile
      esac])

    dnl These rules are solely for the distribution goal.  While doing this
    dnl we only have to keep exactly one list of the available catalogs
    dnl in configure.in.
    for lang in $ALL_LINGUAS; do
      GMOFILES="$GMOFILES $lang.gmo"
      POFILES="$POFILES $lang.po"
    done

    dnl Make all variables we use known to autoconf.
    AC_SUBST(CATALOGS)
    AC_SUBST(CATOBJEXT)
    AC_SUBST(DATADIRNAME)
    AC_SUBST(GMOFILES)
    AC_SUBST(INSTOBJEXT)
    AC_SUBST(INTLLIBS)
    AC_SUBST(PO_IN_DATADIR_TRUE)
    AC_SUBST(PO_IN_DATADIR_FALSE)
    AC_SUBST(POFILES)
    AC_SUBST(POSUB)
  ])

# AM_GLIB_GNU_GETTEXT
# -------------------
# Do checks necessary for use of gettext. If a suitable implementation 
# of gettext is found in either in libintl or in the C library,
# it will set INTLLIBS to the libraries needed for use of gettext
# and AC_DEFINE() HAVE_GETTEXT and ENABLE_NLS. (The shell variable
# gt_cv_have_gettext will be set to "yes".) It will also call AC_SUBST()
# on various variables needed by the Makefile.in.in installed by 
# glib-gettextize.
dnl
glib_DEFUN([GLIB_GNU_GETTEXT],
  [AC_REQUIRE([AC_PROG_CC])dnl
   AC_REQUIRE([AC_HEADER_STDC])dnl
   
   GLIB_LC_MESSAGES
   GLIB_WITH_NLS

   if test "$gt_cv_have_gettext" = "yes"; then
     if test "x$ALL_LINGUAS" = "x"; then
       LINGUAS=
     else
       AC_MSG_CHECKING(for catalogs to be installed)
       NEW_LINGUAS=
       for presentlang in $ALL_LINGUAS; do
         useit=no
         if test "%UNSET%" != "${LINGUAS-%UNSET%}"; then
           desiredlanguages="$LINGUAS"
         else
           desiredlanguages="$ALL_LINGUAS"
         fi
         for desiredlang in $desiredlanguages; do
 	   # Use the presentlang catalog if desiredlang is
           #   a. equal to presentlang, or
           #   b. a variant of presentlang (because in this case,
           #      presentlang can be used as a fallback for messages
           #      which are not translated in the desiredlang catalog).
           case "$desiredlang" in
             "$presentlang"*) useit=yes;;
           esac
         done
         if test $useit = yes; then
           NEW_LINGUAS="$NEW_LINGUAS $presentlang"
         fi
       done
       LINGUAS=$NEW_LINGUAS
       AC_MSG_RESULT($LINGUAS)
     fi

     dnl Construct list of names of catalog files to be constructed.
     if test -n "$LINGUAS"; then
       for lang in $LINGUAS; do CATALOGS="$CATALOGS $lang$CATOBJEXT"; done
     fi
   fi

   dnl If the AC_CONFIG_AUX_DIR macro for autoconf is used we possibly
   dnl find the mkinstalldirs script in another subdir but ($top_srcdir).
   dnl Try to locate is.
   MKINSTALLDIRS=
   if test -n "$ac_aux_dir"; then
     MKINSTALLDIRS="$ac_aux_dir/mkinstalldirs"
   fi
   if test -z "$MKINSTALLDIRS"; then
     MKINSTALLDIRS="\$(top_srcdir)/mkinstalldirs"
   fi
   AC_SUBST(MKINSTALLDIRS)

   dnl Generate list of files to be processed by xgettext which will
   dnl be included in po/Makefile.
   test -d po || mkdir po
   if test "x$srcdir" != "x."; then
     if test "x`echo $srcdir | sed 's@/.*@@'`" = "x"; then
       posrcprefix="$srcdir/"
     else
       posrcprefix="../$srcdir/"
     fi
   else
     posrcprefix="../"
   fi
   rm -f po/POTFILES
   sed -e "/^#/d" -e "/^\$/d" -e "s,.*,	$posrcprefix& \\\\," -e "\$s/\(.*\) \\\\/\1/" \
	< $srcdir/po/POTFILES.in > po/POTFILES
  ])

# AM_GLIB_DEFINE_LOCALEDIR(VARIABLE)
# -------------------------------
# Define VARIABLE to the location where catalog files will
# be installed by po/Makefile.
glib_DEFUN([GLIB_DEFINE_LOCALEDIR],
[glib_REQUIRE([GLIB_GNU_GETTEXT])dnl
glib_save_prefix="$prefix"
glib_save_exec_prefix="$exec_prefix"
glib_save_datarootdir="$datarootdir"
test "x$prefix" = xNONE && prefix=$ac_default_prefix
test "x$exec_prefix" = xNONE && exec_prefix=$prefix
datarootdir=`eval echo "${datarootdir}"`
if test "x$CATOBJEXT" = "x.mo" ; then
  localedir=`eval echo "${libdir}/locale"`
else
  localedir=`eval echo "${datadir}/locale"`
fi
prefix="$glib_save_prefix"
exec_prefix="$glib_save_exec_prefix"
datarootdir="$glib_save_datarootdir"
AC_DEFINE_UNQUOTED($1, "$localedir",
  [Define the location where the catalogs will be installed])
])

dnl
dnl Now the definitions that aclocal will find
dnl
ifdef(glib_configure_in,[],[
AC_DEFUN([AM_GLIB_GNU_GETTEXT],[GLIB_GNU_GETTEXT($@)])
AC_DEFUN([AM_GLIB_DEFINE_LOCALEDIR],[GLIB_DEFINE_LOCALEDIR($@)])
])dnl

# GLIB_RUN_PROG(PROGRAM, TEST-FILE, [ACTION-IF-PASS], [ACTION-IF-FAIL])
# 
# Create a temporary file with TEST-FILE as its contents and pass the
# file name to PROGRAM.  Perform ACTION-IF-PASS if PROGRAM exits with
# 0 and perform ACTION-IF-FAIL for any other exit status.
AC_DEFUN([GLIB_RUN_PROG],
[cat >conftest.foo <<_ACEOF
$2
_ACEOF
if AC_RUN_LOG([$1 conftest.foo]); then
  m4_ifval([$3], [$3], [:])
m4_ifvaln([$4], [else $4])dnl
echo "$as_me: failed input was:" >&AS_MESSAGE_LOG_FD
sed 's/^/| /' conftest.foo >&AS_MESSAGE_LOG_FD
fi])


