dnl
dnl $Id: c-attribute.m4 14166 2004-08-26 12:35:42Z joda $
dnl

dnl
dnl Test for __attribute__
dnl

AC_DEFUN([AC_C___ATTRIBUTE__], [
AC_MSG_CHECKING(for __attribute__)
AC_CACHE_VAL(ac_cv___attribute__, [
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[#include <stdlib.h>
static void foo(void) __attribute__ ((noreturn));

static void
foo(void)
{
  exit(1);
}
]])],
[ac_cv___attribute__=yes],
[ac_cv___attribute__=no])])
if test "$ac_cv___attribute__" = "yes"; then
  AC_DEFINE(HAVE___ATTRIBUTE__, 1, [define if your compiler has __attribute__])
fi
AC_MSG_RESULT($ac_cv___attribute__)
])

