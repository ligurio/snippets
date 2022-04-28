AC_INIT([ploop tests], [0.1], [devel@openvz.org], [ploop-tests], [https://www.openvz.org/])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

AC_CHECK_PROG(PLOOP_CHECK,ploop,yes)
if test x"$PLOOP_CHECK" != x"yes" ; then
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([ploop utility is missing.])
fi

AC_MSG_CHECKING([ploop module])
if cat /proc/modules | grep -q "^ploop"; then
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
    AC_MSG_NOTICE([
    NOTE:     Detected that ploop module is absent in loaded Linux kernel.])
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
