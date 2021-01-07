m4_include([version.m4])

dnl Initialize autoconf/automake
AC_INIT(aide, AIDE_VERSION)
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([1.10 -Wall -Werror silent-rules subdir-objects serial-tests])

AC_DEFINE_UNQUOTED(AIDEVERSION, "AIDE_VERSION")
AH_TEMPLATE([AIDEVERSION], [package version])

dnl The name of the configure h-file.
AM_CONFIG_HEADER(config.h)

dnl Checks for programs.
AC_PROG_CC_C99
if test "x$ac_cv_prog_cc_c99" = xno; then
    AC_MSG_ERROR([AIDE needs a C99 compatible compiler])
fi

AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_PROG_INSTALL
AC_PROG_YACC
if test "x${YACC}" != "xbison -y"; then
        echo "AIDE requires GNU bison"
        exit 5
fi

AC_PROG_LEX
if test "x${LEX}" != "xflex"; then
        echo "AIDE requires GNU flex"
        exit 5
fi
AC_CHECK_PROGS(LD, ld)

AC_PATH_TOOL([PKG_CONFIG], [pkg-config], [no])
AM_PROG_CC_C_O

AC_SYS_LARGEFILE

dnl AC_ARG_PROGRAM

AC_ARG_WITH(extra-includes,
	AC_HELP_STRING([--with-extra-includes],
		[Specify additional paths with -I to find headerfiles]),
	[CPPFLAGS="$CPPFLAGS $withval"]
)
AC_ARG_WITH(extra-libs,
	AC_HELP_STRING([--with-extra-libs],
		[Specify additional paths with -L to find libraries]),
	[LDFLAGS="$LDFLAGS $withval"]
)
AC_ARG_WITH(extra-link-libs,
	AC_HELP_STRING([--with-extra-link-libs],
		[Specify additional libraries to link]),
	[LIBS="$LIBS $withval"]
)

dnl Do the right thing for glibc...
AIDE_DEFS="-D_GNU_SOURCE"

dnl This is borrowed from libtool
    
if test $ac_cv_prog_gcc = yes; then
    LD_STATIC_FLAG='-static'

    case "$host_os" in
    beos* | irix5* | irix6* | osf3* | osf4* | osf5*)
	# PIC is the default for these OSes.
	;;
    aix*)
	# Below there is a dirty hack to force normal static linking with -ldl
	# The problem is because libdl dynamically linked with both libc and
	# libC (AIX C++ library), which obviously doesn't included in libraries
	# list by gcc. This cause undefined symbols with -static flags.
	# This hack allows C programs to be linked with "-static -ldl", but
	# we not sure about C++ programs.
	LD_STATIC_FLAG="$LD_STATIC_FLAG ${wl}-lC"
	;;
    cygwin* | mingw* | os2*)
	# We can build DLLs from non-PIC.
	;;
    amigaos*)
	# FIXME: we need at least 68020 code to build shared libraries, but
	# adding the `-m68020' flag to GCC prevents building anything better,
	# like `-m68040'.
	## pic_flag='-m68020 -resident32 -malways-restore-a4'
	;;
    sysv4*MP*)
	## if test -d /usr/nec; then
	## pic_flag=-Kconform_pic
	## fi
	;;
    *)
	## pic_flag='-fPIC'
	;;
    esac
else
    # PORTME Check for PIC flags for the system compiler.
    case "$host_os" in
    aix3* | aix4*)
	# All AIX code is PIC.
	LD_STATIC_FLAG='-bnso -bI:/lib/syscalls.exp'
	;;
	
    hpux9* | hpux10* | hpux11*)
	# Is there a better LD_STATIC_FLAG that works with the bundled CC?
	## wl='-Wl,'
	LD_STATIC_FLAG="${wl}-a ${wl}archive"
	## pic_flag='+Z'
	;;
	
    irix5* | irix6*)
	## wl='-Wl,'
	LD_STATIC_FLAG='-non_shared'
	# PIC (with -KPIC) is the default.
	;;
	
    cygwin* | mingw* | os2*)
	# We can build DLLs from non-PIC.
	;;
	
    osf3* | osf4* | osf5*)
	# All OSF/1 code is PIC.
	## wl='-Wl,'
	LD_STATIC_FLAG='-non_shared'
	;;
	
    sco3.2v5*)
	## pic_flag='-Kpic'
	LD_STATIC_FLAG='-dn'
	## special_shlib_compile_flags='-belf'
	;;
	
    solaris*)
	## pic_flag='-KPIC'
	LD_STATIC_FLAG='-Bstatic'
	## wl='-Wl,'
	;;
	
    sunos4*)
	## pic_flag='-PIC'
	LD_STATIC_FLAG='-Bstatic'
	## wl='-Qoption ld '
	;;
	
    sysv4 | sysv4.2uw2* | sysv4.3* | sysv5*)
	## pic_flag='-KPIC'
	LD_STATIC_FLAG='-Bstatic'
	## wl='-Wl,'
	;;
	
    uts4*)
	## pic_flag='-pic'
	LD_STATIC_FLAG='-Bstatic'
	;;
    sysv4*MP*)
	if test -d /usr/nec ;then
	## pic_flag='-Kconform_pic'
	LD_STATIC_FLAG='-Bstatic'
	fi
	;;
    *)
	## can_build_shared=no
	;;
    esac
fi

# Check whether static linking has explicitly been disabled
AC_ARG_ENABLE(static,[  --disable-static        Disable static linking (lowers the security of aide)], [aide_static_choice=$enableval], [aide_static_choice=yes])

dnl Borrowed from dbus
cc_supports_flag() {
  AC_MSG_CHECKING(whether $CC supports "$@")
  Cfile=/tmp/foo${$}
  touch ${Cfile}.c
  $CC -c "$@" ${Cfile}.c -o ${Cfile}.o >/dev/null 2>&1
  rc=$?
  rm -f ${Cfile}.c ${Cfile}.o
  case $rc in
    0) AC_MSG_RESULT(yes);;
    *) AC_MSG_RESULT(no);;
  esac
  return $rc
}

dnl Borrowed from dbus
ld_supports_flag() {
  AC_MSG_CHECKING([whether $LD supports "$@"])
  AC_TRY_LINK([
    int one(void) { return 1; }
    int two(void) { return 2; }
  ], [ two(); ] , [_ac_ld_flag_supported=yes], [_ac_ld_flag_supported=no])

  if test "$_ac_ld_flag_supported" = "yes"; then
    rm -f conftest.c
    touch conftest.c
    if $CC -c conftest.c; then
      ld_out=`$LD $@ -o conftest conftest.o 2>&1`
      ld_ret=$?
      if test $ld_ret -ne 0 ; then
        _ac_ld_flag_supported=no
      elif echo "$ld_out" | egrep 'option ignored|^usage:|unrecognized option|illegal option' >/dev/null ; then
        _ac_ld_flag_supported=no
      fi
    fi
    rm -f conftest.c conftest.o conftest
  fi

  AC_MSG_RESULT($_ac_ld_flag_supported)
  if test "$_ac_ld_flag_supported" = "yes" ; then
    return 0
  else
    return 1
  fi
}

if test "$aide_static_choice" != "yes"; then
  LD_STATIC_FLAG=""
  EXTRA_LDFLAGS=""
  EXTRA_CFLAGS=""
  if test x$CC = "xgcc"; then
    if ld_supports_flag -z,relro; then
      EXTRA_LDFLAGS="$EXTRA_LDFLAGS -Wl,-z,relro"
    fi
    if ld_supports_flag -z,now; then
      EXTRA_LDFLAGS="$EXTRA_LDFLAGS -Wl,-z,now"
    fi
    if cc_supports_flag -fPIE -DPIE; then
      EXTRA_CFLAGS="$EXTRA_CFLAGS -fPIE -DPIE"
      EXTRA_LDFLAGS="$EXTRA_LDFLAGS -pie"
    fi
    dnl Check for some optional warnings
    if cc_supports_flag -Wundef; then
      EXTRA_CFLAGS="$EXTRA_CFLAGS -Wundef"
    fi
    if cc_supports_flag -Wmissing-format-attribute; then
      EXTRA_CFLAGS="$EXTRA_CFLAGS -Wmissing-format-attribute"
    fi
    if cc_supports_flag -Wshadow; then
      EXTRA_CFLAGS="$EXTRA_CFLAGS -Wshadow"
    fi
    if cc_supports_flag -Wlogical-op; then
      EXTRA_CFLAGS="$EXTRA_CFLAGS -Wlogical-op"
    fi
  fi
fi

dnl This macro is new in autoconf-2.13
AC_SEARCH_LIBS(syslog, bsd socket inet, [AC_DEFINE(HAVE_SYSLOG,1,[syslog available?])])
AC_CHECK_FUNCS(vsyslog)

AC_C_BIGENDIAN([AC_DEFINE(BIG_ENDIAN_HOST,1,[big endian])], [AC_DEFINE(LITTLE_ENDIAN_HOST,1,[little endian])])

AC_CHECK_TYPES([byte, ushort, ulong, u16, u32, u64])

AC_CHECK_SIZEOF(unsigned short, 2)
AC_CHECK_SIZEOF(unsigned int, 4)
AC_CHECK_SIZEOF(unsigned long, 4)
AC_CHECK_SIZEOF(unsigned long long, 8)

AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(long long)

AC_CHECK_SIZEOF(uid_t)
AC_CHECK_SIZEOF(gid_t)
AC_CHECK_SIZEOF(ino_t)
AC_CHECK_SIZEOF(nlink_t)
AC_CHECK_SIZEOF(off_t)
AC_CHECK_SIZEOF(blkcnt_t)

AC_C_LONG_DOUBLE

AC_HEADER_STDC
AC_CHECK_FUNCS(strtoll strtoimax readdir)
AC_CHECK_FUNCS(stricmp strnstr strnlen)

AC_ARG_WITH([mmap],
	[AC_HELP_STRING([--with-mmap],
		[use mmap @<:@default=check@:>@])],
	[],
	[with_mmap=check]
)

AS_IF([test "x$with_mmap" != xno],
	[AC_CHECK_FUNCS(mmap)]
	compoptionstring="${compoptionstring}WITH_MMAP\\n"
)

AC_CHECK_FUNCS(fcntl ftruncate posix_fadvise asprintf snprintf \
	vasprintf vsnprintf va_copy __va_copy)

# Linux has the O_NOATIME flag, sometimes
AC_CACHE_CHECK([for open/O_NOATIME], db_cv_open_o_noatime, [
echo "test for working open/O_NOATIME" > __o_noatime_file
AC_TRY_RUN([
#include <sys/types.h>
#include <fcntl.h>
#ifndef O_NOATIME
#if defined(__linux__) && (defined(__i386__) || defined(__PPC__))
#define O_NOATIME 01000000
#else
#define O_NOATIME 0
#endif
#endif
main() {
int c, fd = open("__o_noatime_file", O_RDONLY | O_NOATIME, 0);
exit ((!O_NOATIME) || (fd == -1) || (read(fd, &c, 1) != 1));
}], [db_cv_open_o_noatime=yes], [db_cv_open_o_noatime=no],
AC_TRY_LINK([
#include <sys/types.h>   
#include <fcntl.h>
#ifndef O_NOATIME
#if defined(__linux__) && (defined(__i386__) || defined(__PPC__))
#define O_NOATIME 01000000
#else
#define O_NOATIME 0
#endif
#endif], [
	open("__o_noatime_file", O_RDONLY | O_NOATIME, 0);
], [db_cv_open_o_noatime=yes], [db_cv_open_o_noatime=no]))
rm -f __o_noatime_file])
if test "$db_cv_open_o_noatime" = yes; then
	AC_DEFINE(HAVE_O_NOATIME)
	AH_TEMPLATE(HAVE_O_NOATIME, [Define to 1 if you have the O_NOATIME flag.])
fi

AC_CHECK_HEADERS(syslog.h inttypes.h fcntl.h ctype.h)

PCRELIB="-lpcre"
if test "$aide_static_choice" == "yes"; then
    PCRELIB="$PCRELIB -pthread"
fi
AC_CHECK_LIB(pcre, pcre_exec, [
    compoptionstring="${compoptionstring}WITH_PCRE\\n"
    ], [AC_MSG_ERROR([You don't have pcre library properly installed.])]
    )
AC_SUBST(PCRELIB)

AC_ARG_WITH([locale],
	[AC_HELP_STRING([--with-locale],
		[use locale stuff])],
	[],
	[with_locale=no]
)

AS_IF([test "x$with_locale" != xno],
	[AC_CHECK_HEADERS(libintl.h,
		[AC_DEFINE(USE_LOCALE,1,[Define if LOCALE support should be used])
		AIDE_USE_LOCALE=""
		compoptionstring="${compoptionstring}WITH_LOCALE\\n"
dnl        	AC_DEFINE_UNQUOTED(LOCALEDIR,"$prefix/lib/locale",[Localedir to use])],
	)]
)

AC_SUBST(AIDE_USE_LOCALE)

AC_ARG_WITH([syslog_ident],
	AC_HELP_STRING([--with-syslog-ident],
	[syslog ident]),
  	[AC_DEFINE_UNQUOTED(AIDE_IDENT,"$withval",[syslog ident])]
		compoptionstring="${compoptionstring}AIDE_IDENT=${withval}\\n",
  	[AC_DEFINE_UNQUOTED(AIDE_IDENT,"aide",[syslog ident])]
)

AC_ARG_WITH([syslog_facility],
	AC_HELP_STRING([--with-syslog-facility],
		[Specify syslog facility, see man syslog for options]),
	[AC_DEFINE_UNQUOTED(AIDE_SYSLOG_FACILITY,$withval,[syslog facility])]
	compoptionstring="${compoptionstring}AIDE_SYSLOG_FACILITY=${withval}\\n",
	[AC_DEFINE_UNQUOTED(AIDE_SYSLOG_FACILITY,LOG_LOCAL0,[syslog facility])]
)

AC_ARG_WITH([syslog_logopt],
	AC_HELP_STRING([--with-syslog-logopt],
		[Specify syslog logopt, see man syslog for options]),
	[AC_DEFINE_UNQUOTED(AIDE_LOGOPT,$withval,[syslog logopt])],
	[AC_DEFINE_UNQUOTED(AIDE_LOGOPT,LOG_CONS,[syslog logopt])]
)

AC_ARG_WITH([syslog_priority],
	AC_HELP_STRING([--with-syslog-priority],
		[Specify syslog priority, see man syslog for options]),
	[AC_DEFINE_UNQUOTED(SYSLOG_PRIORITY,$withval,[syslog priority])]
	compoptionstring="${compoptionstring}SYSLOG_PRIORITY=${withval}\\n",
	[AC_DEFINE_UNQUOTED(SYSLOG_PRIORITY,LOG_NOTICE,[syslog priority])]
)


AC_ARG_WITH([zlib],
	AC_HELP_STRING([--with-zlib],
		[use zlib compression]),
	,
	[with_zlib=yes]
)

AC_MSG_CHECKING(for posix-acl-support)
AC_ARG_WITH([posix-acl],
	[AC_HELP_STRING([--with-posix-acl],
		[use POSIX ACLs (no checking)])],
	[],
	[with_posix_acl_support=no]
)

AS_IF([test "x$with_posix_acl_support" != xno],
	[AC_DEFINE(WITH_POSIX_ACL,1,[use POSIX ACLs])
	AC_DEFINE(WITH_ACL,1,[use ACL])
	ACLLIB="-lacl"
	compoptionstring="${compoptionstring}WITH_POSIX_ACL\\n"
	aideextragroups="${aideextragroups}+acl"
	AC_MSG_RESULT(yes)],
	[AC_MSG_RESULT(no)]
)

AC_SUBST(ACLLIB)

AC_MSG_CHECKING(for selinux-support)
AC_ARG_WITH([selinux],
	[AC_HELP_STRING([--with-selinux],
		[use SELinux (no checking)])],
	[with_selinux_support="$withval"],
	[with_selinux_support=no]
)

AS_IF([test "x$with_selinux_support" != xno],
    AC_DEFINE(WITH_SELINUX,1,[use SELinux])
    [AC_MSG_RESULT(yes)
    if test "x$PKG_CONFIG" != xno && $PKG_CONFIG --exists libselinux; then
        if test "$aide_static_choice" == "yes"; then
            SELINUXLIB=$(${PKG_CONFIG} --libs libselinux --static)
        else
            SELINUXLIB=$(${PKG_CONFIG} --libs libselinux)
        fi
    else
    SELINUXLIB="-lselinux"
    if test "$aide_static_choice" == "yes"; then
        saveLIBS=$LIBS
        LIBS="-static $SELINUXLIB"
        AC_SEARCH_LIBS([lgetfilecon_raw], [], [], [SELINUXLIB="$SELINUXLIB -lpthread"])
        LIBS=$saveLIBS
    fi
    fi
	compoptionstring="${compoptionstring}WITH_SELINUX\\n"
	aideextragroups="${aideextragroups}+selinux"
    ],
	[AC_MSG_RESULT(no)]
)

AC_SUBST(SELINUXLIB)


AC_MSG_CHECKING(for prelink-support)
AC_ARG_WITH([prelink], 
            [AC_HELP_STRING([--with-prelink],[use prelink (no checking)])],
            [case $with_prelink in 
		yes) AC_DEFINE_UNQUOTED(PRELINK_PATH, "/usr/sbin/prelink", [path to prelink])
		     AC_DEFINE(WITH_PRELINK,1,[use prelink])
		     ELFLIB="-lelf"
		     compoptionstring="${compoptionstring}WITH_PRELINK\\n"
		     AC_MSG_RESULT([/usr/sbin/prelink])
		     ;;
		no)  AC_MSG_RESULT(no)
		     ;;
		*)   AC_DEFINE_UNQUOTED(PRELINK_PATH, "$with_prelink", [path to prelink])
		     AC_DEFINE(WITH_PRELINK,1,[use prelink])
		     ELFLIB="-lelf"
		     compoptionstring="${compoptionstring}WITH_PRELINK\\n"
		     AC_MSG_RESULT([$with_prelink])
		     ;;
	     esac],
	    [with_prelink=no
			AC_MSG_RESULT(no)
			]
)
AC_SUBST(ELFLIB)

AC_MSG_CHECKING(for xattr-support)
AC_ARG_WITH([xattr],
	[AC_HELP_STRING([--with-xattr],
		[use xattr (no checking)])],
	[with_xattr_support="$withval"],
	[with_xattr_support=no]
)
	
AS_IF([test "x$with_xattr_support" != xno],
	[AC_DEFINE(WITH_XATTR,1,[use xattr])
	ATTRLIB=-lattr
	compoptionstring="${compoptionstring}WITH_XATTR\\n"
	aideextragroups="${aideextragroups}+xattrs"
	AC_MSG_RESULT(yes)],
	[AC_MSG_RESULT(no)]
)

AC_SUBST(ATTRLIB)

AC_MSG_CHECKING(for capabilities-support)
AC_ARG_WITH([capabilities],
        [AC_HELP_STRING([--with-capabilities],
                [use caps (no checking)])],
        [with_capabilities_support="$withval"],
        [with_capabilities_support=no]
)

AS_IF([test "x$with_capabilities_support" != xno],
        [AC_DEFINE(WITH_CAPABILITIES,1,[use capabilities])
        CAPLIB=-lcap
        compoptionstring="${compoptionstring}WITH_CAPABILITIES\\n"
        aideextragroups="${aideextragroups}+caps"
        AC_MSG_RESULT(yes)],
        [AC_MSG_RESULT(no)]
)

AC_SUBST(CAPLIB)

AC_MSG_CHECKING(for e2fsattrs-support)
AC_ARG_WITH([e2fsattrs],
	[AC_HELP_STRING([--with-e2fsattrs],
		[use e2fsattrs (no checking)])],
	[with_e2fsattrs_support="$withval"],
	[with_e2fsattrs_support=no]
)

AS_IF([test "x$with_e2fsattrs_support" != xno],
	[AC_DEFINE(WITH_E2FSATTRS,1,[use e2fsattrs])
	E2FSATTRSLIB=-le2p
	compoptionstring="${compoptionstring}WITH_E2FSATTRS\\n"
	aideextragroups="${aideextragroups}+e2fsattrs"
	AC_MSG_RESULT(yes)],
	[AC_MSG_RESULT(no)]
)

AC_SUBST(E2FSATTRSLIB)

PKG_CHECK_MODULES(CHECK, [check >= 0.9.4], , [AC_MSG_RESULT([Check not found (testing via 'make check' disabled)])])
AM_CONDITIONAL(HAVE_CHECK, [test "x$CHECK_LIBS" != "x"])

AC_ARG_WITH([config_file],
	AC_HELP_STRING([--with-config-file=config-file],
    [specify default config file (use --without-config-file to disable default config file)]),
    [with_config_file=$withval],[with_config_file=yes])

if test "$with_config_file" != "no"; then
    if test "$with_config_file" != "yes"; then
        config_file=$with_config_file
    else
        if test "x$sysconfdir" != x'${prefix}/etc'; then
            config_file=`eval echo "$sysconfdir/aide.conf"`
        elif test "x$prefix" != xNONE; then
            config_file="$prefix/etc/aide.conf"
        else
            config_file="$ac_default_prefix/etc/aide.conf"
        fi
    fi
    AC_DEFINE_UNQUOTED(CONFIG_FILE,"$config_file",[Location of configuration file])
fi

if test "x$sysconfdir" != x'${prefix}/etc'; then
	evalled_sysconfdir=`eval echo "$sysconfdir"`
	default_db="$evalled_sysconfdir/aide.db"
	default_db_out="$evalled_sysconfdir/aide.db.new"
elif test "x$prefix" != xNONE; then
	default_db="$prefix/etc/aide.db"
	default_db_out="$prefix/etc/aide.db.new"
else
	default_db="$ac_default_prefix/etc/aide.db"
	default_db_out="$ac_default_prefix/etc/aide.db.new"
fi

AC_DEFINE_UNQUOTED(DEFAULT_DB,"$default_db",[Default location of signature database])
AC_DEFINE_UNQUOTED(DEFAULT_DB_OUT,"$default_db_out",[Default output location for newly-generated signature database])

dnl Do the library tests with the static flag
LDFLAGS="$LDFLAGS $LD_STATIC_FLAG"
if test x$with_zlib = xyes; then
  AC_CHECK_HEADERS(zlib.h,[],
 	[AC_MSG_ERROR([You don't have zlib properly installed. Install it or try --without-zlib.])])
  save_LDFLAGS=$LDFLAGS
  AC_CHECK_LIB(z, deflate,[],
 	  [AC_MSG_ERROR([You don't have zlib properly installed. Install it or try --without-zlib.])]
  )
  AC_DEFINE(WITH_ZLIB,1,[use zlib])
  compoptionstring="${compoptionstring}WITH_ZLIB\\n"
fi

AC_ARG_WITH([curl],
 AS_HELP_STRING([--with-curl],
  [use curl library for http, https and ftp database backend (default: no)]),
 [with_curl=$withval], [with_curl=no])
AS_IF([test "x$with_curl" = "xyes"], [
       if test "$aide_static_choice" == "yes"; then
           PKG_CHECK_MODULES_STATIC(CURL, [libcurl], , [AC_MSG_RESULT([libcurl not found by pkg-config - Try --without-curl or add directory containing libcurl.pc to PKG_CONFIG_PATH environment variable])])
        else
           PKG_CHECK_MODULES(CURL, [libcurl], , [AC_MSG_RESULT([libcurl not found by pkg-config - Try --without-curl or add directory containing libcurl.pc to PKG_CONFIG_PATH environment variable])])
        fi
        AC_DEFINE(WITH_CURL,1,[Define to 1 if libcurl is available])
        compoptionstring="${compoptionstring}WITH_CURL\\n"
])
AM_CONDITIONAL(USE_CURL, [test "x$CURL_LIBS" != "x"])

AC_ARG_WITH(mhash,
	AC_HELP_STRING([--with-mhash],
		[use libmhash, needed for hmacs @<:@default=check@:>@]),
	[],
	[with_mhash=check]
)

AS_IF([test "x$with_mhash" != xno],
	AC_CHECK_LIB([mhash],[mhash_get_block_size],
		[CRYPTLIB="${CRYPTLIB} -lmhash"
		compoptionstring="${compoptionstring}WITH_MHASH\\n"
		with_mhash=yes
		aideextragroups="${aideextragroups}+whirlpool"
		AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
		[[#include <mhash.h>
		int i=MHASH_WHIRLPOOL;
		]])],AC_DEFINE(HAVE_MHASH_WHIRLPOOL,1,[mhash has whirlpool]))
		AC_DEFINE(WITH_MHASH,1,[use mhash library])],
		[AC_MSG_WARN(No mhash means no hmac.)]
	)
)

AC_ARG_WITH([gcrypt],
	[AC_HELP_STRING([--with-gcrypt],
		[use gcrypt library])],
		[],
		[if test "x$with_mhash" != xyes; then
			with_gcrypt=check
		else
			with_gcrypt=no
		fi]
)

AS_IF([test "x$with_gcrypt" != xno],
	[AC_DEFINE(WITH_GCRYPT,1,[use gcrypt library])
	if test "x$with_mhash" = xyes; then
		AC_MSG_ERROR([Using gcrypt together with mhash makes no sense. To disable mhash use --without-mhash])
	fi
	AC_CHECK_LIB([gpg-error], [gpg_strerror],
		[saveLIBS="$LIBS"
		LIBS="$LIBS -lgpg-error"
		AC_CHECK_LIB([gcrypt], [gcry_md_hash_buffer],[],
			AC_MSG_ERROR([Aide requires mhash or libcrypt to be installed with static libraries.])
		)
		LIBS="$saveLIBS"],
		[AC_MSG_ERROR([You need to have libgpg-error.a installed to use libgcrypt.])]
	)
	CRYPTLIB="${CRYPTLIB} -lgcrypt -lgpg-error"
	with_gcrypt=yes
	compoptionstring="${compoptionstring}WITH_GCRYPT\\n"],
	[with_gcrypt=no]
)

AC_SUBST(CRYPTLIB)

# Check for Linux auditing API
#
AC_ARG_WITH([audit],
	[AC_HELP_STRING([--with-audit],
		[use audit library])],
	[],
	[with_audit=no]
)

AS_IF([test "x$with_audit" != xno],
	[AC_DEFINE(WITH_AUDIT,1,[use audit library])
	AC_CHECK_HEADER(libaudit.h,,
		AC_MSG_ERROR(You don't have libaudit properly installed. Install it if you need it.)
	)
	AUDITLIB="-laudit"
	if test "$aide_static_choice" == "yes"; then
		saveLIBS=$LIBS
		LIBS="-static $AUDITLIB"
		AC_CHECK_LIB([audit], [audit_log_user_message], [], [
			LIBS="$LIBS -lcap-ng"
			AC_CHECK_LIB([cap-ng], [audit_log_user_message], [AUDITLIB="$AUDITLIB -lcap-ng"],
			AC_MSG_ERROR([You don't have libaudit properly installed. Install it or try --without-audit.])
			, [])
		], [])
		LIBS=$saveLIBS
	fi
	compoptionstring="${compoptionstring}WITH_AUDIT\\n"],
	[with_audit=no]
)
AC_SUBST(AUDITLIB)

extrasub="s&@aideextragroups@&$aideextragroups&;t t
s&@AIDEVERSION@&$PACKAGE_VERSION&;t t"

AC_DEFINE_UNQUOTED(AIDECOMPILEOPTIONS, "${compoptionstring}",[Compile-time options displayed in -v output])

dnl Add in the optional compiler features
LDFLAGS="$LDFLAGS $EXTRA_LDFLAGS"
CFLAGS="$CFLAGS $EXTRA_CFLAGS"

AC_SUBST(AIDE_DEFS)
AC_OUTPUT(Makefile doc/aide.conf doc/aide.1 doc/aide.conf.5)

