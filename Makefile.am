#
# AIDE (Advanced Intrusion Detection Environment)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

BUILT_SOURCES = src/conf_yacc.h
AM_YFLAGS= -d

LEX_OUTPUT_ROOT = lex.yy

bin_PROGRAMS = aide
aide_SOURCES = src/aide.c include/aide.h \
	include/base64.h src/base64.c \
	include/be.h src/be.c \
	include/commandconf.h src/commandconf.c \
	include/attributes.h src/attributes.c \
	include/report.h src/report.c \
	include/report_plain.h src/report_plain.c \
	include/report_json.h src/report_json.c \
	include/conf_ast.h src/conf_ast.c \
	include/conf_eval.h src/conf_eval.c \
	include/conf_lex.h src/conf_lex.l  \
	src/conf_yacc.h src/conf_yacc.y \
	include/db.h src/db.c \
	include/db_line.h include/db_config.h \
	include/db_disk.h src/db_disk.c \
	include/db_file.h src/db_file.c \
	include/db_lex.h src/db_lex.l \
	include/db_list.h src/db_list.c \
	include/do_md.h src/do_md.c \
	include/errorcodes.h \
	include/gen_list.h src/gen_list.c \
	src/getopt1.c \
	include/getopt.h src/getopt.c \
	include/hashsum.h src/hashsum.c \
	include/rx_rule.h src/rx_rule.c \
	include/list.h src/list.c \
	include/log.h src/log.c \
	include/locale-aide.h \
	include/md.h src/md.c \
	include/queue.h src/queue.c \
	include/seltree_struct.h \
	include/seltree.h src/seltree.c \
	include/symboltable.h src/symboltable.c \
	include/url.h src/url.c\
	include/util.h src/util.c
if HAVE_E2FSATTRS
aide_SOURCES += include/e2fsattrs.h src/e2fsattrs.c
endif
if HAVE_CURL
aide_SOURCES += include/fopen.h src/fopen.c
endif

aide_CFLAGS = @AIDE_DEFS@ -W -Wall -g ${PTHREAD_CFLAGS}
aide_LDADD = -lm ${PCRE2_LIBS} ${ZLIB_LIBS} ${MHASH_LIBS} ${GCRYPT_LIBS} ${POSIX_ACL_LIBS} ${SELINUX_LIBS} ${AUDIT_LIBS} ${XATTR_LIBS} ${ELF_LIBS} ${E2FSATTRS_LIBS} ${CAPABILITIES_LIBS} ${CURL_LIBS} ${PTHREAD_LIBS}

if HAVE_CHECK
TESTS				= check_aide
check_PROGRAMS		= check_aide
check_aide_SOURCES	= tests/check_aide.c tests/check_aide.h \
					  tests/check_attributes.c src/attributes.c \
					  src/log.c src/util.c
check_aide_CFLAGS	= -I$(top_srcdir)/include $(CHECK_CFLAGS)
check_aide_LDADD	= -lm ${PCRE2_LIBS} ${MHASH_LIBS} ${GCRYPT_LIBS} $(CHECK_LIBS)
endif # HAVE_CHECK

AM_CFLAGS = @AIDE_DEFS@ -W -Wall -g
AM_CPPFLAGS = -I$(top_srcdir) \
			  -I$(top_srcdir)/include \
			  -I$(top_srcdir)/src \
			  -I$(top_builddir)/src

CLEANFILES = src/conf_yacc.h src/conf_yacc.c src/conf_lex.c src/db_lex.c

man_MANS = doc/aide.1 doc/aide.conf.5

EXTRA_DIST = $(man_MANS) SECURITY.md

src/conf_yacc.c: src/conf_yacc.y
	$(YACC) $(AM_YFLAGS) -Wno-yacc -Wall -Werror -o $@ -p conf $<

src/conf_lex.c: src/conf_lex.l src/conf_yacc.c
	$(LEX) $(AM_LFLAGS) -o$@ -Pconf $<

src/db_lex.c: src/db_lex.l src/conf_yacc.h
	$(LEX) $(AM_LFLAGS) -o$@ -Pdb $<

autoreconf-clean: maintainer-clean
	-rm -f INSTALL Makefile.in aclocal.m4 compile config.guess \
	 include/config.h.in include/config.h.in~ config.sub configure depcomp \
	 install-sh missing version.m4 ylwrap
