#
# aide, Advanced Intrusion Detection Environment
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.
#

BUILT_SOURCES = src/conf_yacc.h
AM_YFLAGS= -d

LEX_OUTPUT_ROOT = lex.yy

bin_PROGRAMS = aide
aide_SOURCES = src/aide.c include/aide.h \
	include/base64.h src/base64.c \
	include/be.h src/be.c \
	include/commandconf.h src/commandconf.c \
	include/compare_db.h src/compare_db.c \
	include/conf_lex.h src/conf_lex.l  \
	src/conf_yacc.h src/conf_yacc.y \
	include/db.h src/db.c \
	include/db_config.h \
	include/db_disk.h src/db_disk.c \
	include/db_file.h src/db_file.c \
	src/db_lex.l \
	include/db_list.h src/db_list.c \
	include/db_sql.h src/db_sql.c \
	include/do_md.h src/do_md.c \
	include/report.h src/error.c \
	include/gen_list.h src/gen_list.c \
	src/getopt1.c \
	include/getopt.h src/getopt.c \
	include/list.h src/list.c \
	include/locale-aide.h \
	include/md.h src/md.c \
	src/snprintf.c \
	include/seltree.h \
	include/symboltable.h src/symboltable.c \
	include/types.h \
	include/url.h \
	include/util.h src/util.c
if USE_CURL
aide_SOURCES += include/fopen.h src/fopen.c
endif

aide_LDADD = -lm @PCRELIB@ @CRYPTLIB@ @ACLLIB@ @SELINUXLIB@ @AUDITLIB@ @ATTRLIB@ @E2FSATTRSLIB@ @ELFLIB@
AM_CFLAGS = @AIDE_DEFS@ -W -Wall -g
AM_CPPFLAGS = -I$(top_srcdir) \
			  -I$(top_srcdir)/include \
			  -I$(top_srcdir)/src \
			  -I$(top_builddir)/src

CLEANFILES = src/conf_yacc.h src/conf_yacc.c src/conf_lex.c src/db_lex.c

man_MANS = doc/aide.1 doc/aide.conf.5

EXTRA_DIST = $(man_MANS) Todo doc/manual.html \
	contrib/bzip2.sh contrib/gpg2_check.sh contrib/gpg2_update.sh \
	contrib/gpg_check.sh contrib/gpg_update.sh contrib/sshaide.sh \
	contrib/aide-attributes.sh

src/conf_yacc.c: src/conf_yacc.y
	$(YACC) $(AM_YFLAGS) -o $@ -p conf $<

src/conf_lex.c: src/conf_lex.l src/conf_yacc.c
	$(LEX) $(AM_LFLAGS) -o$@ -Pconf $<

src/db_lex.c: src/db_lex.l src/conf_yacc.h
	$(LEX) $(AM_LFLAGS) -o$@ -Pdb $<
