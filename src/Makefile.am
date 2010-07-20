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

bin_PROGRAMS = aide
noinst_HEADERS = conf_yacc.h
BUILT_SOURCES = conf_yacc.h

AM_YFLAGS= -d
#AM_LFLAGS= -d
LEX_OUTPUT_ROOT = lex.yy

LDADD = -lm @CRYPTLIB@ @ACLLIB@ @SELINUXLIB@ @AUDITLIB@ @ATTRLIB@ @E2FSATTRSLIB@ @ELFLIB@
AM_CFLAGS = @AIDE_DEFS@ -W -Wall -g

CLEANFILES = conf_yacc.h conf_yacc.c conf_lex.c db_lex.c *~

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include -I$(top_srcdir)/src \
	-I$(top_builddir)/src

aide_SOURCES =	aide.c		\
		base64.c	\
		be.c		\
		commandconf.c	\
		compare_db.c	\
		conf_lex.l 	\
		conf_yacc.y	\
		db.c		\
		db_disk.c	\
		db_file.c	\
		db_lex.l	\
		db_list.c	\
		db_sql.c	\
		do_md.c		\
		error.c		\
		gen_list.c	\
		getopt1.c	\
		getopt.c	\
		gnu_regex.c	\
		list.c		\
		md.c		\
		snprintf.c	\
		symboltable.c	\
		util.c 

if USE_CURL
aide_SOURCES += fopen.c
endif

conf_yacc.c: conf_yacc.y
	$(YACC) $(AM_YFLAGS) -o $@ -p conf $<

conf_lex.c: conf_lex.l conf_yacc.c
	$(LEX) $(AM_LFLAGS) -o$@ -Pconf $<

conf_lex2.c: conf_lex.c

db_lex.c: db_lex.l conf_yacc.h
	$(LEX) $(AM_LFLAGS) -o$@ -Pdb $<

db_lex2.c: db_lex.c

