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

# This is no longer needed
# SUBDIRS = crypt

bin_PROGRAMS = aide

aide_SOURCES =	\
		conf_yacc.y	\
		conf_lex.l	\
		getopt.c	\
		getopt1.c	\
		gnu_regex.c	\
		error.c		\
		md.c		\
		db.c		\
		commandconf.c	\
		db_file.c	\
		db_disk.c	\
		db_lex.l	\
		db_sql.c	\
		gen_list.c	\
		list.c		\
		do_md.c		\
		base64.c	\
		symboltable.c	\
		compare_db.c	\
		be.c		\
		util.c		\
		aide.c

INCLUDES = -I$(prefix)/include -I$(top_srcdir)/include

LDADD = @CRYPTLIB@ @ACLLIB@

LDFLAGS = @LDFLAGS@ @LD_STATIC_FLAG@

CFLAGS = @CFLAGS@ @MAINTAINER_MODE_TRUE@ -Wall -g

CLEANFILES = conf_yacc.h conf_yacc.c conf_lex.c db_lex.c *~
LEX_OUTPUT_ROOT = lex.yy

YFLAGS= -d

db_lex.c:db_lex.l
	${LEX} -Pdb -odb_lex.c $(top_srcdir)/src/db_lex.l

conf_yacc.c:conf_yacc.y
	${YACC} ${YFLAGS} -p conf -o conf_yacc.c $(top_srcdir)/src/conf_yacc.y

conf_lex.c:conf_lex.l
	${LEX} -Pconf -oconf_lex.c $(top_srcdir)/src/conf_lex.l
