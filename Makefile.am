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

SUBDIRS = src doc

datadir = @datadir@
localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@

CLEANFILES = *~

DIST_SOURCES = src/conf_lex.l src/db_lex.l
DIST_SUBDIRS = $(SUBDIRS)
EXTRA_DIST = version.m4 Todo LICENSE-snprintf.txt README-snprintf

check: update-db
	src/aide -c doc/aide.conf -V20

update-db: all
	src/aide -B "database_out=file://$(top_srcdir)/doc/aide.db" -c doc/aide.conf -i

dist-hook: configure
	mkdir $(distdir)/include
	cp -p   include/*.h $(distdir)/include

	mkdir $(distdir)/contrib
	cp -p   contrib/[a-z]* $(distdir)/contrib

	rm -f	$(distdir)/src/conf_yacc.c $(distdir)/src/conf_yacc.h

