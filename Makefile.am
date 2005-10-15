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

SUBDIRS = src doc po

CLEANFILES = *~

check: all
	src/aide -c doc/aide.conf -V20

update-db: all
	src/aide -B "database_out=file://$(top_srcdir)/doc/aide.db" -c doc/aide.conf -i

dist-hook: 
	mkdir $(distdir)/include
	cp -p   include/aide.h\
		include/base64.h\
		include/be.h\
		include/commandconf.h\
		include/compare_db.h\
		include/conf_lex.h\
		include/db.h\
		include/db_config.h\
		include/db_disk.h\
		include/db_file.h\
		include/db_list.h\
		include/db_sql.h\
		include/do_md.h\
		include/gen_list.h\
		include/getopt.h\
		include/gnu_regex.h\
		include/list.h\
		include/locale-aide.h\
		include/md.h\
		include/report.h\
		include/seltree.h\
		include/snprintf.h\
		include/symboltable.h\
		include/types.h\
		include/url.h\
		include/util.h\
		$(distdir)/include

	rm 	$(distdir)/src/conf_yacc.c\
		$(distdir)/src/conf_lex.c
