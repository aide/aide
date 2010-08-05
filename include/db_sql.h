/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2002,2004,2006,2010 Rami Lehti, Pablo Virolainen,
 * Richard van den Berg
 * $Header$
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _DB_SQL_H_INCLUDED
#define _DB_SQL_H_INCLUDED


static const char* db_sql_types[] = {
   "text unique primary key",/* "name",   */
   "text", 	         /* "lname",   */
   "int", 	         /* "perm",    */
   "int", 	         /* "uid",     */
   "int", 	         /* "gid",     */
   "bigint",         /* "size",    */
   "text", 	         /* "atime",   */
   "text", 	         /* "ctime",   */
   "text", 	         /* "mtime",   */
   "int", 	         /* "inode",   */
   "int", 	         /* "bcount",  */
   "int", 	         /* "lcount",  */
   "text", 	         /* "md5",     */
   "text", 	         /* "sha1",    */
   "text", 	         /* "rmd160",  */
   "text", 	         /* "tiger",   */
   "text", 	         /* "crc32",   */
   "text", 	         /* "haval",   */
   "text", 	         /* "gost",    */
   "text", 	         /* "crc32b",  */
   "int",                /* "attr",    */
   "text",               /* "acl",     */
   "int",                /* "checkmask",     */
   "text" 	         /* "unknown"  */
};

int db_close_sql(void*);
db_line* db_readline_sql(int db, db_config* conf);
int db_writeline_sql(db_line* line,db_config* conf);
int db_writespec_sql(db_config* conf);

#endif
