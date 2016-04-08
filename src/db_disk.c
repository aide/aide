/* aide, Advanced Intrusion Detection Environment
 * vi: ts=2 sw=2
 *
 * Copyright (C) 1999-2006,2010,2011,2016 Rami Lehti, Pablo Virolainen,
 * Richard van den Berg, Mike Markley, Hannes von Haugwitz
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

#include "aide.h"
#ifndef _POSIX_C_SOURCE
# define _POSIX_C_SOURCE 199506L
#endif
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <time.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>

#include "seltree.h"
#include "gen_list.h"
#include "types.h"
#include "base64.h"
#include "db_disk.h"
#include "conf_yacc.h"
#include "util.h"
#include "commandconf.h"
/*for locale support*/
#include "locale-aide.h"
/*for locale support*/

#ifdef WITH_MHASH
#include <mhash.h>
#endif

#ifdef WITH_ZLIB
#include <zlib.h>
#endif

static DIR *dirh = NULL;
static struct AIDE_DIRENT_TYPE *entp = NULL;
static struct AIDE_DIRENT_TYPE **resp = NULL;

static struct seltree *r = NULL;


#if defined HAVE_READDIR && !defined HAVE_READDIR_R
static long td = -1;
#endif
static int rdres = 0;

static int root_handled = 0;

static DIR *open_dir(char* path) {
   if (dirh != NULL) {
       if (closedir(dirh) != 0) {
           /* Closedir did not success? */
       }
   }
   return opendir(path);
}

static void next_in_dir (void)
{
#ifdef HAVE_READDIR_R
	if (dirh != NULL)
		rdres = AIDE_READDIR_R_FUNC (dirh, entp, resp);
#else
#ifdef HAVE_READDIR
	if (dirh != NULL) {
		entp = AIDE_READDIR_FUNC (dirh);
		if(entp!=NULL)
			td = telldir(dirh);
		else
			td=-1;
	}
#endif
#endif

}

static int in_this (void)
{
#ifdef HAVE_READDIR_R
	return (dirh != NULL && rdres == 0 && (*resp) != NULL);
#else
#ifdef HAVE_READDIR
	return (dirh != NULL && entp != NULL && td >= 0);
#endif
#endif
}

static char *name_construct (const char *s)
{
	char *ret;
	int len2 = strlen (r->path);
	int len = len2 + strlen (s) + 2 + conf->root_prefix_length;

	if (r->path[len2 - 1] != '/') {
		len++;
	}

	ret = (char *) malloc (len);
	ret[0] = (char) 0;
	strncpy(ret, conf->root_prefix, conf->root_prefix_length+1);
	strncat (ret, r->path, len2);
	if (r->path[len2 - 1] != '/') {
		strncat (ret, "/", 1);
	}
	strcat (ret, s);
	return ret;
}

void add_child (db_line * fil)
{
	int i;
	struct seltree *new_r;

	error (255, "Adding child %s\n", fil->filename);

	new_r = get_seltree_node (r, fil->filename);
	if (new_r != NULL) {
		if (S_ISDIR (fil->perm_o)) {
			;
		} else {
			new_r->checked |= NODE_CHECKED;
			new_r->checked |= NODE_TRAVERSE;
		}
		return;
	}

	new_r = malloc (sizeof (seltree));

	new_r->attr = 0;
	i = strlen (fil->filename);

	new_r->path = malloc (i + 1);
	strncpy(new_r->path, fil->filename, i+1);
	new_r->childs = NULL;
	new_r->sel_rx_lst = NULL;
	new_r->neg_rx_lst = NULL;
	new_r->equ_rx_lst = NULL;
	new_r->parent = r;
	new_r->checked = 0;
	new_r->new_data = NULL;
	new_r->old_data = NULL;
	if (S_ISDIR (fil->perm_o)) {
		;
	} else {
		new_r->checked |= NODE_CHECKED;
		new_r->checked |= NODE_TRAVERSE;
	}
	r->childs = list_sorted_insert (r->childs, new_r, compare_node_by_path);
}

static int get_file_status(char *filename, struct AIDE_STAT_TYPE *fs) {
    int sres = 0;
    sres = AIDE_LSTAT_FUNC(filename,fs);
    if(sres == -1){
        char* er = strerror(errno);
        if (er == NULL) {
            error(0,"get_file_status: lstat() failed for %s. strerror() failed for %i\n", filename, errno);
        } else {
            error(0,"get_file_status: lstat() failed for %s: %s\n", filename, er);
        }
    }
    return sres;
}

/*
  It might be a good idea to make this non recursive.
  Now implemented with goto-statement. Yeah, it's ugly and easy.
*/

db_line *db_readline_disk ()
{
	db_line *fil = NULL;
	DB_ATTR_TYPE attr;
	char *fullname;
	int add = 0;
	struct AIDE_STAT_TYPE fs;

	/* root needs special handling */
	if (!root_handled) {
		root_handled = 1;
		fullname=malloc((conf->root_prefix_length+2)*sizeof(char));
		strncpy(fullname, conf->root_prefix, conf->root_prefix_length+1);
		strncat (fullname, "/", 1);
		if (!get_file_status(&fullname[conf->root_prefix_length], &fs)) {
		add = check_rxtree (&fullname[conf->root_prefix_length], conf->tree, &attr, fs.st_mode);
		error (240, "%s match=%d, tree=%p, attr=%llu\n", &fullname[conf->root_prefix_length], add,
					 conf->tree, attr);

		if (add > 0) {
			fil = get_file_attrs (fullname, attr, &fs);

			error (240, "%s attr=%llu\n", &fullname[conf->root_prefix_length], attr);

			if (fil != NULL) {
				error (240, "%s attr=%llu\n", fil->filename, fil->attr);
				return fil;
			}
        }
		}
		free (fullname);
	}
recursion:
	next_in_dir ();

	if (in_this ()) {

		/*
		   Let's check if we have '.' or '..' entry.
		   If have, just skipit.
		   If don't do the 'normal' thing.
		 */
		if (strcmp (entp->d_name, ".") == 0 || strcmp (entp->d_name, "..") == 0) {
			goto recursion;						// return db_readline_disk(db);
		}

		/*
		   Now we know that we actually can do something.
		 */

		fullname = name_construct (entp->d_name);

		/*
		   Now we have a filename, which we must remember to free if it is
		   not used. 

		   Next thing is to see if we want to do something with it.
		   If not call, db_readline_disk again...
		 */

		if (get_file_status(&fullname[conf->root_prefix_length], &fs)) {
		    free (fullname);
		    goto recursion;
		}
		add = check_rxtree (&fullname[conf->root_prefix_length], conf->tree, &attr, fs.st_mode);
		error (240, "%s match=%d, tree=%p, attr=%llu\n", &fullname[conf->root_prefix_length], add,
					 conf->tree, attr);

		if (add > 0) {
			fil = get_file_attrs (fullname, attr, &fs);

			error (240, "%s attr=%llu\n", &fullname[conf->root_prefix_length], attr);

			if (fil != NULL) {
				error (240, "%s attr=%llu\n", fil->filename, fil->attr);
			} else {
				/*
				   Something went wrong during read process -> 
				   Let's try next one.
				 */
				free (fullname);
				goto recursion;					// return db_readline_disk(db);
			}

			if (add == 1) {
				/*
				   add_children -> if dir, then add to children list.
				 */
				/* If ee are adding a file that is not a dir */
				/* add_child can make the determination and mark the tree
				   accordingly
				 */
				add_child (fil);
			} else if (add == 2) {
				/*
				   Don't add to children list.
				 */

				/*
				   Should we do something?
				 */
			}
		} else {
			/*
			   Make us traverse the tree:)
			 */

			/*
			   We have no use for fullname.
			 */

			free (fullname);
			goto recursion;
		}
		/*
		   Make sure that next time we enter
		   we have something.
		 */
	} else {

		if (r == NULL) {
			return NULL;
		}

		error (255, "r->childs %p, r->parent %p, r->checked %i\n", r->childs,
					 r->parent, r->checked);

		if ((0 == (r->checked & NODE_CHECKED)) && r->childs != NULL) {
			seltree *rr;
			list *l;
			l = r->childs->header->head;

			while (l != NULL
						 && (((seltree *) (l->data))->checked & NODE_TRAVERSE) != 0) {
				l = l->next;
			}
			if (l != NULL) {
				if (l == l->header->tail) {
					r->checked |= NODE_CHECKED;
				}

				rr = (seltree *) l->data;

				error (255, "rr->checked %i\n", rr->checked);
				rr->checked |= NODE_TRAVERSE;

				r = rr;

				error (255, "r->childs %p, r->parent %p,r->checked %i\n",
							 r->childs, r->parent, r->checked);
				fullname=malloc((conf->root_prefix_length+strlen(r->path)+1)*sizeof(char));
				strncpy(fullname, conf->root_prefix, conf->root_prefix_length+1);
				strncat(fullname, r->path, strlen(r->path));
				dirh=open_dir(fullname);
				if (! dirh) {

					/* open_dir failed so we need to know why and print 
					   an errormessage if needed.
					   errno should still be the one from opendir() since it's global
					 */
					if (errno == ENOENT && r->old_data != NULL &&
							r->sel_rx_lst == NULL && r->neg_rx_lst == NULL &&
							r->equ_rx_lst == NULL) {
						/* The path did not exist and there is old data for this node
						   and there are no regexps for this node
						   There is no new data for this node otherwise it would not
						   come to this part of the code.
						   So we don't print any error message.
						 */
					} else if (errno == ENOENT &&
										 ((r->sel_rx_lst != NULL || r->neg_rx_lst != NULL ||
											r->equ_rx_lst != NULL) || r->childs != NULL)) {
						/* The dir did not exist and there are regexps referring to
						   this node or there are children to this node. 
						   The only way a nonexistent dirnode can have children is by 
						   having rules referring to them.
						 */
						error (10,
									 "There are rules referring to non-existent directory %s\n", fullname);
					} else if (errno != ENOTDIR) {
						/* We print the message unless it is "Not a directory". */
						char *er = strerror (errno);
						if (er != NULL) {
							error (3, "open_dir(): %s: %s\n", er, fullname);
						} else {
							error (3, "open_dir(): %i: %s\n", errno, fullname);
						}
					}
					r->checked |= NODE_TRAVERSE | NODE_CHECKED;
					r = r->parent;
					error (255, "dropping back to parent\n");
				}
				free(fullname);
			} else {
				r->checked |= NODE_TRAVERSE | NODE_CHECKED;
				r = r->parent;
				/* We have gone out of the tree. This happens in some instances */
				if (r == NULL) {
					return NULL;
				}
				error (255, "dropping back to parent\n");
			}
			goto recursion;
		}

		if (r->parent != NULL) {
			/*
			   Go back in time:)
			 */
			r->checked |= NODE_CHECKED;

			r = r->parent;

			goto recursion;
		}
		/*
		   The end has been reached. Nothing to do.
		 */
	}

	return fil;
}

int db_disk_init ()
{

	r = conf->tree;

#  ifdef HAVE_READDIR_R
	resp = (struct AIDE_DIRENT_TYPE **)
		malloc (sizeof (struct AIDE_DIRENT_TYPE) + _POSIX_PATH_MAX);
	entp = (struct AIDE_DIRENT_TYPE *)
		malloc (sizeof (struct AIDE_DIRENT_TYPE) + _POSIX_PATH_MAX);
#  else
#   ifdef HAVE_READDIR
	/*
	   Should we do something here?

	 */
#   else
#    error AIDE needs readdir or readdir_r
#   endif
#  endif


	char* fullname=malloc((conf->root_prefix_length+2)*sizeof(char));
	strncpy(fullname, conf->root_prefix, conf->root_prefix_length+1);
	strncat (fullname, "/", 1);
	dirh=open_dir(fullname);
	free(fullname);

	return RETOK;
}

/*
  We don't support writing to the pseudo-database disk, since we are'n a
  backup/restore software. Hence the functions db_writespec_disk,
  db_writeline_disk and db_close_disk aren't declared.
 */

const char *aide_key_6 = CONFHMACKEY_06;
const char *db_key_6 = DBHMACKEY_06;
