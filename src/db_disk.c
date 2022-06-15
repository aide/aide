/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2006, 2010-2011, 2016-2017, 2019-2022 Rami Lehti,
 *               Pablo Virolainen, Mike Markley, Richard van den Berg,
 *               Hannes von Haugwitz
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "aide.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include "db_config.h"
#include "list.h"
#include "log.h"
#include "rx_rule.h"
#include "seltree_struct.h"
#include "seltree.h"
#include "gen_list.h"
#include "db.h"
#include "db_line.h"
#include "db_disk.h"
#include "util.h"


static DIR *dirh = NULL;
static struct dirent *entp = NULL;

static struct seltree *r = NULL;


static long td = -1;

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
	if (dirh != NULL) {
		entp = readdir (dirh);
		if(entp!=NULL)
			td = telldir(dirh);
		else
			td=-1;
	}

}

static int in_this (void)
{
	return (dirh != NULL && entp != NULL && td >= 0);
}

static char *name_construct (const char *s)
{
	char *ret;
	int len2 = strlen (r->path);
	int len = len2 + strlen (s) + 2 + conf->root_prefix_length;

	if (r->path[len2 - 1] != '/') {
		len++;
	}

	ret = (char *) checked_malloc (len);
	snprintf(ret, len, "%s%s%s%s", conf->root_prefix, r->path, (r->path[len2 - 1] != '/')?"/":"", s);
	return ret;
}

void add_child (db_line * fil)
{
	int i;
	struct seltree *new_r;

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

	log_msg(LOG_LEVEL_DEBUG, "add child '%s' to %s", fil->filename, r->path);

	new_r = checked_malloc (sizeof (seltree));

	i = strlen (fil->filename);

	new_r->path = checked_malloc (i + 1);
	strncpy(new_r->path, fil->filename, i+1);
	new_r->childs = NULL;
	new_r->sel_rx_lst = NULL;
	new_r->neg_rx_lst = NULL;
	new_r->equ_rx_lst = NULL;
	new_r->parent = r;
	new_r->checked = 0;
	new_r->changed_attrs=0;
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

static int get_file_status(char *filename, struct stat *fs) {
    int sres = 0;
    sres = lstat(filename,fs);
    if(sres == -1){
        char* er = strerror(errno);
        if (er == NULL) {
            log_msg(LOG_LEVEL_WARNING, "get_file_status: lstat() failed for %s. strerror() failed with %i", filename, errno);
        } else {
            log_msg(LOG_LEVEL_WARNING, "get_file_status: lstat() failed for %s: %s", filename, er);
        }
    }
    return sres;
}

/*
  It might be a good idea to make this non recursive.
  Now implemented with goto-statement. Yeah, it's ugly and easy.
*/

db_line *db_readline_disk (bool dry_run)
{
	db_line *fil = NULL;
	rx_rule *rule = NULL;
	char *fullname;
	int add = 0;
	struct stat fs;

	/* root needs special handling */
	if (!root_handled) {
		root_handled = 1;
		int len = (conf->root_prefix_length+2)*sizeof(char);
		fullname=checked_malloc(len);
		snprintf(fullname, len, "%s/",  conf->root_prefix);
		if (!get_file_status(fullname, &fs)) {
		add = check_rxtree (&fullname[conf->root_prefix_length], conf->tree, &rule, get_restriction_from_perm(fs.st_mode), dry_run);

		if (add > 0) {
            log_msg(LOG_LEVEL_DEBUG, "get file attributes '%s'", &fullname[conf->root_prefix_length]);
			fil = get_file_attrs (fullname, rule->attr, &fs, dry_run);

			if (fil != NULL) {
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

		if (get_file_status(fullname, &fs)) {
		    free (fullname);
		    goto recursion;
		}
		add = check_rxtree (&fullname[conf->root_prefix_length], conf->tree, &rule, get_restriction_from_perm(fs.st_mode), dry_run);

		if (add > 0) {
            log_msg(LOG_LEVEL_DEBUG, "get file attributes '%s'", &fullname[conf->root_prefix_length]);
			fil = get_file_attrs (fullname, rule->attr, &fs, dry_run);

			if (fil == NULL) {
				/*
				   Something went wrong during read process -> 
				   Let's try next one.
				 */
				free (fullname);
				goto recursion;					// return db_readline_disk(db);
			}

			if (add == SELECTIVE_MATCH) {
				/*
				   add_children -> if dir, then add to children list.
				 */
				/* If ee are adding a file that is not a dir */
				/* add_child can make the determination and mark the tree
				   accordingly
				 */
				add_child (fil);
			} else if (add == EQUAL_MATCH) {
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

		log_msg(LOG_LEVEL_TRACE, "r->childs %p, r->parent %p, r->checked %i", r->childs,
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

				log_msg(LOG_LEVEL_TRACE, "rr->checked %i", rr->checked);
				rr->checked |= NODE_TRAVERSE;

				r = rr;

				log_msg (LOG_LEVEL_TRACE, "r->childs %p, r->parent %p,r->checked %i",
							 r->childs, r->parent, r->checked);
				int len = (conf->root_prefix_length+strlen(r->path)+1)*sizeof(char);
				fullname=checked_malloc(len);
				snprintf(fullname, len, "%s%s",  conf->root_prefix, r->path);
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
						log_msg (LOG_LEVEL_RULE,
									 "There are rules referring to non-existent directory %s", fullname);
					} else if (errno != ENOTDIR) {
						/* We print the message unless it is "Not a directory". */
						char *er = strerror (errno);
						if (er != NULL) {
							log_msg(LOG_LEVEL_WARNING, "open_dir() failed for %s: %s", fullname, er);
						} else {
							log_msg(LOG_LEVEL_WARNING, "open_dir(): failed for %s: %i", fullname, errno);
						}
					}
					r->checked |= NODE_TRAVERSE | NODE_CHECKED;
					r = r->parent;
					log_msg(LOG_LEVEL_TRACE, "dropping back to parent");
				}
				free(fullname);
			} else {
				r->checked |= NODE_TRAVERSE | NODE_CHECKED;
				r = r->parent;
				/* We have gone out of the tree. This happens in some instances */
				if (r == NULL) {
					return NULL;
				}
				log_msg(LOG_LEVEL_TRACE, "dropping back to parent");
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

	int len = (conf->root_prefix_length+2)*sizeof(char);
	char* fullname=checked_malloc(len);
	snprintf(fullname, len, "%s/",  conf->root_prefix);
	dirh=open_dir(fullname);
	free(fullname);

	return RETOK;
}

/*
  We don't support writing to the pseudo-database disk, since we are'n a
  backup/restore software. Hence the functions db_writespec_disk,
  db_writeline_disk and db_close_disk aren't declared.
 */
