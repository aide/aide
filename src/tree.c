/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2023 Hannes von Haugwitz
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

#include <stdlib.h>
#include "tree.h"
#include "util.h"

struct tree_node {
    void *key;
    void *data;

    long unsigned level;

    struct tree_node *parent;
    struct tree_node *left;
    struct tree_node *right;
};

static tree_node *tree_new_node(void *key, tree_node *parent) {
        tree_node *n = checked_malloc(sizeof(tree_node));
        n->key = key;
        n->data = NULL;

        n->level = 1;

        n->parent = parent;
        n->left = NULL;
        n->right = NULL;

        return n;
}

/* implements an AA tree, a simplified red-black tree */
static tree_node *_insert(tree_node *n, tree_node *parent, void *key, void *data, tree_cmp_f compare) {
    if  (n == NULL) {
        n = tree_new_node(key, parent);
        n->data = data;
        return n;
    }
    int c = compare(key, n->key);
    if (c < 0) {
        n->left = _insert(n->left, n, key, data, compare);
    } else if (c > 0) {
        n->right = _insert(n->right, n, key, data, compare);
    }
    if (n != NULL && n->left != NULL && n->level == (n->left)->level) {
        tree_node *l = n->left;
        n->left = l->right;
        if (n->left) {
            (n->left)->parent = n;
        }
        l->right = n;
        l->parent = n->parent;
        n->parent = l;
        n = l;
    }
    if (n != NULL && n->right != NULL && (n->right)->right != NULL
                && n->level == ((n->right)->right)->level) {
        tree_node *r = n->right;
        n->right = r->left;
        if (n->right) {
            (n->right)->parent = n;
        }
        r->left = n;
        r->parent = n->parent;
        n->parent = r;
        r->level++;
        n = r;
    }
    return n;
}

tree_node *tree_insert(tree_node *root, void *key, void * data, tree_cmp_f compare) {
    root = _insert(root, NULL, key, data, compare);
    root->parent = NULL;
    return root;
}

void *tree_search(tree_node *root, void *key, int (*compare) (const void*, const void*)) {
    if (root == NULL) {
        return NULL;
    }
    tree_node *n = root;

    int c;
    while (n != NULL && (c = compare(key, n->key)) != 0) {
        if (c < 0) {
            n = n->left;
        } else {
            n = n->right;
        }
    }
    return n?n->data:NULL;
}

tree_node *tree_walk_first(tree_node *root) {
    tree_node *n = root;
    if (n) {
        if (n->left) {
            while (n->left != NULL) {
                n = n->left;
            }
        }
    }
    return n;
}

tree_node *tree_walk_next(tree_node *m) {
    if (m != NULL) {
        if (m->right != NULL) {
            m = m->right;
            while (m->left) {
                m = m->left;
            }
        } else {
            while (m->parent != NULL && (m->parent)->right == m) {
                m = m->parent;
            }
            m = m->parent;
        }
    }
    return m;
}

void *tree_get_data(tree_node *n) {
    return n->data;
}
