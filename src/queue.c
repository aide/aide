/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2022 Hannes von Haugwitz
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

#include "queue.h"
#include "log.h"
#include "util.h"

typedef struct qnode_s qnode_t;

struct qnode_s {
    qnode_t *next;
    qnode_t *prev;

    void *data;
};

struct queue_s {
    qnode_t *head;
    qnode_t *tail;

    int (*sort_func) (const void*, const void*);
};

LOG_LEVEL queue_log_level = LOG_LEVEL_TRACE;

queue_ts_t *queue_init(int (*sort_func) (const void*, const void*)) {
    queue_ts_t *queue = checked_malloc (sizeof(queue_ts_t));

    queue->head = NULL;
    queue->tail = NULL;

    queue->sort_func = sort_func;

    log_msg(queue_log_level, "queue(%p): create new queue (sorted: %s)", queue, btoa(sort_func != NULL));
    return queue;
}

void queue_free(queue_ts_t *queue) {
    if (queue) {
        free(queue);
    }
}

void queue_enqueue(queue_ts_t * const queue, void * const data) {
    qnode_t *new, *current;
    new = checked_malloc(sizeof(qnode_t)); /* freed in queue_dequeue */
    new->data = data;

    if (queue->head == NULL) {
        /* new node is first element in empty queue */
        queue->head = new;
        queue->tail = new;
        new->next = NULL;
        new->prev = NULL;
        log_msg(queue_log_level, "queue(%p): add node %p with payload %p as new head and new tail", queue, new, new->data);
    } else if (queue->sort_func) {
        /* add element in sorted, non-empty queue (use insertion sort) */
        current = queue->head;
        if (queue->sort_func(new->data, current->data) <= 0) {
            /* new node is new head */
            queue->head = new;
            current->next = new;
            new->prev = current;
            new->next = NULL;
            log_msg(queue_log_level, "queue(%p): add node %p with payload %p as new head", queue, new, new->data);
        } else {
            while (current != NULL && queue->sort_func(new->data, current->data) > 0) {
                current = current->prev;
            }
            if (current == NULL) {
                /* new node is new tail */
                (queue->tail)->prev = new;
                new->next = queue->tail;
                new->prev = NULL;
                queue->tail = new;
                log_msg(queue_log_level, "queue(%p): add node %p with payload %p as new tail", queue, new, new->data);
            } else {
                /* new node is inner node */
                (current->next)->prev = new;
                new->next = current->next;
                current->next = new;
                new->prev = current;
                log_msg(queue_log_level, "queue(%p): add node %p with payload %p as inner element between %p and %p", queue, new, new->data, new->prev, new->next);
            }
        }
    } else {
        /* new node is new tail */
        (queue->tail)->prev = new;
        new->next = queue->tail;
        new->prev = NULL;
        queue->tail = new;
        log_msg(queue_log_level, "queue(%p): add node %p with payload %p as new tail", queue, new, new->data);
    }

}

void *queue_dequeue(queue_ts_t * const queue) {
    qnode_t *head;
    void *data = NULL;

    if ((head = queue->head) != NULL) {
        if ((queue->head = head->prev) == NULL) {
            queue->tail = NULL;
        } else {
            (queue->head)->next = NULL;
        }
        log_msg(queue_log_level, "queue(%p): return head node %p with payload %p", queue, head, head->data);
        data = head->data;
        free(head);
    }
    return data;
}
