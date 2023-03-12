/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2022-2023 Hannes von Haugwitz
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

#include "config.h"
#include <stdlib.h>
#include <stdbool.h>

#include <pthread.h>

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

    pthread_mutex_t mutex;
    pthread_cond_t cond;

    bool release;

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

bool queue_enqueue(queue_ts_t * const queue, void * const data) {
    qnode_t *new, *current;
    new = checked_malloc(sizeof(qnode_t)); /* freed in queue_dequeue */
    new->data = data;

    bool new_head_tail = false;

    if (queue->head == NULL) {
        /* new node is first element in empty queue */
        queue->head = new;
        queue->tail = new;
        new->next = NULL;
        new->prev = NULL;
        new_head_tail = true;
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
    return new_head_tail;
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

queue_ts_t *queue_ts_init(int (*sort_func) (const void*, const void*)) {
    queue_ts_t *queue = checked_malloc (sizeof(queue_ts_t));

    pthread_mutexattr_t attr;
    pthread_mutexattr_init (&attr);
    pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&queue->mutex, &attr);
    pthread_cond_init(&queue->cond, NULL);

    pthread_mutex_lock(&queue->mutex);

    queue->release = false;

    queue->head = NULL;
    queue->tail = NULL;

    queue->sort_func = sort_func;

    pthread_mutex_unlock(&queue->mutex);

    log_msg(queue_log_level, "queue(%p): create new queue (sorted: %s)", queue, btoa(sort_func != NULL));
    return queue;
}

void queue_ts_free(queue_ts_t *queue) {
    if (queue) {
        pthread_cond_destroy(&queue->cond);
        pthread_mutex_destroy(&queue->mutex);
        queue_free(queue);
    }
}

bool queue_ts_enqueue(queue_ts_t * const queue, void * const data, const char *whoami) {
    pthread_mutex_lock(&queue->mutex);
    bool new_head_tail = queue_enqueue(queue,data);
    pthread_mutex_unlock(&queue->mutex);

    if (new_head_tail) {
        pthread_cond_broadcast(&queue->cond);
        log_msg(LOG_LEVEL_THREAD, "%10s: queue(%p): broadcast waiting threads for new head node in queue", whoami, queue);
    }
    return new_head_tail;
}

void *queue_ts_dequeue_wait(queue_ts_t * const queue, const char *whoami) {
    qnode_t *head;
    void *data = NULL;
    pthread_mutex_lock(&queue->mutex);

    while ((head = queue->head) == NULL && queue->release == false){
        log_msg(LOG_LEVEL_THREAD, "%10s: queue(%p): waiting for new node", whoami, queue);
        pthread_cond_wait(&queue->cond, &queue->mutex);
        log_msg(LOG_LEVEL_THREAD, "%10s: queue(%p): got broadcast (head: %p)", whoami, queue, queue->head);
    }
    if (head != NULL) {
        if ((queue->head = head->prev) == NULL) {
            queue->tail = NULL;
        } else {
            (queue->head)->next = NULL;
        }
        data = head->data;
        log_msg(queue_log_level, "queue(%p): return head node %p with payload %p", queue, head, head->data);
        free(head);
    } else {
        log_msg(queue_log_level, "queue(%p): return NULL from empty, released queue", queue);
    }
    pthread_mutex_unlock(&queue->mutex);
    return data;
}

void queue_ts_release(queue_ts_t * const queue, const char *whoami) {
    pthread_mutex_lock(&queue->mutex);
    queue->release = true;
    pthread_mutex_unlock(&queue->mutex);
    pthread_cond_broadcast(&queue->cond);
    log_msg(LOG_LEVEL_THREAD, "%10s: queue(%p): release queue and broadcast waiting threads", whoami, queue);
}
