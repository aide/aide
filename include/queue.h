/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2022-2023,2025 Hannes von Haugwitz
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

#ifndef _QUEUE_H_INCLUDED
#define _QUEUE_H_INCLUDED

#include <stdbool.h>

typedef struct queue_s queue_ts_t;

queue_ts_t *queue_init(int (*) (const void*, const void*));
void queue_free(queue_ts_t *);

bool  queue_enqueue(queue_ts_t * const, void * const);
void *queue_dequeue(queue_ts_t * const);

queue_ts_t *queue_ts_init(int (*) (const void*, const void*));
void  queue_ts_free(queue_ts_t *);
bool  queue_ts_enqueue(queue_ts_t * const, void * const, const char *);
void *queue_ts_dequeue_wait(queue_ts_t * const, const char *);
void  queue_ts_register(queue_ts_t * const, const char *);
void  queue_ts_release(queue_ts_t * const, const char *);

#endif
