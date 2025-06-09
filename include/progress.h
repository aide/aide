/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2023,2025 Hannes von Haugwitz
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

#ifndef _PROGRESS_H_INCLUDED
#define _PROGRESS_H_INCLUDED

#include <stdbool.h>

typedef enum progress_state {
    PROGRESS_NONE = 0,
    PROGRESS_CONFIG,
    PROGRESS_DISK,
    PROGRESS_OLDDB,
    PROGRESS_NEWDB,
    PROGRESS_WRITEDB,
    PROGRESS_CLEAR,
    PROGRESS_SKIPPED,
} progress_state;

typedef enum progress_worker_state {
    progress_worker_state_idle,
    progress_worker_state_processing,
} progress_worker_state;

bool progress_start(void);
void progress_stop(void);

void progress_worker_state_init(void);

void update_progress_status(progress_state, const char*);

void update_progress_worker_status(int, progress_worker_state, void*);
void update_progress_worker_progress(int, int);

#endif
