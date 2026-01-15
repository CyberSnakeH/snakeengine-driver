// SPDX-License-Identifier: GPL-2.0
/*
 * SnakeEngine Kernel Driver - Manual Mapping Injector
 *
 * Provides kernel-level primitives for stealthy memory allocation,
 * protection changes, and thread hijacking/creation in target processes.
 *
 * Copyright (c) 2024 SnakeEngine Project
 */

#ifndef _SNAKEDRV_INJECTOR_H_
#define _SNAKEDRV_INJECTOR_H_

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/sched.h>

/* Forward declarations */
struct snake_inject_alloc;
struct snake_inject_protect;
struct snake_inject_thread;

/**
 * injector_allocate - Allocate memory in a remote process context
 * @alloc_info: Allocation parameters (pid, size, prot)
 *
 * Uses direct mm_struct manipulation to perform vm_mmap in the context
 * of the target process without standard ptrace visibility.
 */
int injector_allocate(struct snake_inject_alloc *alloc_info);
int injector_protect(struct snake_inject_protect *protect_info);
int injector_apply_stealth(struct snake_inject_protect *info);
int injector_create_thread(struct snake_inject_thread *thread_info);

#endif /* _SNAKEDRV_INJECTOR_H_ */
