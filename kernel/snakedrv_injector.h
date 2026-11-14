// SPDX-License-Identifier: GPL-2.0
/*
 * SnakeEngine Kernel Driver - Manual Mapping Injector
 *
 * Provides tracked memory allocation and execution primitives. Remote
 * mprotect is implemented by the SDK through the native target syscall.
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
 * Runs vm_mmap in an owned worker with an independent mm reference.
 */
/* Allocations retain their normal VMAs. Unsupported legacy operations fail. */
int injector_allocate(struct snake_inject_alloc *alloc_info);
int injector_protect(struct snake_inject_protect *protect_info);
int injector_apply_stealth(struct snake_inject_protect *info);
int injector_create_thread(struct snake_inject_thread *thread_info);

/* Pinned mappings retain normal VMAs; resources belong to the opening client. */
struct snake_shadow_alloc;
struct snake_shadow_write;
int injector_init(void);
void injector_cleanup(void);
int injector_shadow_alloc(struct snake_shadow_alloc *info, void *owner);
int injector_shadow_free(struct snake_shadow_alloc *info, void *owner);
ssize_t injector_shadow_write(struct snake_shadow_write *info, void *owner);
ssize_t injector_shadow_read(void *owner, pid_t pid, u64 address, void *buf, size_t len);
void injector_shadow_cleanup_owner(void *owner);

#endif /* _SNAKEDRV_INJECTOR_H_ */
