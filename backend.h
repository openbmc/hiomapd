/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2018 IBM Corp. */
/* Copyright (C) 2018 Evan Lojewski. */

#ifndef BACKEND_H
#define BACKEND_H

#include <stdint.h>
#include <mtd/mtd-abi.h>

#ifdef VIRTUAL_PNOR_ENABLED
#include "vpnor/mboxd_pnor_partition_table.h"
#endif

#define FLASH_DIRTY	0x00
#define FLASH_ERASED	0x01

/* Estimate as to how long (milliseconds) it takes to access a MB from flash */
#define FLASH_ACCESS_MS_PER_MB		8000

struct mbox_context;
struct protocol_create_window;

int	probe_mtd_backed_flash(struct mbox_context *context);
#ifdef VIRTUAL_PNOR_ENABLED
int	probe_vpnor_backed_flash(struct mbox_context *context);
#endif

struct backend {
	/**
	 * init() - Main initialization function for backing device
	 * @context:	The mbox context pointer
	 * Return:	Zero on success, otherwise negative error
	 */
	int 	(*init)(struct mbox_context *context);

	/**
	 * free() - Main teardown function for backing device
	 * @context:	The mbox context pointer
	 */
	void 	(*free)(struct mbox_context *context);

	/*
	 * copy() - Copy data from the flash device into a provided buffer
	 * @context:	The mbox context pointer
	 * @offset:	The flash offset to copy from (bytes)
	 * @mem:	The buffer to copy into (must be of atleast 'size' bytes)
	 * @size:	The number of bytes to copy
	 * Return:	Number of bytes copied on success, otherwise negative error
	 *		code. flash_copy will copy at most 'size' bytes, but it may
	 *		copy less.
	 */
	int64_t (*copy)(struct mbox_context *context,
				uint32_t offset, void *mem, uint32_t size);

	/*
	 * set_bytemap() - Set the flash erased bytemap
	 * @context:	The mbox context pointer
	 * @offset:	The flash offset to set (bytes)
	 * @count:	Number of bytes to set
	 * @val:	Value to set the bytemap to
	 *
	 * The flash bytemap only tracks the erased status at the erase block level so
	 * this will update the erased state for an (or many) erase blocks
	 *
	 * Return:	0 if success otherwise negative error code
	 */
	 int 	(*set_bytemap)(struct mbox_context *context,
				uint32_t offset, uint32_t count, uint8_t val);

	/*
	 * erase() - Erase the flash
	 * @context:	The mbox context pointer
	 * @offset:	The flash offset to erase (bytes)
	 * @size:	The number of bytes to erase
	 *
	 * Return:	0 on success otherwise negative error code
	 */
	int 	(*erase)(struct mbox_context *context,
				uint32_t offset, uint32_t count);
	/*
	 * write - Write the flash from a provided buffer
	 * @context:	The mbox context pointer
	 * @offset:	The flash offset to write to (bytes)
	 * @buf:	The buffer to write from (must be of atleast size)
	 * @size:	The number of bytes to write
	 *
	 * Return:	0 on success otherwise negative error code
	 */
	int 	(*write)(struct mbox_context *context,
				uint32_t offset, void *buf, uint32_t count);

	/*
	 * validate - Validates a requested window
	 * @context:	The mbox context pointer
	 * io:		The window information
	 *
	 * Return:	0 on valid otherwise negative error code
	 */
	int 	(*validate)(struct mbox_context *context,
				struct protocol_create_window *io);

	/*
	 * lpc_reset() - Reset the lpc bus mapping
	 * @context:    The mbox context pointer
	 *
	 * Return:      0 on success otherwise negative error code
	 */
	int	(*lpc_reset)(struct mbox_context *context);

	/* Bytemap of the erased state of the entire flash */
	uint8_t *flash_bmap;
	/* Erase size (as a shift) */
	uint32_t erase_size_shift;
	/* Block size (as a shift) */
	uint32_t block_size_shift;
	/* Actual Flash Info */
	struct mtd_info_user mtd_info;
#ifdef VIRTUAL_PNOR_ENABLED
	/* Virtual PNOR partition table */
	struct vpnor_partition_table *vpnor;
	struct vpnor_partition_paths paths;
#endif
};

#endif /* BACKEND_H */
