#include <assert.h>
#include <sys/mman.h>

#include "mbox.h"
#include "mboxd_msg.h"

#include "test/mbox.h"
#include "test/system.h"

static const uint8_t get_info[] = {
	0x02, 0xaa, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t get_flash_info[] = {
	0x03, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t create_write_window[] = {
	0x06, 0xaa, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t mark_write_dirty[] = {
	0x07, 0xaa, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t write_flush[] = {
	0x08, 0xaa, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t response[] = {
	0x08, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

const uint8_t start_data[] = { 0xaa, 0x55, 0xaa };
const uint8_t finish_data[] = { 0xaa, 0x00, 0xaa };

#define MEM_SIZE	sizeof(start_data)
#define ERASE_SIZE	1
#define N_WINDOWS	1
#define WINDOW_SIZE	sizeof(start_data)

int main(void)
{
	struct mbox_context *ctx;
	uint8_t *map;
	int rc;

	system_set_reserved_size(MEM_SIZE);
	system_set_mtd_sizes(MEM_SIZE, ERASE_SIZE);

	ctx = mbox_create_test_context(N_WINDOWS, WINDOW_SIZE);
	rc = mbox_set_mtd_data(ctx, start_data, sizeof(start_data));
	assert(rc == 0);

	rc = mbox_command(ctx, get_info, sizeof(get_info));
	assert(rc == 0);

	rc = dispatch_mbox(ctx);
	assert(rc == 0);

	rc = mbox_command(ctx, get_flash_info, sizeof(get_flash_info));
	assert(rc == 0);

	rc = dispatch_mbox(ctx);
	assert(rc == 0);

	rc = mbox_command(ctx, create_write_window, sizeof(create_write_window));
	assert(rc == 0);

	rc = dispatch_mbox(ctx);
	assert(rc == 0);

	((uint8_t *)ctx->mem)[1] = 0x00;

	rc = mbox_command(ctx, mark_write_dirty, sizeof(mark_write_dirty));
	assert(rc == 0);

	rc = dispatch_mbox(ctx);
	assert(rc == 0);

	rc = mbox_command(ctx, write_flush, sizeof(write_flush));
	assert(rc == 0);

	rc = dispatch_mbox(ctx);
	assert(rc == 0);

	rc = mbox_cmp(ctx, response, sizeof(response));
	assert(rc == 0);

	map = mmap(NULL, MEM_SIZE, PROT_READ, MAP_PRIVATE, ctx->fds[MTD_FD].fd, 0);
	assert(map != MAP_FAILED);

	rc = memcmp(finish_data, map, sizeof(finish_data));
	assert(rc == 0);

	return 0;
};
