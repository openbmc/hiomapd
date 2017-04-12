#include <assert.h>

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

static const uint8_t create_read_window[] = {
	0x04, 0xaa, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t close_window_no_flag[] = {
	0x05, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t close_window_short_lifetime[] = {
	0x05, 0xaa, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t response[] = {
	0x05, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

#define MEM_SIZE	3
#define ERASE_SIZE	1
#define N_WINDOWS	1
#define WINDOW_SIZE	3

void setup(struct mbox_context *ctx)
{
	int rc;

	rc = mbox_command(ctx, get_info, sizeof(get_info));
	assert(rc == 0);

	rc = dispatch_mbox(ctx);
	assert(rc == 0);

	rc = mbox_command(ctx, get_flash_info, sizeof(get_flash_info));
	assert(rc == 0);

	rc = dispatch_mbox(ctx);
	assert(rc == 0);

	rc = mbox_command(ctx, create_read_window, sizeof(create_read_window));
	assert(rc == 0);

	rc = dispatch_mbox(ctx);
	assert(rc == 0);
}

void no_flag(struct mbox_context *ctx)
{
	int rc;

	setup(ctx);

	rc = mbox_command(ctx, close_window_no_flag, sizeof(close_window_no_flag));
	assert(rc == 0);

	rc = dispatch_mbox(ctx);
	assert(rc == 0);

	rc = mbox_cmp(ctx, response, sizeof(response));
	assert(rc == 0);
}

void short_lifetime(struct mbox_context *ctx)
{
	int rc;

	setup(ctx);

	rc = mbox_command(ctx, close_window_short_lifetime, sizeof(close_window_short_lifetime));
	assert(rc == 0);

	rc = dispatch_mbox(ctx);
	assert(rc == 0);

	rc = mbox_cmp(ctx, response, sizeof(response));
	assert(rc == 0);
}

int main(void)
{
	struct mbox_context *ctx;

	system_set_reserved_size(MEM_SIZE);
	system_set_mtd_sizes(MEM_SIZE, ERASE_SIZE);

	ctx = mbox_create_test_context(N_WINDOWS, WINDOW_SIZE);

	no_flag(ctx);

	short_lifetime(ctx);

	return 0;
};
