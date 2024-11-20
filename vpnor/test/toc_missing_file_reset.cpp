// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2018 IBM Corp.
#include "config.h"

extern "C" {
#include "backend.h"
#include "test/mbox.h"
#include "test/system.h"
}

#include "vpnor/table.hpp"
#include "vpnor/test/tmpd.hpp"

#include <cassert>
#include <cstring>

static constexpr auto BLOCK_SIZE = 0x1000;
static constexpr auto ERASE_SIZE = BLOCK_SIZE;
static constexpr auto PNOR_SIZE = 64 * 1024 * 1024;
static constexpr auto MEM_SIZE = 32 * 1024 * 1024;
static constexpr auto N_WINDOWS = 1;
static constexpr auto WINDOW_SIZE = BLOCK_SIZE * 2;

static const uint8_t reset_state[] = {0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0x00, 0x00};
static const uint8_t reset_state1[] = {0x01, 0x02, 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00};

const std::string toc[] = {
    "partition01=ONE,00001000,00002000,80,",
    "partition02=TWO,00002000,00003000,80,",
};

int main()
{
    namespace test = openpower::virtual_pnor::test;
    namespace fs = std::filesystem;
    namespace vpnor = openpower::virtual_pnor;

    int rc;
    struct mbox_context* ctx;

    system_set_reserved_size(MEM_SIZE);
    system_set_mtd_sizes(MEM_SIZE, ERASE_SIZE);

    ctx = mbox_create_frontend_context(N_WINDOWS, WINDOW_SIZE);

    test::VpnorRoot root(&ctx->backend, toc, BLOCK_SIZE);

    fs::remove(root.ro() / "TWO");

    /*
     * First reset should fail due to missing file but it should keep objects
     * state sane.
     */
    rc = mbox_command_dispatch(ctx, reset_state, sizeof(reset_state));
    assert(rc == 2);

    /*
     * Run one more reset to make sure that reset can free the objects may be
     * created by previous reset.
     */
    rc = mbox_command_dispatch(ctx, reset_state1, sizeof(reset_state1));
    assert(rc == 2);
}
