hiomap_test_lib = static_library(
  'hiomap-test',
  'tmpf.c',
  'mbox.c',
  'system.c',
  '../transport_mbox.c',
  include_directories: include_directories(
    '..',
  ),
)

hiomap_test_dep = declare_dependency(
  link_with: hiomap_test_lib,
  include_directories: include_directories(
    '..',
  ),
)

tests = [
  'bmc_event_ack_v2',
  'close_window_v2',
  'create_oversize_window',
  'create_read_window_v2',
  'create_zero_size_window',
  'flash_copy',
  'flash_erase',
  'flash_write',
  'get_flash_info_v2',
  'get_mbox_info_v2',
  'get_mbox_info_v2_timeout',
  'implicit_flush',
  'invalid_command',
  'mark_read_dirty',
  'mark_write_dirty_v2',
  'mark_write_erased_v2',
  'read_window_cycle',
  'read_window_mark_write_erased',
  'read_window_write_flush',
  'request_high_version',
  'request_low_version',
  'reset_state',
  'sequence_numbers',
  'windows_equally_evictable',
  'write_flush_v2',
  'write_window_dirty_erase',
]

foreach t : tests
  test(
    'test_' + t.underscorify(),
    executable(
      'test-' + t.underscorify(),
      t + '.c',
      dependencies: [
        hiomap_test_dep,
        mboxd_dep,
      ],
    )
  )
endforeach
