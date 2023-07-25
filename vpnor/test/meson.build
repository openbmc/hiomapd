tests = [
  'create_aligned_window',
  'create_pnor_partition_table',
  'create_read_window_partition_exists',
  'write_prsv',
  'write_ro',
  'write_rw',
  'write_patch',
  'toc_no_name',
  'toc_start_gt_end',
  'toc_no_start',
  'toc_no_end',
  'toc_no_version',
  'toc_flags',
  'toc_overlap',
  'toc_lookup_found',
  'toc_lookup_failed',
  'toc_missing_file',
  'create_read_window_oob',
  'create_read_window_toc',
  'create_read_window_straddle_partitions',
  'create_read_window_partition_invalid',
  'read_patch',
  'write_patch_resize',
  'dump_flash',
  'create_read_window_size',
  'create_read_window_remap',
  'create_write_window_ro_partition',
  'create_write_window_rw_partition',
  'create_write_window_unmapped',
  'write_toc',
  'force_readonly_toc',
]

foreach t : tests
  test(
    'test_vpnor_' + t.underscorify(),
    executable(
      'test_vpnor_' + t.underscorify(),
      t + '.cpp',
      'tmpd.cpp',
      dependencies: [
        hiomap_test_dep,
        mboxd_dep,
      ],
    )
  )
endforeach
