from angr import sim_options as so
import angr

from bin_check.tracing import get_funcs_and_prj
from bin_check.celery_app import do_trace
from bin_check.backward_slicing import (
    create_initial_program_slice,
    get_next_predecessor_path,
    get_r2_instance,
)


def test_can_create_xref_slice():
    test_file = "examples/upload.cgi"
    mtd_write_firmware = 0x004012B8

    p_slice = create_initial_program_slice(mtd_write_firmware)
    r2 = get_r2_instance(test_file)

    p_slices = get_next_predecessor_path(r2, p_slice)

    assert len(p_slices) > 0


def test_can_create_block_slice():
    test_file = "examples/upload.cgi"
    mtd_write_firmware = 0x004012B8

    p_slice = create_initial_program_slice(mtd_write_firmware)
    r2 = get_r2_instance(test_file)

    # This will use xref
    p_slices = get_next_predecessor_path(r2, p_slice)

    assert len(p_slices) > 0

    # This will use bb predecessors
    p_slices_2 = get_next_predecessor_path(r2, p_slices[0])

    assert len(p_slices_2) > 0


def test_find_bug_in_slices():
    test_file = "examples/upload.cgi"
    mtd_write_firmware = 0x004012B8

    p_slice = create_initial_program_slice(mtd_write_firmware)
    r2 = get_r2_instance(test_file)

    p_slices = get_next_predecessor_path(r2, p_slice)

    assert len(p_slices) > 0

    funcs, proj = get_funcs_and_prj(
        test_file, system_check=True, printf_check=False, use_angr=False, r2=r2
    )

    assert len(funcs) > 0

    # Xref slices working?
    for slice in p_slices:
        addr, cmd = do_trace(proj, slice.end_addr, avoid_list=slice.avoid_list)

        assert addr is not None
        assert cmd is not None

    # This will use bb predecessors
    p_slices_2 = get_next_predecessor_path(r2, p_slices[0])

    assert len(p_slices_2) > 0

    for slice in p_slices_2:
        addr, cmd = do_trace(proj, slice.end_addr, avoid_list=slice.avoid_list)

        assert addr is not None
        assert cmd is not None