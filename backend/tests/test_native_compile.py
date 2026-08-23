from app.native_compile import shared_library_clang_args


def test_windows_shared_library_flags_do_not_use_fpic() -> None:
    assert shared_library_clang_args("nt") == [
        "clang",
        "-shared",
        "-Wl,/export:block_frame",
        "-O2",
    ]


def test_posix_shared_library_flags_keep_fpic() -> None:
    assert shared_library_clang_args("posix") == ["clang", "-shared", "-fPIC", "-O2"]
