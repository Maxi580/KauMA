import subprocess
import sys
from ctypes import CDLL, c_uint64, Structure
from pathlib import Path
import platform

C_SCRIPT_NAME = "gfmul.c"
WINDOWS_LIBRARY_NAME = "gfmul.dll"
LINUX_LIBRARY_NAME = "libgfmul.so"


class Uint128(Structure):
    _fields_ = [("low", c_uint64),
                ("high", c_uint64)]


def _compile_library():
    """Compile the gfmul library if it doesn't exist."""
    current_dir = Path(__file__).parent.absolute()
    source_path = current_dir / C_SCRIPT_NAME

    if platform.system() == "Windows":
        # Need to have mingw64 installed:
        # https://github.com/niXman/mingw-builds-binaries/releases/download/14.2.0-rt_v12-rev0/x86_64-14.2.0-release-posix-seh-msvcrt-rt_v12-rev0.7z
        # Install, unpack, add it to path, restart => should be able to compile, (Can be done manually as well)
        output_name = WINDOWS_LIBRARY_NAME
        compiler_args = [
            "gcc",
            "-O3",
            "-march=native",
            "-msse2",
            "-msse4.1",
            "-maes",
            "-mpclmul",
            "-shared",
            str(source_path),
            "-o",
            current_dir / output_name,
        ]
    else:
        output_name = LINUX_LIBRARY_NAME
        compiler_args = [
            "gcc",
            "-O3",
            "-march=native",
            "-msse2",
            "-msse4.1",
            "-maes",
            "-mpclmul",
            "-shared",
            "-fPIC",
            str(source_path),
            "-o",
            current_dir / output_name,
        ]

    lib_path = current_dir / output_name
    if not lib_path.exists():
        try:
            result = subprocess.run(
                compiler_args,
                check=True,
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                raise RuntimeError(f"Compilation failed:\n{result.stderr}")

        except subprocess.CalledProcessError as e:
            print(f"Compilation failed with error:\n{e.stderr}")
            return None
        except FileNotFoundError:
            print("gcc not found. Please ensure gcc is installed and in your PATH")
            return None

    return lib_path


def load_library():
    """Load the appropriate library file based on platform."""
    lib_path = _compile_library()

    try:
        if not lib_path.exists():
            raise FileNotFoundError(f"Library not found at {lib_path}")
        lib = CDLL(str(lib_path))

        lib.gfmul.argtypes = [
            c_uint64,  # a_low
            c_uint64,  # a_high
            c_uint64,  # b_low
            c_uint64,  # b_high
        ]
        lib.gfmul.restype = Uint128

        return lib
    except Exception as e:
        print(f"Error loading gfmul library: {e}")
        print(f"Tried to load from: {lib_path}")
        return None
