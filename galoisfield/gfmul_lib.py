import subprocess
from functools import lru_cache
import time
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
    output_name = WINDOWS_LIBRARY_NAME if platform.system() == "Windows" else LINUX_LIBRARY_NAME

    lib_path = current_dir / output_name
    if not lib_path.exists():
        try:
            if output_name == WINDOWS_LIBRARY_NAME:
                # Need to have mingw64 installed:
                # https://github.com/niXman/mingw-builds-binaries/releases/download/14.2.0-rt_v12-rev0/x86_64-14.2.0-release-posix-seh-msvcrt-rt_v12-rev0.7z
                # Install, unpack, add it to path, restart => should be able to compile, (Can be done manually as well)
                compiler_args = [
                    "gcc",
                    "-O3",
                    "-march=native",
                    "-msse2",
                    "-msse4.1",
                    "-maes",
                    "-mpclmul",
                    "-shared",
                    str(current_dir / C_SCRIPT_NAME),
                    "-o",
                    current_dir / output_name,
                ]
            else:
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
                    str(current_dir / C_SCRIPT_NAME),
                    "-o",
                    current_dir / output_name,
                ]

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


@lru_cache(maxsize=1)
def _load_library():
    """Load the appropriate library file based on platform.
       The Library only gets loaded once (lru_cache) and gets cached for further calls.
       also it doesn't get loaded on the GaloisfieldElement import
       (maxsize: remembers the result of one function call => perfect since we return same thing everytime"""
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


def c_multiply(a: int, b: int) -> int:
    """Used intel algorithm from:
       https://www.intel.com/content/dam/develop/external/us/en/documents/clmul-wp-rev-2-02-2014-04-20.pdf
       needs __m128i, which can be seen as two 64bit values (cant pass __m128i directly)"""
    library = _load_library()  # Library is cached

    a_low = a & ((1 << 64) - 1)
    a_high = a >> 64
    b_low = b & ((1 << 64) - 1)
    b_high = b >> 64
    m128i_result = library.gfmul(a_low, a_high, b_low, b_high)

    result = (m128i_result.high << 64) + m128i_result.low
    assert result < (1 << 128), "Gfmul result is bigger than field size"
    return result
