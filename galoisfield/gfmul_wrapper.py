import subprocess
import sys
from ctypes import CDLL, c_uint64, Structure
from pathlib import Path


class Uint128(Structure):
    _fields_ = [("low", c_uint64),
                ("high", c_uint64)]


def _compile_library():
    """Compile the gfmul library if it doesn't exist."""
    current_dir = Path(__file__).parent.absolute()
    source_file = current_dir / "gfmul.c"

    lib_name = "libgfmul.so"
    compile_cmd = ["gcc", "-O3", "-march=native", "-msse2", "-msse4.1", "-maes",
                   "-mpclmul", "-fPIC", "-Wall", "-shared",
                   str(source_file), "-o", lib_name]

    lib_path = current_dir / lib_name

    if not lib_path.exists():
        try:
            result = subprocess.run(compile_cmd, cwd=str(current_dir),
                                    capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(f"Compilation failed:\n{result.stderr}")
        except Exception as e:
            print(f"Error compiling gfmul library: {e}", file=sys.stderr)
            raise

    return lib_path


def _load_so_library():
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


def _load_dll_library():
    """Helper Script for Local testing on Windows/
    MSYS2 command: gcc -O3 -march=native -msse2 -msse4.1 -maes -mpclmul -shared gfmul.c -o gfmul.dll"""

    current_dir = Path(__file__).parent.absolute()
    lib_path = current_dir / "gfmul.dll"

    try:
        if not lib_path.exists():
            raise FileNotFoundError(
                f"gfmul.dll not found at {lib_path}\n"
                "Please compile it using build_dll.py or manually with:\n"
                "gcc -O3 -march=native -msse2 -msse4.1 -maes -mpclmul -shared gfmul.c -o gfmul.dll"
            )
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


lib = _load_so_library()


def c_multiply(a: int, b: int) -> int:
    """Used intel algorithm from:
       https://www.intel.com/content/dam/develop/external/us/en/documents/clmul-wp-rev-2-02-2014-04-20.pdf
       needs __m128i, which can be seen as two 64bit values (cant pass __m128i directly)"""

    a_low = a & ((1 << 64) - 1)
    a_high = a >> 64
    b_low = b & ((1 << 64) - 1)
    b_high = b >> 64

    result = lib.gfmul(a_low, a_high, b_low, b_high)
    return result.low + (result.high << 64)
