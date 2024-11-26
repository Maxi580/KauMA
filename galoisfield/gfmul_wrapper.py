from ctypes import CDLL, c_uint64, POINTER, Structure
from pathlib import Path
import platform


class Uint128(Structure):
    _fields_ = [("low", c_uint64),
                ("high", c_uint64)]


def _load_library():
    """Load the appropriate library file based on platform."""
    current_dir = Path(__file__).parent.absolute()

    if platform.system() == "Windows":
        lib_name = "gfmul.dll"
    else:
        lib_name = "libgfmul.so"

    lib_path = current_dir / lib_name

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


lib = _load_library()


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
