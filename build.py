from galoisfield.gfmul_lib import compile_library


def main():
    try:
        compile_library()
    except Exception as e:
        print(f"Error during library compilation: {e}")
        exit(1)


if __name__ == '__main__':
    main()
