#! /usr/bin/python3

import sys
import r2pipe
import sctokenizer


def main():
    if len(sys.argv) != 3:
        print('Invalid argument count!')
        return -1

    binary_path = sys.argv[1]
    source_path = sys.argv[2]

    r2 = r2pipe.open(binary_path)
    r2.cmd('aaa')
    binary_funcs = r2.cmdj('aflj')

    tokens = sctokenizer.tokenize_file(filepath=source_path)
    print(tokens)
    print(binary_funcs)

    r2.quit()


if __name__ == '__main__':
    main()