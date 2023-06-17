#! /usr/bin/python3

import sys
import capstone
import r2pipe
from elftools.elf.elffile import ELFFile


def extract_text(p):
    text_data = b''
    with open(p) as f:
        e = ELFFile(f)
        text_segment = e.get_section_by_name('.text')
        text_data = text_segment.data()
        text_addr = text_segment['sh_addr']
    return text_data, text_addr


def main():
    if len(sys.argv) != 2:
        print('Invalid argument count!')
        return -1

    binary_path = sys.argv[1]
    r2 = r2pipe.open(binary_path)
    r2.cmd('aaa')
    functions = r2.cmdj('aflj')

    print(functions)
    r2.quit()







if __name__ == '__main__':
    main()