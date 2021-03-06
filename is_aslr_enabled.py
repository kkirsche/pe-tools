#!/usr/bin/env python

from pefile import PE
from logging import getLogger, DEBUG
from sys import argv, exit
# installed with pip install -U colorlog
from colorlog import ColoredFormatter, StreamHandler

logger = getLogger(__name__)
logger.setLevel(DEBUG)
f = ColoredFormatter('%(log_color)s[%(levelname)s] %(message)s')
h = StreamHandler()
h.setLevel(DEBUG)
h.setFormatter(f)
logger.addHandler(h)

def get_pe_aslr_status(pe):
    DYNAMIC_BASE = 0x40
    is_aslr = pe.OPTIONAL_HEADER.DllCharacteristics & DYNAMIC_BASE
    if is_aslr:
        logger.warning('the binary has ASLR enabled!')
    else:
        logger.info('the binary does not have ASLR enabled')

if __name__ == '__main__':
    if len(argv) != 2:
        logger.error('usage: ./is_aslr_enabled.py <PE file>')
        exit(1)
    path = argv[1]
    logger.debug('opening PE file with path {path}'.format(path=path))
    pe = PE(path)
    logger.info('checking status of ASLR within the binary')
    get_pe_aslr_status(pe)
