#!/usr/bin/env python

from argparse import ArgumentParser, RawDescriptionHelpFormatter
from logging import (
    getLogger, StreamHandler, FileHandler, Formatter, DEBUG, INFO
)
from logging.handlers import (
    RotatingFileHandler, TimedRotatingFileHandler
)
import platform
import sys
import time


def do_log(args, logger):
    for i in range(args.num_iterations):
        logger.info('{}'.format(i))
        time.sleep(0.01)


def main():
    parser = ArgumentParser(description=(__doc__),
                            formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument('-n', '--num-iterations', type=int, default=1000,
                        help='Number of logs')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Show debug log')
    parser.add_argument('-t', '--rotation-type', default='none',
                        choices=['none', 'file', 'size', 'time'],
                        help='Rotation type')
    parser.add_argument('-f', '--log-file-path', default='result.log',
                        help='Log file path')
    parser.add_argument('-c', '--rotation-backup-count', default=10,
                        help='Log backup count')
    parser.add_argument('-s', '--rotation-backup-size', default=10*1024,
                        help='Size of each log (size-based log only)')
    parser.add_argument('-w', '--rotation-when', default='S',
                        help='When log rotates (time-based log only)')
    args = parser.parse_args()

    logger = getLogger(__name__)

    if args.rotation_type == 'file':
        handler = FileHandler(args.log_file_path)
    elif args.rotation_type == 'size':
        handler = RotatingFileHandler(
            args.log_file_path,
            maxBytes=args.rotation_backup_size,
            backupCount=args.rotation_backup_count)
    elif args.rotation_type == 'time':
        handler = TimedRotatingFileHandler(
            args.log_file_path,
            when=args.rotation_when,
            backupCount=args.rotation_backup_count)
    else:
        handler = StreamHandler()
    logger.addHandler(handler)
    if args.debug:
        logger.setLevel(DEBUG)
        handler.setLevel(DEBUG)
    else:
        logger.setLevel(INFO)
        handler.setLevel(INFO)
    handler.setFormatter(Formatter(
        '%(asctime)s %(process)5d %(levelname)7s %(message)s'))
    logger.debug('Start Running (Python {})'
                 .format(platform.python_version()))
    do_log(args, logger)
    logger.debug('Finished Running')
    return 0


if __name__ == '__main__':
    sys.exit(main())
