#!/usr/bin/env python

from argparse import ArgumentParser, RawDescriptionHelpFormatter
import glob
from logging import getLogger, StreamHandler, Formatter, DEBUG, INFO
import os
import platform
import re
import shlex
import subprocess
import sys

# e.g.
# 2017-06-14 13:24:27,429 97127    INFO 985
RE_LOG = re.compile(r'(?P<date>\d{4}-\d{2}-\d{2})'
                    r'\s+(?P<time>\d{2}:\d{2}:\d{2},\d{3})'
                    r'\s+(?P<pid>\d+)'
                    r'\s+(?P<log_level>[a-zA-Z]+)'
                    r'\s+(?P<number>\d+)')


def prepare(args, logger):
    log_paths = glob.glob('result.log*')
    if log_paths:
        logger.info('Removing {} logs'.format(len(log_paths)))
        for log_path in log_paths:
            logger.debug('Removing {}'.format(log_path))
            os.remove(log_path)


def multi_run(args, logger):
    cmd = ('python do_log.py -t {} -n {}'
           .format(args.rotation_type, args.num_iterations))
    logger.info('Using command "{}"'.format(cmd))
    cmd_args = shlex.split(cmd)
    logger.info('Start running {} processes'.format(args.num_processes))
    processes = []
    for i in range(args.num_processes):
        p = subprocess.Popen(cmd_args,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             universal_newlines=True)
        logger.debug('Start running process {}'.format(p.pid))
        processes.append(p)

    logger.info('Waiting for {} processes'.format(args.num_processes))
    for p in processes:
        logger.debug('Wating for process {} finishing'.format(p.pid))
        (stdout_data, stderr_data) = p.communicate()
        p.wait()
        if stdout_data:
            logger.warning('stdout for process {}:'.format(p.pid))
            for line in stdout_data.split('\n'):
                logger.warning('>> {}'.format(line.rstrip()))
        if stderr_data:
            logger.warning('stderr for process {}:'.format(p.pid))
            for line in stderr_data.split('\n'):
                logger.warning('>> {}'.format(line.rstrip()))
    return [p.pid for p in processes]


def confirm(pids, args, logger):
    logger.info('Confirming (pids: {})'.format(pids))
    # 各PID毎に0〜999の値がログに出ているかを確認する
    should_exist = set((pid, i)
                       for pid in pids
                       for i in range(0, args.num_iterations))
    expected_total = len(should_exist)
    already_found = set()

    duplicate_entries = []
    unexpected_entries = []
    log_paths = glob.glob('result.log*')

    for log_path in log_paths:
        with open(log_path) as f:
            for line in f:
                m = RE_LOG.match(line)
                if not m:
                    logger.warning('Bad log found: {}'
                                   .format(line.rstrip()))
                    continue
                entry = (int(m.group('pid')), int(m.group('number')))
                if entry in should_exist:
                    logger.debug('Removing {}'.format(entry))
                    already_found.add(entry)
                    should_exist.remove(entry)
                elif entry in already_found:
                    duplicate_entries.append(entry)
                else:
                    unexpected_entries.append(entry)
    # ログに全て表示されていれば空になるはず
    if should_exist:
        s = ','.join([str(t) for t in sorted(should_exist)])
        logger.warning('{}/{} entries are missing ({})'
                       .format(len(should_exist),
                               expected_total,
                               s))
    if duplicate_entries:
        logger.warning('{}/{} entries are duplicates'
                       .format(len(duplicate_entries), expected_total))
        for entry in duplicate_entries:
            logger.debug('>> {}'.format(entry))
    if unexpected_entries:
        logger.warning('{}/{} entries are unexpected'
                       .format(len(unexpected_entries), expected_total))
        for entry in unexpected_entries:
            logger.debug('>> {}'.format(entry))


def main():
    parser = ArgumentParser(description=(__doc__),
                            formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument('-n', '--num-iterations', type=int, default=200,
                        help='Number of logs per process.')
    parser.add_argument('-t', '--rotation-type', default='size',
                        choices=['file', 'size', 'time'],
                        help='Rotation type')
    parser.add_argument('-p', '--num-processes', type=int, default=5,
                        help='Num of do_log processes')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Show debug log')
    args = parser.parse_args()

    logger = getLogger(__name__)
    handler = StreamHandler()
    logger.addHandler(handler)
    if args.debug:
        logger.setLevel(DEBUG)
        handler.setLevel(DEBUG)
    else:
        logger.setLevel(INFO)
        handler.setLevel(INFO)
    handler.setFormatter(Formatter('%(asctime)s %(levelname)7s %(message)s'))
    logger.info('Start Running (Python {})'.format(platform.python_version()))
    prepare(args, logger)
    pids = multi_run(args, logger)
    confirm(pids, args, logger)
    logger.info('Finished Running')
    return 0


if __name__ == '__main__':
    sys.exit(main())
