#!/usr/bin/env python
# -*- coding: utf-8 -*-

from os.path import abspath, isfile, isdir, join
from glob import iglob
from argparse import ArgumentParser
from lib import init_redis

REDIS_HOST = '127.0.0.1'
REDIS_PORT = 6389


def enumerate_paths(path_list, recursive_scan):
    ret_paths = []
    while path_list:
        path = path_list.pop()
        file_path = abspath(path)
        if isfile(file_path):
            ret_paths.append(file_path)
        elif isdir(file_path):
            for p in iglob(join(file_path, "*")):
                p = join(file_path, p)
                if isfile(p) or (isdir(p) and recursive_scan):
                    path_list.append(p)
    return ret_paths

if __name__ == "__main__":
    parser = ArgumentParser(description="Push a directory into redis.")
    parser.add_argument('path', metavar='path', type=str, nargs='+', help="Paths to files or directories to scan")
    parser.add_argument('-r', '--recursive', default=False, required=False, action='store_true',
                        help="Scan paths recursively")
    args = parser.parse_args()
    root_path = args.path
    paths = enumerate_paths(root_path, args.recursive)

    r = init_redis('ssdc.conf')

    for p in paths:
        try:
            r.set(p, open(p, 'r').read())
            r.sadd('to_process', p)
        except Exception as e:
            print(e)
