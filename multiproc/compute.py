#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
from lib import init_redis, prepare_hashes, find_matches


def compute(r):
    while not r.exists('stop'):
        path_key = r.spop('to_process')
        if path_key is not None:
            buf = r.get(path_key)
            prepare_hashes(r, buf, path_key)
            r.delete(path_key)
        elif r.exists('all_keys_similar_new'):
            find_matches(r.spop('all_keys_similar_new'), r)
        else:
            time.sleep(1)


if __name__ == "__main__":
    r = init_redis('ssdc.conf')
    r.delete('stop')
    compute(r)
