#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
from lib import init_redis, make_groups, make_graph, display


if __name__ == "__main__":
    r = init_redis('ssdc.conf')
    while not r.exists('stop'):
        if not r.exists('to_process') and not r.exists('all_keys_similar_new'):
            make_groups(r)
            break
        else:
            time.sleep(1)
    make_graph(r)
    display(r, True)
