#!/usr/bin/env python
# -*- coding: utf-8 -*-

import networkx
import hashlib
import pydeep
from struct import unpack
import base64
import re
from ConfigParser import SafeConfigParser
import redis

# https://www.virusbtn.com/virusbulletin/archive/2015/11/vb201511-ssDeep
# https://github.com/trendmicro/tlsh
# https://drive.google.com/file/d/0B6FS3SVQ1i0GTXk5eDl3Y29QWlk/edit
# https://www.usenix.org/system/files/conference/cset15/cset15-li.pdf


def init_redis(configfile):
    config = SafeConfigParser()
    config.read('ssdc.conf')
    return redis.StrictRedis(host=config.get('redis', 'host'), port=config.get('redis', 'port'))


def get_all_7_char_chunks(h):
    return set((unpack("<Q", base64.b64decode(h[i:i + 7] + "=") + "\x00\x00\x00")[0] for i in xrange(len(h) - 6)))


def preprocess_hash(h):
    block_size, block_data, double_block_data = h.split(':')

    # Reduce any sequence of the same char greater than 3 to 3
    re.sub(r'(\w)\1\1\1(\1+)', r'\1\1\1', block_data)
    re.sub(r'(\w)\1\1\1(\1+)', r'\1\1\1', double_block_data)

    return block_size, get_all_7_char_chunks(block_data), get_all_7_char_chunks(double_block_data)


def add_chunks_db(r, block_size, chunk, sha256):
    for i in chunk:
        key = '{}:{}'.format(block_size, i)
        r.sadd(key, sha256)
        r.sadd('all_keys_similar', key)
        r.sadd('all_keys_similar_new', key)


def prepare_hashes(r, buf, path):
    deephash = pydeep.hash_buf(buf)
    sha256 = hashlib.sha256(file(path, 'rb').read()).hexdigest()
    p = r.pipeline(False)
    p.hmset(sha256, {'path': path, 'ssdeep': deephash})
    p.sadd('hashes', sha256)

    block_size, chunk, double_chunk = preprocess_hash(deephash)
    add_chunks_db(p, block_size, chunk, sha256)
    add_chunks_db(p, block_size, double_chunk, sha256)
    p.execute()


def find_matches(key, r):
    similar_hashes = r.smembers(key)
    if len(similar_hashes) > 1:
        cur_hash = similar_hashes.pop()
        cur_ssdeep = r.hget(cur_hash, 'ssdeep')
        p = r.pipeline(False)
        for sha256 in similar_hashes:
            score = pydeep.compare(cur_ssdeep, r.hget(sha256, 'ssdeep'))
            if score > 0:
                p.zadd('matches_{}'.format(cur_hash), score, sha256)
                p.zadd('matches_{}'.format(sha256), score, cur_hash)
        p.execute()


def compute_all_similarities(r):
    for key in r.smembers('all_keys_similar'):
        find_matches(key, r)


def clean_groups(r):
    for g in r.smembers('groups'):
        r.delete(g)
    r.delete('groups')
    r.delete('no_matches')


def make_groups(r):
    clean_groups(r)
    all_hashes = r.smembers('hashes')
    while all_hashes:
        cur_hash = all_hashes.pop()
        matches = r.zrange('matches_{}'.format(cur_hash), 0, -1)
        if matches:
            if isinstance(matches, list):
                matches = set(matches)
            else:
                matches = set([matches])
            all_hashes -= matches
            matches |= set([cur_hash])
        else:
            # NOTE: Should we make a group?
            # matches = set([cur_hash])
            r.sadd('no_matches', cur_hash)
            continue
        key = 'group_{}'.format(r.scard('groups'))
        r.sadd('groups', key)
        r.sadd(key, *matches)


def display(r, verbose=False):
    print("{0} files are in no group ".format(r.scard('no_matches')))
    print("{0} files organized into {1} groups".format(r.scard('hashes') - r.scard('no_matches'), r.scard('groups')))
    print("Groups distribution:")
    for group in r.smembers('groups'):
        if r.scard(group) > 1:
            print("Group {0} has {1} files".format(group, r.scard(group)))
            if verbose:
                for sha256 in r.smembers(group):
                    print("\t{}".format(r.hget(sha256, 'path')))


def make_graph(r):
    g = networkx.Graph()
    groups = r.smembers('groups')
    for group in groups:
        if r.scard(group) < 2:
            continue
        g.add_node(group)
        for h in r.smembers(group):
            g.add_edge(group, h)

    networkx.write_gexf(g, './test.gexf')
