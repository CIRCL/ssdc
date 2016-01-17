Why
===

This code uses the same ideas as the standalone ssdc code but allows to store everything
in a redis database, compute the hashes and compare the samples with multiple processes at once.

Installation
============

`pip install -r requirements.txt`

Usage
=====

1. Run redis with the config file provided: `redis-server redis.conf`
2. Edit `run_compute.sh` and modify the seq value to the amount of CPU you have on the machine
3. Run `run_compute.sh`
4. Run `import_dir.py -r <directory to import>`
5. When finished (check if the `compute.py` processes are working), run `compare.py`
