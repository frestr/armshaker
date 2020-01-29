#!/usr/bin/env python3
import subprocess
import time
import multiprocessing

if __name__ == '__main__':
    procs = []

    for i in range(multiprocessing.cpu_count()):
        proc = subprocess.Popen(['./fuzzer', '-l', str(i), '-d', '-q'],
                                stdout=subprocess.PIPE,
                                stdin=subprocess.PIPE)
        procs.append(proc)

    time.sleep(0.1)

    try:
        while True:
            status = {}
            try:
                while True:
                    for i in range(len(procs)):
                        with open('data/status{}'.format(i), 'r') as f:
                            for line in f.readlines():
                                try:
                                    key, val = line.split(':')
                                except ValueError:
                                    print("ERROR: Ill-formmated statusfile")
                                    exit(1)
                                status[key] = val.strip()

                            print('W{}|curr_insn: {}\tchecked: {}\tskipped: {}\thidden: {}\tips: {}'
                                  .format(i,
                                          status['curr_insn'],
                                          status['instructions_checked'],
                                          status['instructions_skipped'],
                                          status['hidden_instructions_found'],
                                          status['instructions_per_sec']
                                          )
                                  )
                    time.sleep(1)
                    print()
            except FileNotFoundError:
                time.sleep(0.1)
    except KeyboardInterrupt:
        for proc in procs:
            proc.kill()
