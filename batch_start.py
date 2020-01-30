#!/usr/bin/env python3
import subprocess
import time
import multiprocessing
import curses
import atexit
import sys
import argparse
import fcntl

WORKER_AREA_WIDTH = 45

def get_status(proc_num):
    f = open('data/status{}'.format(proc_num), 'r')
    fcntl.flock(f, fcntl.LOCK_EX)

    lines = f.readlines()

    fcntl.flock(f, fcntl.LOCK_UN)
    f.close()

    status = {}
    for line in lines:
        try:
            key, val = line.split(':')
        except ValueError:
            print("ERROR: Ill-formatted statusfile")
            return None
        status[key] = val.replace('\t', ' ').strip()

    # TODO: Remove nasty hardcode
    if len(status) != 7:
        # Sometimes we read the statusfile while it's being written to.
        # Ideally we should have a lock or something, but this works for now...
        return None

    return status


def print_worker(stdscr, proc_num, status, global_y_offset):
    lines = []
    lines.append('insn:      {}'.format(status['curr_insn']))
    lines.append('cs_disas:  {}'.format(status['cs_disas']))
    lines.append('opc_disas: {}'.format(status['libopcodes_disas']))
    lines.append('checked:   {:,}'.format(int(status['instructions_checked'])))
    lines.append('skipped:   {:,}'.format(int(status['instructions_skipped'])))
    lines.append('hidden:    {:,}'.format(int(status['hidden_instructions_found'])))
    lines.append('ips:       {:,}'.format(int(status['instructions_per_sec'])))

    max_line_length = WORKER_AREA_WIDTH - 4
    for line_num in range(len(lines)):
        lines[line_num] = lines[line_num][:max_line_length].ljust(max_line_length)

    y_offset = (11 if proc_num > 1 else 1) + global_y_offset
    x_offset = (proc_num % 2)*(WORKER_AREA_WIDTH+2) + 1

    header = '╔═ Worker {} '.format(proc_num).ljust(WORKER_AREA_WIDTH-1, '═') + '╗'
    stdscr.addstr(y_offset, x_offset, header)
    for line_num in range(len(lines)):
        stdscr.addstr(y_offset+1+line_num, x_offset, '║ {} ║'.format(lines[line_num]))
    footer = '╚'.ljust(WORKER_AREA_WIDTH-1, '═') + '╝'
    stdscr.addstr(y_offset+1+len(lines), x_offset, footer)


def print_summary(stdscr, statuses, just_height=False):
    sum_status = {
            'checked': 0,
            'skipped': 0,
            'hidden': 0,
            'ips': 0
    }

    for status in statuses:
        if status is None:
            continue
        sum_status['checked'] += int(status['instructions_checked'])        
        sum_status['skipped'] += int(status['instructions_skipped'])        
        sum_status['hidden'] += int(status['hidden_instructions_found'])        
        sum_status['ips'] += int(status['instructions_per_sec'])        

    lines = []
    lines.append('checked:   {:,}'.format(int(sum_status['checked'])))
    lines.append('skipped    {:,}'.format(int(sum_status['skipped'])))
    lines.append('hidden:    {:,}'.format(int(sum_status['hidden'])))
    lines.append('ips:       {:,}'.format(int(sum_status['ips'])))

    max_line_length = (WORKER_AREA_WIDTH) * 2 - 2

    for line_num in range(len(lines)):
        lines[line_num] = lines[line_num][:max_line_length].ljust(max_line_length)

    y_offset = 1
    x_offset = 1

    if not just_height:
        header = '╔═ Summary '.ljust(max_line_length+3, '═') + '╗'
        stdscr.addstr(y_offset, x_offset, header)
        for line_num in range(len(lines)):
            stdscr.addstr(y_offset+1+line_num, x_offset, '║ {} ║'.format(lines[line_num]))
        footer = '╚'.ljust(max_line_length+3, '═') + '╝'
        stdscr.addstr(y_offset+1+len(lines), x_offset, footer)

    return len(lines) + 3


def update(stdscr, procs):
    # Read the statusfiles
    statuses = []
    for proc_num in range(len(procs)):
        statuses.append(get_status(proc_num))

    # Sometimes reading the status files fails. In those cases, don't
    # update the values, as they will be incorrect
    height = print_summary(stdscr, statuses, None in statuses)

    # Print workers
    for proc_num, status in enumerate(statuses):
        if status is None:
            continue
        print_worker(stdscr, proc_num, status, height)

    stdscr.refresh()


def start_procs(search_range):
    procs = []
    proc_count = multiprocessing.cpu_count()
    proc_search_size = int((search_range[1] - search_range[0] + 1) / proc_count)
    for i in range(proc_count):
        insn_start = search_range[0] + proc_search_size * i
        insn_end  = search_range[0] + (proc_search_size) * (i + 1) - 1
        if i == proc_count - 1:
            insn_end = search_range[1]

        cmd = ['./fuzzer',
               '-l', str(i),
               '-s', hex(insn_start),
               '-e', hex(insn_end),
               '-d', '-q']
        proc = subprocess.Popen(cmd,
                                stdout=subprocess.PIPE,
                                stdin=subprocess.PIPE)
        procs.append(proc)

    return procs


def exit_handler(procs):
    for proc in procs:
        proc.kill()


def main(stdscr, args):
    search_range = (args.start if type(args.start) is int else args.start[0],
                    args.end if type(args.end) is int else args.end[0])
    procs = start_procs(search_range)

    curses.cbreak()
    stdscr.keypad(True)
    curses.noecho()
    curses.curs_set(False)
    stdscr.nodelay(True)

    atexit.register(exit_handler, procs)

    while True:
        try:
            update(stdscr, procs)
            if stdscr.getch() == ord('q'):
                break
            time.sleep(0.1)
        except FileNotFoundError:
            # Wait a little if the status files haven't been created yet
            time.sleep(0.1)
        except KeyboardInterrupt:
            break

    curses.nocbreak()
    stdscr.keypad(False)
    curses.echo()
    curses.curs_set(True)
    curses.endwin()


if __name__ == '__main__':
    def hex_int(x):
        return int(x, 16)

    parser = argparse.ArgumentParser(description='fuzzer front-end')
    parser.add_argument('-s', '--start',
                        type=hex_int, nargs=1,
                        help='search range start',
                        metavar='INSN', default=0)
    parser.add_argument('-e', '--end',
                        type=hex_int, nargs=1,
                        help='search range end',
                        metavar='INSN', default=0xffffffff)

    args = parser.parse_args()
    curses.wrapper(main, args)
