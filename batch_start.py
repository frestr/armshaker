#!/usr/bin/env python3
import subprocess
import time
import multiprocessing
import curses
import atexit
import sys
import argparse
import fcntl
import time

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
    if len(status) != 8:
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
    lines.append('discreps:  {:,}'.format(int(status['disas_discrepancies'])))
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


def print_summary(stdscr, statuses, extra_data, just_height=False):
    sum_status = {
            'checked': 0,
            'skipped': 0,
            'hidden': 0,
            'ips': 0,
            'discreps': 0,
            'insns_so_far': 0
    }

    for status in statuses:
        if status is None:
            continue
        sum_status['checked'] += int(status['instructions_checked'])
        sum_status['skipped'] += int(status['instructions_skipped'])
        sum_status['hidden'] += int(status['hidden_instructions_found'])
        sum_status['ips'] += int(status['instructions_per_sec'])
        sum_status['discreps'] += int(status['disas_discrepancies'])

        sum_status['insns_so_far'] += (int(status['instructions_checked'])
                                     + int(status['instructions_skipped'])
                                     + int(status['hidden_instructions_found']))

    total_insns = extra_data['search_range'][1] - extra_data['search_range'][0] + 1
    progress = (sum_status['insns_so_far'] / total_insns) * 100
    elapsed_hrs = (time.time() - extra_data['time_started']) / 60 / 60

    if sum_status['ips'] != 0:
        eta_hrs = ((total_insns - sum_status['insns_so_far']) / sum_status['ips']) / 60 / 60
    else:
        eta_hrs = float('inf')

    lines = []
    lines.append('checked:   {:,}'.format(int(sum_status['checked'])))
    lines.append('skipped:   {:,}'.format(int(sum_status['skipped'])))
    lines.append('hidden:    {:,}'.format(int(sum_status['hidden'])))
    lines.append('discreps:  {:,}'.format(int(sum_status['discreps'])))
    lines.append('ips:       {:,}'.format(int(sum_status['ips'])))
    lines.append('progress:  {:.4f}%'.format(progress))
    lines.append('elapsed:   {:.2f}hrs'.format(elapsed_hrs))
    lines.append('eta:       {:.1f}hrs'.format(eta_hrs))

    max_line_length = (WORKER_AREA_WIDTH) + 2
    max_height = 4

    for line_num in range(len(lines)):
        lines[line_num] = lines[line_num][:max_line_length].ljust(max_line_length)

    y_offset = 1
    x_offset = 1

    if not just_height:
        header = '╔═ Summary '.ljust(max_line_length*2-3, '═') + '╗'
        stdscr.addstr(y_offset, x_offset, header)
        # Add actual strings
        for line_num in range(len(lines)):
            stdscr.addstr(y_offset+1+(line_num % max_height),
                          x_offset + (line_num // max_height)*max_line_length,
                          '  {}  '.format(lines[line_num]))
        # Add border
        for line_num in range(max_height):
            stdscr.addstr(y_offset+1+line_num, x_offset, '║')
            stdscr.addstr(y_offset+1+line_num, x_offset+max_line_length*2-3, '║')
        footer = '╚'.ljust(max_line_length*2-3, '═') + '╝'
        stdscr.addstr(y_offset+1+max_height, x_offset, footer)

    return max_height + 3


def print_done(stdscr):
    y_offset = 15
    x_offset = WORKER_AREA_WIDTH - 5
    stdscr.addstr(y_offset+0, x_offset, '╔═════════════╗')
    stdscr.addstr(y_offset+1, x_offset, '║             ║')
    stdscr.addstr(y_offset+2, x_offset, '║    Done!    ║')
    stdscr.addstr(y_offset+3, x_offset, '║             ║')
    stdscr.addstr(y_offset+4, x_offset, '╚═════════════╝')


def update(stdscr, pad, procs, extra_data):
    # Read the statusfiles
    statuses = []
    for proc_num in range(len(procs)):
        statuses.append(get_status(proc_num))

    # Sometimes reading the status files fails. In those cases, don't
    # update the values, as they will be incorrect
    height = print_summary(pad, statuses, extra_data, None in statuses)

    # Print workers
    for proc_num, status in enumerate(statuses):
        if status is None:
            continue
        print_worker(pad, proc_num, status, height)

    y_size, x_size = stdscr.getmaxyx()
    pad.refresh(0, 0, 0, 0, y_size-1, x_size-1)


def start_procs(search_range, disable_null=False):
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
               '-d' if disable_null else '',
               '-q']
        proc = subprocess.Popen(cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                stdin=subprocess.PIPE)
        procs.append(proc)

    return procs


def exit_handler(procs):
    for proc in procs:
        proc.kill()


def main(stdscr, args):
    search_range = (args.start if type(args.start) is int else args.start[0],
                    args.end if type(args.end) is int else args.end[0])
    procs = start_procs(search_range, args.disable_null)

    curses.cbreak()
    curses.noecho()
    curses.curs_set(False)
    stdscr.keypad(True)
    stdscr.nodelay(True)

    pad = curses.newpad(100, 100)
    pad.nodelay(True)
    pad.keypad(True)

    atexit.register(exit_handler, procs)

    extra_data = {
            'search_range': search_range,
            'time_started': time.time()
    }

    quit_str = 'Done'

    while True:
        try:
            update(stdscr, pad, procs, extra_data)
            if stdscr.getch() == ord('q'):
                quit_str = 'User abort'
                break
            quit = False
            done = True
            for i in range(len(procs)):
                ret = procs[i].poll()
                if ret == 1:
                    outs, errs = procs[i].communicate()
                    quit_str = 'Worker {} crashed:\n{}'.format(i, errs.decode('utf-8'))
                    quit = True
                    break
                elif ret != 0:
                    done = False
                    break
            if quit:
                break
            elif done:
                # All processes terminated sucessfully.
                # When done, update one last time, show a message and
                # wait for any key before quitting
                stdscr.nodelay(False)
                pad.nodelay(False)
                update(stdscr, pad, procs, extra_data)
                print_done(stdscr)
                stdscr.getch()
                break
            else:
                time.sleep(0.1)
        except FileNotFoundError:
            # Wait a little if the status files haven't been created yet
            time.sleep(0.1)
        except KeyboardInterrupt:
            break

    curses.nocbreak()
    stdscr.keypad(False)
    pad.keypad(False)
    curses.echo()
    curses.curs_set(True)
    curses.endwin()

    return quit_str


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
    parser.add_argument('-d', '--disable-null',
                        action='store_true',
                        help='Enable non-root execution by disabling null page allocation')

    args = parser.parse_args()
    quit_str = curses.wrapper(main, args)
    print(quit_str)
