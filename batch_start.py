#!/usr/bin/env python3
import subprocess
import time
import multiprocessing
import curses
import atexit
import sys

def update(stdscr, procs):
    for proc_num in range(len(procs)):
        with open('data/status{}'.format(proc_num), 'r') as f:
            status = {}
            for line in f.readlines():
                try:
                    key, val = line.split(':')
                except ValueError:
                    print("ERROR: Ill-formatted statusfile")
                    exit(1)
                status[key] = val.replace('\t', ' ').strip()

            lines = []
            try:
                lines.append('insn:      {}'.format(status['curr_insn']))
                lines.append('cs_disas:  {}'.format(status['cs_disas']))
                lines.append('opc_disas: {}'.format(status['libopcodes_disas']))
                lines.append('checked:   {:,}'.format(int(status['instructions_checked'])))
                lines.append('skipped:   {:,}'.format(int(status['instructions_skipped'])))
                lines.append('hidden:    {:,}'.format(int(status['hidden_instructions_found'])))
                lines.append('ips:       {:,}'.format(int(status['instructions_per_sec'])))
            except KeyError:
                # Sometimes we read the statusfile while it's being written to.
                # Ideally we should have a lock or something, but this works for now...
                continue

            max_line_length = 45
            for line_num in range(len(lines)):
                lines[line_num] = lines[line_num][:max_line_length].ljust(max_line_length)

            y_offset = 11 if proc_num > 1 else 1
            x_offset = (proc_num % 2)*50 + 1

            header = '╔═ Worker {} '.format(proc_num).ljust(max_line_length+1, '═') + '╗'
            stdscr.addstr(y_offset, x_offset, header)
            for line_num in range(len(lines)):
                stdscr.addstr(y_offset+1+line_num, x_offset, '║{}║'.format(lines[line_num]))
            footer = '╚'.ljust(max_line_length+1, '═') + '╝'
            stdscr.addstr(y_offset+1+len(lines), x_offset, footer)

    stdscr.refresh()

def start_procs():
    procs = []
    proc_count = multiprocessing.cpu_count()
    search_range = (0, 0xffffffff)
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

def main(stdscr):
    procs = start_procs()

    curses.cbreak()
    stdscr.keypad(True)
    curses.noecho()
    curses.curs_set(False)

    atexit.register(exit_handler, procs)

    while True:
        try:
            update(stdscr, procs)
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

class Stdout_wrapper:
    text = ""
    def write(self,txt):
        self.text += txt
        self.text = '\n'.join(self.text.split('\n')[-30:])
    def get_text(self):
        return '\n'.join(self.text.split('\n'))

if __name__ == '__main__':
    # For debugging
    mystdout = Stdout_wrapper()
    sys.stdout = mystdout
    sys.stderr = mystdout

    curses.wrapper(main)

    sys.stdout = sys.__stdout__
    sys.stderr = sys.__stdout__
    sys.stdout.write(mystdout.get_text())
