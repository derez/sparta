#!/usr/bin/env python
# tuned to work with sparta scanner

import sys
import os
import subprocess
import argparse

current_path = os.path.abspath(os.path.dirname(__file__))
sparta_path = os.path.abspath(os.path.join(current_path, '..'))

SOURCE_WORDLIST_FOLDERS = ['/usr/share/dirb/wordlists', '/usr/share/dirb/wordlists/vulns']

def command_line_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true', help='Debug script')
    parser.add_argument('--target', action='store', required=True, help='Target to scan')
    parser.add_argument('--output', action='store', help='Path to store output')

    options = parser.parse_args()
    try:
        dirb_wordlist = os.path.join(sparta_path, 'wordlists', 'dirb_wordlist.lst')

        if not os.path.isfile(dirb_wordlist):
            print('Regenerating deduped dirb wordlist file')
            # Generate it since it will be used again - considering memory usage
            seen = set()
            for folder in SOURCE_WORDLIST_FOLDERS:
                for dirpath, dirnames, filenames in os.walk(folder):
                    for f in filenames:
                        file_path = os.path.join(dirpath, f)
                        with open(file_path, 'r') as fp:
                            for line in fp:
                                seen.add(line)
        
            with open(dirb_wordlist, 'w') as dwf:
                dwf.writelines(seen)
        

        if not options.output:
            options.output = os.path.join(current_path, 'outfile.dirb')

        print('[*] Starting dirb scan for {!s}'.format(options.target))
        print('[*] Output written to {!s}'.format(options.output))

        DIRBSCAN = 'dirb {0!s} {1!s} -o {2!s} -S -r -l'.format(options.target, dirb_wordlist, options.output)
        try:
            results = subprocess.check_output(DIRBSCAN, shell=True)

        except:
            pass


    except KeyboardInterrupt:
        raise

    except SystemExit:
        raise

    except Exception as err:
        print('Exception occurred : {0!r}'.format(err))

if __name__ == '__main__':
    sys.exit(command_line_interface())


