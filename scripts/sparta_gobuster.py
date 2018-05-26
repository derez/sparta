#!/usr/bin/env python
# written to work with sparta scanner

import sys
import os
import subprocess
import argparse

current_path = os.path.abspath(os.path.dirname(__file__))
sparta_path = os.path.abspath(os.path.join(current_path, '..'))

SOURCE_WORDLIST_FILES = [
    '/usr/share/dirb/wordlists/common.txt', 
    #'/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt',
    '/usr/share/dirb/wordlists/vulns/apache.txt',
    '/usr/share/dirb/wordlists/vulns/frontpage.txt',
    '/usr/share/dirb/wordlists/vulns/jrun.txt',
    '/usr/share/dirb/wordlists/vulns/tests.txt',
    '/usr/share/dirb/wordlists/vulns/axis.txt',
    '/usr/share/dirb/wordlists/vulns/hpsmh.txt',
    '/usr/share/dirb/wordlists/vulns/netware.txt',
    '/usr/share/dirb/wordlists/vulns/tomcat.txt',
    '/usr/share/dirb/wordlists/vulns/cgis.txt',
    '/usr/share/dirb/wordlists/vulns/hyperion.txt',
    '/usr/share/dirb/wordlists/vulns/oracle.txt',
    '/usr/share/dirb/wordlists/vulns/vignette.txt',
    '/usr/share/dirb/wordlists/vulns/coldfusion.txt',
    '/usr/share/dirb/wordlists/vulns/iis.txt',
    '/usr/share/dirb/wordlists/vulns/ror.txt',        
    '/usr/share/dirb/wordlists/vulns/weblogic.txt',
    '/usr/share/dirb/wordlists/vulns/domino.txt',
    '/usr/share/dirb/wordlists/vulns/iplanet.txt', 
    '/usr/share/dirb/wordlists/vulns/sap.txt',   
    '/usr/share/dirb/wordlists/vulns/websphere.txt',
    '/usr/share/dirb/wordlists/vulns/fatwire_pagenames.txt',  
    '/usr/share/dirb/wordlists/vulns/jboss.txt',
    '/usr/share/dirb/wordlists/vulns/sharepoint.txt',
    '/usr/share/dirb/wordlists/vulns/fatwire.txt',
    '/usr/share/dirb/wordlists/vulns/jersey.txt',
    '/usr/share/dirb/wordlists/vulns/sunas.txt',
    '/usr/share/wfuzz/wordlist/Injections/All_attack.txt',
    '/usr/share/wfuzz/wordlist/vulns/sql_inj.txt',
    '/usr/share/wfuzz/wordlist/vulns/dirTraversal-nix.txt',
    '/usr/share/wfuzz/wordlist/vulns/dirTraversal-win.txt',
]

SOURCE_MERGE_FILES = [
    ('/usr/share/dirb/wordlists/indexes.txt', '/usr/share/dirb/wordlists/extensions_common.txt'),
]



def command_line_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true', help='Debug script')
    parser.add_argument('--target', action='store', required=True, help='Target to scan')
    parser.add_argument('--output', action='store', help='Path to store output')

    options = parser.parse_args()
    try:
        wordlist_file = os.path.join(sparta_path, 'wordlists', 'web_wordlist.lst')

        if not os.path.isfile(wordlist_file):
            print('Regenerating deduped wordlist file')
            # Generate it since it will be used again - considering memory usage
            seen = set()
            for file_path in SOURCE_WORDLIST_FILES:
                print('Adding {!s}'.format(file_path))
                with open(file_path, 'r') as fp:
                    for line in fp:
                        seen.add(line)
        
            for path_file, ext_file in SOURCE_MERGE_FILES:
                print('Merging files {0!s} and {1!s}'.format(path_file, ext_file))
                for p in path_file:
                    for e in ext_file:
                        nline = p + e
                        seen.add(nline)

            with open(wordlist_file, 'w') as dwf:
                dwf.writelines(seen)
        

        if not options.output:
            options.output = os.path.join(current_path, 'outfile.gobust')


        print('[*] Starting gobuster scan for {!s}'.format(options.target))
        print('[*] Output written to {!s}'.format(options.output))

        CMDLINE = 'gobuster -u {0!s} -w {1!s} -o {2!s} -l -q -k'.format(options.target, wordlist_file, options.output)
        try:
            results = subprocess.check_output(CMDLINE, shell=True)

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


