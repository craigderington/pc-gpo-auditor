# /usr/bin/python

import os
import errno
import time
import run_as_admin

local_path = 'C:\\Security\\FY2018\\'


def read_gpo(filename):
    """ Read the GPO output file and create an array of values """
    if os.path.exists(os.path.dirname(local_path)):
        with open(filename, 'r') as f:
            lines = f.readlines()
            for line in lines:
                print(line)


def main():
    """
    Run the main program.  Check that the path exists to store the output GPO file.
    Once generated, read the file and parse the data
    """
    if not os.path.exists(os.path.dirname(local_path)):
        try:
            os.makedirs(os.path.dirname(local_path))
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
 
    run_as_admin.generate_gpo_file()
    time.sleep(2)
    filename = 'SecurityContoso.inf'
    read_gpo(os.path.join(local_path, filename)) 
    

if __name__ == '__main__':
    main()
