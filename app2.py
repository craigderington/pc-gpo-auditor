"""
Application stub
"""
import os
import sys
import platform
from datetime import datetime
import traceback
import types
from pyparser import convert_file, read_gpo


def isUserAdmin():
    if os.name == 'nt':
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            traceback.print_exc()
            print('Admin check failed, assuming user is not an admin...')
            return False

    elif os.name == 'posix':
        return os.getuid() == 0

    else:
        raise RuntimeError('Unsupported operating system for this module: {}'.format(os.name))


def runAsAdmin(cmdLine=None, wait=True):
    if os.name != 'nt':
        raise RuntimeError('This function is only implemented on Windows')

    import win32api, win32con, win32event, win32process
    from win32com.shell.shell import ShellExecuteEx
    from win32com.shell import shellcon

    python_exe = sys.executable

    if cmdLine is None:
        cmdLine = [python_exe] + sys.argv
    elif type(cmdLine) not in (types.TupleType, types.ListType):
        raise ValueError('cmdLine is not a sequence.')

    cmd = '{}'.format(cmdLine[0])
    params = ' '.join(['{}'.format(x, ) for x in cmdLine[1:]])
    cmdDir = ''
    showCmd = win32con.SW_SHOWNORMAL
    lpVerb = 'runas'   # causes a UAC elevation prompt

    procInfo = ShellExecuteEx(
        nShow=showCmd,
        fMask=shellcon.SEE_MASK_NOCLOSEPROCESS,
        lpVerb=lpVerb,
        lpFile=cmd,
        lpParameters=params
    )

    if wait:
        procHandle = procInfo['hProcess']
        obj = win32event.WaitForSingleObject(procHandle, win32event.INFINITE)
        rc = win32process.GetExitCodeProcess(procHandle)
    else:
        rc = None


def initialize():
    """
    Initialize the application
    :return True
    """    
    return True


def get_response():
    """
    Example response from the backend
    :return Response object 
    """
    response = "This is the response from my Python backend"
    return response


def get_pc_info():
    """
    Get the PC data for the templates 
    :return dict 'pc_info'
    """
    pc_info = {
        'today': datetime.now().strftime('%x'),
        'pc_platform': platform.platform(),
        'pc_name': platform.node(),
        'pc_release': platform.release(),
        'win_ver': platform.version(),
    }
    
    return pc_info


def generate_gpo_file():
    """ 
    Create the Group Policy File Output
    :return rc int
    """
    rc = 0
    os.system('secedit /export /cfg C:\Security\FY2018\SecurityContoso.inf /areas SECURITYPOLICY GROUP_MGMT USER_RIGHTS /log C:\Security\FY2018\securityexport.log')
    return rc


def create_gpo_file():
    """
    Generate the GPO data file
    :return: none
    """
    local_path = 'C:\\Security\\FY2018\\'

    if not os.path.exists(os.path.dirname(local_path)):
        try:
            os.makedirs(os.path.dirname(local_path))
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise

    generate_gpo_file()
    return True


def get_gpo_results():

    try:
        local_path = 'C:\\Security\\FY2018\\'
        filename = local_path + '\group-policy-results.txt'
        read_gpo(filename)
    except IOError as err:
        print(err)
    
    results = {}  
    
    return dict(results)
