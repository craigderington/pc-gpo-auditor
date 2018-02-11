from flask import Flask, render_template, Flask, url_for, render_template, jsonify, request, redirect, make_response, flash
from flask_mail import Mail, Message 
import webview
import sys
from threading import Thread, Lock
import os
import platform
from datetime import datetime
import traceback
import types
from pyparser import convert_file, read_gpo
from time import sleep
import logging
import config

# create a thread lock
server_lock = Lock()
logger = logging.getLogger(__name__)
 
app = Flask(__name__)

# set the app config
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 1  # disable caching
app.secret_key = config.SECRET_KEY
app.config.update(dict(
    MAIL_SERVER='mail.bellcurvetechnology.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='compliant@bellcurvetechnology.com',
    MAIL_PASSWORD='2112Rl#e',
    MAIL_DEFAULT_SENDER='Compliant Devices <compliant@bellcurvetechnology.com>'
))

# Flask-Mail
mail = Mail(app)

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

def url_ok(url, port):
    """
    Function to check the status of the server
    before launching the pywebviewer
    :return conn
    """
    try:
        from http.client import HTTPConnection
    except ImportError:
        from httplib import HTTPConnection

    try:
        conn = HTTPConnection(url, port)
        conn.request("GET", "/")
        r = conn.getresponse()
        return r.status == 200
    except:
        logger.exception("Server not started")
        return False
 
@app.after_request
def add_header(response):
    """ 
    Modify the response headers
    :return response
    """
    response.headers['Cache-Control'] = 'no-cache, no-store, no-transform'    
    return response


@app.route("/init")
def initialize():
    """
    Initialize app asynchronously.
    :return: app
    """
    can_start = app.initialize()

    if can_start:
        response = {
            "status": "ok",
        }
    else:
        response = {
            "status": "error"
        }

    return jsonify(response)


@app.route("/")
def index():
    """
    PyWebView Application Entry Point.
    :return template   
    """
    return render_template(
        "index.html",
        pc = get_pc_info()    
    )


@app.route('/access', methods=['GET'])
def access():
    """
    GPO section for System Access"
    :return template
    """
    return render_template(
        'access.html',
        pc=get_pc_info(),
        results=get_gpo_results(),
    )


@app.route('/events', methods=['GET'])
def events():
    """
    GPO section for System Events
    :return dict
    """
    results = {}

    return render_template(
        'events.html',
        pc=get_pc_info(),
        results=get_gpo_results(),
    )


@app.route('/registry', methods=['GET'])
def registry():
    """
    GPO section for System Registry
    :return dict
    """
    results = {}

    return render_template(
        'registry.html',
        pc=get_pc_info(),
        results=get_gpo_results(),
    )


@app.route('/user', methods=['GET'])
def user():
    """
    GPO section for User Rights
    "return dict
    """
    results = {}

    return render_template(
        'user.html',
        pc=get_pc_info(),
        results=get_gpo_results(),
    )


@app.route('/version', methods=['GET'])
def version():
    """
    GPO section for System Version
    :return dict
    """
    return render_template(
        'version.html',
        pc=get_pc_info(),
        results=get_gpo_results(),
    )


@app.route('/email', methods=['POST'])
def email():
    """
    Create and send email from the server app
    :return none
    """
    pc = get_pc_info()
    email = request.form['input_email']
    subject = 'Bellcurve - GPO HIPAA Compliance Audit Report for ' + pc['pc_name']    
    msg = Message(subject=subject, sender=config.MAIL_DEFAULT_SENDER, recipients=[email])
    msg.body = 'This email contains a PDF report.'
    #pdf = create_pdf(render_template('email.html', pc=get_pc_info()))
    #msg.attach('report.pdf', 'application/pdf', pdf.getvalue())
    mail.send(msg)
    flash('The GPO Audit Report was successfully sent to {}'.format(email), 'info')
    return redirect(url_for('index'))
    

@app.route('/email/help', methods=['GET'])
def email_help():
    """
    Create and send the email support team
    :return Flask-Mail sender
    """
    pc = get_pc_info()
    subject = 'Bellcurve Technology - GPO HIPAA Complaince Audit Report for ' + pc['pc_name']
    receiver = 'helpme@bellcurvetechnology.com'
    msg = Message(subject=subject, sender=config.MAIL_DEFAULT_SENDER, recipients=[receiver])
    msg.body = 'This email contains a PDF report.'
    #pdf = create_pdf(render_template('email_help.html', pc=get_pc_info()))
    #msg.attach('report.pdf', 'application/pdf', pdf.getvalue())
    mail.send(msg)
    flash('The GPO audit report was successfully sent to {}.'.format(receiver), 'info')
    return redirect(url_for('index'))


@app.errorhandler(404)
def page_not_found(e):
    """
    Handle 404 Errors
    :return errorhandler
    """
    logger.warning('An warning error occurred: {}.'.format(e))
    return render_template(
        '404.html'
    ), 404


@app.errorhandler(500)
def internal_server_error(e):
    """
    Handle 500 Errors
    :return errorhandler
    """
    logger.error('An app error occurred: {}.'.format(e))
    return render_template(
        '500.html'
    ), 500


@app.route("/choose/path")
def choose_path():
    """
    Invoke a folder selection dialog here
    :return: path
    """
    dirs = webview.create_file_dialog(webview.FOLDER_DIALOG)
    if dirs and len(dirs) > 0:
        directory = dirs[0]
        if isinstance(directory, bytes):
            directory = directory.decode("utf-8")

        response = {"status": "ok", "directory": directory}
    else:
        response = {"status": "cancel"}

    return jsonify(response)


@app.route("/fullscreen")
def fullscreen():
    """
    Toggle full-screen
    return: none
    """
    webview.toggle_fullscreen()
    return jsonify({})


@app.route("/open-url", methods=["POST"])
def open_url():
    """Open a URL
    :return URI (webpage)
    """
    url = request.json["url"]
    webbrowser.open_new_tab(url)

    return jsonify({})


@app.route("/do/stuff")
def do_stuff():
    """
    Example function
    :return response
    """
    result = app.get_response()

    if result:
        response = {"status": "ok", "result": result}
    else:
        response = {"status": "error"}

    return jsonify(response)
 
def start_server():
    app.run(
        host='127.0.0.1',
        port=23948
    )
 
if __name__ == '__main__':
    logger.debug('Starting pyViewer...')
    t = Thread(target=start_server)
    t.daemon = True
    t.start()
    logger.debug('Checking server...')

     # create our group policy document and convert to utf-8
    create_gpo_file()
    convert_file(config.INFILE, config.OUTFILE)
    
    # check to make sure the server is running before opening the webviewer
    while not url_ok("127.0.0.1", 23948):
        sleep(0.1)

    # log the server start and webview create window
    logger.debug("Server started...")
    
    webview.create_window("HIPAA PC Compliance Auditor", "http://127.0.0.1:23948", min_size=(1280, 920))
    
    # exit the app gracefully
    sys.exit(1)