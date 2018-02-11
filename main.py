import sys
from threading import Thread, Lock
import logging
import webview
import app
from time import sleep
from server import run_server
from pyparser import convert_file
import config

server_lock = Lock()
logger = logging.getLogger(__name__)


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

if __name__ == '__main__':
    logger.debug("Starting server")
    t = Thread(target=run_server)
    t.daemon = True
    t.start()
    logger.debug("Checking server")
    
    # create our group policy document and convert to utf-8
    app.create_gpo_file()
    convert_file(config.INFILE, config.OUTFILE)
    
    # check to make sure the server is running before opening the webviewer
    while not url_ok("127.0.0.1", 23948):
        sleep(0.1)

    # log the server start and webview create window
    logger.debug("Server started")
    webview.create_window("HIPAA PC Compliance Auditor", "http://127.0.0.1:23948", min_size=(1280, 920))
