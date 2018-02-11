import sys
import os
from flask import Flask
# Other imports

if getattr(sys, 'frozen', False):
    template_folder = os.path.join(sys.executable, '..', 'templates')
    app = Flask(__name__, template_folder=template_folder)
else:
    app = Flask(__name__)