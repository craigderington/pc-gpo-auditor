import os
from flask import Flask, url_for, render_template, jsonify, request, redirect, make_response, flash
from flask_mail import Mail, Message
#from pdfs import create_pdf
import config
import webview
import webbrowser
import app

# set up the gui directory path
# gui_dir = os.path.join(os.getcwd(), "gui")  # development path
# if not os.path.exists(gui_dir):             # frozen executable path
# frozen path gui dir    
gui_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gui")

# set the server and server config
server = Flask(__name__, static_folder=gui_dir, template_folder=gui_dir)
server.config["SEND_FILE_MAX_AGE_DEFAULT"] = 1  # disable caching
server.secret_key = config.SECRET_KEY
server.config.update(dict(
    MAIL_SERVER='mail.bellcurvetechnology.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='compliant@bellcurvetechnology.com',
    MAIL_PASSWORD='2112Rl#e',
    MAIL_DEFAULT_SENDER='Compliant Devices <compliant@bellcurvetechnology.com>'
))

# Flask-Mail
mail = Mail(server)

@server.after_request
def add_header(response):
    """ 
    Modify the response headers
    :return response
    """
    response.headers['Cache-Control'] = 'no-cache, no-store, no-transform'    
    return response


@server.route("/init")
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


@server.route("/")
def index():
    """
    PyWebView Application Entry Point.
    :return template   
    """
    return render_template(
        "index.html",
        pc = app.get_pc_info()    
    )


@server.route('/access', methods=['GET'])
def access():
    """
    GPO section for System Access"
    :return template
    """
    return render_template(
        'access.html',
        pc=app.get_pc_info(),
        results=app.get_gpo_results(),
    )


@server.route('/events', methods=['GET'])
def events():
    """
    GPO section for System Events
    :return dict
    """
    results = {}

    return render_template(
        'events.html',
        pc=app.get_pc_info(),
        results=app.get_gpo_results(),
    )


@server.route('/registry', methods=['GET'])
def registry():
    """
    GPO section for System Registry
    :return dict
    """
    results = {}

    return render_template(
        'registry.html',
        pc=app.get_pc_info(),
        results=app.get_gpo_results(),
    )


@server.route('/user', methods=['GET'])
def user():
    """
    GPO section for User Rights
    "return dict
    """
    results = {}

    return render_template(
        'user.html',
        pc=app.get_pc_info(),
        results=app.get_gpo_results(),
    )


@server.route('/version', methods=['GET'])
def version():
    """
    GPO section for System Version
    :return dict
    """
    return render_template(
        'version.html',
        pc=app.get_pc_info(),
        results=app.get_gpo_results(),
    )


@server.route('/email', methods=['POST'])
def email():
    """
    Create and send email from the server app
    :return none
    """
    pc = app.get_pc_info()
    email = request.form['input_email']
    subject = 'Bellcurve - GPO HIPAA Compliance Audit Report for ' + pc['pc_name']    
    msg = Message(subject=subject, sender=config.MAIL_DEFAULT_SENDER, recipients=[email])
    msg.body = 'This email contains a PDF report.'
    #pdf = create_pdf(render_template('email.html', pc=app.get_pc_info()))
    #msg.attach('report.pdf', 'application/pdf', pdf.getvalue())
    mail.send(msg)
    flash('The GPO Audit Report was successfully sent to {}'.format(email), 'info')
    return redirect(url_for('index'))
    

@server.route('/email/help', methods=['GET'])
def email_help():
    """
    Create and send the email support team
    :return Flask-Mail sender
    """
    pc = app.get_pc_info()
    subject = 'Bellcurve Technology - GPO HIPAA Complaince Audit Report for ' + pc['pc_name']
    receiver = 'helpme@bellcurvetechnology.com'
    msg = Message(subject=subject, sender=config.MAIL_DEFAULT_SENDER, recipients=[receiver])
    msg.body = 'This email contains a PDF report.'
    #pdf = create_pdf(render_template('email_help.html', pc=app.get_pc_info()))
    #msg.attach('report.pdf', 'application/pdf', pdf.getvalue())
    mail.send(msg)
    flash('The GPO audit report was successfully sent to {}.'.format(receiver), 'info')
    return redirect(url_for('index'))


@server.errorhandler(404)
def page_not_found(e):
    """
    Handle 404 Errors
    :return errorhandler
    """
    server.logger.warning('An warning error occurred: {}.'.format(e))
    return render_template(
        '404.html'
    ), 404


@server.errorhandler(500)
def internal_server_error(e):
    """
    Handle 500 Errors
    :return errorhandler
    """
    server.logger.error('An app error occurred: {}.'.format(e))
    return render_template(
        '500.html'
    ), 500


@server.route("/choose/path")
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


@server.route("/fullscreen")
def fullscreen():
    """
    Toggle full-screen
    return: none
    """
    webview.toggle_fullscreen()
    return jsonify({})


@server.route("/open-url", methods=["POST"])
def open_url():
    """Open a URL
    :return URI (webpage)
    """
    url = request.json["url"]
    webbrowser.open_new_tab(url)

    return jsonify({})


@server.route("/do/stuff")
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


def run_server():
    """ 
    Start the server
    :return server
    """
    server.run(
        host="127.0.0.1", 
        port=23948, 
        threaded=True
    )


if __name__ == "__main__":
    run_server()
