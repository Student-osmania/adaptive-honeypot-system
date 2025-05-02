from flask import Flask, render_template, request
import os
from core.logger import log_event  # Import the log_event function

# Initialize the Flask application
app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), 'templates'))

@app.route('/')
def index():
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'unknown')
    log_event(
        event_type="HTTP_REQUEST",
        file_path="/",
        user=user_agent,
        ip_address=ip_address,
        additional_metadata={"method": request.method, "headers": dict(request.headers)}
    )
    return render_template('login.html')

@app.route('/admin')
def admin():
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'unknown')
    log_event(
        event_type="HTTP_REQUEST",
        file_path="/admin",
        user=user_agent,
        ip_address=ip_address,
        additional_metadata={"method": request.method, "headers": dict(request.headers)}
    )
    return render_template('admin.html')

@app.route('/config')
def config():
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'unknown')
    log_event(
        event_type="HTTP_REQUEST",
        file_path="/config",
        user=user_agent,
        ip_address=ip_address,
        additional_metadata={"method": request.method, "headers": dict(request.headers)}
    )
    return render_template('config.html')

def start_http_server():
    # Start the Flask server
    app.run(host='0.0.0.0', port=8080, debug=False)
