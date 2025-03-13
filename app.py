import base64
import gzip
import ipaddress
import os
import re
import tempfile
import time
from collections import Counter
from datetime import datetime
from io import BytesIO

import folium
import geoip2.database
import matplotlib.pyplot as plt
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import seaborn as sns
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

# Create Flask app
flask_app = Flask(__name__)
flask_app.secret_key = os.urandom(24)
flask_app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max file size
flask_app.config["UPLOAD_FOLDER"] = tempfile.gettempdir()

ALLOWED_EXTENSIONS = {"log", "gz"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def read_log_file(file_path):
    """Read a log file, handling both regular and gzipped files"""
    if file_path.endswith(".gz"):
        return gzip.open(file_path, "rt", errors="ignore")
    return open(file_path, "r", errors="ignore")


def parse_timestamp(timestamp_str):
    """Parse timestamp string into datetime object"""
    try:
        if ":" in timestamp_str and len(timestamp_str.split()) == 3:
            # Standard syslog format
            month, day, time = timestamp_str.split()
            year = datetime.now().year
            timestamp_str = f"{month} {day} {time} {year}"
            return datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
        elif "T" in timestamp_str:
            # ISO format
            return datetime.fromisoformat(timestamp_str.replace("T", " "))
        else:
            # Try common formats
            try:
                return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return datetime.now()
    except Exception as e:
        print(f"Error parsing timestamp '{timestamp_str}': {e}")
        return datetime.now()


def analyze_auth_log(log_file_path):
    # Check if file exists
    if not os.path.exists(log_file_path):
        print(f"File not found: {log_file_path}")
        return None

    # Expanded patterns to match failed login attempts
    failed_login_patterns = [
        r"((?:\w+\s+\d+\s+\d+:\d+:\d+)|(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})).*sshd\[\d+\]: Failed password for.*from (\d+\.\d+\.\d+\.\d+)",
        r"((?:\w+\s+\d+\s+\d+:\d+:\d+)|(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})).*sshd\[\d+\]: Invalid user .* from (\d+\.\d+\.\d+\.\d+)",
        r"((?:\w+\s+\d+\s+\d+:\d+:\d+)|(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})).*authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)",
        r"((?:\w+\s+\d+\s+\d+:\d+:\d+)|(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})).*FAILED su for .* by .* from (\d+\.\d+\.\d+\.\d+)",
        r"((?:\w+\s+\d+\s+\d+:\d+:\d+)|(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})).*PAM: Authentication failure.*from=(\d+\.\d+\.\d+\.\d+)",
        r"((?:\w+\s+\d+\s+\d+:\d+:\d+)|(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})).*login\[\d+\]: FAILED LOGIN.*from (\d+\.\d+\.\d+\.\d+)",
        r"((?:\w+\s+\d+\s+\d+:\d+:\d+)|(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})).*Failed password for invalid user .* from (\d+\.\d+\.\d+\.\d+)",
        r"((?:\w+\s+\d+\s+\d+:\d+:\d+)|(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})).*Connection closed by authenticating user .* (\d+\.\d+\.\d+\.\d+)",
        r"((?:\w+\s+\d+\s+\d+:\d+:\d+)|(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})).*maximum authentication attempts exceeded for .* from (\d+\.\d+\.\d+\.\d+)",
        r"((?:\w+\s+\d+\s+\d+:\d+:\d+)|(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})).*Disconnecting: Too many authentication failures.*from (\d+\.\d+\.\d+\.\d+)",
    ]

    results = []

    # Read the file using the appropriate method
    with read_log_file(log_file_path) as file:
        line_count = 0
        for line in file:
            line_count += 1

            # Check against all patterns
            match_found = False
            for pattern in failed_login_patterns:
                match = re.search(pattern, line)
                if match:
                    timestamp_str = match.group(1)
                    ip = match.group(2)

                    # Parse timestamp
                    timestamp = parse_timestamp(timestamp_str)

                    # Extract username if available
                    username_match = re.search(r"(user|for) (\w+)", line)
                    username = username_match.group(2) if username_match else "unknown"

                    results.append(
                        {
                            "timestamp": timestamp,
                            "ip": ip,
                            "username": username,
                            "log_entry": line.strip(),
                            "source_file": os.path.basename(log_file_path),
                            "line_number": line_count,
                        }
                    )
                    match_found = True
                    break

    return results


@flask_app.route("/")
def index():
    return render_template("index.html")


@flask_app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        flash("No file part", "danger")
        return render_template("index.html"), 400

    file = request.files["file"]
    if file.filename == "":
        flash("No selected file", "danger")
        return render_template("index.html"), 400

    if not file or not allowed_file(file.filename):
        flash("Invalid file type", "danger")
        return render_template("index.html"), 400

    # Save file temporarily
    filename = secure_filename(file.filename)
    temp_path = os.path.join(flask_app.config["UPLOAD_FOLDER"], filename)
    file.save(temp_path)

    try:
        # Process the log file
        results = analyze_auth_log(temp_path)
        if not results:
            flash("No failed login attempts found in the file", "warning")
            return render_template("index.html")

        # Convert results to DataFrame
        df = pd.DataFrame(results)

        # Store results in session
        session["analysis_results"] = df.to_dict("records")

        return render_template("results.html", results=df.to_dict("records"))
    except Exception as e:
        flash(f"Error processing file: {str(e)}", "danger")
        return render_template("index.html")
    finally:
        # Clean up temporary file
        if os.path.exists(temp_path):
            os.remove(temp_path)


if __name__ == "__main__":
    flask_app.run(debug=True)
