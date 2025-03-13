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


def parse_log_line(line):
    """Parse a single log line and extract relevant information"""
    patterns = [
        r"((?:\w+\s+\d+\s+\d+:\d+:\d+)|(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})).*sshd\[\d+\]: Failed password for.*from (\d+\.\d+\.\d+\.\d+)",
        r"((?:\w+\s+\d+\s+\d+:\d+:\d+)|(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})).*sshd\[\d+\]: Invalid user .* from (\d+\.\d+\.\d+\.\d+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            timestamp_str = match.group(1)
            ip = match.group(2)
            username_match = re.search(r"(user|for) (\w+)", line)
            username = username_match.group(2) if username_match else "unknown"
            return {
                "timestamp": parse_timestamp(timestamp_str),
                "ip": ip,
                "username": username,
                "log_entry": line.strip(),
            }
    return None


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

    results = []
    with read_log_file(log_file_path) as file:
        line_count = 0
        for line in file:
            line_count += 1
            parsed = parse_log_line(line)
            if parsed:
                parsed["source_file"] = os.path.basename(log_file_path)
                parsed["line_number"] = line_count
                results.append(parsed)

    return results


def get_ip_info(ip):
    """Get geolocation information for an IP address"""
    try:
        reader = geoip2.database.Reader("GeoLite2-City.mmdb")
        response = reader.city(ip)
        return {
            "latitude": response.location.latitude,
            "longitude": response.location.longitude,
            "country": response.country.name,
            "city": response.city.name,
        }
    except Exception as e:
        print(f"Error getting IP info for {ip}: {e}")
        return None


def geolocate_ips(ip_list):
    """Get geolocation information for a list of IP addresses"""
    results = {}
    for ip in ip_list:
        info = get_ip_info(ip)
        if info:
            results[ip] = info
    return results


def plot_activity(df):
    """Create a time series plot of failed login attempts"""
    fig = px.line(df, x="timestamp", y="count", title="Failed Login Attempts Over Time")
    return fig


def create_world_map(ip_locations):
    """Create a world map with markers for attack sources"""
    m = folium.Map(location=[0, 0], zoom_start=2)
    for ip, info in ip_locations.items():
        if info.get("latitude") and info.get("longitude"):
            folium.Marker(
                [info["latitude"], info["longitude"]],
                popup=f"IP: {ip}<br>Country: {info.get('country', 'Unknown')}<br>City: {info.get('city', 'Unknown')}",
            ).add_to(m)
    return m


def create_visualizations(df):
    """Create all visualizations for the analysis results"""
    # Time series plot
    time_plot = plot_activity(df)

    # Username distribution
    username_counts = df["username"].value_counts()
    username_plot = px.pie(
        values=username_counts.values,
        names=username_counts.index,
        title="Username Distribution in Failed Login Attempts",
    )

    # IP geolocation
    ip_locations = geolocate_ips(df["ip"].unique())
    world_map = create_world_map(ip_locations)

    return {
        "time_plot": time_plot,
        "username_plot": username_plot,
        "world_map": world_map,
    }


def generate_report(df):
    """Generate a comprehensive report of the analysis"""
    total_attempts = len(df)
    unique_ips = df["ip"].nunique()
    unique_usernames = df["username"].nunique()
    time_range = df["timestamp"].max() - df["timestamp"].min()

    visualizations = create_visualizations(df)

    return {
        "stats": {
            "total_attempts": total_attempts,
            "unique_ips": unique_ips,
            "unique_usernames": unique_usernames,
            "time_range": time_range,
        },
        "visualizations": visualizations,
    }


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

        # Generate report with visualizations
        report = generate_report(df)

        # Store results in session
        session["analysis_results"] = df.to_dict("records")

        return render_template(
            "results.html", results=df.to_dict("records"), report=report
        )
    except Exception as e:
        flash(f"Error processing file: {str(e)}", "danger")
        return render_template("index.html")
    finally:
        # Clean up temporary file
        if os.path.exists(temp_path):
            os.remove(temp_path)


if __name__ == "__main__":
    flask_app.run(debug=True)
