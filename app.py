import base64
import gzip
import ipaddress
import os
import re
import tempfile
import time
from collections import Counter
from datetime import datetime
from io import BytesIO, StringIO

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
    Response,
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
    """Parse a single line from the auth.log file"""
    # Common patterns for failed login attempts
    patterns = [
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (?:invalid user )?(?P<username>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)',
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*authentication failure.*ruser=(?P<username>\S+).*rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)',
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*Invalid user (?P<username>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)',
    ]

    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            data = match.groupdict()
            # Convert timestamp to datetime
            try:
                current_year = datetime.now().year
                timestamp_str = f"{current_year} {data['timestamp']}"
                data['timestamp'] = datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
            except ValueError:
                continue
            return data
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


def analyze_auth_log(file_path):
    """Analyze the auth.log file and return a DataFrame with failed login attempts"""
    failed_attempts = []
    
    # Handle both regular and gzipped files
    opener = gzip.open if file_path.endswith('.gz') else open
    
    try:
        with opener(file_path, 'rt') as f:
            for line in f:
                parsed = parse_log_line(line)
                if parsed:
                    failed_attempts.append(parsed)
    except Exception as e:
        print(f"Error reading log file: {e}")
        return None

    if not failed_attempts:
        return None

    # Convert to DataFrame
    df = pd.DataFrame(failed_attempts)
    
    # Ensure all required columns are present
    required_columns = ['timestamp', 'username', 'ip']
    if not all(col in df.columns for col in required_columns):
        return None

    return df


def get_ip_info(ip, database_path="GeoLite2-City.mmdb"):
    """Get geolocation information for an IP address"""
    try:
        # Check if IP is private
        if ipaddress.ip_address(ip).is_private:
            return {
                "latitude": None,
                "longitude": None,
                "country": "Local",
                "city": "Local",
                "region": "Local",
                "isp": "Local",
            }

        reader = geoip2.database.Reader(database_path)
        response = reader.city(ip)
        return {
            "latitude": response.location.latitude,
            "longitude": response.location.longitude,
            "country": response.country.name or "Unknown",
            "city": response.city.name or "Unknown",
            "region": (
                response.subdivisions.most_specific.name
                if response.subdivisions
                else "Unknown"
            ),
            "isp": "Unknown",  # ISP info requires a different database
        }
    except Exception as e:
        print(f"Error getting IP info for {ip}: {e}")
        return None  # Return None for error case


def geolocate_ips(df):
    """Get geolocation information for IP addresses in the DataFrame"""
    if df.empty:
        return df

    # Create new columns for geolocation data
    geo_columns = ['latitude', 'longitude', 'country', 'city', 'region', 'isp']
    for col in geo_columns:
        df[col] = None

    # Get geolocation info for each unique IP
    for ip in df['ip'].unique():
        info = get_ip_info(ip)
        if info and isinstance(info, dict):  # Only process valid dictionary responses
            mask = df['ip'] == ip
            for col in geo_columns:
                df.loc[mask, col] = info.get(col)

    return df


def plot_activity(df):
    """Create a time series plot of failed login attempts"""
    if df.empty:
        # Create an empty figure with a message
        fig = go.Figure()
        fig.add_annotation(
            text="No data available",
            xref="paper",
            yref="paper",
            x=0.5,
            y=0.5,
            showarrow=False,
        )
        fig.update_layout(title="Failed Login Attempts Over Time")
        return fig

    # Group by hour and count attempts
    hourly_counts = (
        df.groupby(df["timestamp"].dt.floor("h")).size().reset_index(name="count")
    )

    # Create the plot
    fig = px.line(
        hourly_counts,
        x="timestamp",
        y="count",
        title="Failed Login Attempts Over Time",
        labels={"timestamp": "Time", "count": "Number of Attempts"},
    )

    fig.update_layout(
        xaxis_title="Time", yaxis_title="Number of Failed Attempts", showlegend=False
    )

    return fig


def create_world_map(df):
    """Create a world map with markers for each IP location"""
    # Create a base map
    m = folium.Map(location=[0, 0], zoom_start=2)

    if df.empty:
        # Add a message for empty data
        folium.Element(
            """
            <div style='position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
                       background-color: white; padding: 10px; border-radius: 5px;'>
                No location data available
            </div>
        """
        ).add_to(m)
        return m

    # Check for required columns
    required_columns = ["ip", "latitude", "longitude", "country", "city", "region"]
    if not all(col in df.columns for col in required_columns):
        # Add a message for missing columns
        folium.Element(
            """
            <div style='position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
                       background-color: white; padding: 10px; border-radius: 5px;'>
                Missing required location data
            </div>
        """
        ).add_to(m)
        return m

    # Add markers for each IP location
    for _, row in df.iterrows():
        if pd.notna(row["latitude"]) and pd.notna(row["longitude"]):
            popup_html = f"""
                <div style='font-family: Arial, sans-serif;'>
                    <h4>IP: {row['ip']}</h4>
                    <p>Country: {row['country'] if pd.notna(row['country']) else 'Unknown'}</p>
                    <p>City: {row['city'] if pd.notna(row['city']) else 'Unknown'}</p>
                    <p>Region: {row['region'] if pd.notna(row['region']) else 'Unknown'}</p>
                </div>
            """
            folium.Marker(
                location=[row["latitude"], row["longitude"]],
                popup=folium.Popup(popup_html, max_width=300),
                icon=folium.Icon(color="red", icon="info-sign"),
            ).add_to(m)

    return m


def create_visualizations(df, ip_info_dict=None):
    """Create visualizations from the data"""
    if df.empty:
        return "", ""

    # Create time series plot
    hourly_chart = plot_activity(df)
    hourly_chart_html = hourly_chart.to_html(full_html=False) if hourly_chart else ""

    # Create world map
    world_map = create_world_map(df)
    map_html = world_map._repr_html_() if world_map else ""

    return hourly_chart_html, map_html


def generate_report(df):
    """Generate a report from the analysis results"""
    if df is None or df.empty:
        return "No data to analyze."

    # Convert timestamp column to datetime if it's not already
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    # Calculate statistics
    total_attempts = len(df)
    unique_ips = df['ip'].nunique()
    unique_usernames = df['username'].nunique()
    time_range = f"{df['timestamp'].min().strftime('%Y-%m-%d %H:%M:%S')} to {df['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S')}"

    # Get top attacking IPs
    top_ips = df['ip'].value_counts().head(5)
    ip_list = "\n".join([f"{ip}: {count} attempts" for ip, count in top_ips.items()])

    # Get top targeted usernames
    top_usernames = df['username'].value_counts().head(5)
    username_list = "\n".join([f"{user}: {count} attempts" for user, count in top_usernames.items()])

    # Get country statistics
    country_stats = df['country'].value_counts()
    country_list = "\n".join([f"{country}: {count} attempts" for country, count in country_stats.items()])

    # Generate report
    report = f"""Total failed login attempts: {total_attempts}
Unique IP addresses: {unique_ips}
Unique usernames: {unique_usernames}
Time range: {time_range}

Top attacking IP addresses:
{ip_list}

Top targeted usernames:
{username_list}

Country statistics:
{country_list}"""

    return report


def process_log_files(file_path):
    """Process log files and return a DataFrame with analysis results"""
    # Analyze the log file
    results = analyze_auth_log(file_path)
    if not results:
        return None

    # Convert to DataFrame
    df = pd.DataFrame(results)

    # Add hourly counts
    df["hour"] = df["timestamp"].dt.floor("H")
    hourly_counts = df.groupby("hour").size().reset_index(name="count")
    df = df.merge(hourly_counts, left_on="hour", right_on="hour", how="left")

    return df


@flask_app.route("/")
def index():
    return render_template("index.html")


@flask_app.route("/upload", methods=["POST"])
def upload_file():
    """Handle file upload and process the log file"""
    if "file" not in request.files:
        flash("No file selected", "error")
        return render_template("index.html", error="No file selected"), 400

    file = request.files["file"]
    if file.filename == "":
        flash("No file selected", "error")
        return render_template("index.html", error="No filename provided"), 400

    if not file or not file.stream.read():
        flash("File is empty", "error")
        return render_template("index.html", error="File is empty"), 400

    # Reset file pointer after reading
    file.stream.seek(0)

    if not allowed_file(file.filename):
        flash("Invalid file type. Please upload a .log or .log.gz file.", "error")
        return render_template("index.html", error="Invalid file type"), 400

    try:
        # Save the file temporarily
        temp_path = os.path.join(flask_app.config["UPLOAD_FOLDER"], secure_filename(file.filename))
        file.save(temp_path)

        # Process the log file
        df = process_log_files(temp_path)
        if df is None or df.empty:
            flash("No failed login attempts found in the file", "warning")
            return render_template("index.html", error="No failed login attempts found"), 400

        # Store DataFrame as JSON in session
        session['df_json'] = df.to_json()

        # Geolocate IP addresses
        df = geolocate_ips(df)

        # Create visualizations
        hourly_chart, world_map = create_visualizations(df)

        # Generate report
        report = generate_report(df)

        # Store report in session for download
        session['report_data'] = report

        # Render template with results
        return render_template(
            "results.html",
            report=report,
            hourly_chart=hourly_chart,
            world_map=world_map
        )

    except Exception as e:
        flask_app.logger.error(f"Error processing file: {str(e)}")
        flash(f"Error processing file: {str(e)}", "error")
        return render_template("index.html", error=f"Error processing file: {str(e)}"), 400

    finally:
        # Clean up temporary file
        if 'temp_path' in locals() and os.path.exists(temp_path):
            os.remove(temp_path)


@flask_app.route("/download/report")
def download_report():
    """Download the analysis report as a text file"""
    if 'report_data' not in session:
        flash("No report data available", "error")
        return redirect(url_for("index"))

    report_data = session['report_data']
    return Response(
        report_data,
        mimetype="text/plain",
        headers={"Content-disposition": "attachment; filename=security_report.txt"}
    )

@flask_app.route("/download/csv")
def download_csv():
    """Download the analysis data as a CSV file"""
    if 'df_json' not in session:
        flash("No data available", "error")
        return redirect(url_for("index"))

    # Convert JSON back to DataFrame
    df = pd.read_json(session['df_json'])

    # Convert DataFrame to CSV
    output = StringIO()
    df.to_csv(output, index=False)
    output.seek(0)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=security_analysis.csv"}
    )


if __name__ == "__main__":
    flask_app.run(debug=True)
