from io import BytesIO
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest
from flask import session


def test_index_page(client):
    """Test the index page loads correctly"""
    response = client.get("/")
    assert response.status_code == 200


def test_upload_no_file(client):
    """Test upload endpoint with no file"""
    with client:  # Use client context to access session
        response = client.post("/upload")
        assert response.status_code == 400
        assert b"No file part" in response.data


def test_upload_empty_filename(client):
    """Test upload endpoint with empty filename"""
    with client:  # Use client context to access session
        response = client.post("/upload", data={"file": (BytesIO(), "")})
        assert response.status_code == 400
        assert b"No selected file" in response.data


def test_upload_invalid_file_type(client):
    """Test upload endpoint with invalid file type"""
    with client:  # Use client context to access session
        response = client.post(
            "/upload", data={"file": (BytesIO(b"test content"), "test.txt")}
        )
        assert response.status_code == 400
        assert b"Invalid file type" in response.data


@patch("app.process_log_files")
@patch("app.geolocate_ips")
def test_upload_valid_file(mock_geolocate, mock_process, client, sample_log_content):
    """Test upload endpoint with valid log file"""
    # Mock the processing functions
    mock_df = pd.DataFrame(
        {
            "timestamp": pd.date_range(start="2024-01-01", periods=2),
            "ip": ["8.8.8.8", "1.1.1.1"],
            "username": ["test1", "test2"],
            "country": ["US", "GB"],
            "city": ["New York", "London"],
            "region": ["NY", "England"],
            "latitude": [40.7128, 51.5074],
            "longitude": [-74.0060, -0.1278],
            "isp": ["Unknown", "Unknown"],
        }
    )
    mock_process.return_value = mock_df
    mock_geolocate.return_value = mock_df

    # Create test file
    data = {"file": (BytesIO(sample_log_content.encode()), "auth.log")}

    # Test upload
    with client:  # Use client context to access session
        response = client.post(
            "/upload",
            data=data,
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert response.status_code == 200
        # Check for presence of key elements in the response
        assert (
            b"Analysis Results - Auth Log Analyzer" in response.data
        )  # Check for page title
        assert b"navbar" in response.data  # Check for navigation bar
        assert b"Total Failed Attempts" in response.data  # Check for results section
        assert b"Download Report" in response.data  # Check for download button


def test_download_no_report(client):
    """Test download endpoint with no report available"""
    with client:  # Use client context to access session
        response = client.get("/download", follow_redirects=True)
        assert response.status_code == 200
        assert b"No report available" in response.data


@patch("app.generate_report")
def test_download_with_report(mock_generate_report, client):
    """Test download endpoint with report available"""
    # Mock report generation
    test_report = "Test security report content"
    mock_generate_report.return_value = test_report

    # Set up session data
    with client.session_transaction() as session:
        session["report_data"] = test_report

    # Test download
    response = client.get("/download")

    assert response.status_code == 200
    assert response.headers["Content-Type"].startswith(
        "text/plain"
    )  # Changed to use startswith
    assert response.headers["Content-Disposition"].startswith("attachment; filename=")
    assert response.data.decode() == test_report


@patch("app.process_log_files")
@patch("app.geolocate_ips")
def test_attack_origin_map(mock_geolocate, mock_process, client):
    """Test that the Attack Origin Map is properly generated"""
    # Create a mock DataFrame with geolocation data
    mock_df = pd.DataFrame(
        {
            "timestamp": pd.date_range(start="2024-01-01", periods=3),
            "ip": ["8.8.8.8", "1.1.1.1", "2.2.2.2"],
            "username": ["test1", "test2", "test3"],
            "country": ["US", "GB", "FR"],
            "city": ["New York", "London", "Paris"],
            "region": ["NY", "England", "Ile-de-France"],
            "latitude": [40.7128, 51.5074, 48.8566],
            "longitude": [-74.0060, -0.1278, 2.3522],
            "isp": ["Google", "Cloudflare", "Orange"],
        }
    )

    mock_process.return_value = mock_df
    mock_geolocate.return_value = mock_df

    # Create test file with some content
    data = {"file": (BytesIO(b"test log content"), "auth.log")}

    # Test upload
    with client:
        response = client.post(
            "/upload",
            data=data,
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert response.status_code == 200

        # Check for map container and Plotly elements
        assert b'<div class="map-container">' in response.data
        assert b"Attack Origin Map" in response.data
        assert b"plotly-latest.min.js" in response.data
        assert b"Plotly.newPlot" in response.data
