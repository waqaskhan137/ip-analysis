import os
import tempfile
from datetime import datetime
from io import BytesIO
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest


@pytest.fixture
def sample_auth_log():
    """Create a sample auth.log file content"""
    return """Mar 13 16:08:03 server sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
Mar 13 16:08:05 server sshd[12346]: Invalid user test from 192.168.1.101
Mar 13 16:08:09 server PAM: Authentication failure for user from=192.168.1.103"""


@pytest.fixture
def sample_gzipped_log(tmp_path, sample_auth_log):
    """Create a gzipped auth.log file"""
    import gzip

    gz_file = tmp_path / "auth.log.gz"
    with gzip.open(gz_file, "wt") as f:
        f.write(sample_auth_log)
    return gz_file


@pytest.fixture
def mock_dataframe():
    """Create a mock DataFrame for testing"""
    return pd.DataFrame(
        {
            "timestamp": pd.date_range(start="2024-01-01", periods=3),
            "ip": ["192.168.1.100", "192.168.1.101", "192.168.1.103"],
            "username": ["admin", "test", "user"],
            "country": ["US", "US", "US"],
            "city": ["New York", "New York", "New York"],
            "region": ["NY", "NY", "NY"],
            "latitude": [40.7128, 40.7128, 40.7128],
            "longitude": [-74.0060, -74.0060, -74.0060],
            "isp": ["Unknown", "Unknown", "Unknown"],
        }
    )


def test_upload_regular_log_file(client, sample_auth_log, mock_dataframe):
    """Test uploading a regular auth.log file"""
    # Create test file
    data = {"file": (BytesIO(sample_auth_log.encode()), "auth.log")}

    # Mock the processing functions
    with patch("app.process_log_files") as mock_process, patch(
        "app.geolocate_ips"
    ) as mock_geolocate, patch("app.create_visualizations") as mock_visualizations:

        mock_process.return_value = mock_dataframe
        mock_geolocate.return_value = mock_dataframe
        mock_visualizations.return_value = ("<div>Hourly Chart</div>", "<div>Map</div>")

        # Test upload
        with client:
            response = client.post(
                "/upload",
                data=data,
                content_type="multipart/form-data",
                follow_redirects=True,
            )

            # Check response
            assert response.status_code == 200
            assert b"Analysis Results - Auth Log Analyzer" in response.data
            assert b"Total Failed Attempts" in response.data
            assert b"Unique IP Addresses" in response.data
            assert b"<div>Hourly Chart</div>" in response.data
            assert b"<div>Map</div>" in response.data

            # Verify the processing functions were called
            mock_process.assert_called_once()
            mock_geolocate.assert_called_once()
            mock_visualizations.assert_called_once()


def test_upload_gzipped_log_file(client, sample_gzipped_log, mock_dataframe):
    """Test uploading a gzipped auth.log file"""
    with open(sample_gzipped_log, "rb") as f:
        data = {"file": (BytesIO(f.read()), "auth.log.gz")}

    # Mock the processing functions
    with patch("app.process_log_files") as mock_process, patch(
        "app.geolocate_ips"
    ) as mock_geolocate, patch("app.create_visualizations") as mock_visualizations:

        mock_process.return_value = mock_dataframe
        mock_geolocate.return_value = mock_dataframe
        mock_visualizations.return_value = ("<div>Hourly Chart</div>", "<div>Map</div>")

        # Test upload
        with client:
            response = client.post(
                "/upload",
                data=data,
                content_type="multipart/form-data",
                follow_redirects=True,
            )

            # Check response
            assert response.status_code == 200
            assert b"Analysis Results - Auth Log Analyzer" in response.data
            assert b"Total Failed Attempts" in response.data
            assert b"Unique IP Addresses" in response.data
            assert b"<div>Hourly Chart</div>" in response.data
            assert b"<div>Map</div>" in response.data


def test_upload_empty_file(client):
    """Test uploading an empty file"""
    data = {"file": (BytesIO(b""), "auth.log")}

    with patch("app.process_log_files") as mock_process:
        mock_process.return_value = None

        with client:
            response = client.post(
                "/upload", data=data, content_type="multipart/form-data"
            )
            assert response.status_code == 400
            assert b"File is empty" in response.data


def test_upload_invalid_content(client):
    """Test uploading a file with invalid content"""
    data = {"file": (BytesIO(b"This is not a valid auth log file"), "auth.log")}

    with patch("app.process_log_files") as mock_process:
        mock_process.return_value = None

        with client:
            response = client.post(
                "/upload",
                data=data,
                content_type="multipart/form-data",
                follow_redirects=True,
            )
            assert response.status_code == 200
            assert b"No failed login attempts found in the file" in response.data


def test_upload_large_file(client):
    """Test uploading a file that exceeds the size limit"""
    # Create a large file (17MB)
    large_content = b"x" * (17 * 1024 * 1024)
    data = {"file": (BytesIO(large_content), "auth.log")}

    with client:
        response = client.post(
            "/upload",
            data=data,
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert response.status_code == 413  # Request Entity Too Large


def test_upload_processing_error(client, sample_auth_log):
    """Test handling of processing errors during upload"""
    data = {"file": (BytesIO(sample_auth_log.encode()), "auth.log")}

    with patch("app.process_log_files") as mock_process:
        mock_process.side_effect = Exception("Processing error")

        with client:
            response = client.post(
                "/upload",
                data=data,
                content_type="multipart/form-data",
                follow_redirects=True,
            )
            assert response.status_code == 200
            assert b"Error processing file" in response.data
