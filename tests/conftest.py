import pytest
import os
import tempfile
from app import flask_app


@pytest.fixture
def app():
    """Create application for testing"""
    flask_app.config.update({"TESTING": True, "UPLOAD_FOLDER": tempfile.gettempdir()})
    return flask_app


@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()


@pytest.fixture
def sample_log_content():
    """Sample auth.log content for testing"""
    return """Mar 13 16:08:03 server sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
Mar 13 16:08:05 server sshd[12346]: Invalid user test from 192.168.1.101
Mar 13 16:08:07 server sshd[12347]: Failed password for root from 192.168.1.102 port 54323 ssh2
Mar 13 16:08:09 server PAM: Authentication failure for user from=192.168.1.103"""


@pytest.fixture
def sample_log_file(tmp_path, sample_log_content):
    """Create a temporary log file for testing"""
    log_file = tmp_path / "auth.log"
    log_file.write_text(sample_log_content)
    return log_file


@pytest.fixture
def mock_geoip_response():
    """Mock GeoIP response data"""
    return {
        "country": "United States",
        "city": "New York",
        "region": "New York",
        "latitude": 40.7128,
        "longitude": -74.0060,
        "isp": "Unknown",
    }
