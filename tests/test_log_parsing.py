import pytest
from datetime import datetime
from app import parse_log_line, analyze_auth_log, read_log_file

def test_parse_log_line_failed_password():
    """Test parsing a failed password attempt log line"""
    line = "Mar 13 16:08:03 server sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2"
    result = parse_log_line(line)
    
    assert result is not None
    assert result['ip'] == '192.168.1.100'
    assert result['username'] == 'invalid'
    assert isinstance(result['timestamp'], datetime)
    assert result['log_entry'] == line.strip()

def test_parse_log_line_invalid_user():
    """Test parsing an invalid user log line"""
    line = "Mar 13 16:08:05 server sshd[12346]: Invalid user test from 192.168.1.101"
    result = parse_log_line(line)
    
    assert result is not None
    assert result['ip'] == '192.168.1.101'
    assert result['username'] == 'test'
    assert isinstance(result['timestamp'], datetime)

def test_parse_log_line_authentication_failure():
    """Test parsing an authentication failure log line"""
    line = "Mar 13 16:08:09 server PAM: Authentication failure for user from=192.168.1.103"
    result = parse_log_line(line)
    
    assert result is not None
    assert result['ip'] == '192.168.1.103'
    assert result['username'] == 'user'
    assert isinstance(result['timestamp'], datetime)

def test_parse_log_line_invalid_format():
    """Test parsing an invalid log line format"""
    line = "This is not a valid log line"
    result = parse_log_line(line)
    assert result is None

def test_analyze_auth_log(sample_log_file):
    """Test analyzing a complete auth log file"""
    results = analyze_auth_log(str(sample_log_file))
    
    assert len(results) == 4  # Should find 4 failed login attempts
    assert all(isinstance(r['timestamp'], datetime) for r in results)
    assert all('ip' in r for r in results)
    assert all('username' in r for r in results)
    assert all('log_entry' in r for r in results)

def test_read_log_file_regular(sample_log_file):
    """Test reading a regular log file"""
    with read_log_file(str(sample_log_file)) as f:
        content = f.read()
    assert len(content.splitlines()) == 4

def test_read_log_file_gzip(tmp_path, sample_log_content):
    """Test reading a gzipped log file"""
    import gzip
    
    # Create a gzipped log file
    gz_file = tmp_path / "auth.log.gz"
    with gzip.open(gz_file, 'wt') as f:
        f.write(sample_log_content)
    
    # Read and verify content
    with read_log_file(str(gz_file)) as f:
        content = f.read()
    assert len(content.splitlines()) == 4 