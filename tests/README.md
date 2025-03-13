# Auth Log Analyzer Tests

This directory contains the test suite for the Auth Log Analyzer application.

## Test Structure

- `conftest.py`: Contains pytest fixtures and configuration
- `test_log_parsing.py`: Tests for log file parsing functionality
- `test_geolocation.py`: Tests for IP geolocation features
- `test_web_interface.py`: Tests for Flask web interface
- `test_reporting.py`: Tests for report generation and visualization
- `requirements-test.txt`: Test dependencies

## Running Tests

1. Install test dependencies:
```bash
pip install -r tests/requirements-test.txt
```

2. Run the test suite:
```bash
pytest tests/
```

3. Run with coverage report:
```bash
pytest tests/ --cov=app --cov-report=html
```

## Test Coverage

The test suite covers:
- Log file parsing and analysis
- IP geolocation functionality
- Web interface endpoints
- Report generation
- Data visualization

## Adding New Tests

When adding new tests:
1. Use appropriate fixtures from `conftest.py`
2. Follow the existing test structure
3. Include both positive and negative test cases
4. Add docstrings explaining test purpose
5. Update this README if adding new test categories 