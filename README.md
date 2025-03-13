# IP Analysis - Auth Log Analyzer

A web application for analyzing authentication log files, built with Flask and featuring interactive visualizations using Plotly.

## Features

- 📊 Interactive visualizations of failed login attempts
- 🌍 Geographic distribution of attack sources
- 👤 Analysis of targeted usernames
- 📈 Time-based attack pattern analysis
- 📁 Support for both plain text and gzipped log files
- 🎨 Modern, responsive UI built with Bootstrap
- 🔒 Secure file upload handling

## Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/waqaskhan137/ip-analysis.git
   cd ip-analysis
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:
   ```bash
   python app.py
   ```

5. Open your browser and navigate to `http://localhost:5000`

## Requirements

- Python 3.10+
- Flask
- Plotly
- Pandas
- GeoIP2 database (included)
- See `requirements.txt` for full list

## Development Setup

1. Install development dependencies:
   ```bash
   pip install -r requirements-test.txt
   ```

2. Run tests:
   ```bash
   python -m pytest tests/
   ```

## Testing

The project includes comprehensive tests:

- Unit tests for core functionality
- Integration tests for file processing
- UI tests using Selenium
- API endpoint tests

Run specific test categories:
```bash
python -m pytest tests/test_ui.py  # UI tests only
python -m pytest tests/test_app.py  # Application tests only
```

## Project Structure

```
ip-analysis/
├── app.py              # Main Flask application
├── templates/          # HTML templates
│   ├── base.html      # Base template
│   ├── index.html     # Upload page
│   └── results.html   # Analysis results
├── tests/             # Test suite
├── data/              # Sample data and GeoIP database
└── static/            # Static assets
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- GeoLite2 data created by MaxMind
- Bootstrap for UI components
- Plotly for interactive visualizations 