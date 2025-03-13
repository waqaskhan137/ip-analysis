import pytest
import pandas as pd
from datetime import datetime
import os
from app import generate_report, plot_activity, create_world_map, create_visualizations


def create_test_dataframe():
    """Create a test DataFrame for reporting tests"""
    return pd.DataFrame(
        {
            "timestamp": pd.date_range(start="2024-01-01", periods=5),
            "ip": ["8.8.8.8", "1.1.1.1", "8.8.8.8", "2.2.2.2", "1.1.1.1"],
            "username": ["root", "admin", "test", "root", "admin"],
            "country": ["US", "GB", "US", "FR", "GB"],
            "city": ["New York", "London", "New York", "Paris", "London"],
            "region": ["NY", "England", "NY", "IDF", "England"],
            "latitude": [40.7128, 51.5074, 40.7128, 48.8566, 51.5074],
            "longitude": [-74.0060, -0.1278, -74.0060, 2.3522, -0.1278],
            "isp": ["Unknown", "Unknown", "Unknown", "Unknown", "Unknown"],
        }
    )


def test_generate_report():
    """Test report generation"""
    df = create_test_dataframe()
    report = generate_report(df)

    # Check report content
    assert "AUTH.LOG SECURITY ANALYSIS REPORT" in report
    assert "Total failed login attempts: 5" in report
    assert "Unique IP addresses: 3" in report
    assert "8.8.8.8" in report
    assert "1.1.1.1" in report
    assert "root" in report
    assert "admin" in report
    assert "US" in report
    assert "GB" in report


def test_generate_report_empty_data():
    """Test report generation with empty data"""
    df = pd.DataFrame()
    report = generate_report(df)
    assert report == "No data to analyze."


@pytest.mark.mpl_image_compare
def test_plot_activity(tmp_path):
    """Test activity plotting"""
    df = create_test_dataframe()
    plot_activity(df)

    # Check if the plot file was created
    plot_file = "auth_log_analysis.png"
    assert plot_file in [f for f in os.listdir(".") if f.endswith(".png")]


def test_plot_activity_empty_data():
    """Test activity plotting with empty data"""
    df = pd.DataFrame()
    # Should not raise an error
    plot_activity(df)


def test_create_world_map():
    """Test world map creation"""
    df = create_test_dataframe()
    create_world_map(df)

    # Check if the map file was created
    map_file = "attack_map.html"
    assert map_file in os.listdir(".")

    # Check map file content
    with open(map_file, "r") as f:
        content = f.read()
        assert "leaflet" in content.lower()
        assert "map" in content.lower()


def test_create_world_map_empty_data():
    """Test world map creation with empty data"""
    df = pd.DataFrame()
    # Should not raise an error
    create_world_map(df)


def test_create_visualizations():
    """Test visualization creation for web interface"""
    df = create_test_dataframe()
    ip_info_dict = {
        "8.8.8.8": {
            "country": "US",
            "city": "New York",
            "region": "NY",
            "latitude": 40.7128,
            "longitude": -74.0060,
            "isp": "Unknown",
        },
        "1.1.1.1": {
            "country": "GB",
            "city": "London",
            "region": "England",
            "latitude": 51.5074,
            "longitude": -0.1278,
            "isp": "Unknown",
        },
    }

    hourly_chart, map_html = create_visualizations(df, ip_info_dict)

    # Check visualization output
    assert isinstance(hourly_chart, str)
    assert isinstance(map_html, str)
    assert "plotly" in hourly_chart.lower()
    assert "map" in map_html.lower()


def test_create_visualizations_empty_data():
    """Test visualization creation with empty data"""
    df = pd.DataFrame(
        {
            "timestamp": pd.Series(dtype="datetime64[ns]"),
            "ip": pd.Series(dtype="object"),
            "username": pd.Series(dtype="object"),
            "country": pd.Series(dtype="object"),
            "city": pd.Series(dtype="object"),
            "region": pd.Series(dtype="object"),
            "latitude": pd.Series(dtype="float64"),
            "longitude": pd.Series(dtype="float64"),
            "isp": pd.Series(dtype="object"),
        }
    )
    ip_info_dict = {}

    hourly_chart, map_html = create_visualizations(df, ip_info_dict)

    # Check that we get valid (empty) visualizations
    assert isinstance(hourly_chart, str)
    assert isinstance(map_html, str)
