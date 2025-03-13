from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

from app import geolocate_ips, get_ip_info


def test_get_ip_info_private_ip():
    """Test getting info for a private IP address"""
    reader = MagicMock()
    result = get_ip_info("192.168.1.1", reader)

    assert result["country"] == "Private Network"
    assert result["city"] == "Local"
    assert result["region"] == "N/A"
    assert result["isp"] == "Private"
    assert result["latitude"] == 0
    assert result["longitude"] == 0

    # Verify reader was not called for private IP
    reader.city.assert_not_called()


def test_get_ip_info_public_ip(mock_geoip_response):
    """Test getting info for a public IP address"""
    reader = MagicMock()
    mock_country = MagicMock()
    mock_country.name = mock_geoip_response["country"]
    mock_city = MagicMock()
    mock_city.name = mock_geoip_response["city"]
    mock_region = MagicMock()
    mock_region.name = mock_geoip_response["region"]
    mock_location = MagicMock()
    mock_location.latitude = mock_geoip_response["latitude"]
    mock_location.longitude = mock_geoip_response["longitude"]

    reader.city.return_value = MagicMock(
        country=mock_country,
        city=mock_city,
        subdivisions=[mock_region],
        location=mock_location,
    )

    result = get_ip_info("8.8.8.8", reader)

    assert result["country"] == mock_geoip_response["country"]
    assert result["city"] == mock_geoip_response["city"]
    assert result["region"] == mock_geoip_response["region"]
    assert result["latitude"] == mock_geoip_response["latitude"]
    assert result["longitude"] == mock_geoip_response["longitude"]
    assert result["isp"] == "Unknown"

    reader.city.assert_called_once_with("8.8.8.8")


def test_get_ip_info_error():
    """Test handling of errors in IP info lookup"""
    reader = MagicMock()
    reader.city.side_effect = Exception("Test error")

    result = get_ip_info("8.8.8.8", reader)

    assert result["country"] == "Unknown"
    assert result["city"] == "Unknown"
    assert result["region"] == "Unknown"
    assert result["isp"] == "Unknown"
    assert result["latitude"] == 0
    assert result["longitude"] == 0


@patch("geoip2.database.Reader")
def test_geolocate_ips(mock_reader, mock_geoip_response):
    """Test geolocating IPs in a DataFrame"""
    # Create mock reader instance
    reader_instance = MagicMock()
    mock_country = MagicMock()
    mock_country.name = mock_geoip_response["country"]
    mock_city = MagicMock()
    mock_city.name = mock_geoip_response["city"]
    mock_region = MagicMock()
    mock_region.name = mock_geoip_response["region"]
    mock_location = MagicMock()
    mock_location.latitude = mock_geoip_response["latitude"]
    mock_location.longitude = mock_geoip_response["longitude"]

    reader_instance.city.return_value = MagicMock(
        country=mock_country,
        city=mock_city,
        subdivisions=[mock_region],
        location=mock_location,
    )
    mock_reader.return_value = reader_instance

    # Create test DataFrame
    df = pd.DataFrame(
        {
            "ip": ["8.8.8.8", "192.168.1.1", "1.1.1.1"],
            "timestamp": pd.date_range(start="2024-01-01", periods=3),
            "username": ["test1", "test2", "test3"],
        }
    )

    # Test geolocation
    result_df = geolocate_ips(df)

    assert "country" in result_df.columns
    assert "city" in result_df.columns
    assert "region" in result_df.columns
    assert "latitude" in result_df.columns
    assert "longitude" in result_df.columns
    assert "isp" in result_df.columns

    # Check private IP was handled correctly
    private_ip_row = result_df[result_df["ip"] == "192.168.1.1"].iloc[0]
    assert private_ip_row["country"] == "Private Network"
    assert private_ip_row["city"] == "Local"

    # Check public IP was geolocated
    public_ip_row = result_df[result_df["ip"] == "8.8.8.8"].iloc[0]
    assert public_ip_row["country"] == mock_geoip_response["country"]
    assert public_ip_row["city"] == mock_geoip_response["city"]
