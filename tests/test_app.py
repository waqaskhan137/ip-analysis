from io import BytesIO


def test_invalid_file_upload(client):
    """Test handling of invalid file uploads"""
    # Test with non-log file
    data = {"file": (BytesIO(b"This is not a log file"), "test.txt")}
    response = client.post("/upload", data=data, content_type="multipart/form-data")
    assert response.status_code == 400
    assert b"Invalid file type" in response.data

    # Test with empty file
    data = {"file": (BytesIO(b""), "test.log")}
    response = client.post("/upload", data=data, content_type="multipart/form-data")
    assert response.status_code == 400
    assert b"File is empty" in response.data

    # Test with no file
    data = {}
    response = client.post("/upload", data=data, content_type="multipart/form-data")
    assert response.status_code == 400
    assert b"No file part" in response.data
