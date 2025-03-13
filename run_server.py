import os
from app import flask_app
from waitress import serve

if __name__ == '__main__':
    # Get host and port from environment variables or use defaults
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 6001))
    
    print(f"Starting Auth Log Analyzer server on {host}:{port}")
    print("Press Ctrl+C to stop the server")
    
    # Use waitress for production server
    serve(flask_app, host=host, port=port, threads=4) 