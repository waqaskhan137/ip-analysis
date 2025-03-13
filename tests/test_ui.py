import os
import pytest
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from app import flask_app
import threading
import time
import signal
import socket
import atexit
import psutil

# Global to track server threads and processes
server_threads = []
server_processes = []

def cleanup_threads():
    """Clean up any running threads and processes"""
    # Clean up threads
    for thread in server_threads:
        if thread.is_alive():
            try:
                os.kill(thread.ident, signal.SIGTERM)
            except:
                pass
    
    # Clean up processes
    for proc in server_processes:
        try:
            process = psutil.Process(proc)
            for child in process.children(recursive=True):
                child.kill()
            process.kill()
        except:
            pass

# Register cleanup function
atexit.register(cleanup_threads)

@pytest.fixture
def driver():
    """Set up Chrome WebDriver with headless mode"""
    chrome_options = webdriver.ChromeOptions()
    chrome_options.add_argument('--headless')  # Run in headless mode
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)
    yield driver
    driver.quit()

@pytest.fixture
def test_client():
    """Create a test client for the Flask app"""
    with flask_app.test_client() as client:
        yield client

@pytest.fixture(scope="function")
def live_server(request):
    """Fixture to run Flask app in a separate thread during tests"""
    def find_free_port():
        """Find a free port to use for the test server"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            s.listen(1)
            port = s.getsockname()[1]
        return port
    
    port = find_free_port()
    print(f"Using port {port} for test server")
    
    def run_app():
        try:
            flask_app.run(port=port, use_reloader=False, threaded=True)
        except Exception as e:
            print(f"Error starting Flask app: {str(e)}")
    
    thread = threading.Thread(target=run_app)
    thread.daemon = True
    server_threads.append(thread)
    thread.start()
    
    # Wait for server to start and verify it's responding
    start_time = time.time()
    timeout = 10
    while time.time() - start_time < timeout:
        try:
            # Try to connect to the server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('localhost', port))
            sock.close()
            
            if result == 0:
                # Server is listening, wait a bit more for Flask to be fully ready
                time.sleep(1)
                break
        except:
            pass
        time.sleep(0.5)
    else:
        raise Exception(f"Server did not start within {timeout} seconds")
    
    def cleanup():
        if thread.is_alive():
            try:
                # Try graceful shutdown first
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(('localhost', port))
                sock.close()
            except:
                pass
            
            try:
                os.kill(thread.ident, signal.SIGTERM)
            except:
                pass
            thread.join(timeout=1)
    
    request.addfinalizer(cleanup)
    return f'http://localhost:{port}'

def test_home_page(driver, live_server):
    """Test that the home page loads correctly"""
    driver.get(live_server)
    
    # Check title
    assert "Upload Auth Log - Auth Log Analyzer" in driver.title
    
    # Check for main elements
    upload_area = driver.find_element(By.ID, "dropZone")
    assert upload_area.is_displayed()
    
    file_input = driver.find_element(By.ID, "fileInput")
    assert file_input.get_attribute("accept") == ".log,.gz"
    
    submit_btn = driver.find_element(By.ID, "submitBtn")
    assert submit_btn.is_displayed()
    assert submit_btn.is_enabled() == False  # Should be disabled initially

def test_file_upload_interaction(driver, live_server):
    """Test file upload interaction without actually uploading"""
    driver.get(live_server)
    
    # Get the file input element
    file_input = driver.find_element(By.ID, "fileInput")
    submit_btn = driver.find_element(By.ID, "submitBtn")
    
    # Create a temporary test file
    test_file_path = "test_auth.log"
    with open(test_file_path, "w") as f:
        f.write("Test log content")
    
    try:
        # Simulate file selection
        file_input.send_keys(os.path.abspath(test_file_path))
        
        # Check if submit button is enabled
        WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.ID, "submitBtn"))
        )
        assert submit_btn.is_enabled()
        
    finally:
        # Clean up test file
        os.remove(test_file_path)

def test_upload_invalid_file(driver, live_server):
    """Test uploading an invalid file type"""
    driver.get(live_server)
    
    # Create a temporary invalid file
    test_file_path = "test.txt"
    with open(test_file_path, "w") as f:
        f.write("Invalid file content")
    
    try:
        # Upload invalid file
        file_input = driver.find_element(By.ID, "fileInput")
        file_input.send_keys(os.path.abspath(test_file_path))
        
        # Submit form
        submit_btn = driver.find_element(By.ID, "submitBtn")
        submit_btn.click()
        
        # Check for error message
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CLASS_NAME, "alert-danger"))
        )
        
    finally:
        # Clean up test file
        os.remove(test_file_path)

def test_successful_upload_and_results(driver, live_server):
    """Test successful file upload and results page"""
    driver.get(live_server)
    
    # Create a sample auth.log file
    test_file_path = "test_auth.log"
    with open(test_file_path, "w") as f:
        f.write("May 15 10:51:12 localhost sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2")
    
    try:
        # Upload file
        file_input = driver.find_element(By.ID, "fileInput")
        file_input.send_keys(os.path.abspath(test_file_path))
        
        # Submit form
        submit_btn = driver.find_element(By.ID, "submitBtn")
        WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.ID, "submitBtn")))
        submit_btn.click()
        
        # Check for results page elements
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CLASS_NAME, "results-container"))
        )
        
        # Wait for Plotly to load and initialize
        WebDriverWait(driver, 10).until(
            lambda d: d.execute_script("return typeof Plotly !== 'undefined'")
        )
        
        # Wait for chart containers to be present
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, "timeChart"))
        )
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, "usernameChart"))
        )
        
        # Wait for SVG elements to be present
        WebDriverWait(driver, 10).until(
            lambda d: len(d.find_elements(By.CSS_SELECTOR, "#timeChart .main-svg")) > 0
        )
        WebDriverWait(driver, 10).until(
            lambda d: len(d.find_elements(By.CSS_SELECTOR, "#usernameChart .main-svg")) > 0
        )
        
        # Verify chart data is present
        time_chart_data = driver.execute_script("""
            const timeChart = document.querySelector('#timeChart .main-svg');
            return {
                width: timeChart.getAttribute('width'),
                height: timeChart.getAttribute('height'),
                hasPlots: timeChart.querySelector('.scatterlayer') !== null
            };
        """)
        print("\nTime chart data:", time_chart_data)
        
        username_chart_data = driver.execute_script("""
            const usernameChart = document.querySelector('#usernameChart .main-svg');
            return {
                width: usernameChart.getAttribute('width'),
                height: usernameChart.getAttribute('height'),
                hasPlots: usernameChart.querySelector('.pielayer') !== null
            };
        """)
        print("\nUsername chart data:", username_chart_data)
        
        # Assert that both charts have dimensions and plot layers
        assert time_chart_data['width'] and time_chart_data['height'] and time_chart_data['hasPlots'], "Time chart is not properly rendered"
        assert username_chart_data['width'] and username_chart_data['height'] and username_chart_data['hasPlots'], "Username chart is not properly rendered"
        
    finally:
        # Clean up test file
        if os.path.exists(test_file_path):
            os.remove(test_file_path) 