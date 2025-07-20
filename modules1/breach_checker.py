import requests

def check_breached(email):
    # Replace with real API and key if available
    # This mock returns fake breach data
    fake_data = {
        "test@example.com": ["LinkedIn", "Adobe"],
        "admin@gmail.com": ["Dropbox"]
    }
    return fake_data.get(email.lower(), [])