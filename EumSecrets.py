import requests
import json

# Docker API URL (assuming Docker is running locally)
DOCKER_API_URL = "http://localhost:2375"

def get_secrets():
    # Get list of all secrets
    response = requests.get(f"{DOCKER_API_URL}/secrets")
    if response.status_code != 200:
        print("Failed to get secrets")
        return []
    return response.json()

def get_secret_value(secret_id):
    # Get secret details (including value) for a specific secret
    response = requests.get(f"{DOCKER_API_URL}/secrets/{secret_id}")
    if response.status_code != 200:
        print(f"Failed to get info for secret {secret_id}")
        return None
    
    secret_data = response.json()
    # Extract the secret's value, which is base64 encoded
    secret_value = secret_data.get('Spec', {}).get('Data', '')
    return secret_value

def main():
    secrets = get_secrets()
    if not secrets:
        print("No secrets found.")
        return
    
    for secret in secrets:
        secret_id = secret['ID']
        secret_name = secret['Spec']['Name']
        print(f"\nSecret Name: {secret_name}")
        print(f"Secret ID: {secret_id}")
        
        secret_value = get_secret_value(secret_id)
        if secret_value:
            # The secret value is base64 encoded, so we'll decode it
            decoded_value = secret_value.decode('utf-8')
            print(f"Secret Value: {decoded_value}")
        else:
            print("No secret value found.")

if __name__ == "__main__":
    main()
