import requests
import json

# Docker API URL (assuming Docker is running locally)
DOCKER_API_URL = "http://localhost:2375"

def get_containers():
    # Get list of all containers
    response = requests.get(f"{DOCKER_API_URL}/containers/json?all=true")
    if response.status_code != 200:
        print("Failed to get containers")
        return []
    return response.json()

def get_container_env(container_id):
    # Get environment variables for a specific container
    response = requests.get(f"{DOCKER_API_URL}/containers/{container_id}/json")
    if response.status_code != 200:
        print(f"Failed to get info for container {container_id}")
        return []
    
    container_data = response.json()
    env_vars = container_data.get('Config', {}).get('Env', [])
    return env_vars

def main():
    containers = get_containers()
    if not containers:
        print("No containers found.")
        return
    
    for container in containers:
        container_id = container['Id']
        container_name = container['Names'][0]
        print(f"\nContainer Name: {container_name}")
        print(f"Container ID: {container_id}")
        
        env_vars = get_container_env(container_id)
        if env_vars:
            print("Environment Variables:")
            for env in env_vars:
                print(f"  - {env}")
        else:
            print("No environment variables found.")

if __name__ == "__main__":
    main()
