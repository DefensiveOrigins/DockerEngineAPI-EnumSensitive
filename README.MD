# Docker API Enumeration Tools

These scripts query the **Docker Engine HTTP API** to collect information about containers and secrets.  
They are designed for security assessments and administrative auditing, providing quick insights into environment variables, secrets, and general engine configuration.

**Warning**: Exposing the Docker Engine API without TLS or authentication is a serious security risk.  
Use these scripts only against environments you are authorized to assess.

---

## Scripts

### 1. `docker_envs.py`
Enumerates running and stopped containers, extracts their **environment variables**, and prints them to the console.  
Can also save the results in structured JSON.

#### Features
- Fetches `/info` for Docker Engine overview (version, OS, CPUs, memory, etc.).
- Lists all containers (like `docker ps -a`).
- Shows each container’s environment variables.
- Displays a progress bar with [`alive-progress`](https://github.com/rsalmei/alive-progress).
- Optionally saves results to a JSON file.

#### Usage

##### Environment Variables Enumeration

```bash
# Local Docker API (default: http://localhost:2375)
python EnumEnvVars.py

# Remote engine and save to file
python EnumEnvVars.py --url http://docker-host:2375 --out results.json

# Include full /info JSON
python EnumEnvVars.py --show-info-json
```

##### Secrets Enumeration

```bash

# Local secrets enumeration
python EnumSecrets.py

# Remote engine, attempt values, save to file
python EnumSecrets.py --url http://docker-host:2375 --attempt-values --out secrets.json

# Include full /info JSON
python EnumSecrets.py --show-info-json
```

#### Installation

```bash
pip install requests alive-progress
```