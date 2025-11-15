# Docker API Enumeration Tools

These scripts query the **Docker Engine HTTP API** to collect information about containers and secrets.  
They are designed for security assessments and administrative auditing, providing quick insights into environment variables, secrets, and general engine configuration.

**Warning**: Exposing the Docker Engine API without TLS or authentication is a serious security risk.  
Use these scripts only against environments you are authorized to assess.

## Install
From pip: 
```bash
pip install docker-enumsensitive
```
From github:
```bash
git clone https://github.com/DefensiveOrigins/DockerEngineAPI-EnumSensitive.git
```
---


 
## Scripts

### docker-enum-envvars / EnumEnvVars.py`
Enumerates running and stopped containers, extracts their **environment variables**, and prints them to the console.  
Can also save the results in structured JSON.

### docker-enum-secrets / EnumSecrets.py
Enumerates Secrets from Docker Swarm mode, attempting to read their values if specified. Can also save the results in structured JSON.

### docker-enum-images / EnumImages.py
Inspects the contents of images for sensitive information such as tokens, keys, etc.


### Usage

#####  Environment Variables Enumeration

```bash
# Local Docker API (default: http://localhost:2375)
python EnumEnvVars.py
docker-enum-envvars

# Remote engine and save to file
python EnumEnvVars.py --url http://docker-host:2375 --out results.json
docker-enum-envvars --url http://docker-host:2375 --out results.json


# Include full /info JSON
python EnumEnvVars.py --show-info-json
docker-enum-envvars --show-info-json
```

##### Secrets Enumeration 

```bash

# Local secrets enumeration
python EnumSecrets.py
docker-enum-secrets

# Remote engine, attempt values, save to file
python EnumSecrets.py --url http://docker-host:2375 --attempt-values --out secrets.json
docker-enum-secrets --url http://docker-host:2375 --attempt-values --out secrets.json

# Include full /info JSON
python EnumSecrets.py --show-info-json
docker-enum-secrets --show-info-json
```
