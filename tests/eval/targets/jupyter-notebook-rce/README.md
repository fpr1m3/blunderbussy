# Jupyter Notebook 5.2.2 - Unauthenticated RCE

## Overview
Jupyter Notebook 5.2.2 running with an empty authentication token, allowing
unauthenticated access. An attacker can execute arbitrary Python code (including
operating system commands) through the notebook interface.

## Target Details
- **Image:** docker.io/vulhub/jupyter-notebook:5.2.2
- **Port:** 8888
- **Vulnerability:** Misconfiguration (no auth token)
- **Difficulty:** Easy

## Attack Path
1. Discover Jupyter Notebook on port 8888
2. Access notebook interface (no token needed)
3. Create new notebook and execute Python with subprocess to run commands
4. Establish reverse shell or read flags directly
5. Escalate privileges to root

## Flags
- User flag: `/home/user/user.txt` or `/tmp/user.txt`
- Root flag: `/root/root.txt`
