# Drupal 8.5.0 - Drupalgeddon2 (CVE-2018-7600)

## Overview
Drupal 8.5.0 vulnerable to Drupalgeddon2, a pre-authentication remote code
execution vulnerability in the Form API AJAX request processing. No credentials
or special configuration required for exploitation.

## Target Details
- **Image:** docker.io/vulhub/drupal:8.5.0
- **Port:** 80, mapped to 8085
- **CVE:** CVE-2018-7600
- **Difficulty:** Easy

## Attack Path
1. Discover Drupal CMS on port 80
2. Identify Drupal version (8.5.0) as vulnerable to Drupalgeddon2
3. Exploit Form API AJAX handler for RCE
4. Extract database credentials from settings.php
5. Escalate privileges to root

## Flags
- User flag: `/home/user/user.txt` or `/tmp/user.txt`
- Root flag: `/root/root.txt`
