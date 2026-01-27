# Security Anti-Patterns Reference

> Comprehensive guide to dangerous code patterns for LLM-based vulnerability analysis.
> Inject relevant sections into Analysis Agent prompts to improve detection accuracy.

## Quick Reference Table

| Vulnerability | CWE | Critical Functions | Severity |
|--------------|-----|-------------------|----------|
| Code Injection | CWE-94/95 | eval, assert, preg_replace /e | Critical |
| Command Injection | CWE-78 | system, popen, subprocess | Critical |
| SQL Injection | CWE-89 | query, execute (concatenated) | Critical |
| Deserialization | CWE-502 | unserialize, pickle, yaml.load | Critical |
| Path Traversal | CWE-22 | include, fopen, file_get_contents | High |
| XSS | CWE-79 | echo, innerHTML, v-html | Medium |
| SSRF | CWE-918 | curl, requests, file_get_contents(url) | Medium |
| Hardcoded Secrets | CWE-798 | API keys, passwords in source | High |
| Auth Bypass | CWE-287 | Missing auth checks, weak tokens | Critical |

---

## Code Injection (CWE-94, CWE-95)

### Overview
Code injection occurs when untrusted data is executed as code. This is the most severe vulnerability class, often leading to complete system compromise.

### Detection Priority: CRITICAL
- Always analyze first
- Any occurrence warrants immediate attention
- Often disguised in "rule engines" or "template systems"

### PHP Patterns

**BAD: Direct eval with user input**
```php
// VULNERABLE: Direct code execution
$code = $_GET['code'];
eval($code);

// VULNERABLE: Database-sourced code execution
$rule = $auction['rule'];  // From DB, potentially admin-controlled
$result = eval("return " . $rule . ";");
```

**BAD: preg_replace with /e modifier (PHP < 7.0)**
```php
// VULNERABLE: /e modifier executes replacement as PHP code
preg_replace('/.*/e', $_GET['replacement'], $text);
```

**BAD: Assert with string argument**
```php
// VULNERABLE: assert() evaluates string as code in PHP 5
assert($_GET['condition']);
```

**BAD: Dynamic function calls**
```php
// VULNERABLE: Arbitrary function execution
$func = $_GET['function'];
$func();  // Variable function

// VULNERABLE: call_user_func with user input
call_user_func($_GET['callback'], $args);
```

**GOOD: Safe alternatives**
```php
// SAFE: Whitelist allowed operations
$allowed = ['add', 'subtract', 'multiply'];
if (in_array($_GET['op'], $allowed, true)) {
    $result = call_user_func($operations[$_GET['op']], $a, $b);
}

// SAFE: Use expression language with sandboxing
use Symfony\Component\ExpressionLanguage\ExpressionLanguage;
$language = new ExpressionLanguage();
$result = $language->evaluate($expression, ['a' => $a, 'b' => $b]);
```

### Python Patterns

**BAD: eval/exec with user input**
```python
# VULNERABLE: Arbitrary expression evaluation
result = eval(request.args.get('expr'))

# VULNERABLE: Statement execution
exec(user_code)
```

**GOOD: Safe alternatives**
```python
# SAFE: Use ast.literal_eval for data literals only
import ast
data = ast.literal_eval(user_input)  # Only parses literals

# SAFE: Use restricted execution environments
from RestrictedPython import compile_restricted
code = compile_restricted(source, '<string>', 'exec')
```

### JavaScript Patterns

**BAD: Dynamic code evaluation**
```javascript
// VULNERABLE: Direct eval
eval(req.body.code);

// VULNERABLE: Function constructor
new Function(req.query.code)();

// VULNERABLE: setTimeout with string (acts as eval)
setTimeout(userCode, 1000);
```

**GOOD: Safe alternatives**
```javascript
// SAFE: Use JSON.parse for data
const data = JSON.parse(userInput);

// SAFE: Use a sandboxed VM
const vm2 = require('vm2');
const vm = new vm2.VM({ timeout: 1000 });
const result = vm.run(code);
```

### False Positive Indicators
- eval() of hardcoded strings only
- compile() for template engines with no user input in template
- Expression languages with proper sandboxing

---

## Command Injection (CWE-78)

### Overview
Command injection occurs when user input is incorporated into shell commands without proper sanitization. Allows attackers to execute arbitrary system commands, typically leading to full server compromise.

### Detection Priority: CRITICAL
- Check all shell/system call functions
- Look for string concatenation in command arguments
- Verify shell metacharacter handling

### PHP Patterns

**BAD: Direct command execution with user input**
```php
// VULNERABLE: Direct concatenation into system command
$host = $_GET['host'];
system("ping -c 4 " . $host);
// Attack: ?host=127.0.0.1; cat /etc/passwd

// VULNERABLE: Backtick operator
$output = `ls $dir`;

// VULNERABLE: exec with user input
exec("convert " . $_FILES['image']['tmp_name'] . " output.png");

// VULNERABLE: passthru
passthru("whois " . $_GET['domain']);

// VULNERABLE: popen/proc_open
$handle = popen("grep " . $_POST['pattern'] . " /var/log/app.log", "r");
```

**GOOD: Safe command execution**
```php
// SAFE: escapeshellarg for single arguments
$host = escapeshellarg($_GET['host']);
system("ping -c 4 " . $host);

// SAFE: escapeshellcmd for entire command (less preferred)
$cmd = escapeshellcmd("ping -c 4 " . $_GET['host']);

// SAFE: Whitelist approach
$allowed_hosts = ['localhost', 'google.com', 'example.com'];
if (in_array($_GET['host'], $allowed_hosts, true)) {
    system("ping -c 4 " . escapeshellarg($_GET['host']));
}

// SAFE: Avoid shell entirely - use PHP functions
$ip = filter_var($_GET['ip'], FILTER_VALIDATE_IP);
if ($ip) {
    // Use socket functions instead of ping command
}
```

### Python Patterns

**BAD: Shell command execution with user input**
```python
# VULNERABLE: os.system
os.system("ping -c 4 " + user_host)

# VULNERABLE: subprocess with shell=True
subprocess.run(f"grep {pattern} /var/log/app.log", shell=True)
subprocess.call("ls " + directory, shell=True)

# VULNERABLE: os.popen
os.popen("cat " + filename)

# VULNERABLE: commands module (Python 2)
commands.getoutput("host " + domain)
```

**GOOD: Safe command execution**
```python
# SAFE: subprocess with list arguments (no shell)
subprocess.run(["ping", "-c", "4", user_host], shell=False)

# SAFE: shlex.quote for shell commands when unavoidable
import shlex
subprocess.run(f"ping -c 4 {shlex.quote(user_host)}", shell=True)

# SAFE: Avoid shell - use Python libraries
import socket
socket.gethostbyname(hostname)  # Instead of: os.system("host " + hostname)
```

### JavaScript/Node.js Patterns

**BAD: Shell execution with user input**
```javascript
// VULNERABLE: child_process.exec (uses shell)
const { exec } = require('child_process');
exec(`ping -c 4 ${userHost}`);

// VULNERABLE: spawn with shell option
spawn(command, { shell: true });

// VULNERABLE: execSync
execSync('git clone ' + repoUrl);
```

**GOOD: Safe command execution**
```javascript
// SAFE: execFile (no shell interpolation)
const { execFile } = require('child_process');
execFile('ping', ['-c', '4', userHost]);

// SAFE: spawn without shell
const { spawn } = require('child_process');
spawn('ping', ['-c', '4', userHost]);

// SAFE: Use libraries instead of shell commands
const dns = require('dns');
dns.lookup(hostname, callback);  // Instead of exec('host ' + hostname)
```

### Shell Metacharacters to Block
```
; | & $ ` \ ! # ~ [ ] { } ( ) ' " < > * ? \n \r
```

### False Positive Indicators
- Commands with only hardcoded arguments
- execFile/spawn with array arguments (no shell)
- Input validated against strict whitelist
- escapeshellarg/shlex.quote properly applied

---

## SQL Injection (CWE-89)

### Overview
SQL injection occurs when user input is concatenated into SQL queries without parameterization. Enables data theft, authentication bypass, and sometimes RCE.

### Detection Priority: CRITICAL
- Check ALL database query calls
- Look for string concatenation/interpolation
- Verify parameterized queries are actually used

### PHP Patterns

**BAD: String concatenation**
```php
// VULNERABLE: Direct concatenation
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
mysqli_query($conn, $query);

// VULNERABLE: Variable interpolation
$name = $_POST['name'];
$query = "SELECT * FROM users WHERE name = '$name'";

// VULNERABLE: sprintf doesn't protect against injection
$query = sprintf("SELECT * FROM users WHERE id = %s", $_GET['id']);
```

**GOOD: Parameterized queries**
```php
// SAFE: PDO prepared statement
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);

// SAFE: mysqli prepared statement
$stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();
```

### Python Patterns

**BAD: String formatting in queries**
```python
# VULNERABLE: f-string interpolation
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# VULNERABLE: % formatting
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)

# VULNERABLE: .format()
cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))

# VULNERABLE: String concatenation
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
```

**GOOD: Parameterized queries**
```python
# SAFE: Parameter tuple
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# SAFE: Named parameters
cursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})

# SAFE: SQLAlchemy ORM
User.query.filter_by(id=user_id).first()
```

### JavaScript Patterns

**BAD: Template literals in queries**
```javascript
// VULNERABLE: Template literal interpolation
db.query(`SELECT * FROM users WHERE id = ${userId}`);

// VULNERABLE: String concatenation
db.query("SELECT * FROM users WHERE id = " + userId);
```

**GOOD: Parameterized queries**
```javascript
// SAFE: Parameterized query
db.query("SELECT * FROM users WHERE id = ?", [userId]);

// SAFE: Sequelize ORM
await User.findOne({ where: { id: userId } });
```

### False Positive Indicators
- Queries using only integer-cast values: `(int)$_GET['id']`
- ORM methods (usually safe by default)
- Queries with hardcoded values only
- Proper use of prepared statements even if query looks dynamic

---

## Path Traversal (CWE-22)

### Overview
Path traversal allows attackers to access files outside intended directories using sequences like `../`. Can lead to source code disclosure, configuration leaks, or arbitrary file operations.

### Detection Priority: HIGH
- Focus on file operations with user input
- Check for `../` filtering and bypass potential

### Universal Dangerous Patterns

**BAD: Direct path concatenation**
```php
// PHP - VULNERABLE
$file = $_GET['file'];
include("/var/www/templates/" . $file);
// Attack: ?file=../../../etc/passwd

// Python - VULNERABLE
path = os.path.join(base_dir, request.args['file'])
# Note: os.path.join doesn't prevent absolute paths or traversal

// JavaScript - VULNERABLE
const file = path.join(__dirname, 'uploads', req.query.file);
fs.readFile(file);
```

**GOOD: Proper validation**
```php
// PHP - SAFE: Use basename and realpath validation
$filename = basename($_GET['file']);  // Strips directory components
$fullpath = realpath("/var/www/templates/" . $filename);
if ($fullpath && strpos($fullpath, "/var/www/templates/") === 0) {
    include($fullpath);
}
```

```python
# Python - SAFE: Resolve and validate path
from pathlib import Path

base = Path('/var/www/uploads').resolve()
requested = (base / request.args['file']).resolve()

if requested.is_relative_to(base):  # Python 3.9+
    return requested.read_bytes()
```

```javascript
// JavaScript - SAFE: Normalize and validate
const path = require('path');
const base = path.resolve(__dirname, 'uploads');
const requested = path.resolve(base, req.query.file);

if (requested.startsWith(base + path.sep)) {
    fs.readFile(requested);
}
```

### False Positive Indicators
- Files loaded from whitelist/enum
- Paths derived from database with no user input
- basename() applied before use (but check for null bytes)

---

## Deserialization (CWE-502)

### Overview
Unsafe deserialization allows attackers to instantiate arbitrary objects, often leading to RCE through "gadget chains". Particularly dangerous in PHP (magic methods) and Python (pickle).

### Detection Priority: CRITICAL
- Any deserialization of user data is suspicious
- Check cookies, request bodies, and stored data

### PHP Patterns

**BAD: Unserialize user data**
```php
// VULNERABLE: Cookie-based deserialization
$data = unserialize($_COOKIE['user_data']);

// VULNERABLE: Base64 doesn't add safety
$data = unserialize(base64_decode($_GET['object']));

// VULNERABLE: Even with "trusted" source
$data = unserialize($db_row['serialized_config']);  // If user can modify DB
```

**GOOD: Safe alternatives**
```php
// SAFE: Use JSON instead
$data = json_decode($_COOKIE['user_data'], true);

// SAFE: Restrict allowed classes (PHP 7+)
$data = unserialize($input, ['allowed_classes' => false]);

// SAFE: Whitelist specific classes
$data = unserialize($input, ['allowed_classes' => ['SafeClass']]);
```

### Python Patterns

**BAD: Pickle with untrusted data**
```python
# VULNERABLE: Pickle allows arbitrary code execution
import pickle
data = pickle.loads(request.data)  # CRITICAL: RCE

# VULNERABLE: yaml.load default behavior
import yaml
config = yaml.load(user_yaml)  # Creates arbitrary objects
```

**GOOD: Safe alternatives**
```python
# SAFE: Use JSON
import json
data = json.loads(request.data)

# SAFE: yaml with SafeLoader
import yaml
config = yaml.safe_load(user_yaml)
```

### JavaScript Patterns

**BAD: node-serialize**
```javascript
// VULNERABLE: node-serialize allows RCE
const serialize = require('node-serialize');
const data = serialize.unserialize(req.body.data);
```

**GOOD: Safe alternatives**
```javascript
// SAFE: JSON.parse
const data = JSON.parse(req.body.data);

// SAFE: yaml with safe schema
const yaml = require('js-yaml');
const data = yaml.load(input, { schema: yaml.SAFE_SCHEMA });
```

### False Positive Indicators
- Serialization of internal data only (no user input)
- allowed_classes restriction in PHP
- SafeLoader/safe_load in Python YAML

---

## Cross-Site Scripting (CWE-79)

### Overview
XSS allows attackers to inject client-side scripts. LLMs miss 86% of XSS vulnerabilities, so careful pattern matching is essential.

### Detection Priority: MEDIUM
- High volume, lower individual impact
- Focus on reflected and stored variants
- Check all user input rendered in HTML

### PHP Patterns

**BAD: Direct output without encoding**
```php
// VULNERABLE: Reflected XSS
echo "Hello, " . $_GET['name'];

// VULNERABLE: Stored XSS from database
echo $user['bio'];  // If bio contains user HTML

// VULNERABLE: Attribute context
echo '<img src="' . $_GET['url'] . '">';
```

**GOOD: Proper output encoding**
```php
// SAFE: HTML entity encoding
echo "Hello, " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');

// SAFE: Using templating engine with auto-escaping
// Twig, Blade, etc. escape by default
```

### JavaScript Patterns

**BAD: DOM manipulation without sanitization**
```javascript
// VULNERABLE: innerHTML
element.innerHTML = userInput;

// VULNERABLE: document.write
document.write(userData);

// VULNERABLE: React dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{__html: userContent}} />

// VULNERABLE: Vue v-html
<div v-html="userContent"></div>
```

**GOOD: Safe DOM manipulation**
```javascript
// SAFE: textContent
element.textContent = userInput;

// SAFE: DOMPurify sanitization
element.innerHTML = DOMPurify.sanitize(userInput);
```

### False Positive Indicators
- Output in JSON responses (usually safe)
- Admin-only content display
- Content already sanitized upstream
- Content Security Policy in place (mitigates but doesn't prevent)

---

## Server-Side Request Forgery (CWE-918)

### Overview
SSRF occurs when an attacker can make the server perform HTTP requests to arbitrary destinations. Can be used to access internal services, cloud metadata endpoints, or scan internal networks.

### Detection Priority: MEDIUM-HIGH
- Check all URL fetching functions
- Look for user-controlled URLs or URL components
- Verify URL validation and allowlisting

### PHP Patterns

**BAD: Fetching user-controlled URLs**
```php
// VULNERABLE: Direct URL fetch
$url = $_GET['url'];
$content = file_get_contents($url);
// Attack: ?url=http://169.254.169.254/latest/meta-data/

// VULNERABLE: cURL with user URL
$ch = curl_init($_POST['webhook_url']);
curl_exec($ch);

// VULNERABLE: Partial URL control
$endpoint = "http://api.internal/" . $_GET['path'];
file_get_contents($endpoint);
// Attack: ?path=@169.254.169.254/latest/meta-data/
```

**GOOD: Safe URL handling**
```php
// SAFE: URL allowlist
$allowed_domains = ['api.trusted.com', 'cdn.example.com'];
$parsed = parse_url($_GET['url']);
if (in_array($parsed['host'], $allowed_domains, true)) {
    $content = file_get_contents($_GET['url']);
}

// SAFE: Validate URL scheme and host
function is_safe_url($url) {
    $parsed = parse_url($url);
    if (!in_array($parsed['scheme'], ['http', 'https'])) return false;
    if (filter_var($parsed['host'], FILTER_VALIDATE_IP)) {
        // Block private IP ranges
        if (!filter_var($parsed['host'], FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return false;
        }
    }
    return true;
}
```

### Python Patterns

**BAD: Requests with user-controlled URLs**
```python
# VULNERABLE: Direct URL from user
response = requests.get(request.args['url'])

# VULNERABLE: URL construction with user input
url = f"http://internal-api/{request.args['endpoint']}"
requests.post(url, data=payload)

# VULNERABLE: Redirect following (default behavior)
requests.get(user_url)  # May follow redirects to internal URLs
```

**GOOD: Safe URL handling**
```python
# SAFE: URL allowlist
from urllib.parse import urlparse

ALLOWED_HOSTS = {'api.trusted.com', 'cdn.example.com'}

def fetch_url(url):
    parsed = urlparse(url)
    if parsed.netloc not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")
    if parsed.scheme not in ('http', 'https'):
        raise ValueError("Scheme not allowed")
    return requests.get(url, allow_redirects=False)

# SAFE: Block private IPs
import ipaddress

def is_private_ip(host):
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False  # Not an IP, need DNS resolution check
```

### JavaScript Patterns

**BAD: Fetch with user URLs**
```javascript
// VULNERABLE: Direct fetch of user URL
const response = await fetch(req.query.url);

// VULNERABLE: axios with user URL
axios.get(req.body.webhookUrl);

// VULNERABLE: URL path injection
const apiUrl = `http://internal-api/${req.params.resource}`;
```

**GOOD: Safe URL handling**
```javascript
// SAFE: URL allowlist
const ALLOWED_HOSTS = new Set(['api.trusted.com', 'cdn.example.com']);

function safeFetch(url) {
    const parsed = new URL(url);
    if (!ALLOWED_HOSTS.has(parsed.hostname)) {
        throw new Error('Host not allowed');
    }
    if (!['http:', 'https:'].includes(parsed.protocol)) {
        throw new Error('Protocol not allowed');
    }
    return fetch(url, { redirect: 'error' });
}
```

### Cloud Metadata Endpoints to Block
```
# AWS
http://169.254.169.254/
http://[fd00:ec2::254]/

# GCP
http://metadata.google.internal/
http://169.254.169.254/

# Azure
http://169.254.169.254/metadata/

# DigitalOcean
http://169.254.169.254/metadata/
```

### False Positive Indicators
- URLs from configuration files only (not user input)
- Proper URL allowlisting implemented
- Private IP blocking in place
- Redirect following disabled

---

## Hardcoded Secrets (CWE-798)

### Overview
Hardcoded credentials in source code are exposed within minutes of commit. Check all string literals containing key-like patterns.

### Detection Priority: HIGH
- Often low-hanging fruit
- Immediate exploitation potential
- Check environment variable fallbacks

### Universal Patterns

**BAD: Secrets in source**
```php
// VULNERABLE: Hardcoded API key
$api_key = "sk_live_AbCdEf123456789";

// VULNERABLE: Database credentials
$db_password = "production_password_123";
```

```python
# VULNERABLE: AWS credentials
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

```javascript
// VULNERABLE: JWT secret
const JWT_SECRET = "super_secret_jwt_key_12345";
```

**GOOD: Environment variables**
```php
$api_key = getenv('API_KEY') ?: throw new Exception('API_KEY not set');
```

```python
import os
API_KEY = os.environ['API_KEY']
```

```javascript
const API_KEY = process.env.API_KEY;
if (!API_KEY) throw new Error('API_KEY required');
```

### Regex Patterns for Detection
```
# API Keys
(api[_-]?key|apikey)\s*[=:]\s*['"][a-zA-Z0-9]{20,}['"]

# AWS Keys
AKIA[0-9A-Z]{16}

# Private Keys
-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----

# Generic Secrets
(password|passwd|pwd|secret|token)\s*[=:]\s*['"][^'"]{8,}['"]
```

### False Positive Indicators
- Test/example credentials in comments
- Placeholder values (e.g., "your-api-key-here")
- Public API keys (some services have public keys)
- Hashed/encrypted values

---

## Authentication Failures (CWE-287)

### Overview
Authentication bypass and weak authentication allow attackers to impersonate users. Check auth middleware, session handling, and password verification.

### Detection Priority: CRITICAL
- Focus on entry points and auth checks
- Verify auth is applied consistently
- Check for timing attacks in comparisons

### PHP Patterns

**BAD: Weak/missing authentication**
```php
// VULNERABLE: No auth check on sensitive endpoint
// admin.php - Missing session_start() or auth verification
$_POST['delete_user'];  // Processes without checking auth

// VULNERABLE: Type juggling in comparison
if ($_POST['password'] == $stored_hash) {  // == allows type coercion
    authenticate();
}

// VULNERABLE: Predictable session tokens
$token = md5(time());  // Easily guessable
```

**GOOD: Proper authentication**
```php
// SAFE: Consistent auth middleware
session_start();
if (!isset($_SESSION['user_id']) || !validate_session($_SESSION)) {
    http_response_code(401);
    exit('Unauthorized');
}

// SAFE: Constant-time comparison
if (hash_equals($stored_hash, password_hash($password, PASSWORD_DEFAULT))) {
    authenticate();
}
```

### Python Patterns

**BAD: Weak session handling**
```python
# VULNERABLE: Predictable tokens
token = hashlib.md5(str(time.time()).encode()).hexdigest()

# VULNERABLE: No auth decorator
@app.route('/admin/users', methods=['DELETE'])
def delete_user():
    # No @login_required decorator!
    User.delete(request.args['id'])
```

**GOOD: Secure session handling**
```python
# SAFE: Cryptographic random tokens
import secrets
token = secrets.token_urlsafe(32)

# SAFE: Auth decorator applied
@app.route('/admin/users', methods=['DELETE'])
@login_required
@admin_required
def delete_user():
    User.delete(request.args['id'])
```

### False Positive Indicators
- Public endpoints intentionally without auth
- Auth handled by framework middleware globally
- Rate limiting in place (mitigates but doesn't prevent)

---

## Detection Strategy

### Analysis Order
1. **Critical**: Code Injection, Command Injection, Deserialization, Auth Bypass
2. **High**: SQL Injection, Path Traversal, Hardcoded Secrets
3. **Medium**: XSS, SSRF, Open Redirect

### Taint Analysis Steps
1. Identify sources (user input entry points)
2. Trace through transforms (encoding, parsing, assignment)
3. Check for sanitization (validation, escaping, parameterization)
4. Verify sink is reached (dangerous function call)

### Confidence Scoring
- **0.9+**: Direct user input to sink, no sanitization
- **0.7-0.9**: User input reaches sink, weak/bypassable sanitization
- **0.5-0.7**: User input may reach sink, sanitization present but uncertain
- **<0.5**: Possible but unlikely, multiple conditions required

---

## False Positive Checklist

Before reporting a vulnerability, verify:

- [ ] User input actually reaches the sink (not just similar variable names)
- [ ] Sanitization isn't applied between source and sink
- [ ] The code path is reachable (not dead code)
- [ ] Test/example code isn't being flagged as production
- [ ] Framework protections aren't in place (CSRF tokens, CSP, etc.)
- [ ] Type casting/validation doesn't prevent exploitation

---

## References

- [OWASP Top 10](https://owasp.org/Top10/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Arcanum Sec-Context](https://github.com/Arcanum-Sec/sec-context)
