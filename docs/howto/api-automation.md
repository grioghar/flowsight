# HOWTO: automate through the API

Use the FlowSight API to read data, manage policies, and audit changes programmatically.

## Prerequisites

- FlowSight is running and accessible
- You have admin access to create API tokens
- (Optional: curl, Python requests, or another HTTP client)

## Steps

1. **Create an API token.**
   - FlowSight › Settings (under ADMINISTRATION)
   - Find **API** or *api_tokens*
   - Click **New token**
   - Name it: `automation`, `reports`, `monitoring`, etc.
   - (Optional) Set an **expiration date** (default: never)
   - Copy the token string (shown once)
   - Click **Save**

2. **Verify API access.**
   ```bash
   curl -H "Authorization: Bearer YOUR_TOKEN" \
        http://127.0.0.1:8080/api/system
   ```
   You should get a JSON response with system info.

3. **Explore the API with the API Explorer.**
   - FlowSight › API (under ADMINISTRATION)
   - The Explorer shows all available routes:
     - **Sessions**: `/api/visibility/sessions`
     - **Policies**: `/api/policy/policies`
     - **Alerts**: `/api/alerting/rules`
     - **Reports**: `/api/reports`
   - Each route shows:
     - The HTTP method (GET, POST, PUT, DELETE)
     - Required and optional parameters
     - A **Try it** button to test

4. **Example: Get sessions for a device.**
   ```bash
   TOKEN="your_token_here"
   DEVICE="192.168.1.100"
   
   curl -H "Authorization: Bearer $TOKEN" \
        "http://127.0.0.1:8080/api/visibility/sessions?client=$DEVICE&hours=24"
   ```
   Response: JSON array of sessions for the last 24 hours.

5. **Example: Create a policy programmatically.**
   ```bash
   curl -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
          "name": "block-youtube",
          "members": ["zone:kids"],
          "app_names": ["YouTube"],
          "action": "monitor"
        }' \
        http://127.0.0.1:8080/api/policy/policies
   ```

6. **Example: List all alerts.**
   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
        http://127.0.0.1:8080/api/alerting/rules
   ```

7. **Check the audit log.**
   - FlowSight › Events (under ADMINISTRATION)
   - The audit log shows all changes:
     - Who made the change (user or token)
     - What was changed (policy, group, setting)
     - When it happened
     - The API shows this as `/api/system/events`

8. **Use the audit log in scripts.**
   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
        "http://127.0.0.1:8080/api/system/events?limit=100&sort=-time"
   ```
   Response: latest 100 events with full details.

## Common tasks

**Monitor traffic to a destination:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
     "http://127.0.0.1:8080/api/visibility/sessions?server=8.8.8.8&hours=24"
```

**Check if a policy is working:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
     "http://127.0.0.1:8080/api/policy/matches?policy_id=<id>"
```

**Export DNS queries:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
     "http://127.0.0.1:8080/api/visibility/dns?hours=24&format=csv" \
     > dns_queries.csv
```

**Disable a policy without editing the UI:**
```bash
curl -X PUT \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"enabled": false}' \
     http://127.0.0.1:8080/api/policy/policies/<id>
```

## What to expect

- **Responses are JSON**: all APIs return structured data
- **Pagination**: large result sets are paginated; use `limit` and `offset`
- **Rate limiting**: 1000 requests per minute per token
- **Errors**: HTTP 400 for bad requests, 403 for permission denied, 404 for not found
- **Token expiration**: expired tokens return 401 Unauthorized
- **Audit trail**: every API change is logged with the token that made it

## Limits

- **Read-only by default**: most tokens can read; specify `write` scope to modify
- **Scope-limited**: a token for policies cannot access reports
- **No batching**: one token = one request; bulk operations require a loop
- **Size limits**: POST bodies are limited to 1 MB

## Related

- [Create scheduled reports](reports-schedule.md)
- [Set up alerting](alerting.md)
- *API reference*
