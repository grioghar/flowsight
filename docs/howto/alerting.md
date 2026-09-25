# HOWTO: set up alerting

Configure alert channels and rules to be notified of suspicious activity, policy violations, and findings.

## Prerequisites

- FlowSight is capturing traffic
- You have identified what you want to alert on (policy violations, threats, findings, etc.)
- (Optional: email, webhook, or syslog server for delivery)

## Steps

1. **Create an alert channel.**
   - FlowSight › Alerting (under ADMINISTRATION)
   - Click **New channel**
   - Choose the **Type**:
     - **Email**: send to a mail server (SMTP)
     - **Webhook**: POST to a URL (Slack, Discord, Teams, custom server)
     - **Syslog**: send to a syslog server
     - **PagerDuty**: incident management platform

2. **Configure the channel.**
   
   **Email:**
   - **SMTP server**: `mail.example.com` or `127.0.0.1:25`
   - **From address**: `flowsight@example.com`
   - **To address**: your email
   - **Test**: click to send a test message
   
   **Webhook:**
   - **URL**: e.g., `https://hooks.slack.com/services/YOUR/WEBHOOK/URL`
   - **Test**: click to send a test message
   - (Slack: Workflows › Send a webhook request › copy the URL)
   
   **Syslog:**
   - **Server**: `syslog.example.com` or `192.168.1.100`
   - **Port**: 514 (UDP) or 1514 (TCP)
   - **Protocol**: UDP or TCP
   
   **PagerDuty:**
   - **API key**: from your PagerDuty account
   - **Integration key**: from your PagerDuty service

3. **Test the channel.**
   - Click **Test** to verify delivery
   - Check your email, Slack, or syslog server for the test message

4. **Create an alert rule.**
   - Go to Alerting › **New rule**
   - Name it: `policy-violations`, `threats-detected`, `repeated-scanning`, etc.

5. **Set the trigger.**
   Choose what causes an alert:
   - **Policy violation**: blocked session from a policy
   - **Threat**: IDS/IPS alert
   - **Finding**: automated detection (scanning, DGA, evasion)
   - **All findings**: catch everything
   - **Custom metric** (Business tier): CPU, memory, disk, session count thresholds

6. **Set the condition (optional).**
   
   **Filter by policy**: which policies trigger alerts
   - Leave empty for all
   - Or specify: `country-block`, `malware-block`, etc.
   
   **Filter by severity**: 
   - Findings come with levels: info, low, medium, high, critical
   - Choose which levels to alert on

7. **Set the channel.**
   - Pick the channel(s) to use: Email, Webhook, Syslog, etc.
   - You can send to multiple channels

8. **Set delivery options.**
   - **Digest**: group alerts and send them as a batch:
     - Every minute (real-time)
     - Every 5 minutes
     - Every hour
     - Every day
   - **Escalation**: send to a second channel if the first fails
   - **Quiet hours**: do not alert between certain times (e.g., midnight–6am)

9. **Save the rule.**
   - Click **Save**
   - The rule is now active

10. **Verify it is working.**
    - Generate a trigger manually (if possible)
    - Check the Deliveries log under Alerting › **Deliveries**
    - Each delivery shows: time, rule, channel, status

## What to expect

- **Alert delivery takes 5–10 seconds** from trigger to delivery
- **Digest mode batches alerts**: they arrive after the digest period
- **Quiet hours**: alerts during quiet hours are queued and sent after quiet hours end (if escalation is on)
- **Failures are retried**: if email fails, it retries up to 3 times
- **Webhook format**: the body is JSON with alert details, customizable via templates

## Limits

- **Email**: requires an SMTP server you can reach; Gmail requires an app-specific password
- **Webhook**: the endpoint must respond within 10 seconds
- **Syslog**: limited to the syslog protocol; no authentication by default
- **PagerDuty**: requires an active PagerDuty account and integration
- **Digest**: alerts are batched but not deduplicated (same alert multiple times is still sent once per period)

## Related

- [Create scheduled reports](reports-schedule.md)
- [Block apps and categories on a schedule](policy-schedule.md)
- *User guide › Alerting*
