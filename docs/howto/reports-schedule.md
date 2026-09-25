# HOWTO: create scheduled reports

Define a report template with custom sections, schedule it to run automatically, and receive the results via email or API.

## Prerequisites

- FlowSight has captured traffic (at least 1 week of history for meaningful reports)
- (Optional: email channel set up for delivery)

## Steps

1. **Create a report definition.**
   - FlowSight › Reports (under ADMINISTRATION)
   - Click **New definition**
   - Name it: `weekly-summary`, `daily-threats`, `monthly-audit`, etc.

2. **Choose sections to include.**
   Each report can contain:
   - **Overview**: traffic summary, throughput, active hosts
   - **Top hosts**: devices by sessions or bytes
   - **Top applications**: apps used
   - **Web categories**: content categories accessed
   - **DNS**: lookups and blocked names
   - **Policy violations**: blocked sessions and firewall hits
   - **Threats**: IDS/IPS alerts and findings
   - **Geographic**: which countries traffic goes to
   - **Time series**: traffic over time (graphs)
   - **Audit log**: user actions and API calls
   - (Business tier: custom sections)

3. **Set the time window.**
   - The report covers a period:
     - Last day
     - Last week
     - Last month
     - Custom range

4. **Choose the output formats.**
   The report can be generated as:
   - **PDF**: formatted document with graphs and tables
   - **JSON**: raw data for further processing
   - **CSV**: tables for spreadsheet import
   - **Markdown**: plain text with tables

5. **Set up scheduling.**
   - Click **Schedule** (or find it in the definition)
   - Choose the **frequency**:
     - Daily (every morning at 6am)
     - Weekly (every Monday at 8am)
     - Monthly (first of the month at 9am)
   - Choose the **time zone**
   - Choose the **delivery channel**:
     - Email: sends the report as an attachment
     - Webhook: POSTs the report to a URL
     - FTP/SFTP: uploads to a server

6. **Test the report.**
   - Click **Run now** to generate a test report
   - Wait 30 seconds–1 minute for it to complete
   - Download the result and verify it includes the sections you want

7. **Save and activate.**
   - Click **Save**
   - The report now runs on schedule
   - Check **Runs** or **History** to see past executions

## What to expect

- **Report generation takes 1–5 minutes** depending on size and complexity
- **PDF reports** can be 5–20 MB for a month of data (with graphs)
- **Large reports** (>50 MB) may fail; reduce the time window or sections
- **Time zones**: report generation uses UTC; check that the scheduled time is correct for your zone
- **Scheduling**: a report scheduled for 8am runs sometime between 8:00–8:05am

## Limits

- **PDF size limit**: reports are limited to ~100 MB; monthly reports on large networks may exceed this
- **Retention**: report runs are kept for 30 days; older runs are deleted
- **Sections**: not all sections work with all time windows (e.g., time-series graphs for 1-hour windows have little data)
- **Bandwidth**: very large reports sent via email may hit mail server limits
- **Custom sections**: Business tier only

## Advanced: send reports via API

Instead of email, you can retrieve reports programmatically:

```bash
# List report definitions
curl http://127.0.0.1:8080/api/reports

# Run a report by id and get the result
curl http://127.0.0.1:8080/api/reports/<id>/run?format=pdf > report.pdf
curl http://127.0.0.1:8080/api/reports/<id>/run?format=json > report.json
```

See the [API Automation](api-automation.md) guide for authentication.

## Related

- [Set up alerting](alerting.md)
- [Automate through the API](api-automation.md)
- *User guide › Reports*
