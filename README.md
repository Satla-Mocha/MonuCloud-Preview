MonuCloud — Cloud Security Posture Management (Preview)
*Lightweight CSPM with scheduled scans, External ID onboarding, and clear remediation guidance.*

This repository contains **non-executable preview code** and architecture docs for MonuCloud.
The **live, working demo** is running at https://monucloud.com.

What you'll find here:
- Architecture diagrams
- Schema overview
- Sample data for screenshots
- Two example rules (safe to publish)
- Small code previews (trimmed & redacted; not runnable)

> For a walkthrough or a technical deep dive, DM me.

Live demo
 · [Public preview repo](https://github.com/Satla-Mocha/MonuCloud-Preview)
 · [Contact](omeragniho23@gmail.com)

Overview:
MonuCloud is a lightweight Cloud Security Posture Management (CSPM) project that helps teams continuously scan their cloud accounts, surface misconfigurations, and track fixes over time. It’s designed for DevOps/Cloud engineers and security-minded builders who want a clear, shippable baseline: scheduled scans, findings with evidence, and remediation guidance in a clean UI. The MVP focuses on AWS today, with Azure and GCP checks on the roadmap next.

Key Features:
1. Scheduled scans with Celery (cron-like scheduling).
2. Secure onboarding via AWS AssumeRole + External ID.
3. Findings dashboard with filters (cloud, account, severity, rule, resource).
4. Time-series charts (findings over time).
5. Remediation guidance (built-in text). Automated remediation in progress.
6. Postgres-backed storage model (scans, resources, findings)

Architecture (High-level):
MonuCloud consists of a lightweight Flask web app for the UI and API, a Celery worker for scheduled and on-demand scans, and a PostgreSQL database for users, connected AWS accounts, scans, resources, and findings (plus daily snapshots for charts). The web app handles auth and multi-tenant scoping, then enqueues scan jobs; the worker assumes a read-only cross-account IAM role in each connected account using STS AssumeRole with External ID, calls the relevant AWS service APIs (e.g., EC2, S3, IAM), evaluates rules, and upserts findings into Postgres idempotently. A small rules catalog defines severities/titles, while the worker streams evidence per resource and updates time-series counts. By default, everything runs in Docker; Celery can use Redis or RabbitMQ as the broker. The hosted demo enables a safe “demo mode” that loads sample data without touching real tenants.

[Architecture Diagram](docs/monucloud-arch.mmd)

Screenshots / Demo:
- “Connect AWS” screen:
[Connect AWS](docs/screens/connect_aws.png)
- “Run scan” + status toast:
[Run Scan - Starting](docs/screens/starting_scan.png)
[Run Scan - Running](docs/screens/running_scan.png)
- Dashboard KPIs + filters:
[Dashboard KPIs](docs/screens/dashboard_KPIs.png)
- Findings table + detail panel:
[Findings table](docs/screens/findings_table.png)
[Findings chart](docs/screens/findings_chart.png)
- Dashboard Overview, Scan and Resolve:
[Scan & Resolve](docs/screens/Scan.gif)
[Full Video](docs/screens/Scanning%20and%20resolving%20a%20misconfiguration.mp4)


Quickstart:
- Open MonuCloud.com 
- Register -> Login
- See demo with sample data 

Connecting Your AWS Account (Production):
1. Create a cross-account role using our template (External ID required).
2. Paste the Role ARN and External ID in the app.
3. Run a scan and view findings.

Checks Catalog (Public Subset):
AWS-001 (EC2, High): Security groups allow 0.0.0.0/0 on non-HTTP(S) ports.
AWS-002 (S3, High): Bucket public read/write (ACL/Policy) when not intended.
AWS-003 (CloudTrail, Medium): Trail not enabled in all required regions.
AWS-004 (IAM, High): Root account without MFA.
AWS-005 (KMS, Medium): CMK rotation disabled.
AWS-006 (RDS, High): Publicly accessible DB instances.
AWS-007 (CloudWatch, Low): “Never expire” log retention.
AWS-008 (EBS, Medium): Unencrypted EBS volumes.
- Full catalog available to trial users on request.

Automated Remediation (Roadmap):
- Approval-based, safe-mode first.
- Dry-run → human approval → apply
- Guardrails: scoped remediator role, allowlists, idempotent changes, audit log
- Initial candidates: SG ingress tightening, S3 public access fixes, key rotation

Data Model (Schema Summary):
  accounts:
    - id (PK, int) – internal
    - cloud (text) – e.g., AWS
    - account_id (text, indexed) – cloud’s account identifier
    - account_alias (text, nullable)

  connections:
    - id (PK, int)
    - cloud (text)
    - account_id (text, indexed)
    - role_arn (text)
    - external_id (text)
    - created_at (timestamptz, default now)

  rules:
    - rule_id (PK, text) – like “AWS-001”
    - service (text)
    - severity (text: Critical/High/Medium/Low)
    - title (text)
    - description (text)
    - enabled (bool, default true)

  scans:
    - scan_id (PK, bigserial)
    - cloud (text)
    - account_id (text)
    - started_at (timestamptz)
    - finished_at (timestamptz, nullable)
    - status (text: RUNNING/SUCCESS/FAILED)
    - tool_version (text)
    - notes (text, nullable)

  resources:
    - resource_pk (PK, bigserial)
    - cloud (text)
    - account_id (text)
    - resource_type (text) – e.g., ec2:security-group
    - resource_id (text, indexed)
    - region (text, nullable)
    - properties (jsonb)

  findings
    - finding_id (PK, text/uuid)
    - rule_id (FK → rules.rule_id, indexed)
    - cloud (text)
    - account_id (text, indexed)
    - resource_id (text, indexed)
    - region (text, nullable)
    - severity (text)
    - title (text)
    - evidence (jsonb)
    - first_seen (timestamptz)
    - last_seen (timestamptz)
    - status (text: OPEN/RESOLVED/SUPPRESSED)

  remediation_logs:
    - action_id (PK, bigserial)
    - finding_id (FK → findings.finding_id)
    - action_type (text: DRY_RUN/AUTO/FIX)
    - status (text: PENDING/SUCCESS/FAILED)
    - details (jsonb)
    - executed_at (timestamptz)


Sample Data:
- Folder: /sample_data/
- accounts.csv, connections.csv, rules.csv, scans.csv, findings.json

Security Notes:
- Read-only scans by default; cross-account access via External ID.
- No production secrets in this repo; sample configs only.
- Demo/sample data is segregated and remediation disabled on demo rows.

Tech Stack:
Flask (Python) · Celery · PostgreSQL · Docker · boto3 · Bootstrap UI

Local Development:
- python -m venv .venv && source .venv/bin/activate
- pip install -r requirements.txt
- FLASK_APP=app.py flask run

Deployment (Summary):
- Docker images for API and worker.
- Postgres as managed service or container.
- Environment variables for DB URL, broker, and demo flags.

Roadmap
- Approval-based automated remediation (In Development).
- Azure + GCP checks.
- AI-assisted remediation text and step-by-step playbooks.
- Org-level rollups and multi-account “scan all” button.

Limitations:
- MVP focuses on AWS; multi-cloud next.
- Certain checks simplified for demo performance.

License:
[Read License](/license.lic)

Contact:
Omer Agniho • Owner/Developer
[Email](omeragniho23@gmail.com) or [LinkedIn](https://www.linkedin.com/in/omer-agniho-34a922332/)
---------
“I’m currently looking for DevOps/Cloud roles—DM for a walkthrough.”
---------


Thanks for reading and contact me for any question
