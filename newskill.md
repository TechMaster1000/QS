---
name: atlassian-cred-scan
description: >
  Scan Confluence pages AND Jira issues for production cleartext credentials
  (passwords, API keys, tokens, client secrets, access keys) per security/privacy/
  compliance requirements. Searches Confluence page content and Jira issue descriptions,
  comments, and custom fields. Only flags actual secret values that can directly
  authenticate or grant access to production systems. Excludes AWS ARNs, non-production
  credentials that are clearly labeled, and identifier-only values. Uses the Atlassian
  MCP server. Trigger whenever asked to audit Confluence or Jira for exposed production
  secrets, find hardcoded credentials, run a credential sweep, or check for
  PII/secret leaks. Requires the Atlassian MCP server to be connected.
disable-model-invocation: true
---

# Atlassian Production Credential Scanner (Confluence + Jira)

Scan **Confluence pages** and **Jira issues** for **production cleartext credentials**
using Atlassian MCP tools.

This skill implements the organization's security, privacy, and compliance requirements:
all users, project owners, and space owners must review their content and remediate any
production cleartext sensitive data.

## What IS a Cleartext Credential (in scope)

Cleartext credentials are **actual secret values** that can be directly used to
authenticate or access a **production** system:

- **Passwords** — actual production passwords (not placeholders)
- **API keys** — production API keys that grant access
- **Tokens** — bearer tokens, access tokens, refresh tokens for production
- **Client secret values** — OAuth client secrets for production apps
- **Access keys** — AWS access keys (AKIA...), GCP service account keys, Azure keys
- **Private keys** — RSA, SSH, EC, PGP private key blocks
- **Connection strings** — database URIs with embedded production passwords
- **Webhook URLs** — Slack/Teams/etc. webhook URLs containing tokens

These are values that, if copied, could immediately grant access.

## What is NOT a Cleartext Credential (out of scope — MUST exclude)

- **AWS ARNs and similar identifiers** — ARNs are identifiers only and do NOT grant
  access by themselves. They are acceptable to remain. Do NOT flag ARN patterns like
  `arn:aws:*`. Same applies to Azure resource IDs, GCP resource names, etc.
- **Non-production credentials** (eng/test/dev/staging/sandbox/local) — these are
  acceptable to remain **as long as they are clearly labeled** as non-production.
  Look for context clues: page title contains "test"/"dev"/"staging"/"sandbox",
  or the credential is inside a section/heading labeled as non-production, or
  env variable names include `_DEV`, `_TEST`, `_STAGING`, `_LOCAL`.
- **Placeholder/example values** — `password=<YOUR_PASSWORD>`, `password=xxxxx`,
  `password=changeme`, `password=****`, `password=example`, `YOUR_API_KEY_HERE`
- **Documentation about how to set credentials** (e.g., "set your password in vault")
- **References to secret managers** (e.g., "retrieve from 1Password / Vault / ASM")
- **Resource identifiers** — account IDs, subscription IDs, tenant IDs, project IDs
- **Public endpoints** — URLs without embedded credentials

## Prerequisites

Before starting, verify the Atlassian MCP server is connected by checking available
tools. If not connected, instruct the user to run:

```
claude mcp add --transport http atlassian https://mcp.atlassian.com/v1/mcp
```

Then authenticate via `/mcp` in Claude Code.

## Workflow

### Step 1: Determine Scan Scope

`$ARGUMENTS` is required and must be one or more **project keys** (comma-separated).

Examples:
```
/atlassian-cred-scan DEVOPS
/atlassian-cred-scan ENG,PLATFORM,INFRA
```

For each project key, the skill scans **both** Confluence and Jira:
- **Confluence:** the space matching the project key
- **Jira:** all issues in the project

**Confluence space resolution:**
1. Use the Atlassian MCP `searchConfluence` tool with CQL to verify the space exists:
   ```
   space = "<PROJECT_KEY>" AND type = "page" order by lastModified desc
   ```
2. If no results, use `getConfluenceSpaces` to list all spaces and find a match.
3. If no Confluence space matches, log it and continue with Jira scanning only.

**Jira project resolution:**
1. Use the Atlassian MCP `searchJiraIssues` tool with JQL to verify the project exists:
   ```
   project = "<PROJECT_KEY>" ORDER BY updated DESC
   ```
2. If no results, log it and continue with Confluence scanning only.
3. If neither Confluence space nor Jira project exists, inform the user.

If no arguments are given, prompt the user:
"Please provide a project key. Example: `/atlassian-cred-scan DEVOPS`"

---

## Part A: Confluence Scanning

### Step 2A: Confluence CQL-First Search (DO NOT fetch all pages)

**CRITICAL PERFORMANCE RULE:** NEVER use `getPagesInConfluenceSpace` to pull all
pages and then inspect them one by one. This is the #1 cause of slow scans.

Instead, run **individual CQL searches per credential pattern** using `searchConfluence`.
This offloads filtering to Confluence's server and only returns matching pages.

Run these CQL queries sequentially. Each query is one MCP call and returns only
pages that match — far faster than fetching hundreds of pages:

**Query Group 1 — Critical patterns (run these first):**
```
space = "<PROJECT_KEY>" AND text ~ "BEGIN RSA PRIVATE KEY"
space = "<PROJECT_KEY>" AND text ~ "BEGIN OPENSSH PRIVATE KEY"
space = "<PROJECT_KEY>" AND text ~ "AKIA"
space = "<PROJECT_KEY>" AND text ~ "service_account"
space = "<PROJECT_KEY>" AND text ~ "jdbc"
space = "<PROJECT_KEY>" AND (text ~ "mongodb://" OR text ~ "postgres://" OR text ~ "mysql://")
```

**Query Group 2 — High severity:**
```
space = "<PROJECT_KEY>" AND (text ~ "password=" OR text ~ "password:")
space = "<PROJECT_KEY>" AND (text ~ "api_key" OR text ~ "apikey" OR text ~ "api-key")
space = "<PROJECT_KEY>" AND (text ~ "access_token" OR text ~ "client_secret" OR text ~ "secret_key")
space = "<PROJECT_KEY>" AND text ~ "Authorization: Bearer"
space = "<PROJECT_KEY>" AND text ~ "hooks.slack.com"
```

**Query Group 3 — Medium severity:**
```
space = "<PROJECT_KEY>" AND (text ~ "sshpass" OR text ~ ".env")
space = "<PROJECT_KEY>" AND text ~ "credential"
```

**Deduplicate results** across queries — the same page may match multiple patterns.
Track which patterns matched each page to avoid redundant work.

### Step 3A: Inspect Only Matched Confluence Pages

Only fetch full page content (via `getConfluencePage`) for pages that appeared in
the CQL search results from Step 2. This should typically be 5-20 pages, not hundreds.

For each matched page, confirm the finding by:
1. Checking if the credential is for a **production** system (in scope)
2. Verifying it is an **actual secret value** (not an identifier or placeholder)
3. Ensuring it is NOT in the exclusion list below

**In-Scope — Flag these (production cleartext credentials):**
- Private keys: `BEGIN RSA PRIVATE KEY`, `BEGIN OPENSSH PRIVATE KEY`, `BEGIN EC PRIVATE KEY`, `BEGIN PGP PRIVATE KEY`
- AWS access keys: strings matching `AKIA[0-9A-Z]{16}` (these are secrets, NOT ARNs)
- GCP service account JSON keys: `"type": "service_account"` with `"private_key"`
- Database connection URIs with embedded passwords: `mongodb://user:pass@`, `postgres://user:pass@`, `mysql://user:pass@`, `jdbc:...:password=`
- Explicit password assignments: `password=`, `password:`, `passwd=`, `pwd=` followed by real values
- API key assignments: `api_key=`, `apikey=`, `api-key:`, `x-api-key:` with real values
- Token assignments: `token=`, `access_token=`, `secret_key=`, `client_secret=` with real values
- Bearer tokens: `Authorization: Bearer <actual_token_value>`
- Webhook URLs with tokens: `hooks.slack.com/services/T.../B.../...`

**Out-of-Scope — MUST NOT flag these:**
- **AWS ARNs**: `arn:aws:*` — these are identifiers, NOT credentials. Skip entirely.
- **Azure resource IDs**: `/subscriptions/...` — identifiers only.
- **GCP resource names**: `projects/*/locations/*/...` — identifiers only.
- **Account IDs / Tenant IDs / Subscription IDs** — identifiers only.
- **Non-production credentials clearly labeled**: if the page title, section heading,
  or surrounding context contains words like `test`, `dev`, `development`, `staging`,
  `sandbox`, `local`, `non-prod`, `nonprod`, `eng`, `qa`, `demo`, or if the env
  variable name contains `_DEV`, `_TEST`, `_STAGING`, `_LOCAL`, `_SANDBOX` — these
  are acceptable and must be SKIPPED.
- **Placeholder values**: `<YOUR_PASSWORD>`, `xxxxx`, `changeme`, `****`, `example`,
  `YOUR_API_KEY_HERE`, `TODO`, `REPLACE_ME`, `dummy`, `fake`, `sample`
- **Vault/manager references**: "stored in 1Password", "see HashiCorp Vault",
  "retrieve from AWS Secrets Manager"

**Environment classification logic:**
When a credential is found, determine if it is production by checking:
1. Page title / heading — does it say "prod", "production", or is it unlabeled?
2. Surrounding context — env names like `PROD_DB_PASSWORD`, `DATABASE_URL` (no env prefix = assume prod)
3. If environment is ambiguous (no clear label), **flag it as "Needs Review"** —
   unlabeled credentials should be treated as potentially production.

---

## Part B: Jira Scanning

### Step 2B: Jira JQL-First Search (DO NOT fetch all issues)

**CRITICAL PERFORMANCE RULE:** NEVER use broad JQL like `project = X` to pull all
issues and inspect them one by one. Use **text-search JQL** to pre-filter.

Run these JQL queries using the Atlassian MCP `searchJiraIssues` tool. Each query
returns only issues with matching text in description, comments, or summary:

**Query Group 1 — Critical patterns:**
```
project = "<PROJECT_KEY>" AND text ~ "BEGIN RSA PRIVATE KEY"
project = "<PROJECT_KEY>" AND text ~ "BEGIN OPENSSH PRIVATE KEY"
project = "<PROJECT_KEY>" AND text ~ "AKIA"
project = "<PROJECT_KEY>" AND text ~ "service_account"
project = "<PROJECT_KEY>" AND text ~ "jdbc"
project = "<PROJECT_KEY>" AND text ~ "mongodb://" OR text ~ "postgres://" OR text ~ "mysql://"
```

**Query Group 2 — High severity:**
```
project = "<PROJECT_KEY>" AND text ~ "password="
project = "<PROJECT_KEY>" AND text ~ "api_key" OR text ~ "apikey"
project = "<PROJECT_KEY>" AND text ~ "access_token" OR text ~ "client_secret" OR text ~ "secret_key"
project = "<PROJECT_KEY>" AND text ~ "Authorization: Bearer"
project = "<PROJECT_KEY>" AND text ~ "hooks.slack.com"
```

**Query Group 3 — Medium severity:**
```
project = "<PROJECT_KEY>" AND text ~ "sshpass"
project = "<PROJECT_KEY>" AND text ~ "credential"
```

**Deduplicate results** across queries — the same issue may match multiple patterns.

### Step 3B: Inspect Only Matched Jira Issues

For each matched issue, use the Atlassian MCP `getJiraIssue` tool to retrieve the
full issue details. Inspect ALL of these fields for credentials:

1. **Description** — the main issue body (most common place for pasted credentials)
2. **Comments** — all comments on the issue (use `getJiraIssueComments` if available)
3. **Summary** — the issue title (less common but check it)
4. **Custom fields** — environment fields, deployment notes, config fields

Apply the same in-scope/out-of-scope rules as Confluence (see Step 3A above).

**Jira-specific context clues for environment classification:**
- Issue labels: `production`, `prod`, `staging`, `dev`, `test`
- Fix version names: `prod-release`, `staging-deploy`
- Component names: `prod-infra`, `dev-tools`
- Environment field value (if populated)
- The issue type and workflow status can hint at environment

---

## Part C: Combined Analysis

### Step 4: Filter False Positives

Exclude matches that are:
- **AWS ARNs** (`arn:aws:...`) — identifiers, not credentials
- **Resource IDs** — Azure subscription IDs, GCP project names, account numbers
- **Non-production credentials clearly labeled** — dev/test/staging/sandbox/local/qa/eng/demo
- **Placeholder values** — `<YOUR_PASSWORD>`, `xxxxx`, `changeme`, `****`, `example`, `REPLACE_ME`
- **Documentation about how to set credentials** — instructional content, not actual secrets
- **References to secret managers or vaults** — 1Password, HashiCorp Vault, AWS Secrets Manager
- **Code examples from public documentation** using dummy values
- **Public URLs** without embedded credentials

When uncertain whether a credential is production or non-production, include the
match but flag it as **"Needs Review — environment unclear"**.

### Step 5: Generate Report

Present findings as a structured report combining Confluence and Jira results:

```
## Atlassian Production Credential Scan Report
**Compliance:** Security, Privacy & Compliance — Cleartext PII/Secrets Remediation
**Date:** [current date]
**Project Key(s) Scanned:** [list of project keys]
**Confluence Spaces Resolved:** [list of space keys, or "N/A" if none found]
**Jira Projects Resolved:** [list of project keys confirmed in Jira]
**CQL Queries Run (Confluence):** [count]
**JQL Queries Run (Jira):** [count]
**Candidate Items Found:** [count from CQL + JQL]
**Items Inspected:** [count after dedup]
**Production Findings:** [count]
**Skipped (non-prod/identifiers):** [count]

### Confluence — Production Credential Findings (Action Required)
| # | Project Key | Space | Page Title | Page URL | Credential Type | Environment | Matched Content (redacted) | Recommendation |
|---|-------------|-------|------------|----------|-----------------|-------------|---------------------------|----------------|
| 1 | DEVOPS      | DO    | DB Setup   | [link]   | DB URI          | PROD        | postgres://admin:r***d@... | Rotate & vault |

### Jira — Production Credential Findings (Action Required)
| # | Project Key | Issue Key | Summary | Field | Credential Type | Environment | Matched Content (redacted) | Recommendation |
|---|-------------|-----------|---------|-------|-----------------|-------------|---------------------------|----------------|
| 1 | DEVOPS      | DEV-1234  | Deploy  | Desc  | Password        | PROD        | password=Pr***d!           | Rotate & vault |
| 2 | DEVOPS      | DEV-5678  | Config  | Comment | API Key       | UNCLEAR     | api_key=sk-****Xm          | Needs Review   |

### Skipped — Non-Production (No Action Required)
| # | Source     | Title/Key   | Credential Type | Environment Label | Reason Skipped |
|---|-----------|-------------|-----------------|-------------------|----------------|
| 1 | Confluence | Dev Setup   | Password        | DEV               | Clearly labeled dev |
| 2 | Jira       | DEV-9999   | Token           | STAGING           | Labeled staging |

### Skipped — Identifiers Only (Not Credentials)
| # | Source     | Title/Key  | Pattern Found | Type | Reason Skipped |
|---|-----------|------------|---------------|------|----------------|
| 1 | Confluence | AWS Infra  | arn:aws:s3::: | ARN  | Identifier only |

### Scan Performance
- Confluence: CQL pre-filter reduced pages from [total] to [candidate count]
- Jira: JQL pre-filter reduced issues from [total] to [candidate count]
- Total MCP calls: [count]
```

## Important Rules

1. **Redact actual secrets** in the report. Show only enough to identify the finding
   (e.g., first 4 and last 2 characters: `AKIA****XZ`). Never output full credentials.
2. **Do not modify** any Confluence pages or Jira issues. This is a read-only audit.
3. **Log progress** as you scan:
   - Confluence: "Running Confluence CQL query 3/13... Found 2 candidates."
   - Jira: "Running Jira JQL query 5/13... Found 1 candidate."
4. **NEVER fetch all pages/issues** in a space/project. Always use CQL/JQL pre-filtering.
5. **Deduplicate** — if the same page or issue matches multiple queries, fetch it only
   ONCE and report all matched patterns together.
6. **Stop early on critical findings** — report critical findings immediately as they
   are discovered, don't wait until the full scan completes.
7. **Scan both Confluence AND Jira** for every project key. If one doesn't exist for
   a given project key, log it and continue with the other.
8. **Jira comments are high-value targets** — developers frequently paste credentials
   in issue comments during debugging. Always inspect comments, not just descriptions.

## Remediation Guidance

After presenting findings, provide actionable next steps per compliance requirements:

**For production credentials found in Confluence (Action Required):**
- **Rotate** the exposed credential immediately — assume it is compromised
- **Remove** the cleartext value from the Confluence page
- **Move** secrets to an approved vault (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, etc.)
- **Replace** the page content with a reference like "See 1Password vault: [vault-name]"
- **Restrict** page permissions if the page must reference sensitive configuration
- **Audit** access logs for the affected pages to assess exposure window

**For production credentials found in Jira (Action Required):**
- **Rotate** the exposed credential immediately
- **Edit** the issue description or comment to remove the cleartext value
- If the credential was in a **comment**, edit or delete the comment
- **Replace** with a vault reference or link to secure documentation
- **Check issue visibility** — ensure the issue is not publicly accessible
- **Review issue watchers/participants** to assess who may have seen the credential

**For non-production credentials (No immediate action, but recommended):**
- Ensure they are **clearly labeled** with environment (dev/test/staging/sandbox)
- Consider moving to a vault anyway as a best practice

**For ambiguous findings (Needs Review):**
- Page/issue owner must verify whether the credential is production or non-production
- If production or unclear, treat as production and remediate
- If confirmed non-production, add a clear label (e.g., "[DEV ONLY]")
