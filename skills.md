---
name: confluence-cred-scan
description: >
  Scan Confluence pages for cleartext credentials, secrets, API keys, passwords,
  tokens, and connection strings using the Atlassian MCP server. Trigger this skill
  whenever asked to audit Confluence for exposed secrets, find hardcoded credentials
  in wiki pages, run a credential sweep, or check for secret leaks in documentation.
  Requires the Atlassian MCP server to be connected.
disable-model-invocation: true
---

# Confluence Credential Scanner

Scan Confluence pages for cleartext credentials using the Atlassian MCP tools.

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
/confluence-cred-scan DEVOPS
/confluence-cred-scan ENG,PLATFORM,INFRA
```

For each project key provided:
1. Use the Atlassian MCP `searchConfluence` tool with CQL to find pages in the
   matching Confluence space:
   ```
   space = "<PROJECT_KEY>" order by lastModified desc
   ```
2. If the space key does not match the project key directly, use the Atlassian MCP
   `getConfluenceSpaces` tool to list all spaces, then find the space whose key
   matches or is associated with the given project key.
3. If no matching space is found, try a broader CQL search:
   ```
   label = "<PROJECT_KEY>" or ancestor = "<PROJECT_KEY>"
   ```
4. If still no match, inform the user that the project key could not be resolved
   and list available space keys for them to choose from.

If no arguments are given, prompt the user:
"Please provide a project key. Example: `/confluence-cred-scan DEVOPS`"

### Step 2: Retrieve Pages Using CQL Pre-Filter

Rather than pulling every page in the space, use CQL via `searchConfluence` to
pre-filter pages that are likely to contain credentials:

```
space = "<PROJECT_KEY>" AND (text ~ "password" OR text ~ "token" OR text ~ "secret"
OR text ~ "api_key" OR text ~ "apikey" OR text ~ "BEGIN RSA"
OR text ~ "jdbc" OR text ~ "mongodb://" OR text ~ "postgres://"
OR text ~ "Authorization" OR text ~ "aws_access_key_id"
OR text ~ "private_key" OR text ~ "client_secret")
```

This CQL pre-filter drastically reduces the number of pages to inspect and keeps
the scan fast even for spaces with hundreds of pages.

If the user explicitly requests a full scan (all pages regardless of keyword match),
fall back to using `getPagesInConfluenceSpace` and process in batches.

### Step 3: Inspect Page Content

For each page, use the Atlassian MCP `getConfluencePage` tool to retrieve the full
page body. Search the content for matches against ALL of the following patterns:

**Critical Severity:**
- Private keys: `BEGIN RSA PRIVATE KEY`, `BEGIN OPENSSH PRIVATE KEY`, `BEGIN EC PRIVATE KEY`, `BEGIN PGP PRIVATE KEY`
- AWS keys: strings matching `AKIA[0-9A-Z]{16}`
- GCP service account keys: `"type": "service_account"`
- Database connection URIs with embedded credentials: `mongodb://...@`, `postgres://...@`, `mysql://...@`, `jdbc:...:password=`

**High Severity:**
- Explicit password assignments: `password=`, `password:`, `passwd=`, `pwd=` followed by a non-placeholder value
- API key assignments: `api_key=`, `apikey=`, `api-key:`, `x-api-key:`
- Token assignments: `token=`, `access_token=`, `secret_key=`, `client_secret=`
- Bearer tokens: `Authorization: Bearer <actual_token>`
- Webhook URLs containing tokens (e.g., Slack webhook URLs)

**Medium Severity:**
- Generic mentions of `password`, `secret`, `credential` near `=` or `:` that may be documentation or placeholders
- References to `.env` file contents pasted inline
- SSH connection strings with inline passwords: `sshpass -p`
- Base64-encoded strings that decode to credential-like content

### Step 4: Filter False Positives

Exclude matches that are clearly:
- Placeholder values: `password=<YOUR_PASSWORD>`, `password=xxxxx`, `password=changeme`, `password=****`, `password=example`
- Documentation about how to set credentials (e.g., "set your password in the .env file")
- References to password managers or vaults (e.g., "retrieve from 1Password")
- Code examples from public documentation that use dummy values

When uncertain, include the match but flag it as "Needs Review".

### Step 5: Generate Report

Present findings as a structured report:

```
## Confluence Credential Scan Report
**Date:** [current date]
**Project Key(s) Scanned:** [list of project keys]
**Spaces Resolved:** [list of space keys]
**Pages Scanned:** [count]
**Findings:** [count]

### Critical Findings
| # | Project Key | Space | Page Title | Pattern | Matched Content (redacted) | Recommendation |
|---|-------------|-------|------------|---------|---------------------------|----------------|
| 1 | DEVOPS      | DO    | DB Setup   | DB URI  | postgres://admin:r***d@... | Rotate & vault |

### High Findings
| # | Project Key | Space | Page Title | Pattern | Matched Content (redacted) | Recommendation |
|---|-------------|-------|------------|---------|---------------------------|----------------|

### Medium Findings (Needs Review)
| # | Project Key | Space | Page Title | Pattern | Matched Content (redacted) | Recommendation |
|---|-------------|-------|------------|---------|---------------------------|----------------|
```

## Important Rules

1. **Redact actual secrets** in the report. Show only enough to identify the finding
   (e.g., first 4 and last 2 characters: `AKIA****XZ`). Never output full credentials.
2. **Do not modify** any Confluence pages. This is a read-only audit.
3. **Log progress** as you scan: "Scanning project DEVOPS — space DO — page 12/47..."
4. If a space has more than 100 pages, ask the user whether to proceed or apply
   keyword-based pre-filtering using Confluence search (CQL) first.
5. For large-scale scans, prefer using CQL search via the Atlassian MCP
   `searchConfluence` tool with queries like `text ~ "password"` to narrow down
   candidate pages before doing full content inspection.

## Remediation Guidance

After presenting findings, provide actionable next steps:
- **Rotate** any exposed credential immediately
- **Move** secrets to a vault (HashiCorp Vault, AWS Secrets Manager, etc.)
- **Replace** hardcoded values with references like "See 1Password vault: [vault-name]"
- **Restrict** page permissions if the page must reference sensitive config
- **Audit** access logs for the affected Confluence pages to assess exposure
