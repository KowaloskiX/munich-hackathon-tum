# Gmail threat review setup

The implementation is disabled until Gmail OAuth, Pub/Sub, encryption, and Devin are configured.
It supports one allowlisted Gmail account and a local Pub/Sub pull subscriber.

## 1. Google Cloud

Use one development project for the OAuth client, Gmail API, Pub/Sub topic, and subscription.
The Gmail watch rejects topics from a different project.

```bash
gcloud config set project PROJECT_ID
gcloud services enable gmail.googleapis.com pubsub.googleapis.com
gcloud pubsub topics create sentinel-gmail-events
gcloud pubsub topics add-iam-policy-binding sentinel-gmail-events \
  --member="serviceAccount:gmail-api-push@system.gserviceaccount.com" \
  --role="roles/pubsub.publisher"
gcloud pubsub subscriptions create sentinel-gmail-local \
  --topic=sentinel-gmail-events \
  --ack-deadline=60 \
  --message-retention-duration=604800s \
  --expiration-period=never
gcloud pubsub subscriptions add-iam-policy-binding sentinel-gmail-local \
  --member="user:YOUR_GOOGLE_ACCOUNT" \
  --role="roles/pubsub.subscriber"
gcloud auth application-default login
gcloud auth application-default set-quota-project PROJECT_ID
```

In Google Auth Platform:

1. Set audience to `External / Testing`, or `Internal` for an eligible Workspace organization.
2. Add the connected address as a test user.
3. Add restricted scope `https://www.googleapis.com/auth/gmail.modify`.
4. Create a Web Application OAuth client.
5. Add redirect URI `http://localhost:8000/v1/gmail/oauth/callback`.

External/Testing refresh tokens for Gmail scopes expire after seven days. Reconnect weekly during
the demo, or use an eligible Internal application.

## 2. Devin

Create an organization service user with `UseDevinSessions`, `ViewOrgSessions`, and
`ManageOrgSessions`. Generate a `cog_...` API key and obtain the organization ID.

Disable training in Devin Data Controls before processing Gmail data. Email sessions receive
untrusted message content and selected attachments, but never Gmail credentials, repositories,
knowledge, or session secrets.

## 3. Backend environment

Copy `backend/.env.example` to `backend/.env`, then set:

```dotenv
EMAIL_SECURITY_ENABLED=true
EMAIL_AGENT=devin
GOOGLE_CLOUD_PROJECT=PROJECT_ID
GMAIL_OAUTH_CLIENT_ID=...
GMAIL_OAUTH_CLIENT_SECRET=...
GMAIL_PUBSUB_TOPIC=projects/PROJECT_ID/topics/sentinel-gmail-events
GMAIL_PUBSUB_SUBSCRIPTION=projects/PROJECT_ID/subscriptions/sentinel-gmail-local
GMAIL_ALLOWED_EMAIL=you@example.com
EMAIL_TOKEN_ENCRYPTION_KEY=...
APP_SESSION_SECRET=...
DEVIN_API_KEY=...
DEVIN_ORG_ID=...
DEVIN_BASE_URL=https://api.devin.ai/v3
```

Generate independent secrets:

```bash
cd backend
uv run python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
uv run python -c 'import secrets; print(secrets.token_urlsafe(48))'
```

The first output is `EMAIL_TOKEN_ENCRYPTION_KEY`; the second is `APP_SESSION_SECRET`.
Never commit either value. The database lives at `backend/data/email-security.db` and is ignored.

## 4. Run and connect

```bash
cd backend && uv run uvicorn app.main:app --reload --port 8000
cd dashboard && npm run dev
```

Open `http://localhost:5173`, select **Email**, accept the processing disclosure, and connect Gmail.

- **All new Inbox mail** watches `INBOX` and excludes Spam, Sent, Drafts, and Trash.
- **Sentinel/Scan only** watches the app-created label. Apply it manually or create a Gmail filter
  that applies it. The app intentionally does not request the Gmail settings scope needed to create
  filters.
- Connecting or changing modes establishes a new history baseline; existing mail is not backfilled.

Flagged and inconclusive analyses receive `Sentinel/Pending Review`. Human decisions replace that
label with `Sentinel/Confirmed Dangerous` or `Sentinel/Not Dangerous`.

## Production gate

This setup is for a known test account. Public rollout also requires a separate production Cloud
project, verified domain/homepage/privacy/deletion pages, Google's restricted-scope verification
and security assessment, an approved processor agreement with Cognition, managed encrypted
persistence, and an authenticated Pub/Sub push endpoint.
