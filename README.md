# Docker Email Verification App

A learning/demo project with React, Express, PostgreSQL, Redis, Docker Compose, and Mailpit.

## Prerequisites
- Docker Desktop installed and running
- Ports 3000, 5000, 5432, 6379, and 8025 available

## Start
From this directory run:

```bash
docker compose up --build
```

Open:
- Frontend: http://localhost:3000
- API health check: http://localhost:5000/api/health

## Mailpit

Mailpit is included as a local development SMTP server and email inbox. It captures verification emails sent by the backend, so you can test the complete registration flow without sending messages to a real email address.

- Inbox: http://localhost:8025
- SMTP host: `localhost` when running the backend locally, or `mailpit` from Docker Compose
- SMTP port: `1025`
- No captured email is delivered externally.

To test email verification, register with any email address, open the Mailpit inbox, open the verification message, and click its verification link. Then log in to the application.

## Stop
```bash
docker compose down
```

To also remove database and Redis volumes (this deletes saved data):
```bash
docker compose down -v
```

## Workflow
1. Registration validates input and checks PostgreSQL for an existing verified account.
2. Password is hashed with bcrypt before being stored in Redis.
3. Pending registration and a random, single-use verification token are stored in Redis with a 15-minute TTL.
4. The backend sends a verification email through Mailpit's SMTP service.
5. The verification endpoint checks the token in Redis and inserts the user into PostgreSQL.
6. The token and pending Redis keys are deleted after successful verification.
7. Login compares the submitted password with the stored hash and only issues a JWT for a verified database user.

## Important production notes
- Replace all demo passwords and secrets; use environment variables or a secrets manager.
- Use HTTPS and secure, HttpOnly cookies (or carefully protect bearer tokens) in production.
- Configure a real SMTP provider and verify sender/domain settings.
- Add CSRF protections if using cookies, stronger rate limits, request logging, monitoring, and account recovery.
- Consider transactional/idempotent verification handling for concurrent requests and reliable cleanup if the database insert succeeds but Redis deletion fails.
- The SQL schema uses `email_verified` so the login rule is explicit. Only the verification endpoint creates users in this demo.
- Do not expose PostgreSQL or Redis ports publicly in production.
