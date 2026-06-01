# autoreport

Automatically reports IPs caught by [HellPot](https://github.com/yunginnanet/HellPot) to [AbuseIPDB](https://www.abuseipdb.com/).

HellPot is an HTTP honeypot that traps bots crawling for vulnerable endpoints. This project runs alongside it and forwards the offending IPs to AbuseIPDB, with a configurable cooldown to stay within API rate limits.

## How it works

1. HellPot listens on port 80 and accepts all incoming HTTP requests (`catchall = true`).
2. It writes connection events to a JSON log file on a shared Docker volume.
3. `reporter.py` tails that log, extracts the source IP from each entry, and posts a report to the AbuseIPDB v2 API.
4. Duplicate reports for the same IP are suppressed for `COOLDOWN_MINUTES` (default: 15 minutes).

## Requirements

- Docker and Docker Compose
- An [AbuseIPDB API key](https://www.abuseipdb.com/account/api)

## Setup

1. Clone the repository.

2. Copy `.env` and fill in your API key:
   ```
   ABUSEIPDB_KEY=your_key_here
   ```

3. Start the stack:
   ```sh
   docker compose up -d
   ```

That's it. HellPot starts serving on port 80 and the reporter begins tailing its log automatically.

## Configuration

All options are set via environment variables in `docker-compose.yml` (or `.env`).

| Variable               | Default              | Description                                              |
|------------------------|----------------------|----------------------------------------------------------|
| `ABUSEIPDB_KEY`        | *(required)*         | Your AbuseIPDB API key                                   |
| `HELLPOT_LOG`          | `/logs/HellPot.log`  | Path to HellPot's JSON log file inside the container     |
| `COOLDOWN_MINUTES`     | `15`                 | Minimum minutes between reports for the same IP          |
| `ABUSEIPDB_CATEGORIES` | `14,21`              | AbuseIPDB category IDs (14 = port scan, 21 = web attack) |
| `DRY_RUN`              | `false`              | Set to `true` to log without sending any reports         |

## Project structure

```
.
├── docker-compose.yml      # HellPot + reporter services
├── hellpot-config.toml     # HellPot configuration
├── reporter.py             # Log tailer and AbuseIPDB reporter
└── .env                    # API key (git-ignored)
```

## Notes

- Private IP ranges (`10.x`, `192.168.x`, `127.x`, `172.x`) are never reported.
- If the log file is rotated or deleted, the reporter detects it and waits for the file to reappear.
- HTTP 429 responses from AbuseIPDB trigger a 60-second back-off before retrying.
