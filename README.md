# Anomaly Detection Engine

## Live Endpoints
- **Server IP:** `13.218.8.213`
- **Dashboard URL:** `http://13.218.8.213:8080`
- **GitHub Repo:** https://github.com/devops-timi/anomaly-detection-engine

## Language
Python 3.11 — chosen for its readable syntax, powerful standard
library (collections.deque, threading, subprocess), and rich
ecosystem (Flask, psutil, requests, waitress).

## How The Sliding Window Works
Each incoming request appends its Unix timestamp to a
collections.deque — one per IP and one globally. To calculate
the current rate, we call _evict_old() which pops all timestamps
from the left of the deque that are older than 60 seconds. Because
deques are ordered (oldest on left, newest on right), eviction is
O(1) per pop. Whatever remains divided by 60 gives requests per
second. The window slides forward automatically as time passes —
old entries fall off the left, new entries are added to the right.

## How The Baseline Works
Every second's request count is stored as a sample in a rolling
deque of 1800 entries (30 minutes x 60 seconds). Every 60 seconds
we compute mean and standard deviation from all samples. We also
maintain per-hour slots — if the current hour has enough samples
it takes priority over the full 30-minute window. Floor values
(mean >= 1.0, stddev >= 0.5) prevent false positives and division
by zero at very low traffic. A spike guard discards any second
whose count exceeds 10x the current mean — this prevents attack
traffic from corrupting the baseline.

## Setup Instructions

### 1. Provision VPS
- Ubuntu 22.04, minimum 2 vCPU, 2GB RAM
- Open ports 22, 80, 8080 in security group and UFW

### 2. Install Dependencies
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y docker.io docker-compose-plugin python3 python3-pip iptables
sudo usermod -aG docker $USER
newgrp docker
sudo ufw default allow routed
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp  
sudo ufw allow 8080/tcp
sudo ufw enable
```

### 3. Clone Repository
```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO
cd YOUR_REPO
```

### 4. Configure Slack Webhook
```bash
vim detector/config.yaml
# Set slack_webhook_url to your webhook URL
```

### 5. Launch Stack
```bash
docker-compose up -d --build
```

### 6. Verify
```bash
docker-compose ps          # all three containers Up
curl http://localhost:80   # Nextcloud responds
curl http://localhost:8080 # Dashboard responds
```

## Architecture
See docs/architecture.png

