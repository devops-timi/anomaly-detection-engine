from flask import Flask, jsonify, render_template_inline
import psutil
import time
import threading

# We'll pass shared state into the dashboard via a shared object
app = Flask(__name__)

# Global reference to the shared state — set by main.py before starting Flask
_state = None


def set_state(state):
    """Called by main.py to inject the shared state object."""
    global _state
    _state = state


def start_dashboard(host, port):
    """Start Flask in a background thread (non-blocking)."""
    def run():
        # use_reloader=False is important — Flask's reloader conflicts with threading
        app.run(host=host, port=port, debug=False, use_reloader=False)
    
    t = threading.Thread(target=run, daemon=True)
    t.start()
    print(f"[Dashboard] Running at http://{host}:{port}")


@app.route("/")
def index():
    """Serve the main dashboard HTML page."""
    return DASHBOARD_HTML


@app.route("/api/metrics")
def metrics():
    """
    JSON endpoint that the dashboard polls every 3 seconds.
    Returns all the data the dashboard needs.
    """
    if _state is None:
        return jsonify({"error": "Not ready"}), 503

    # CPU and memory from psutil
    cpu_percent = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    mem_percent = mem.percent

    # Uptime
    uptime_seconds = int(time.time() - _state.start_time)
    uptime_str = f"{uptime_seconds // 3600}h {(uptime_seconds % 3600) // 60}m {uptime_seconds % 60}s"

    # Baseline
    baseline = _state.baseline_engine.get_baseline()

    # Top 10 IPs
    top_ips = _state.detector.get_top_ips(10)
    top_ips_list = [{"ip": ip, "rate": round(rate, 3)} for ip, rate in top_ips]

    # Banned IPs
    bans = _state.blocker.get_active_bans()
    banned_list = []
    for ip, info in bans.items():
        remaining = "permanent"
        if info["duration"] != -1:
            elapsed = time.time() - info["banned_at"]
            remaining = max(0, int(info["duration"] - elapsed))
            remaining = f"{remaining}s"
        banned_list.append({
            "ip": ip,
            "offense": info["offense"],
            "duration": info["duration"],
            "remaining": remaining
        })

    return jsonify({
        "global_rate": round(_state.detector.get_global_rate(), 3),
        "top_ips": top_ips_list,
        "banned_ips": banned_list,
        "cpu_percent": cpu_percent,
        "mem_percent": mem_percent,
        "uptime": uptime_str,
        "baseline_mean": round(baseline["mean"], 4),
        "baseline_stddev": round(baseline["stddev"], 4),
        "total_requests": _state.total_requests,
        "total_bans": _state.total_bans,
    })


# The dashboard HTML — a self-contained single-page app
# It polls /api/metrics every 3 seconds and updates the display
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HNG Cloud.ng — Anomaly Detector Dashboard</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #0f172a; color: #e2e8f0; font-family: 'Courier New', monospace; padding: 20px; }
        h1 { color: #38bdf8; font-size: 1.4em; margin-bottom: 20px; border-bottom: 1px solid #1e3a5f; padding-bottom: 10px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 15px; }
        .card h3 { color: #94a3b8; font-size: 0.75em; text-transform: uppercase; margin-bottom: 8px; }
        .card .value { font-size: 1.8em; color: #38bdf8; font-weight: bold; }
        .card .unit { font-size: 0.75em; color: #64748b; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #1e293b; color: #94a3b8; padding: 8px; text-align: left; font-size: 0.75em; }
        td { padding: 8px; border-bottom: 1px solid #1e293b; font-size: 0.85em; }
        .banned-row { background: #450a0a; }
        .status-ok { color: #4ade80; }
        .status-alert { color: #f87171; }
        #last-updated { color: #475569; font-size: 0.75em; margin-top: 15px; }
        .section { background: #1e293b; border-radius: 8px; padding: 15px; margin-bottom: 15px; }
        .section h2 { color: #38bdf8; font-size: 0.9em; margin-bottom: 12px; }
    </style>
</head>
<body>
    <h1>🛡️ HNG Cloud.ng — Anomaly Detection Dashboard</h1>

    <div class="grid">
        <div class="card">
            <h3>Global Rate</h3>
            <div class="value" id="global-rate">—</div>
            <div class="unit">req/s</div>
        </div>
        <div class="card">
            <h3>Baseline Mean</h3>
            <div class="value" id="baseline-mean">—</div>
            <div class="unit">req/s</div>
        </div>
        <div class="card">
            <h3>Baseline Stddev</h3>
            <div class="value" id="baseline-stddev">—</div>
        </div>
        <div class="card">
            <h3>CPU Usage</h3>
            <div class="value" id="cpu">—</div>
            <div class="unit">%</div>
        </div>
        <div class="card">
            <h3>Memory Usage</h3>
            <div class="value" id="mem">—</div>
            <div class="unit">%</div>
        </div>
        <div class="card">
            <h3>Uptime</h3>
            <div class="value" style="font-size:1em;" id="uptime">—</div>
        </div>
        <div class="card">
            <h3>Total Requests</h3>
            <div class="value" id="total-req">—</div>
        </div>
        <div class="card">
            <h3>Total Bans</h3>
            <div class="value" id="total-bans">—</div>
        </div>
    </div>

    <div class="section">
        <h2>🚫 Banned IPs</h2>
        <table id="banned-table">
            <thead><tr><th>IP</th><th>Offense #</th><th>Ban Duration</th><th>Remaining</th></tr></thead>
            <tbody id="banned-body"><tr><td colspan="4" style="color:#475569;">No active bans</td></tr></tbody>
        </table>
    </div>

    <div class="section">
        <h2>📊 Top 10 Source IPs (by req/s)</h2>
        <table id="top-ips-table">
            <thead><tr><th>IP</th><th>Rate (req/s)</th></tr></thead>
            <tbody id="top-ips-body"><tr><td colspan="2" style="color:#475569;">Loading...</td></tr></tbody>
        </table>
    </div>

    <div id="last-updated">Last updated: —</div>

    <script>
        // Poll the /api/metrics endpoint every 3 seconds
        async function refresh() {
            try {
                const res = await fetch('/api/metrics');
                const d = await res.json();

                // Update stat cards
                document.getElementById('global-rate').textContent = d.global_rate;
                document.getElementById('baseline-mean').textContent = d.baseline_mean;
                document.getElementById('baseline-stddev').textContent = d.baseline_stddev;
                document.getElementById('cpu').textContent = d.cpu_percent;
                document.getElementById('mem').textContent = d.mem_percent;
                document.getElementById('uptime').textContent = d.uptime;
                document.getElementById('total-req').textContent = d.total_requests;
                document.getElementById('total-bans').textContent = d.total_bans;

                // Update banned IPs table
                const bannedBody = document.getElementById('banned-body');
                if (d.banned_ips.length === 0) {
                    bannedBody.innerHTML = '<tr><td colspan="4" style="color:#475569;">No active bans</td></tr>';
                } else {
                    bannedBody.innerHTML = d.banned_ips.map(b =>
                        `<tr class="banned-row">
                            <td>${b.ip}</td>
                            <td>${b.offense}</td>
                            <td>${b.duration === -1 ? 'PERMANENT' : b.duration + 's'}</td>
                            <td>${b.remaining}</td>
                        </tr>`
                    ).join('');
                }

                // Update top IPs table
                const topBody = document.getElementById('top-ips-body');
                if (d.top_ips.length === 0) {
                    topBody.innerHTML = '<tr><td colspan="2" style="color:#475569;">No traffic yet</td></tr>';
                } else {
                    topBody.innerHTML = d.top_ips.map((item, i) =>
                        `<tr><td>${item.ip}</td><td>${item.rate}</td></tr>`
                    ).join('');
                }

                document.getElementById('last-updated').textContent =
                    'Last updated: ' + new Date().toLocaleTimeString();

            } catch (e) {
                console.error('Metrics fetch failed:', e);
            }
        }

        // Run immediately, then every 3 seconds
        refresh();
        setInterval(refresh, 3000);
    </script>
</body>
</html>
"""