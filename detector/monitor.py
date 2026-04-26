import time
import json
import os

def tail_log(log_path):
    """
    Generator function that continuously reads new lines from a log file.
    Like 'tail -f' in bash — it waits for new lines and yields them one by one.
    
    We use a generator (yield) so the caller gets one line at a time
    without loading the whole file into memory.
    """
    
    # Wait until the log file actually exists (nginx might not have written yet)
    while not os.path.exists(log_path):
        print(f"[Monitor] Waiting for log file: {log_path}")
        time.sleep(2)   # check every 2 seconds

    print(f"[Monitor] Log file found. Starting to tail: {log_path}")

    with open(log_path, "r") as f:
        # Jump to the END of the file — we don't want to process old logs on startup
        # This is important: we only care about NEW traffic coming in
        f.seek(0, 2)   # 0 bytes from the end (position 2 = SEEK_END)

        while True:
            line = f.readline()   # try to read the next line

            if line:
                line = line.strip()   # remove trailing newline/spaces
                if line:              # skip empty lines
                    parsed = parse_line(line)   # try to parse as JSON
                    if parsed:
                        yield parsed  # send the parsed log entry to the caller
            else:
                # No new line yet — sleep briefly and try again
                # This is the "tail" behaviour: poll for new content
                time.sleep(0.05)   # 50ms polling interval — fast enough, not too heavy


def parse_line(line):
    """
    Parse a single JSON log line from nginx into a Python dictionary.
    Returns None if the line is not valid JSON (so caller can skip it).
    """
    try:
        data = json.loads(line)   # parse the JSON string into a dict
        
        # Validate that all required fields are present
        required = ["source_ip", "timestamp", "method", "path", "status", "response_size"]
        for field in required:
            if field not in data:
                return None   # incomplete line, skip it
        
        # Convert status to int (it might come as string)
        data["status"] = int(data["status"])
        data["response_size"] = int(data["response_size"])
        
        return data
        
    except (json.JSONDecodeError, ValueError):
        # Not valid JSON — nginx might be mid-write, just skip this line
        return None