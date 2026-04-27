# Python 3.11 base image
FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# Install iptables inside the container (needed to run iptables commands)
RUN apt-get update && apt-get install -y iptables procps && rm -rf /var/lib/apt/lists/*

# Copy requirements first (so Docker caches this layer unless requirements change)
COPY requirements.txt .

# Install all Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy all detector source files into the container
COPY . .

# Run main.py when the container starts
CMD ["python3", "-u", "main.py"]
# -u flag = unbuffered output, so logs appear immediately