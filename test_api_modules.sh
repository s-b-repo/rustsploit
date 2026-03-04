#!/bin/bash
set -m

API_KEY="test_key_12345"
BIND_ADDR="127.0.0.1:8081"
API_URL="http://$BIND_ADDR/api"

echo "Starting API server..."
cargo run -- --api --api-key "$API_KEY" --interface "$BIND_ADDR" > api_log.txt 2>&1 &
SERVER_PID=$!

echo "Waiting for API server to be ready..."
for i in {1..120}; do
    if curl -s "http://$BIND_ADDR/health" > /dev/null; then
        echo "API is ready!"
        break
    fi
    sleep 1
done

# Function to run module
run_module() {
    local module=$1
    local target=$2
    echo "----------------------------------------"
    echo "Running module: $module on $target"
    
    response=$(curl -s -X POST "$API_URL/run" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"module\": \"$module\", \"target\": \"$target\"}")
    
    echo "Response: $response"
    
    job_id=$(echo $response | grep -o '"job_id":"[^"]*' | cut -d'"' -f4)
    
    if [ ! -z "$job_id" ]; then
        echo "Job ID: $job_id"
        echo "Waiting for job completion..."
        sleep 2
        curl -s -X GET "$API_URL/output/$job_id" \
             -H "Authorization: Bearer $API_KEY" | grep -o '"status":"[^"]*"'
        echo ""
    else
        echo "Failed to get Job ID"
    fi
}

echo "Testing 3 Random Modules..."

# 1. Scanner
run_module "scanners/port_scanner" "127.0.0.1"

# 2. Exploit
run_module "exploits/sample_exploit" "192.168.1.1"

# 3. Creds
run_module "creds/generic/sample_cred_check" "10.0.0.1"


echo "----------------------------------------"
echo "Cleaning up..."
kill $SERVER_PID
echo "Done."
cat api_log.txt
