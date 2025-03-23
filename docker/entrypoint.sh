#!/bin/sh

# Wait for ACA-PY agent 1 on port 3001
echo "Waiting for aca-py-1 on port 3001..."
while ! nc -z localhost 3001; do
  sleep 1
done

# Wait for ACA-PY agent 2 on port 4001
echo "Waiting for aca-py-2 on port 4001..."
while ! nc -z localhost 4001; do
  sleep 1
done

# Wait for Hardhat node on port 8545
echo "Waiting for hardhat-node on port 8545..."
while ! nc -z localhost 8545; do
  sleep 1
done

echo "All services are up, starting test_flow.py"
python test_flow.py
