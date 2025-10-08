#!/bin/bash

# Define the number of runs
TOTAL_RUNS=10  
COUNTER=0
LOG_FILE="run_log.txt"

# Create or clear the log file
echo "=== Script Execution Log ===" > "$LOG_FILE"
echo "Script started on $(date)" >> "$LOG_FILE"
echo "Total runs: $TOTAL_RUNS" >> "$LOG_FILE"
echo "============================" >> "$LOG_FILE"

while [ $COUNTER -lt $TOTAL_RUNS ]; do
    START_TIME=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$START_TIME] Run $((COUNTER + 1)) started..." | tee -a "$LOG_FILE"

    # Run the script in the background and capture process ID
    pnpm dlx tsx <measurement_script_here>
    sleep 10

  
    # Wait for the script to complete
    wait 7200

    END_TIME=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$END_TIME] Run $((COUNTER + 1)) completed." | tee -a "$LOG_FILE"

    # Increment the counter
    ((COUNTER++))

    # If not the last run, wait for 15 minutes before the next execution
    if [ $COUNTER -lt $TOTAL_RUNS ]; then
        echo "Waiting for 15 minutes before the next run..." | tee -a "$LOG_FILE"
        sleep 900  # 900 seconds = 15 minutes
    fi
done

echo "All $TOTAL_RUNS runs completed. Script finished on $(date)" | tee -a "$LOG_FILE"
