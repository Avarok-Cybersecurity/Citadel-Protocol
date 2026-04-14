#!/bin/bash
set -e

PR_NUMBER=236
LOG_DIR="./tmp/ci-logs"
POLL_INTERVAL=30

mkdir -p "$LOG_DIR"

echo "Monitoring PR #$PR_NUMBER for failures..."
echo "Logs will be saved to: $LOG_DIR"
echo ""

while true; do
    echo "=== Checking PR status at $(date) ==="
    
    # Get all check runs for the PR
    checks=$(gh pr view "$PR_NUMBER" --json statusCheckRollup --jq '.statusCheckRollup[] | select(.__typename == "CheckRun") | {name, status, conclusion, workflowName, detailsUrl}')
    
    # Check for any failures (ignore CodeQL, docker tests, and Ratchet Stability)
    failed_checks=$(echo "$checks" | jq -s '.[] | select(.conclusion == "FAILURE") | select(.name != "CodeQL") | select(.name | contains("docker") | not) | select(.name | contains("Ratchet Stability") | not)')
    
    if [ -n "$failed_checks" ]; then
        echo ""
        echo "❌ FAILURE DETECTED!"
        echo "$failed_checks" | jq -r '"Failed check: \(.name) (workflow: \(.workflowName))\nURL: \(.detailsUrl)"'
        echo ""
        
        # Extract run IDs from failed checks
        failed_runs=$(echo "$failed_checks" | jq -r '.detailsUrl' | grep -o '/runs/[0-9]*' | cut -d'/' -f3 | sort -u)
        
        for run_id in $failed_runs; do
            echo "Downloading logs for run $run_id..."
            log_file="$LOG_DIR/run-${run_id}.zip"
            gh run download "$run_id" --dir "$LOG_DIR/run-${run_id}" 2>/dev/null || {
                echo "Failed to download logs for run $run_id (may not have artifacts)"
            }
            
            # Also get the run view
            gh run view "$run_id" > "$LOG_DIR/run-${run_id}-view.txt" 2>&1 || true
        done
        
        echo ""
        echo "Logs saved to: $LOG_DIR"
        echo ""
        echo "Failed checks summary:"
        echo "$failed_checks" | jq -r '.name'
        
        exit 1
    fi
    
    # Check if all checks are completed
    in_progress=$(echo "$checks" | jq -s '.[] | select(.status == "IN_PROGRESS" or .status == "QUEUED")')
    
    if [ -z "$in_progress" ]; then
        echo ""
        echo "✅ All checks completed successfully!"
        exit 0
    fi
    
    # Show progress
    total=$(echo "$checks" | jq -s 'length')
    completed=$(echo "$checks" | jq -s '.[] | select(.status == "COMPLETED") | select(.conclusion == "SUCCESS")' | jq -s 'length')
    echo "Progress: $completed/$total checks completed successfully"
    
    sleep "$POLL_INTERVAL"
done