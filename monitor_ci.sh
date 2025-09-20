#!/bin/bash

echo "Starting continuous monitoring of CI pipelines..."
echo "================================================"

# Get the latest run IDs dynamically
RATCHET_RUN_ID=$(gh run list --repo Avarok-Cybersecurity/Citadel-Protocol --branch stability-improvements --workflow "Ratchet Stability Test" --limit 1 --json databaseId --jq '.[0].databaseId')
PIPELINE_RUN_ID=$(gh run list --repo Avarok-Cybersecurity/Citadel-Protocol --branch stability-improvements --workflow "Execute Pipeline" --limit 1 --json databaseId --jq '.[0].databaseId')

echo "Monitoring Ratchet Stability Test: $RATCHET_RUN_ID"
echo "Monitoring Execute Pipeline: $PIPELINE_RUN_ID"

while true; do
    # Get status of both runs
    ratchet_json=$(gh api /repos/Avarok-Cybersecurity/Citadel-Protocol/actions/runs/${RATCHET_RUN_ID})
    pipeline_json=$(gh api /repos/Avarok-Cybersecurity/Citadel-Protocol/actions/runs/${PIPELINE_RUN_ID})
    
    # Extract status and conclusion
    ratchet_status=$(echo "$ratchet_json" | jq -r '.status')
    ratchet_conclusion=$(echo "$ratchet_json" | jq -r '.conclusion')
    pipeline_status=$(echo "$pipeline_json" | jq -r '.status')
    pipeline_conclusion=$(echo "$pipeline_json" | jq -r '.conclusion')
    
    # Display current status
    echo ""
    echo "$(date +'%Y-%m-%d %H:%M:%S')"
    echo "----------------------------------------"
    echo "Ratchet Stability Test: status=$ratchet_status, conclusion=$ratchet_conclusion"
    echo "Execute Pipeline:       status=$pipeline_status, conclusion=$pipeline_conclusion"
    
    # Check if either pipeline failed (even before both complete)
    if [ "$ratchet_status" = "completed" ] && [ "$ratchet_conclusion" = "failure" ]; then
        echo ""
        echo "================================================"
        echo "❌ Ratchet Stability Test FAILED"
        echo ""
        echo "Getting failed job details..."
        gh api /repos/Avarok-Cybersecurity/Citadel-Protocol/actions/runs/${RATCHET_RUN_ID}/jobs --jq '.jobs[] | select(.conclusion == "failure") | {name: .name, id: .id}'
        exit 1
    fi
    
    if [ "$pipeline_status" = "completed" ] && [ "$pipeline_conclusion" = "failure" ]; then
        echo ""
        echo "================================================"
        echo "❌ Execute Pipeline FAILED"
        echo ""
        echo "Getting failed jobs..."
        gh api /repos/Avarok-Cybersecurity/Citadel-Protocol/actions/runs/${PIPELINE_RUN_ID}/jobs --jq '.jobs[] | select(.conclusion == "failure") | {name: .name, id: .id}'
        exit 1
    fi
    
    # Check if both completed successfully
    if [ "$ratchet_status" = "completed" ] && [ "$pipeline_status" = "completed" ]; then
        echo ""
        echo "================================================"
        echo "Both pipelines completed!"
        echo ""
        echo "Final Results:"
        echo "  Ratchet Stability Test: $ratchet_conclusion"
        echo "  Execute Pipeline:       $pipeline_conclusion"
        
        if [ "$ratchet_conclusion" = "success" ] && [ "$pipeline_conclusion" = "success" ]; then
            echo ""
            echo "✅ ALL PIPELINES PASSED SUCCESSFULLY! ✅"
            exit 0
        else
            echo ""
            echo "❌ One or more pipelines did not succeed"
            exit 1
        fi
    fi
    
    # Get job counts for Execute Pipeline
    if [ "$pipeline_status" = "in_progress" ]; then
        completed_jobs=$(gh api /repos/Avarok-Cybersecurity/Citadel-Protocol/actions/runs/${PIPELINE_RUN_ID}/jobs --paginate --jq '[.jobs[] | select(.status == "completed")] | length')
        total_jobs=$(gh api /repos/Avarok-Cybersecurity/Citadel-Protocol/actions/runs/${PIPELINE_RUN_ID}/jobs --paginate --jq '.jobs | length')
        echo "  Execute Pipeline Progress: $completed_jobs/$total_jobs jobs completed"
    fi
    
    # Wait before next check
    sleep 30
done