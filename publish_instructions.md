Step 1: Set env var for cargo registry token
Step 2: Make sure you are on master branch, and all changes synced, including the new version you want to publish
Step 3: Run this, which will handle dependency order: cargo workspaces exec --ignore citadel-examples cargo publish --no-verify
