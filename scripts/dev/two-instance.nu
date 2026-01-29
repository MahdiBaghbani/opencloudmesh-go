#!/usr/bin/env nu

# Two-instance development runner for opencloudmesh-go
# Starts sender (port 9200) and receiver (port 9201) for local federation testing

def main [] {
    print "Building opencloudmesh-go..."
    
    let repo_root = ($env.FILE_PWD | path dirname | path dirname)
    cd $repo_root
    
    # Build the binary
    go build -o bin/opencloudmesh-go ./cmd/opencloudmesh-go
    
    print "Starting two instances for local federation testing..."
    print "  Sender:   http://localhost:9200"
    print "  Receiver: http://localhost:9201"
    print ""
    print "Press Ctrl+C to stop both instances."
    print ""
    
    # Start sender in background
    let sender = (
        ^./bin/opencloudmesh-go 
            --listen ":9200"
            --public-origin "http://localhost:9200"
            --external-base-path ""
        | complete
    )
    
    # Note: This script is a placeholder. In practice, you'd use job control
    # or a process supervisor to run both instances concurrently.
    # For now, use the shell script fallback for actual two-instance testing.
    
    print "See scripts/dev/two-instance.sh for a working two-instance runner."
}
