#!/bin/sh
# Expect script for handling Certbot interactive prompts
# Usage: expect-certbot.sh <certbot-command-with-args>

# Install expect if not available
if ! command -v expect > /dev/null 2>&1; then
    echo "Installing expect..."
    apk add --no-cache expect tcl > /dev/null 2>&1 || apt-get update && apt-get install -y expect tcl > /dev/null 2>&1 || yum install -y expect tcl > /dev/null 2>&1
fi

# Check if expect is properly installed
if ! command -v expect > /dev/null 2>&1; then
    echo "Error: expect could not be installed"
    exit 1
fi

# Create temporary expect script
TMP_SCRIPT="/tmp/certbot_expect_$.exp"
cat > "$TMP_SCRIPT" << 'EXPECT_EOF'
#!/usr/bin/expect -f
set timeout 900
set force_conservative 0

# Enable logging for debugging
log_user 1
exp_internal 0

# Spawn the command
eval spawn $argv

# Main expect loop
expect {
    -re "Please deploy a DNS TXT record.*?_acme-challenge\.([^\s]+).*?TXT value:\s*([^\s]+)" {
        set domain $expect_out(1,string)
        set txt_value $expect_out(2,string)
        puts "\n=== DNS TXT RECORD REQUIRED ==="
        puts "Domain: _acme-challenge.$domain"
        puts "TXT Value: $txt_value"
        puts "================================\n"
        
        # Wait for user confirmation
        expect {
            -re "Press Enter to Continue" {
                puts "Waiting for DNS propagation..."
                send "\r"
                exp_continue
            }
            timeout {
                puts "Timeout waiting for continuation prompt, retrying..."
                send "\r"
                exp_continue
            }
        }
    }
    -re "Press Enter to Continue" {
        send "\r"
        exp_continue
    }
    -re "Congratulations.*certificate.*successfully" {
        puts $expect_out(0,string)
        exp_continue
    }
    -re "Successfully received certificate" {
        puts $expect_out(0,string)
        exp_continue
    }
    -re "Certificate not yet due for renewal" {
        puts $expect_out(0,string)
        exp_continue
    }
    eof {
        # Command finished
        catch wait result
        exit [lindex $result 3]
    }
    timeout {
        puts "Command timed out after 900 seconds"
        exit 1
    }
}
EXPECT_EOF

# Make script executable and run it
chmod +x "$TMP_SCRIPT"
expect "$TMP_SCRIPT" "$@"
EXIT_CODE=$?

# Cleanup
rm -f "$TMP_SCRIPT"
exit $EXIT_CODE

