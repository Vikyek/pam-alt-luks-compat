#!/bin/bash

# Target user name passed as first argument
USER_NAME="$1"
if [ -z "$USER_NAME" ]; then
    USER_NAME="v"
fi

ROOT_DEV="/dev/sda3"

# Check if the root device is now encrypted
if cryptsetup isLuks "$ROOT_DEV" 2>/dev/null; then
    # Get home directory
    USER_HOME=$(getent passwd "$USER_NAME" | cut -d: -f6)
    SCRIPT_PATH="$USER_HOME/encrypt-root-offline.sh"
    
    if [ -f "$SCRIPT_PATH" ]; then
        rm -f "$SCRIPT_PATH"
        
        # Report success via desktop notification (running as user so notify-send works)
        USER_UID=$(getent passwd "$USER_NAME" | cut -d: -f3)
        
        # Run notify-send in the user's D-Bus session context
        if [ -n "$USER_UID" ]; then
            # Wait a few seconds for the desktop environment / notify daemon to load
            sleep 10
            sudo -u "$USER_NAME" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$USER_UID/bus" notify-send -u critical -i security-high "Root Encryption Success" "Your root partition has been successfully encrypted in-place! The offline script has been removed from your home directory." || true
        fi
        
        echo "Root partition $ROOT_DEV is successfully encrypted. Cleaned up $SCRIPT_PATH."
    fi
    
    # Disable the systemd service so it doesn't run on future boots
    systemctl disable check-root-encryption.service || true
else
    echo "Root partition $ROOT_DEV is not encrypted yet. Waiting for offline script execution."
fi
