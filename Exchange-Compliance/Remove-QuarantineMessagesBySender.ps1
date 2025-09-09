<#
.SYNOPSIS
  Connects to Exchange Online and Security & Compliance Center (IPPSSession), 
  then deletes all quarantine messages from a specified sender.

.DESCRIPTION
  This script ensures active sessions to Exchange Online and Security & Compliance (IPPSSession). 
  It prompts for a sender email address, retrieves all quarantined messages from that sender, 
  and deletes them in bulk without confirmation.  
  The script loops until no more quarantined messages remain for the given sender.

.EXAMPLE
  .\Remove-QuarantineMessagesBySender.ps1

.NOTES
  Requirements:
    - ExchangeOnlineManagement module
    - Permissions to access and delete quarantined messages
    - Deletion is permanent, use with caution
#>

# --- Function: Ensure connection to Exchange Online
function Check-ExchangeOnlineSession {
    try {
        Get-ExchangeOnlineConnection | Out-Null
        Write-Output "You are already connected to Exchange Online."
    }
    catch {
        Write-Output "You are not connected to Exchange Online. Connecting now..."
        Connect-ExchangeOnline   # <-- interactive login required
    }
}

# --- Function: Ensure connection to Security & Compliance (IPPSSession)
function Check-IPPSSession {
    try {
        $session = Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" }
        if (-not $session) {
            Write-Output "You are not connected to Security & Compliance (IPPSSession). Connecting now..."
            Connect-IPPSSession   # <-- interactive login required
        }
        else {
            Write-Output "You are already connected to Security & Compliance (IPPSSession)."
        }
    }
    catch {
        Write-Output "Error checking IPPSSession connection: $_"
        Connect-IPPSSession
    }
}

# --- Ensure connections
Check-ExchangeOnlineSession
Check-IPPSSession

# --- Prompt for sender email
$emailAddress = Read-Host -Prompt "Enter the sender's email address to delete messages from"

# --- Loop until no messages remain
while ($true) {
    $ids = Get-QuarantineMessage -IncludeMessagesFromBlockedSenderAddress -SenderAddress $emailAddress |
           Select-Object -ExpandProperty Identity

    if (-not $ids -or $ids.Count -eq 0) {
        Write-Output "No more messages found from $emailAddress."
        break
    }

    foreach ($id in $ids) {
        try {
            Delete-QuarantineMessage -Identity $id -Confirm:$false
            Write-Output "Deleted message with ID: $id"
        }
        catch {
            Write-Error "Failed to delete message with ID: $id. Error: $_"
        }
    }

    # Optional: Prevent rapid looping
    Start-Sleep -Seconds 2
}

Write-Output "Script completed."
