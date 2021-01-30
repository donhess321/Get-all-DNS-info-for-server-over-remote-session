# Get-all-DNS-info-for-server-over-remote-session

I needed something to get all the DNS settings for all the Domain Controllers.  This script will:

    Get the user credentials for the PS sessions
    Get all the Domain Controllers
    Initiate a PS remote session to each of the DCs
    Get each interface's DNS settings
    Get the general forwarders from the DNS server
    Return an object with all of the information to the local session
    Export to all of the server's information to a CSV file 

This should be run from a machine that has the AD tools installed.
 
This is a reposting from my Microsoft Technet Gallery.
