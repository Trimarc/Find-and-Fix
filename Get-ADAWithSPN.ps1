#Requires -Version 5 -Modules ActiveDirectory

# Enforce strict mode to catch potential scripting errors
Set-StrictMode -Version 5

# Initialize an array to store Active Directory (AD) Admins with Service Principal Names (SPN)
$ADAWithSPN = @()

# Get the Security Identifiers (SIDs) for the Enterprise Admins (EA) and Schema Admins (SA) groups
$EASid = (Get-ADDomain (Get-ADForest).RootDomain).DomainSID.Value + '-519'
$SASid = (Get-ADDomain (Get-ADForest).RootDomain).DomainSID.Value + '-518'

# Retrieve members of the EA and SA groups who have SPNs
$ADAWithSPN += @($EASid, $SASid) | ForEach-Object {
    $sid = $_
    # Get group members recursively and filter out those without SPNs
    Get-ADGroupMember $sid -Server (Get-ADForest).RootDomain -Recursive | ForEach-Object {
        $dn = $_
        # Get AD objects with the specified distinguished name and check for SPNs
        Get-ADObject $dn -Properties ServicePrincipalName | Where-Object ServicePrincipalName
    } # | Where-Object ObjectClass -eq 'user' # Ensure only user objects are included
}

# Retrieve members of built-in Administrators (BA) and Domain Admins (DA) groups who have SPNs
(Get-ADForest).Domains | ForEach-Object {
    $domain = $_
    # Get the SID for the DA group
    $DASid = (Get-ADDomain $domain).DomainSID.Value + '-512'
    # Retrieve members of the BA and DA groups who have
    $ADAWithSPN += @($DASid, 'S-1-5-32-544') | ForEach-Object {
        $sid = $_
        # Get group members recursively and filter out those without SPNs
        Get-ADGroupMember $sid -Server $domain -Recursive | ForEach-Object {
            $dn = $_
            # Get AD objects with the specified distinguished name and check for SPNs
            Get-ADObject $dn -Properties ServicePrincipalName | Where-Object ServicePrincipalName
        } # | Where-Object ObjectClass -eq 'user' # Ensure only user objects are included
    }
}

# Remove duplicates from ADAWithSPN
$ADAWithSPN = $ADAWithSPN | Sort-Object -Unique

# Add snippets that show how to remove the SPNs and display the results
$ADAWithSPN | ForEach-Object {
    $ada = $_
    $ada | Select-Object -ExpandProperty ServicePrincipalName | ForEach-Object {
        $spn = $_
        $ada | Add-Member -NotePropertyName "Remove SPN '$spn'" -NotePropertyValue "setspn -D $spn $($ada.Name)" -Force
    }
    $ada | Select-Object Name, DistinguishedName, ServicePrincipalName, 'Remove *' | Format-List
}