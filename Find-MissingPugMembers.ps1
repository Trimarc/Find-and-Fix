#Requires -Version 5 -Modules ActiveDirectory

# Enforce strict mode to catch potential scripting errors
Set-StrictMode -Version 5

# Initialize array to store Active Directory (AD) Admins and members of the Protected Users Group (PUG)
$ADAs = @()
$PugMembers = @()

# Get the Security Identifiers (SIDs) for the Enterprise Admins (EA) and Schema Admins (SA) groups
$EASid = (Get-ADDomain (Get-ADForest).RootDomain).DomainSID.Value + '-519'
$SASid = (Get-ADDomain (Get-ADForest).RootDomain).DomainSID.Value + '-518'

# Retrieve members of the EA and SA groups
$ADAs += Write-Output @($EASid, $SASid) -PipelineVariable sid | ForEach-Object {
    # Get group members recursively and filter out non-user accounts
    Get-ADGroupMember $sid -Server (Get-ADForest).RootDomain -Recursive | Where-Object ObjectClass -eq 'user'
}

# Retrieve members of built-in Administrators (BA) and Domain Admins (DA) in all domains
Write-Output (Get-ADForest).Domains -PipelineVariable domain | ForEach-Object {
    # Get the SID for the DA group
    $DASid = (Get-ADDomain $domain).DomainSID.Value + '-512'
    # Retrieve members of the BA and DA groups who have
    $ADAs += Write-Output @($DASid, 'S-1-5-32-544') -PipelineVariable sid | ForEach-Object {
        # Get group members recursively and filter out non-user accounts
        Get-ADGroupMember $sid -Server $domain -Recursive | Where-Object ObjectClass -eq 'user'
    }
}

# Retrieve members of the PUG in all domains in the forest
Write-Output (Get-ADForest).Domains -PipelineVariable domain | ForEach-Object {
    # Get the SID for the DA group
    $PugSid = (Get-ADDomain $domain).DomainSID.Value + '-525'
    # Retrieve members of the BA and DA groups who have
    $PugMembers += Write-Output $PugSid -PipelineVariable sid| ForEach-Object {
        # Get group members recursively and filter out non-user accounts
        Get-ADGroupMember $sid -Server $domain -Recursive | Where-Object ObjectClass -eq 'user'
    }
}

# Remove duplicates from collected arrays
$ADAs = $ADAs | Sort-Object -Unique
$PugMembers = $PugMembers | Sort-Object -Unique

# List users that should be in the PUG but aren't
Write-Host "The following users are AD Admins that should be added to the Protected Users Group:" -ForegroundColor DarkYellow
$ADAs | ForEach-Object {
    if ($PugMembers.distinguishedName -notcontains $_.distinguishedName ) { 
        $_
    }
}