#requires -Modules ActiveDirectory

$VerbosePreference = "Continue"
# Ensure the script is running with elevated privileges
$IsElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $IsElevated) {
    $Executable = if ($Host.Name -eq 'Windows PowerShell ISE Host') {
        'powershell_ise.exe'
    } elseif ( ($Host.Name -eq 'ConsoleHost') -and ($Host.Version.Major -gt 6) ) {
        'pwsh.exe'
    } else {
        'powershell.exe'
    }

    throw "This script must be run in an elevated prompt. Please re-open $Executable using `"Run as Administrator`" and start this script again."
}

# Check if running as the appropriate AD Admin
if ((Get-ADForest).Domains.Count -eq 1) {
    $IsDomainAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Domain Admins")
    if (-not $IsDomainAdmin) {
        throw "This script must be run as a Domain Admin in a single-domain forest."
    }
} else {
    $IsEnterpriseAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Enterprise Admins")
    if (-not $IsEnterpriseAdmin) {
        throw "This script must be run as a Enterprise Admin in a multi-domain forest."
    }
}

# Get list of Schema Version 1 templates
$TemplateParameters = @{
    SearchBase = (Get-ADRootDSE).configurationNamingContext
    Filter = 'objectClass -eq "pKICertificateTemplate"'
    Properties = 'msPKI-Template-Schema-Version'
}
$TemplatesToUnpublish = (Get-ADObject @TemplateParameters | Where-Object 'msPKI-Template-Schema-Version' -eq 1).Name

Write-Host '[!] The following templates are using Schema V1 and should be unpublished:' -ForegroundColor Yellow
$TemplatesToUnpublish | Sort-Object 

# Get list of Issuing CAs
$CAParameters = @{
    SearchBase = (Get-ADRootDSE).configurationNamingContext
    Filter = 'objectClass -eq "pKIEnrollmentService"'
    Properties = '*'
}
$IssuingCAs = Get-ADObject @CAParameters

# Unpublish Schema Version 1 templates
Write-Output $IssuingCAs -PipelineVariable ca | ForEach-Object {
    $PublishedCerts = $ca.certificateTemplates
    foreach ($template in $TemplatesToUnpublish) {
        Write-Host "`n[?] Checking if Schema V1 template `"$template`" is published on $($ca.Name) CA." -ForegroundColor Blue
        if ($PublishedCerts -contains $template) {
            Write-Host "[!] Schema V1 template `"$template`" is published on $($ca.Name) CA. Checking for recent use." -ForegroundColor Yellow
            If (Test-WSMan -ComputerName $ca.dNSHostName -UseSSL) {
                $UseSSL = $true
            } else {
                $UseSSL = $false
            }
            Invoke-Command -ComputerName $ca.dNSHostName -UseSSL:$UseSSL -ScriptBlock {
                param (
                    $template,
                    $ca
                )
                try {
                    certutil -view Log | Select-String -Pattern $template -Context 2,0 |
                        Select-Object -Last 1 | Out-File -FilePath tmp.txt -Force
                    if (Get-Content tmp.txt) {
                        $Answer = $null
                        while ($Answer -ne 'y' -and $Answer -ne 'n') {
                            Write-Host "[!] Schema V1 Template `"$template`" has recently been used to issue a certificate on $($ca.Name) CA." -ForegroundColor Yellow
                            Write-Host "Most recent enrollment:"
                            Get-Content tmp.txt
                            Write-Host @"
If the most recently enrolled certificate is still effective, it is likely that this template
is actively in use in your forest. If so, unpublishing this template may cause operational issues. 

In this case, you should duplicate the existing template and publish it.
After publishing the V2 version, it's likely safe to unpublish this version.

Do you want to unpublish this template? [y/n] 
"@ -NoNewLine
                            $Answer = Read-Host 
                        }
                    } else {
                        $Answer = 'y'
                        Write-Host "[i] Schema V1 template `"$template`" has not been used to issue a certificate on $($ca.Name)."
                    }
                    if ($Answer -eq 'y') { 
                        try {
                            Set-ADObject -Identity $ca.DistinguishedName -Remove @{certificateTemplates=$template}
                            Write-Host "[+] Successfully unpublished the `"$template`" template from the $($ca.Name) CA." -ForegroundColor Green
                        } catch {
                            Write-Host "[x] Could not unpublish the `"$template`" template from the $($ca.Name) CA." -ForegroundColor Red
                            Write-Error $_
                        }
                    } else {
                        Write-Host "[i] Respect. Please run this script again after duplicating the V1 template and publishing the V2 template."
                    }
                } catch {
                    Write-Error $_
                }
            } -ArgumentList $template, $ca
        } else {
            Write-Host "[i] Schema V1 template `"$template`" is not published on $($ca.Name) CA."
        }
    }
}
