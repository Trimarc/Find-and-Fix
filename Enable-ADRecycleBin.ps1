if (Get-ADOptionalFeature -filter { Name -eq 'Recycle Bin Feature' } | Select-Object -ExpandProperty EnabledScopes) {
    'The Active Directory Recycle Bin is Enabled.'
} else {
    $answer = Read-Host 'The Active Directory Recycle Bin is NOT Enabled. Do you want to enable it? [Y/N]'
    if ($answer -eq 'y') {
        Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADForest)
    } else {
        'Have a nice day!'
    }
}
