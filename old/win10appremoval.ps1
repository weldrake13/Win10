$ErrorAction = SilentlyContinue
$csvapps = Import-Csv C:\scripts-tools\w10opt\Win10Apps.csv
foreach ($app in $csvapps)
{
$uninstall = $app.AppName
Get-AppxPackage -allusers *$uninnstall* | Remove-AppxPackage -ErrorAction SilentlyContinue |Out-Null
}
