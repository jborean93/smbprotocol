[CmdletBinding()]
param (
    [Parameter(Mandatory, HelpMessage = "Name of the share to create")]
    [String]
    $Name
)

$ErrorActionPreference = "Stop"

Write-Verbose -Message "Creating share directories"
New-Item -Path C:\share -ItemType Directory
New-Item -Path C:\share-encrypted -ItemType Directory
New-Item -Path C:\DFSRoots\dfs -ItemType Directory

Write-Verbose -Message "Configuring SMB shares"
New-SmbShare -Name $Name -Path C:\share -EncryptData $false -FullAccess Everyone
New-SmbShare -Name "$Name-encrypted" -Path C:\share-encrypted -EncryptData $true -FullAccess Everyone
New-SmbShare -Name dfs -Path C:\DFSRoots\dfs -FullAccess Everyone
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force

Write-Verbose -Message "Installing DFS feature"
Install-WindowsFeature -Name FS-DFS-Namespace

Write-Verbose -Message "Creating DFS root"
$dfsPath = "\\$env:COMPUTERNAME\dfs"
$dfsParams = @{
    Path              = $dfsPath
    TargetPath        = $dfsPath
    Type              = 'Standalone'
    EnableSiteCosting = $true
    State             = 'Online'
    TargetState       = 'Online'
}
New-DfsnRoot @dfsParams

Write-Verbose -Message "Creating DFS endpoints"
New-DfsnFolder -Path "$dfsPath\$Name" -TargetPath "\\$env:COMPUTERNAME\$Name"
New-DfsnFolder -Path "$dfsPath\$Name-encrypted" -TargetPath "\\$env:COMPUTERNAME\missing"
New-DfsnFolderTarget -Path "$dfsPath\$Name-encrypted" -TargetPath "\\$env:COMPUTERNAME\$Name-encrypted"
New-DfsnFolder -Path "$dfsPath\broken" -TargetPath "\\$env:COMPUTERNAME\missing"

Write-Verbose -Message "Enabling SMB Firewall rule"
Set-NetFirewallRule -Name FPS-SMB-In-TCP -Enabled True

Write-Verbose -Message "Starting SMB service"
Set-Service -Name LanmanServer -StartupType Automatic -Status Running
