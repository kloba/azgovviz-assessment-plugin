<#
.SYNOPSIS
    Prepares prerequisites and runs Azure Governance Visualizer (AzGovViz) for one tenant.

.DESCRIPTION
    Part of the azgovviz-assessment Copilot CLI plugin. Steps:
      1. Validates PowerShell 7 and the Az.Accounts module (installs to CurrentUser if missing).
      2. Ensures an Az PowerShell context for the requested tenant with a silently refreshable token.
         With -Login an interactive (or -DeviceCode) sign-in is started; otherwise exits with code 10.
      3. Downloads/updates Azure/Azure-Governance-Visualizer into a cache folder (git or zip).
      4. Ensures the AzAPICall module version required by that AzGovViz release.
      5. Runs AzGovVizParallel.ps1 read-only against the tenant root (or a given management group).

    The script never changes Azure resources. AzGovViz only performs read (GET/POST query) calls.

.EXAMPLE
    ./Invoke-AzGovViz.ps1 -TenantId <guid> -OutputPath ./run/azgovviz
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$TenantId,
    [string]$ManagementGroupId,
    [Parameter(Mandatory)][string]$OutputPath,
    [string[]]$SubscriptionIds,
    [string]$SubscriptionId4AzContext,
    [string]$AzGovVizRef = 'master',
    [string]$AzGovVizPath,
    [string]$CacheDir,
    [switch]$Login,
    [switch]$DeviceCode,
    [switch]$Quick,
    [switch]$IncludeConsumption,
    [int]$ConsumptionDays = 30,
    [switch]$NoPIM,
    [switch]$ALZPolicyAssignmentsChecker,
    [switch]$DoNotShowRoleAssignmentsUserData,
    [int]$ThrottleLimit = 10,
    [string]$ExtraArgsJson,
    [switch]$PrepareOnly
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

function Write-Step([string]$Message) { Write-Host "[azgovviz] $Message" -ForegroundColor Cyan }
function Write-Ok([string]$Message) { Write-Host "[  ok   ] $Message" -ForegroundColor Green }
function Write-Problem([string]$Message) { Write-Host "[problem] $Message" -ForegroundColor Yellow }

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Problem "PowerShell 7+ is required (found $($PSVersionTable.PSVersion)). Install from https://aka.ms/powershell"
    exit 3
}
if (-not $ManagementGroupId) { $ManagementGroupId = $TenantId }
# `pwsh -File` passes "a,b" as one string; normalise to a clean array
$SubscriptionIds = @($SubscriptionIds | ForEach-Object { "$_" -split '[,;\s]+' } | Where-Object { $_ })
if (-not $CacheDir) {
    $CacheDir = if ($env:AZGOV_CACHE_DIR) { $env:AZGOV_CACHE_DIR }
    elseif ($IsWindows) { Join-Path $env:LOCALAPPDATA 'azgov-assess' }
    else { Join-Path $HOME '.cache/azgov-assess' }
}
$null = New-Item -ItemType Directory -Force -Path $CacheDir
$null = New-Item -ItemType Directory -Force -Path $OutputPath
$OutputPath = (Resolve-Path $OutputPath).Path

# ---------------------------------------------------------------------------------------------
# 1. Az.Accounts
# ---------------------------------------------------------------------------------------------
Write-Step 'Checking Az.Accounts module'
if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
    Write-Step 'Installing Az.Accounts (CurrentUser scope)'
    Install-Module -Name Az.Accounts -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
}
Import-Module Az.Accounts -ErrorAction Stop
$azAccountsVersion = (Get-Module Az.Accounts).Version.ToString()
Write-Ok "Az.Accounts $azAccountsVersion"
try { $null = Update-AzConfig -LoginExperienceV2 Off -Scope Process -ErrorAction SilentlyContinue } catch { }
try { $null = Update-AzConfig -DisplayBreakingChangeWarning $false -Scope Process -ErrorAction SilentlyContinue } catch { }

# ---------------------------------------------------------------------------------------------
# 2. Azure context for the tenant
# ---------------------------------------------------------------------------------------------
function Test-ArmToken([string]$Tenant) {
    try {
        $null = Get-AzAccessToken -TenantId $Tenant -ResourceUrl 'https://management.azure.com/' -ErrorAction Stop
        return $true
    }
    catch {
        $script:lastAuthError = $_.Exception.Message
        return $false
    }
}

Write-Step "Validating Azure sign-in for tenant $TenantId"
$ctx = Get-AzContext
if (-not $ctx -or $ctx.Tenant.Id -ne $TenantId) {
    $candidate = Get-AzContext -ListAvailable | Where-Object { $_.Tenant.Id -eq $TenantId } | Select-Object -First 1
    if ($candidate) { $null = Select-AzContext -InputObject $candidate; $ctx = Get-AzContext }
}
$tokenOk = $ctx -and $ctx.Tenant.Id -eq $TenantId -and (Test-ArmToken $TenantId)
if (-not $tokenOk) {
    if (-not $Login) {
        Write-Problem "No usable Az PowerShell sign-in for tenant $TenantId. $script:lastAuthError"
        Write-Problem "Sign in first:  pwsh -c `"Connect-AzAccount -Tenant $TenantId`"   (add -UseDeviceAuthentication on headless machines)"
        exit 10
    }
    Write-Step "Starting $(if ($DeviceCode) { 'device-code' } else { 'interactive browser' }) sign-in for tenant $TenantId"
    $connect = @{ Tenant = $TenantId; WarningAction = 'SilentlyContinue' }
    if ($DeviceCode) { $connect.UseDeviceAuthentication = $true }
    if ($SubscriptionId4AzContext) { $connect.Subscription = $SubscriptionId4AzContext }
    $null = Connect-AzAccount @connect
    $ctx = Get-AzContext
    if (-not (Test-ArmToken $TenantId)) {
        Write-Problem "Sign-in completed but no ARM token could be obtained: $script:lastAuthError"
        exit 10
    }
}
Write-Ok "Signed in as $($ctx.Account.Id) ($($ctx.Account.Type))"

try {
    $null = Get-AzAccessToken -TenantId $TenantId -ResourceTypeName MSGraph -ErrorAction Stop
    Write-Ok 'Microsoft Graph token available (identity enrichment enabled)'
}
catch {
    Write-Problem "Microsoft Graph token unavailable - AzGovViz identity enrichment may be limited: $($_.Exception.Message)"
}

$subs = @(Get-AzSubscription -TenantId $TenantId -WarningAction SilentlyContinue -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq 'Enabled' -and $_.TenantId -eq $TenantId })
if ($SubscriptionIds) { $subs = @($subs | Where-Object { $SubscriptionIds -contains $_.Id }) }
if (-not $SubscriptionId4AzContext) {
    if ($ctx.Subscription -and ($subs.Id -contains $ctx.Subscription.Id)) { $SubscriptionId4AzContext = $ctx.Subscription.Id }
    elseif ($subs.Count -gt 0) { $SubscriptionId4AzContext = $subs[0].Id }
}
if (-not $SubscriptionId4AzContext) {
    Write-Problem "No enabled subscription visible in tenant $TenantId for this identity."
    exit 11
}
$null = Set-AzContext -Tenant $TenantId -Subscription $SubscriptionId4AzContext -WarningAction SilentlyContinue
Write-Ok "Context subscription $SubscriptionId4AzContext ($($subs.Count) enabled subscription(s) visible)"

# ---------------------------------------------------------------------------------------------
# 3. AzGovViz source
# ---------------------------------------------------------------------------------------------
if ($AzGovVizPath) {
    $azgvRoot = (Resolve-Path $AzGovVizPath).Path
}
else {
    $azgvRoot = Join-Path $CacheDir 'Azure-Governance-Visualizer'
    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($git) {
        if (Test-Path (Join-Path $azgvRoot '.git')) {
            Write-Step "Updating AzGovViz ($AzGovVizRef)"
            & git -C $azgvRoot fetch --depth 1 origin $AzGovVizRef 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { & git -C $azgvRoot checkout -q --force FETCH_HEAD 2>&1 | Out-Null }
            else { Write-Problem 'git fetch failed - using cached AzGovViz copy' }
        }
        else {
            Write-Step "Cloning Azure/Azure-Governance-Visualizer ($AzGovVizRef)"
            if (Test-Path $azgvRoot) { Remove-Item -Recurse -Force $azgvRoot }
            & git clone -q --depth 1 --branch $AzGovVizRef https://github.com/Azure/Azure-Governance-Visualizer.git $azgvRoot
            if ($LASTEXITCODE -ne 0) { Write-Problem 'git clone failed'; exit 12 }
        }
    }
    elseif (-not (Test-Path (Join-Path $azgvRoot 'pwsh/AzGovVizParallel.ps1'))) {
        Write-Step "Downloading AzGovViz zip ($AzGovVizRef)"
        $zip = Join-Path $CacheDir 'azgovviz.zip'
        $uri = "https://github.com/Azure/Azure-Governance-Visualizer/archive/$AzGovVizRef.zip"
        Invoke-WebRequest -Uri $uri -OutFile $zip -UseBasicParsing
        $extract = Join-Path $CacheDir 'azgovviz-extract'
        if (Test-Path $extract) { Remove-Item -Recurse -Force $extract }
        Expand-Archive -Path $zip -DestinationPath $extract -Force
        $inner = Get-ChildItem $extract -Directory | Select-Object -First 1
        if (Test-Path $azgvRoot) { Remove-Item -Recurse -Force $azgvRoot }
        Move-Item $inner.FullName $azgvRoot
        Remove-Item $zip -Force
    }
}
$scriptFile = Join-Path $azgvRoot 'pwsh/AzGovVizParallel.ps1'
if (-not (Test-Path $scriptFile)) { Write-Problem "AzGovVizParallel.ps1 not found under $azgvRoot"; exit 12 }
# (-Raw cannot be combined with -TotalCount)
$scriptHead = (Get-Content -Path $scriptFile -TotalCount 1200) -join "`n"
$productVersion = if ($scriptHead -match "\`$ProductVersion\s*=\s*'([^']+)'") { $Matches[1] } else { 'unknown' }
$azApiCallVersion = if ($scriptHead -match "\`$AzAPICallVersion\s*=\s*'([^']+)'") { $Matches[1] } else { $null }
$commit = $null
if (Get-Command git -ErrorAction SilentlyContinue) { $commit = (& git -C $azgvRoot rev-parse HEAD 2>$null) }
Write-Ok "AzGovViz $productVersion ($azgvRoot)"

# ---------------------------------------------------------------------------------------------
# 4. AzAPICall module (AzGovViz would install it too; doing it here avoids interactive prompts)
# ---------------------------------------------------------------------------------------------
if ($azApiCallVersion) {
    $have = Get-Module -ListAvailable -Name AzAPICall | Where-Object { $_.Version.ToString() -eq $azApiCallVersion }
    if (-not $have) {
        Write-Step "Installing AzAPICall $azApiCallVersion (CurrentUser scope)"
        Install-Module -Name AzAPICall -RequiredVersion $azApiCallVersion -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
    }
    Write-Ok "AzAPICall $azApiCallVersion"
}

$prep = [ordered]@{
    tenantId                 = $TenantId
    managementGroupId        = $ManagementGroupId
    account                  = $ctx.Account.Id
    accountType              = "$($ctx.Account.Type)"
    subscriptionId4AzContext = $SubscriptionId4AzContext
    visibleSubscriptions     = @($subs | ForEach-Object { [ordered]@{ id = $_.Id; name = $_.Name; state = "$($_.State)" } })
    azGovVizVersion          = $productVersion
    azGovVizCommit           = $commit
    azGovVizPath             = $azgvRoot
    azApiCallVersion         = $azApiCallVersion
    azAccountsVersion        = $azAccountsVersion
    psVersion                = $PSVersionTable.PSVersion.ToString()
}
$prep | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $OutputPath 'azgovviz-prepare.json') -Encoding utf8
if ($PrepareOnly) { Write-Ok 'Preparation complete (-PrepareOnly)'; exit 0 }

# ---------------------------------------------------------------------------------------------
# 5. Run AzGovViz
# ---------------------------------------------------------------------------------------------
# AzGovViz calls `Pause` for interactive hints (least-privilege advice when the user holds more than
# Reader, PIM hint for user accounts, newer version available). Unattended runs must not block on them;
# the hints still appear in the console log.
function global:Pause { Write-Host '[azgovviz] (interactive pause skipped - unattended run)' }

$params = @{
    ManagementGroupId          = $ManagementGroupId
    OutputPath                 = $OutputPath
    SubscriptionId4AzContext   = $SubscriptionId4AzContext
    TenantId4AzContext         = $TenantId
    StatsOptOut                = $true
    DoTranscript               = $true
    NoSingleSubscriptionOutput = $true
    ThrottleLimit              = $ThrottleLimit
    CsvDelimiter               = ';'
}
if ($SubscriptionIds) { $params.SubscriptionIdWhitelist = $SubscriptionIds }
# PIM eligibility reporting needs a service principal with PrivilegedAccess.Read.AzureResources;
# AzGovViz switches it off for user accounts anyway (after an interactive pause), so do it up front.
if ($NoPIM -or $Quick -or "$($ctx.Account.Type)" -eq 'User') { $params.NoPIMEligibility = $true }
if ($Quick) {
    $params.NoResourceProvidersDetailed = $true
    $params.NoScopeInsights = $true
    $params.NoALZPolicyVersionChecker = $true
}
if ($IncludeConsumption) { $params.DoAzureConsumption = $true; $params.AzureConsumptionPeriod = $ConsumptionDays }
if ($ALZPolicyAssignmentsChecker) { $params.ALZPolicyAssignmentsChecker = $true }
if ($DoNotShowRoleAssignmentsUserData) { $params.DoNotShowRoleAssignmentsUserData = $true }
if ($ExtraArgsJson) {
    $extra = $ExtraArgsJson | ConvertFrom-Json -AsHashtable
    foreach ($k in $extra.Keys) { $params[$k] = $extra[$k] }
}
$shown = ($params.GetEnumerator() | Sort-Object Name | ForEach-Object {
        if ($_.Value -is [bool]) { "-$($_.Name)" } else { "-$($_.Name) $($_.Value -join ',')" } }) -join ' '
Write-Step "Running AzGovVizParallel.ps1 $shown"
Set-Location $azgvRoot
$WarningPreference = 'Continue'
& $scriptFile @params
