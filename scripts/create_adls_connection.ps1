param (
    [Parameter(Mandatory)][string]$ConnectionName,
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$ClientSecret,
    [Parameter(Mandatory)][string]$StorageAccount,
    [Parameter(Mandatory)][string]$FileSystem
)

$ErrorActionPreference = "Stop"

Write-Host "Creating Fabric ADLS Gen2 connection: $ConnectionName"

$server = "${StorageAccount}.dfs.core.windows.net"
$path = "/"

Write-Host "Server: $server"
Write-Host "Path: $path"

$properties = @(
    "connectionDetails.type=AzureDataLakeStorage"
    "connectionDetails.creationMethod=AzureDataLakeStorage"
    "credentialDetails.type=ServicePrincipal"
    "credentialDetails.tenantId=$TenantId"
    "credentialDetails.servicePrincipalClientId=$ClientId"
    "credentialDetails.servicePrincipalSecret=$ClientSecret"
    "connectionDetails.parameters.path=$path"
    "connectionDetails.parameters.server=$server"
) -join ","

Write-Host "Running: fab create .connections/$ConnectionName.Connection"
fab create ".connections/$ConnectionName.Connection" -P $properties

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to create connection '$ConnectionName'. Exit code: $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host "Connection '$ConnectionName' created successfully."