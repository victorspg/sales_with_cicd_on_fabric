param (
    [string]$ConnectionName,
    [string]$TenantId,
    [string]$ClientId,
    [string]$ClientSecret,
    [string]$StorageAccount,
    [string]$FileSystem
)

Write-Host "Creating Fabric ADLS Gen2 connection: $ConnectionName"

$server = "https://$StorageAccount.dfs.core.windows.net"
$path = "/"

fab create ".connections/$ConnectionName.Connection" -P connectionDetails.type=AzureDataLakeStorage,connectionDetails.creationMethod=AzureDataLakeStorage,credentialDetails.type=ServicePrincipal,credentialDetails.tenantId=$TenantId,credentialDetails.servicePrincipalClientId=$ClientId,credentialDetails.servicePrincipalSecret=$ClientSecret,connectionDetails.parameters.path=$path,connectionDetails.parameters.server=$server