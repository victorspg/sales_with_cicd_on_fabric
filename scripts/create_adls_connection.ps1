param (
    [string]$ConnectionName,
    [string]$TenantId,
    [string]$ClientId,
    [string]$ClientSecret,
    [string]$StorageAccount,
    [string]$FileSystem
)

Write-Host "Creating Fabric ADLS Gen2 connection: $ConnectionName"

fab create ".connections/$ConnectionName.connection" `
  -P `
  connectionDetails.type=AzureDataLakeStorageGen2,`
  connectionDetails.creationMethod=AzureDataLakeStorageGen2.Contents,`
  connectionDetails.parameters.accountName=$StorageAccount,`
  connectionDetails.parameters.fileSystem=$FileSystem,`
  credentialDetails.type=ServicePrincipal,`
  credentialDetails.tenantId=$TenantId,`
  credentialDetails.servicePrincipalClientId=$ClientId,`
  credentialDetails.servicePrincipalSecret=$ClientSecret