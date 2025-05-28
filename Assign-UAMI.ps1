$uamiResourceId = "/subscriptions/d6fc9b65-12dd-4535-99c3-a7ba2277f2c2/resourceGroups/Intune-Scripts/providers/Microsoft.ManagedIdentity/userAssignedIdentities/Intune-Scripts-Devices"
az login --identity
az vm identity assign --identities $uamiResourceId --name $env:COMPUTERNAME --resource-group Intune-Scripts
