# Az outputok a futtatás végén kiírt értékek, amikre később szükség lesz
# (pl. a Function App beállításaihoz).
output "resource_group_name" {
  value = azurerm_resource_group.rg.name
}

output "storage_account_name" {
  value = azurerm_storage_account.storage.name
}

output "cosmos_account_name" {
  value = azurerm_cosmosdb_account.cosmos.name
}

output "cosmos_endpoint" {
  value = azurerm_cosmosdb_account.cosmos.endpoint
}

# Titkos érték: a 'sensitive' miatt nem íródik ki a képernyőre.
# Lekérés: terraform output -raw cosmos_primary_key
output "cosmos_primary_key" {
  value     = azurerm_cosmosdb_account.cosmos.primary_key
  sensitive = true
}

output "function_app_name" {
  value = azurerm_function_app_flex_consumption.func.name
}

# A webes felület címe.
output "ui_url" {
  value = "https://${azurerm_function_app_flex_consumption.func.default_hostname}/api/ui"
}
