# ---------------------------------------------------------------------------
# 1. lépés: erőforráscsoport
# Az erőforráscsoport egy "mappa", amibe a projekt összes Azure-erőforrása kerül.
# ---------------------------------------------------------------------------
resource "azurerm_resource_group" "rg" {
  name     = "rg-${var.project}-tf"
  location = var.location

  tags = {
    kurzus = "felhoszolgaltatasok"
  }
}

# ---------------------------------------------------------------------------
# 2. lépés: tárfiók és Cosmos DB
# ---------------------------------------------------------------------------

# Egy véletlen, 5 karakteres toldalék. A tárfiók és a Cosmos fiók neve az egész Azure-ban
# egyedi kell legyen, ezért ezt a nevekhez fűzzük. A Terraform a véletlen értéket elmenti
# az állapotfájlba, így a következő futtatásnál már nem változik.
resource "random_string" "suffix" {
  length  = 5
  lower   = true
  numeric = true
  upper   = false
  special = false
}

# Tárfiók: a Function App ide menti a belső működéséhez szükséges adatokat.
resource "azurerm_storage_account" "storage" {
  name                     = "st${var.project}${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.rg.name # <- hivatkozás: a Terraform ebből tudja,
  location                 = azurerm_resource_group.rg.location # hogy előbb az erőforráscsoportot kell létrehozni
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

# Cosmos DB fiók (NoSQL / SQL API), serverless módban: csak a használat után kell fizetni.
resource "azurerm_cosmosdb_account" "cosmos" {
  name                = "cosmos-${var.project}-${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  capabilities {
    name = "EnableServerless"
  }

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = azurerm_resource_group.rg.location
    failover_priority = 0
  }
}

# Adatbázis a Cosmos fiókon belül.
resource "azurerm_cosmosdb_sql_database" "db" {
  name                = "PhishingDb"
  resource_group_name = azurerm_resource_group.rg.name
  account_name        = azurerm_cosmosdb_account.cosmos.name
}

# Konténer (a "tábla" megfelelője), a partíciókulcs a kockázati szint.
resource "azurerm_cosmosdb_sql_container" "analyses" {
  name                  = "Analyses"
  resource_group_name   = azurerm_resource_group.rg.name
  account_name          = azurerm_cosmosdb_account.cosmos.name
  database_name         = azurerm_cosmosdb_sql_database.db.name
  partition_key_paths   = ["/riskLevel"]
}

# ---------------------------------------------------------------------------
# 3. lépés: Function App (Flex Consumption)
# ---------------------------------------------------------------------------

# Az "App Service-terv" határozza meg, milyen típusú és méretű gépen fut az alkalmazás.
# Az FC1 a Flex Consumption csomag azonosítója (használatarányos számlázás).
resource "azurerm_service_plan" "plan" {
  name                = "asp-${var.project}-${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  os_type             = "Linux"
  sku_name            = "FC1"
}

# A Flex Consumption ide tölti fel a telepített alkalmazáscsomagot.
resource "azurerm_storage_container" "deploy" {
  name                  = "app-package"
  storage_account_id    = azurerm_storage_account.storage.id
  container_access_type = "private"
}

resource "azurerm_function_app_flex_consumption" "func" {
  name                = "func-${var.project}-${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  service_plan_id     = azurerm_service_plan.plan.id

  # Hová kerül a feltöltött kód.
  storage_container_type      = "blobContainer"
  storage_container_endpoint  = "${azurerm_storage_account.storage.primary_blob_endpoint}${azurerm_storage_container.deploy.name}"
  storage_authentication_type = "StorageAccountConnectionString"
  storage_access_key          = azurerm_storage_account.storage.primary_access_key

  # Futtatókörnyezet: .NET 10, izolált worker modell.
  runtime_name           = "dotnet-isolated"
  runtime_version        = "10.0"
  maximum_instance_count = 40
  instance_memory_in_mb  = 2048

  site_config {}

  # Az alkalmazás beállításai (a kód ezeket olvassa környezeti változóként).
  # A Cosmos adatok a Cosmos fiókból jönnek, így nem kell kézzel másolni őket.
  app_settings = {
    AzureWebJobsStorage = azurerm_storage_account.storage.primary_connection_string
    COSMOS_ENDPOINT     = azurerm_cosmosdb_account.cosmos.endpoint
    COSMOS_KEY          = azurerm_cosmosdb_account.cosmos.primary_key
    COSMOS_DATABASE     = azurerm_cosmosdb_sql_database.db.name
    COSMOS_CONTAINER    = azurerm_cosmosdb_sql_container.analyses.name
  }
}
