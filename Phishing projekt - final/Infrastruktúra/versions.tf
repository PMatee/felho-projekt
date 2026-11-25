terraform {
  required_version = ">= 1.6"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azurerm" {
  features {}

  subscription_id = var.subscription_id

  # Nem próbál meg szolgáltatókat (resource provider) regisztrálni az előfizetésben.
  # Diákelőfizetésen ehhez gyakran nincs jogosultság, a szükségesek pedig már regisztrálva vannak.
  resource_provider_registrations = "none"
}
