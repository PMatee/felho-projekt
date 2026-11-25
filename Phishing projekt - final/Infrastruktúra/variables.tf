variable "subscription_id" {
  description = "Az Azure előfizetés azonosítója (az 'az account show --query id -o tsv' adja meg)."
  type        = string
}

variable "location" {
  description = "Az Azure régió, ahová az erőforrások kerülnek."
  type        = string
  default     = "germanywestcentral"
}

variable "project" {
  description = "Rövid projektnév, ez kerül az erőforrások nevébe."
  type        = string
  default     = "phishing"
}
