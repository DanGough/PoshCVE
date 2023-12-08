# PoshCVE

A PowerShell module for querying the National Vulnerability Database. Search for CVEs by ID, vendor, product, and more.
<br>

## Installation

Install from the [Powershell Gallery](https://www.powershellgallery.com/packages/PoshCVE) by running the following command:

```powershell
Install-Module -Name PoshCVE -Scope CurrentUser
```
<br>

## Usage

### Get-CVE

#### Parameters:

- ID
  - Specifies the ID of the CVE entry to retrieve.
- ProductType
  - Specifies the type of product to search for. Valid values are Application, Hardware, or OperatingSystem.
- Vendor
  - Specifies the vendor of the product to search for. [opencve.io](https://www.opencve.io/vendors) is a great place to search for these strings.
- Product
  - Specifies the name of the product to search for. [opencve.io](https://www.opencve.io/vendors) is a great place to search for these strings.
- KeyWord
  - Specifies a keyword to search for in the CVE entry description.
- KeyWordExact
  - Indicates that the keyword search should be exact. By default, if KeyWord contains multiple words, they will be searched for anywhere in any order.
- Version
  - Specifies the version of the product to search for.
- MinVersion
  - Specifies the minimum version of the product to search for.
- MinVersionType
  - Specifies whether the minimum version is inclusive (default) or exclusive.
- MaxVersion
  - Specifies the maximum version of the product to search for.
- MaxVersionType
  - Specifies whether the maximum version is inclusive (default) or exclusive.
- LastModifiedStartDate
  - Specifies the start date of the last modified date range to search. Must be a \[datetime\] object.
- LastModifiedEndDate
  - Specifies the end date of the last modified date range to search. Must be a \[datetime\] object. If not set and LastModifiedStartDate is specified, the current date/time will be used.
- PublishStartDate
  - Specifies the start date of the publish date range to search. Must be a \[datetime\] object.
- PublishEndDate
  - Specifies the end date of the publish date range to search. Must be a \[datetime\] object. If not set and LastModifiedStartDate is specified, the current date/time will be used.
- MaxResults
  - Specifies the maximum number of results to return.
- FilterAffectedProducts
  - Indicates whether to filter the products affected by each CVE to match the ProductType / Vendor / Product specified in the search parameters.
- APIKey
  - Specifies the API key to use for the NVD API. This is optional but you may be rate limited if using the public API. You can request a free API key here: https://nvd.nist.gov/developers/request-an-api-key

<br>

#### Examples:

```powershell
Get-CVE -ID 'CVE-2023-4863'
```
Retrieves information about the specific CVE-2023-4863 entry.

<br>

```powershell
Get-CVE -Vendor 'Google' -Product 'Chrome' -PublishStartDate (Get-Date).AddDays(-30) -FilterAffectedProducts
```
Retrieves information about the all Google Chrome CVEs published within the last 30 days, only showing the affected Google Chrome products for each (ignoring Linux distros, etc).

<br>

```powershell
Get-CVE -Vendor 'Microsoft' -Product 'Windows_11_23H2' -PublishStartDate (Get-Date).AddDays(-30)
```
Retrieves information about the Windows 11 23H2 CVEs published within the last 30 days.

<br>

## Roadmap

- Investigate adding support for additional NVD APIs:
  - [CVE Change History API](https://nvd.nist.gov/developers/vulnerabilities)
  - [CPE API](https://nvd.nist.gov/developers/products)
  - [Match Criteria API](https://nvd.nist.gov/developers/products)
- Support searching for vendor/product names in the [CPE dictionary](https://nvd.nist.gov/products/cpe)