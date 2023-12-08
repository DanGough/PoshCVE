<#
.SYNOPSIS
    Retrieves information about Common Vulnerabilities and Exposures (CVE) entries from the National Vulnerability Database (NVD).
.DESCRIPTION
    The Get-CVE function retrieves information via the CVE API: https://nvd.nist.gov/developers/vulnerabilities
.PARAMETER ID
    Specifies the ID of the CVE entry to retrieve.
.PARAMETER ProductType
    Specifies the type of product to search for. Valid values are Application, Hardware, or OperatingSystem.
.PARAMETER Vendor
    Specifies the vendor of the product to search for. You can look these up at https://www.opencve.io/vendors.
.PARAMETER Product
    Specifies the name of the product to search for. You can look these up at https://www.opencve.io/vendors.
.PARAMETER KeyWord
    Specifies a keyword to search for in the CVE entry description.
.PARAMETER KeyWordExact
    Indicates that the keyword search should be exact. By default, if KeyWord contains multiple words, they will be searched for anywhere in any order.
.PARAMETER Version
    Specifies the version of the product to search for.
.PARAMETER MinVersion
    Specifies the minimum version of the product to search for.
.PARAMETER MinVersionType
    Specifies whether the minimum version is inclusive (default) or exclusive.
.PARAMETER MaxVersion
    Specifies the maximum version of the product to search for.
.PARAMETER MaxVersionType
    Specifies whether the maximum version is inclusive (default) or exclusive.
.PARAMETER LastModifiedStartDate
    Specifies the start date of the last modified date range to search. Must be a [datetime] object.
.PARAMETER LastModifiedEndDate
    Specifies the end date of the last modified date range to search. Must be a [datetime] object. If not set and LastModifiedStartDate is specified, the current date/time will be used.
.PARAMETER PublishStartDate
    Specifies the start date of the publish date range to search. Must be a [datetime] object.
.PARAMETER PublishEndDate
    Specifies the end date of the publish date range to search. Must be a [datetime] object. If not set and LastModifiedStartDate is specified, the current date/time will be used.
.PARAMETER MaxResults
    Specifies the maximum number of results to return.
.PARAMETER FilterAffectedProducts
    Indicates whether to filter the products affected by each CVE to match the ProductType / Vendor / Product specified in the search parameters.
.PARAMETER APIKey
    Specifies the API key to use for the NVD API. This is optional but you may be rate limited if using the public API. You can request a free API key here: https://nvd.nist.gov/developers/request-an-api-key
.EXAMPLE
    Get-CVE -ID CVE-2023-4863
    Retrieves information about the specific CVE-2023-4863 entry.
.EXAMPLE
    Get-CVE -Vendor 'Google' -Product 'Chrome' -PublishStartDate (Get-Date).AddDays(-30) -FilterAffectedProducts
    Retrieves information about the all Google Chrome CVEs published within the last 30 days, only showing the affected Google Chrome products for each (ignoring Linux distros, etc).
.EXAMPLE
    Get-CVE -Vendor 'Microsoft' -Product 'Windows_11_23H2' -PublishStartDate (Get-Date).AddDays(-30)
    Retrieves information about the Windows 11 23H2 CVEs published within the last 30 days.
#>
function Get-CVE {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ID,
        
        [Parameter()]
        [ValidateSet('Application', 'Hardware', 'OperatingSystem')]
        [string]$ProductType,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Vendor,
        
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Product,
        
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$KeyWord,

        [Parameter()]
        [switch]$KeyWordExact,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Version,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$MinVersion,
        
        [Parameter()]
        [ValidateSet('Including', 'Excluding')]
        [string]$MinVersionType = 'Including',
        
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$MaxVersion,
        
        [Parameter()]
        [ValidateSet('Including', 'Excluding')]
        [string]$MaxVersionType = 'Including',
        
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [datetime]$LastModifiedStartDate,
        
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [datetime]$LastModifiedEndDate,
        
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [datetime]$PublishStartDate,
        
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [datetime]$PublishEndDate,

        [Parameter()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$MaxResults,

        [Parameter()]
        [switch]$FilterAffectedProducts,
        
        [Parameter(Mandatory = $false)]
        [string]$APIKey
    )

    # Suppress progress bars from calling Invoke-RestMethod
    $ProgressPreference = 'SilentlyContinue'

    # NVD API URL
    $Endpoint = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

    # API supports a max date range of 120 days per request - longer spans needs to be split up into multiple requests
    $MaxDays = 120

    # If the required date range is over 120 days we need to make multiple calls, but start with assuming a single range with no start or end date
    $PublishRanges = @(@{ StartDate = $null; EndDate = $null })
    $LastModifiedRanges = @(@{ StartDate = $null; EndDate = $null })

    # Check for NVDAPIKey environment variable if $APIKey not supplied
    # It is allowed to submit a $APIKey as $null to override your environment variable, hence checking PSBoundParameters
    if ($PSBoundParameters.Keys -notcontains 'APIKey' -and $env:NVDAPIKey) {
        Write-Verbose 'Using API key found in NVDAPIKey environment variable'
        $APIKey = $env:NVDAPIKey
    }
    if ($APIKey) {
        $Headers = @{apiKey = $APIKey }
    }
    else {
        Write-Verbose 'No API key supplied'
        $Headers = $null
    }

    # Set initial values for API query
    $Body = @{
        startIndex = 0
        resultsPerPage = 2000 # this is both the recommended default and maximum value allowed
    }

    if ($ID) {
        $Body.cveId = $ID
    }

    if ($ProductType -or $Vendor -or $Product -or $Version -or $MinVersion -or $MaxVersion) {
        # CPE spec defines 'Part' as being 'a' for an application, and 'o' for an operating system. * is allowed as a wildcard.
        switch ($ProductType) {         
            'Application' { 
                $Part = 'a'
            }
            'Hardware' { 
                $Part = 'h'
            }
            'OperatingSystem' {
                $Part = 'o'
            }
            default {
                $Part = '*'
            }
        }
        # Replace Vendor/Product/Version with * if they are null
        if (!$Vendor) { $Vendor = '*' }
        if (!$Product) { $Product = '*' }
        if (!$Version) { $Version = '*' }
        # A virtualMatchString is required if any of these parameters are supplied
        $Body.virtualMatchString = "cpe:2.3:$Part`:$Vendor`:$Product`:$Version"
    }

    if ($MinVersion -and -not $Version) {
        # API does not allow min/max version in combination with a specific version, so ignore MinVersion if Version is specified
        if ($Version -eq '*') {
            $Body.versionStart = $MinVersion
            $Body.versionStartType = $MinVersionType.ToLower()
        }
    }

    if ($MaxVersion -and -not $Version) {
        # API does not allow min/max version in combination with a specific version, so ignore MaxVersion if Version is specified
        if ($Version -eq '*') {
            $Body.versionEnd = $MaxVersion
            $Body.versionEndType = $MaxVersionType.ToLower()
        }
    }

    if ($KeyWord) {
        $Body.keywordSearch = $KeyWord
        if ($KeyWordExact) {
            # API just expects this property to exist with no value hence set to $null
            $Body.keywordExactMatch = $null
        }
    }

    if ($LastModifiedStartDate) {
        if (!$LastModifiedEndDate) {
            $LastModifiedEndDate = Get-Date
            Write-Verbose "LastModifiedEndDate not supplied - will use current date $LastModifiedDate"
        }
        if ($LastModifiedStartDate -gt $LastModifiedEndDate) {
            throw "LastModifiedStartDate cannot be greater than LastModifiedEndDate"
        }
    }

    if ($LastModifiedEndDate) {
        if (!$LastModifiedStartDate) {
            throw "LastModifiedStartDate required when LastModifiedEndDate supplied"
        }
        # If specified date range is >120 days, we need to break it up into a series of ranges to be used by separate requests
        if (($LastModifiedEndDate - $LastModifiedStartDate) -gt $MaxDays) {
            $LastModifiedRanges = @()
            $SubStartDate = $LastModifiedStartDate
            while ($SubStartDate -lt $LastModifiedEndDate) {
                $SubEndDate = $SubStartDate.AddDays($MaxDays)
                if ($SubEndDate -gt $LastModifiedEndDate) {
                    $SubEndDate = $LastModifiedEndDate
                }
                # Add a hash table to the LastModifiedRanges array
                $LastModifiedRanges += @{
                    StartDate = $SubStartDate
                    EndDate   = $SubEndDate
                }
                $SubStartDate = $SubEndDate
            }
        }
        else {
            # Otherwise if range is <=120 days, just define an array containing a single hash table defining this range
            $LastModifiedRanges = @(@{ StartDate = $LastModifiedStartDate; EndDate = $LastModifiedEndDate })
        }
    }

    if ($PublishStartDate) {
        # If start date supplied but not end date, set end date to now
        if (!$PublishEndDate) {
            $PublishEndDate = Get-Date
            Write-Verbose "PublishEndDate not supplied - will use current date $PublishEndDate"
        }
        if ($PublishStartDate -gt $PublishEndDate) {
            throw "PublishStartDate cannot be greater than PublishEndDate"
        }
    }

    if ($PublishEndDate) {
        if (!$PublishStartDate) {
            throw "PublishStartDate required when PublishEndDate supplied"
        }
        # If specified date range is >120 days, we need to break it up into a series of ranges to be used by separate requests
        if (($PublishEndDate - $PublishStartDate) -gt $MaxDays) {
            $PublishRanges = @()
            $SubStartDate = $PublishStartDate
            while ($SubStartDate -lt $PublishEndDate) {
                $SubEndDate = $SubStartDate.AddDays($MaxDays)
                if ($SubEndDate -gt $PublishEndDate) {
                    $SubEndDate = $PublishEndDate
                }
                # Add a hash table to the PublishRanges array
                $PublishRanges += @{
                    StartDate = $SubStartDate
                    EndDate   = $SubEndDate
                }
                $SubStartDate = $SubEndDate
            }
        }
        else {
            # Otherwise if range is <=120 days, just define an array containing a single hash table defining this range
            $PublishRanges = @(@{ StartDate = $PublishStartDate; EndDate = $PublishEndDate })
        }
    }

    # Use nested loops to check each range of publishing dates and last modified dates
    foreach ($PublishRange in $PublishRanges) {

        # If date range is specified, convert to the format that the API expects
        if ($PublishRange.StartDate) {
            $Body.pubStartDate = $PublishRange.StartDate.ToString('o').Replace('Z','+00:00')
            $Body.pubEndDate = $PublishRange.EndDate.ToString('o').Replace('Z','+00:00')
        }

        foreach ($LastModifiedRange in $LastModifiedRanges) {
    
            # If date range is specified, convert to the format that the API expects
            if ($LastModifiedRange.StartDate) {
                $Body.lastModStartDate = $LastModifiedRange.StartDate.ToString('o').Replace('Z','+00:00')
                $Body.lastModEndDate = $LastModifiedRange.EndDate.ToString('o').Replace('Z','+00:00')
            }
            
            do {

                # If MaxResults was specified, cap the number of results per page being requested. If retrieving >2000 results, this will only kick in on the last request as startIndex grows.
                if ($MaxResults -and ($MaxResults - $Body.startIndex) -lt $Body.resultsPerPage) {
                    $Body.resultsPerPage = $MaxResults - $Body.startIndex
                }

                # Print out all contents of Body hash table to verbose stream
                Write-Verbose ((@("Body:") + $Body.Keys.ForEach({ "$_ = $($Body[$_])" })) -join "`n")

                try {
                    # Get response and show total number of results in verbose information
                    $Response = Invoke-RestMethod -Method Get -Uri $Endpoint -Headers $Headers -Body $Body -ErrorAction Stop
                    if ($Response.totalResults -eq 1) {
                        Write-Verbose "1 result in total"
                    }
                    else {
                        Write-Verbose "$($Response.totalResults) results in total"
                    }
                }
                catch {
                    throw "Error querying NVD API: $_"
                }

                # Check for unexpected result format
                if ($Response.format -ne 'NVD_CVE') {
                    throw "NVD API returned unexpected format $($Response.Format)"
                }
                if ($Response.version -ne '2.0') {
                    throw "NVD API returned unexpected version $($Response.Version)"
                }

                # Loop through each CVE in the response
                foreach ($CVE in $Response.vulnerabilities.cve) {

                    # .Where method used for speed over Where-Object, preceding value wrapped in @() array to avoid errors when single results found.
                    $AffectedProducts = foreach ($MatchCriteria in @($CVE.configurations.nodes).Where({ $_.operator -eq 'OR' -and $_.negate -eq $false }).cpeMatch) {

                        # Use a RegEx to extract all of the portions of the criteria string
                        if ($MatchCriteria.criteria -match "^cpe:2.3:([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+)") {

                            # $matches[1] contains the 'Part' a/h/o in the CPE definition, or ProductType Application/Hardware/OperatingSystem as used in this function
                            switch ($matches[1]) {
                                'a' { 
                                    $AffectedProductType = 'Application'
                                }
                                'h' { 
                                    $AffectedProductType = 'Hardware'
                                }
                                'o' {
                                    $AffectedProductType = 'OperatingSystem'
                                }
                                default {
                                    $AffectedProductType = $matches[1]
                                    Write-Warning "Unknown product type! $($matches[1])"
                                }
                            }

                            # If we're not filtering, or if the affected product matches the Part, Vendor and Product (we are using -like for wildcard search, and null values were converted to * earlier on)
                            if (!$FilterAffectedProducts -or ($matches[1] -like $Part -and $matches[2] -like $Vendor -and $matches[3] -like $Product)) {
                                [PSCustomObject]@{
                                    Vulnerable            = [bool]$MatchCriteria.vulnerable
                                    Criteria              = $MatchCriteria.criteria
                                    MatchCriteriaID       = $MatchCriteria.matchCriteriaId
                                    ProductType           = $AffectedProductType
                                    Vendor                = if ($matches[2] -eq '*') { $null } else { $matches[2] } # Ternary operators not supported in PS5.1 so using if/else. If value is *, just ignore and treat as null.
                                    Product               = if ($matches[3] -eq '*') { $null } else { $matches[3] }
                                    Version               = if ($matches[4] -eq '*') { $null } else { $matches[4] }
                                    VersionStartIncluding = $MatchCriteria.versionStartIncluding
                                    VersionStartExcluding = $MatchCriteria.versionStartExcluding
                                    VersionEndIncluding   = $MatchCriteria.versionEndIncluding
                                    VersionEndExcluding   = $MatchCriteria.versionEndExcluding
                                    Update                = if ($matches[5] -eq '*') { $null } else { $matches[5] }
                                    Edition               = if ($matches[6] -eq '*') { $null } else { $matches[6] }
                                    Language              = if ($matches[7] -eq '*') { $null } else { $matches[7] }
                                    SWEdition             = if ($matches[8] -eq '*') { $null } else { $matches[8] }
                                    TargetSW              = if ($matches[9] -eq '*') { $null } else { $matches[9] }
                                    TargetHW              = if ($matches[10] -eq '*') { $null } else { $matches[10] }
                                    Other                 = if ($matches[11] -eq '*') { $null } else { $matches[11] }
                                }
                            }
                        }
                        else {
                            Write-Warning "Invalid match criteria: $($MatchCriteria.criteria)"
                        }
                    }

                    [PSCustomObject]@{
                        CVE              = $CVE.id
                        Published        = $CVE.published
                        LastModified     = $CVE.lastModified
                        CVSSv2Severity   = @($CVE.metrics.cvssMetricV2).Where({ $_.type -eq 'Primary' }).baseSeverity
                        CVSSv2Score      = @($CVE.metrics.cvssMetricV2).Where({ $_.type -eq 'Primary' }).cvssData.baseScore
                        CVSSv3Severity   = @($CVE.metrics.cvssMetricV31).Where({ $_.type -eq 'Primary' }).cvssData.baseSeverity
                        CVSSv3Score      = @($CVE.metrics.cvssMetricV31).Where({ $_.type -eq 'Primary' }).cvssData.baseScore
                        Exploited        = [bool]$CVE.cisaExploitAdd # Indicates whether the CVE has a known exploit listed on https://www.cisa.gov/known-exploited-vulnerabilities-catalog
                        Description      = @($CVE.descriptions).Where({ $_.lang -eq 'en' }).value
                        URL              = "https://nvd.nist.gov/vuln/detail/$($CVE.id)"
                        References       = $CVE.references.url
                        AffectedProducts = $AffectedProducts
                    }
                }

                # Increase the startIndex for the next request
                $Body.startIndex += $Body.resultsPerPage

            } until ($Body.startIndex -ge $Response.totalResults -or ($MaxResults -and $Body.startIndex -ge $MaxResults)) # Stop if the new startIndex is >= than either the totalResults of the specified MaxResults.
        }
    }

}