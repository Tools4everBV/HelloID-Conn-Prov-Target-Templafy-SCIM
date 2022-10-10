#####################################################
# HelloID-Conn-Prov-Target-Templafy-Scim-Create
#
# Version: 1.0.0.0
#####################################################
$VerbosePreference = "Continue"

# Initialize default value's
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$success = $false
$auditLogs = [Collections.Generic.List[PSCustomObject]]::new()

#correlation
$correlationField = 'sAMAccountName'
$correlationValue = $p.Accounts.MicrosoftActiveDirectory.sAMAccountName

$pdc = (Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain | Select-Object -Property PDCEmulator).PDCEmulator

$user = Get-ADUser -Filter "$correlationField -eq '$correlationValue'" -Server $pdc -Properties * | Select-Object -Property DisplayName, userPrincipalName, mail

#Write-Verbose -Verbose ($user | ConvertTo-Json)
$account = [PSCustomObject]@{
    ExternalId       = $p.ExternalId
    UserName         = $user.mail
    #UserName        = $user.mail
    GivenName        = $p.Name.GivenName
    FamilyName       = $user.sn
    DisplayName      = $user.DisplayName
    FamilyNamePrefix = ''
    #FamilyNamePrefix    = $p.Name.FamilyNamePrefix
    IsUserActive     = $true
    EmailAddress     = $user.mail
    EmailAddressType = 'Work'
    IsEmailPrimary   = $true
    Department       = $p.PrimaryContract.Department.DisplayName
    Organization     = 'Organisation Name'
    Title            = $p.PrimaryContract.Title.Name
}

Write-Verbose -Verbose $account.userName

function Invoke-ScimRestMethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.PowerShell.Commands.WebRequestMethod]
        $Method,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Uri,

        [object]
        $Body,

        [string]
        $ContentType = 'application/json',

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]
        $Headers,

        [string]
        $TotalResults
    )

    try {
        Write-Verbose -Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

        $baseUrl = $($config.BaseUrl)
        $splatParams = @{
            Uri         = "$baseUrl/$Uri"
            Headers     = $Headers
            Method      = $Method
            ContentType = $ContentType
        }

        if ($Body) {
            Write-Verbose -Verbose 'Adding body to request'
            $splatParams['Body'] = $Body
        }

        if ($TotalResults) {
            # Fixed value since each page contains 20 items max
            $count = 20

            [System.Collections.Generic.List[object]]$dataList = @()
            Write-Verbose -Verbose 'Using pagination to retrieve results'
            do {
                #Write-Verbose -Verbose $dataList.Count
                $startIndex = $dataList.Count + 1
                $splatParams['Uri'] = "$($baseUrl)/$($Uri)?startIndex=$startIndex&count=$count"
                $result = Invoke-RestMethod @splatParams
                foreach ($resource in $result.Resources) {
                    $dataList.Add($resource)
                }
            } until ($dataList.Count -eq $TotalResults)
            Write-Output $dataList
        }
        else {
            Invoke-RestMethod @splatParams
        }
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $HttpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            $HttpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $stream = $ErrorObject.Exception.Response.GetResponseStream()
            $stream.Position = 0
            $streamReader = New-Object System.IO.StreamReader $Stream
            $errorResponse = $StreamReader.ReadToEnd()
            $HttpErrorObj.ErrorMessage = $errorResponse
        }
        Write-Output $HttpErrorObj
    }
}
#endregion

try {
    #Begin
    Write-Verbose 'Retrieving accessToken'
    $accessToken = $config.ClientSecret
    
    $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
    $headers.Add("Authorization", "Bearer $accessToken")

    Write-Verbose 'Getting total number of users'
    $response = Invoke-ScimRestMethod -Uri 'Users' -Method 'GET' -headers $headers
    $totalResults = $response.totalResults    

    Write-Verbose "Retrieving '$totalResults' users"
    $responseAllUsers = Invoke-ScimRestMethod -Uri 'Users' -Method 'GET' -headers $headers -TotalResults $totalResults

    
    Write-Verbose "Verifying if account for '$($p.DisplayName)' must be created or correlated"
    $lookup = $responseAllUsers | Group-Object -Property 'externalId' -AsHashTable
    #$lookup = $responseAllUsers | Group-Object -Property 'UserName' -AsHashTable
    
    #Write-Verbose -Verbose ($lookup | ConvertTo-Json)
    $userObject = $lookup[$account.ExternalId]
    #$userObject = $lookup[$account.UserName]

    #Write-Verbose -Verbose ($userObject | ConvertTo-Json)
    if ($userObject) {
        Write-Verbose "Account for '$($p.DisplayName)' found with id '$($userObject.id)', switching to 'correlate'"
        $action = 'Correlate'
    }
    else {
        Write-Verbose "No account for '$($p.DisplayName)' has been found, switching to 'create'"
        $action = 'Create'
    }

    # Add an auditMessage showing what will happen during enforcement
    if ($dryRun) {
        $auditMessage = "$action account for: $($p.DisplayName) will be executed during enforcement"
    }    

    # Process
    if (-not ($dryRun -eq $true)) {
        switch ($action) {
            'Create' {
                Write-Verbose "Creating account for '$($p.DisplayName)'"

                [System.Collections.Generic.List[object]]$emailList = @()
                $emailList.Add(
                    [PSCustomObject]@{
                        primary = $account.IsEmailPrimary
                        type    = $account.EmailAddressType
                        display = $account.EmailAddress
                        value   = $account.EmailAddress
                    }
                )

                $body = [ordered]@{
                    schemas      = @(
                        "urn:ietf:params:scim:schemas:core:2.0:User",
                        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
                    )
                    externalId   = $account.ExternalID
                    userName     = $account.UserName
                    active       = $account.IsUserActive
                    emails       = $emailList
                    meta         = @{
                        resourceType = "User"
                    }
                    name         = [ordered]@{
                        formatted  = $account.DisplayName
                        familyName = $account.FamilyName
                        middleName = $account.FamilyNamePrefix
                        givenName  = $account.GivenName
                    }
                    displayName  = $account.DisplayName
                    department   = $account.Department
                    organization = $account.Organization
                    title        = $account.Title

                } | ConvertTo-Json

                $response = Invoke-ScimRestMethod -Uri 'Users' -Method 'POST' -body $body -headers $headers
                
                # Set aRef object for use in futher actions
                $aRef = $response.id                    
                break
            }

            'Correlate' {
                Write-Verbose "Correlating account for '$($p.DisplayName)'"
                # Set aRef object for use in futher actions
                $aRef = $userObject.id                    
                break
            }
        }

        $success = $true
        $auditLogs.Add([PSCustomObject]@{
                Message = "$action account for: $($p.DisplayName) was successful. AccountReference is: $aRef"
                IsError = $False
            })
    }
}
catch {
    $success = $false
    $ex = $PSItem
    if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-HTTPError -Error $ex
        $errorMessage = "Could not create scim account for: $($p.DisplayName). Error: $($errorObj.ErrorMessage)"
    }
    else {
        $errorMessage = "Could not create scim account for: $($p.DisplayName). Error: $($ex.Exception.Message)"
    }
    Write-Error $errorMessage
    $auditLogs.Add([PSCustomObject]@{
            Message = $errorMessage
            IsError = $true
        })
    # End
}

$result = [PSCustomObject]@{
    Success          = $success
    AccountReference = $aRef
    Auditlogs        = $auditLogs
    AuditDetails     = $auditMessage
    Account          = $account

    # Optionally return data for use in other systems
    ExportData       = [PSCustomObject]@{
        Gebruiker = $aRef
        UserName  = $account.UserName
        Mail      = $account.EmailAddress
    }; 
}
Write-Output $result | ConvertTo-Json -Depth 10
