#####################################################
# HelloID-Conn-Prov-Target-Templafy-Scim-Update
#
# Version: 1.0.0.0
#####################################################
$VerbosePreference = "Continue"

# Initialize default value's
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$pd = $personDifferences | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json
$success = $false
$auditLogs = [Collections.Generic.List[PSCustomObject]]::new()

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

#correlation
$correlationField = 'sAMAccountName'
$correlationValue = $p.Accounts.MicrosoftActiveDirectory.sAMAccountName

$pdc = (Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain | Select-Object -Property PDCEmulator).PDCEmulator
$user = Get-ADUser -Filter "$correlationField -eq '$correlationValue'" -Server $pdc -Properties * | Select-Object -Property *

$account = [PSCustomObject]@{
    ExternalId       = $p.ExternalId #.New
    UserName         = $user.mail
    GivenName        = $p.Name.GivenName #.New
    #FamilyName          = $p.Name.FamilyName.New
    FamilyName       = $user.sn
    DisplayName      = $user.DisplayName
    #FamilyNamePrefix    = $p.Name.FamilyNamePrefix.New
    FamilyNamePrefix = ''
    IsUserActive     = $true
    EmailAddress     = $user.mail    
    EmailAddressType = 'Work'
    IsEmailPrimary   = $true
    Department       = $p.PrimaryContract.Department.DisplayName #.New
    Organization     = "Organisation Name"
    Title            = $p.PrimaryContract.Title.Name #.New
}

$previousAccount = [PSCustomObject]@{
    Gebruiker = $p.Accounts._d20e40840f0466d8139a740f93e15bcc.Gebruiker
    UserName  = $p.Accounts._d20e40840f0466d8139a740f93e15bcc.UserName
    Mail      = $p.Accounts._d20e40840f0466d8139a740f93e15bcc.Mail
}

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

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]
        $Headers,

        [string]
        $TotalResults
    )

    try {
        Write-Verbose -Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        
        $baseUrl = $($config.BaseUrl)
        $splatParams = @{
            Uri     = "$baseUrl/$Uri"
            Headers = $Headers
            Method  = $Method        
        }

       

        if ($Body) {
            Write-Verbose -Verbose 'Adding body to request'
            $splatParams['Body'] = $Body
        }
        
        $result = Invoke-RestMethod @splatParams
        Write-Output $result
        
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

function CreateScimAccount {
    try {
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
            department   = $account.department
            organization = $account.organization
            title        = $account.title

        } | ConvertTo-Json

        $response = Invoke-ScimRestMethod -Uri 'Users' -Method 'POST' -body $body -headers $headers
                
        # Set aRef object for use in futher actions
        $aRef = $response.id     
        $success = $true
        $auditLogs.Add([PSCustomObject]@{
                Message = "$action account for: $($p.DisplayName) was successful. AccountReference is: $aRef"
                IsError = $False
            })                   
        break
            
    }
    catch {
        $ex = $PSItem
        if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $errorObj = Resolve-HTTPError -Error $ex
            $errorMessage = "Could not create new scim account for: $($p.DisplayName). Error: $($errorObj.ErrorMessage)"
        }
        else {
            $errorMessage = "Could not create new scim account for: $($p.DisplayName). Error: $($ex.Exception.Message)"
        }
        Write-Error $errorMessage
        $success = $false
        $auditLogs.Add([PSCustomObject]@{
                Message = $errorMessage
                IsError = $true
            })        
    }    
}

function DeleteScimAccount {
    try {
        Write-Verbose 'Retrieving accessToken'
        $accessToken = $config.ClientSecret
    
        Write-Verbose 'Adding authorization headers'
        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $headers.Add("Authorization", "Bearer $accessToken")

        $body = [ordered]@{
            schemas = @(
                "urn:ietf:params:scim:api:messages:2.0:PatchOp"
            )        
        } | ConvertTo-Json -Depth 10

        Write-Verbose 'Delete user'
        $null = Invoke-ScimRestMethod -Uri "Users/$aRef" -Headers $headers -Body $body -Method 'DELETE'
        $auditLogs.Add([PSCustomObject]@{
                Message = "Account for: $($p.DisplayName) was delete successfully. AccountReference is: $aRef"
                IsError = $False
            })    
        $deleted = $true
    }
    catch {
        $success = $false
        $ex = $PSItem
        
        if ($ex -like "*resource $aRef not found*") {
            Write-Verbose -Verbose "1"
            $errorMessage = "Could not delete templafy scim account for: $($p.DisplayName). Templafy account doesn't exist for $($aRef)."
            $auditLogs.Add([PSCustomObject]@{
                    Message = $errorMessage
                    IsError = $false
                })  
            $success = $true
            
        }
        elseif ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            Write-Verbose -Verbose "2"
            $errorObj = Resolve-HTTPError -Error $ex
            $errorMessage = "Could not delete templafy scim account for: $($p.DisplayName). Error: $($errorObj.ErrorMessage)"
            Write-Error $errorMessage
            $auditLogs.Add([PSCustomObject]@{
                    Message = $errorMessage
                    IsError = $true
                })        
        }
        else {
            Write-Verbose -Verbose "3"
            $errorMessage = "Could not delete templafy scim account for: $($p.DisplayName). Error: $($ex.Exception.Message)"
            Write-Error $errorMessage
            $auditLogs.Add([PSCustomObject]@{
                    Message = $errorMessage
                    IsError = $true
                })        
        }
                
    }
    
}
#endregion

# Process
if ($dryRun) {
    $auditMessage = "Account for: $($p.DisplayName) will be updated"
}
if (-not ($dryRun -eq $true)) {
    if ($account.EmailAddress -ne $previousAccount.Mail -or $account.UserName -ne $previousAccount.UserName) {
        $deleted = $false    
        Write-Verbose "Deleting account '$($aRef)' for '$($p.DisplayName)'"
        DeleteScimAccount
        if ($deleted) {
            Write-Verbose "Creating new account for '$($p.DisplayName)'"
            CreateScimAccount
        }
    }
    else {
        try {
            Write-Verbose "Updating account '$($aRef)' for '$($p.DisplayName)'"
        
            #Begin
            Write-Verbose 'Retrieving accessToken'
            $accessToken = $config.ClientSecret
    
            Write-Verbose 'Adding authorization headers'
            $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
            $headers.Add("Authorization", "Bearer $accessToken")

            [System.Collections.Generic.List[object]]$operations = @()

            if ($pd.Name.Convention.Change -eq "Updated" -or $account.GivenName ) {                

                $operations.Add(
                    [PSCustomObject]@{
                        op    = "Replace"
                        path  = "name.formatted"
                        value = $account.DisplayName
                    }
                ) 

                $operations.Add(
                    [PSCustomObject]@{
                        op    = "Replace"
                        path  = "name.familyName"
                        value = $account.FamilyName
                    }
                ) 

                $operations.Add(
                    [PSCustomObject]@{
                        op    = "Replace"
                        path  = "name.middleName"
                        value = $account.FamilyNamePrefix
                    }
                ) 

                $operations.Add(
                    [PSCustomObject]@{
                        op    = "Replace"
                        path  = "name.givenName"
                        value = $account.GivenName
                    }
                )
            }

            if ($account.Department) {
                $operations.Add(
                    [PSCustomObject]@{
                        op    = "Replace"
                        path  = "department"
                        value = $account.department
                    }
                )
            }

            if ($account.Title) {
                $operations.Add(
                    [PSCustomObject]@{
                        op    = "Replace"
                        path  = "title"
                        value = $account.title                        
                    }
                )
            }

            $body = [ordered]@{
                schemas    = @(
                    "urn:ietf:params:scim:api:messages:2.0:PatchOp"
                )
                Operations = $operations
            } | ConvertTo-Json

            $splatParams = @{
                Uri         = "$($config.BaseUrl)/Users/$aRef"
                Headers     = $headers
                Body        = $body
                ContentType = 'application/json'
                Method      = 'PATCH'
            }


            Write-Verbose -Verbose $body
            $results = Invoke-RestMethod @splatParams
        
            if ($results.id) {
                $success = $true
                $auditLogs.Add([PSCustomObject]@{
                        Message = "Account for: $($p.DisplayName) was successful updated. AccountReference is: $aRef"
                        IsError = $False
                    })
            }
        }

        catch {
            $success = $false
            $ex = $PSItem
            Write-Verbose -Verbose ($ex | ConvertTo-Json)
            if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
                $errorObj = Resolve-HTTPError -Error $ex
                $errorMessage = "Could not update templafy scim account for: $($p.DisplayName). Error: $($errorObj.ErrorMessage)"
            }
            else {
                $errorMessage = "Could not update templafy scim account for: $($p.DisplayName). Error: $($ex.Exception.Message)"
            }
            Write-Error $errorMessage
            $auditLogs.Add([PSCustomObject]@{
                    Message = $errorMessage
                    IsError = $true
                })
            # End
        }
    }
}
$result = [PSCustomObject]@{
    Success          = $success
    AccountReference = $aRef
    PreviousAccount  = $previousAccount
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
