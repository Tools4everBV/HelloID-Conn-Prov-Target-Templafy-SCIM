#####################################################
# HelloID-Conn-Prov-Target-Templafy-Scim-Delete
#
# Version: 1.0.0.0
#####################################################
$VerbosePreference = "Continue"

# Initialize default value's
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json
$success = $false
$auditLogs = [Collections.Generic.List[PSCustomObject]]::new()

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
#endregion

# Process
if ($dryRun) {
    $auditMessage = "Account for: $($p.DisplayName) will be deleted"
}
if (-not ($dryRun -eq $true)) {    
    try {
        #Begin
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
   
        $success = $true
        $auditLogs.Add([PSCustomObject]@{
                Message = "Account for: $($p.DisplayName) was successful deleted. AccountReference is: $aRef"
                IsError = $False
            })
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
$result = [PSCustomObject]@{
    Success      = $success
    AuditLogs    = $auditLogs
    AuditDetails = $auditMessage
}
Write-Output $result | ConvertTo-Json -Depth 10
