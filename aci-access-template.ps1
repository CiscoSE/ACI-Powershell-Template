<#
.NOTES
Copyright (c) 2022 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.

.SYNOPSIS
Example Script demonstrating access to ACI API using PowerShell. The output from this file is a list of switches in the ACI Fabric.

This script is not multisite aware, and will only return the leaf switches from one site.

.PARAMETER apic
The IP or FQDN resolving to the APIC IP address to be accessed.

.PARAMETER user
The user name to be used for authentication to the APIC. If no user name is specified, admin is assumed.

When no password is provided as a argument, it will be requested later. In windows systems the prompt will display the logon name, but changing the logon name in that window will not change the user.

.PARAMETER password
The password to be used to authenticate the user.

.PARAMETER domain
For authentication such as LDAP or TACACs, include the domain here. You cannot provide the domain name as part of the user name.

.PARAMETER failsafe
All post functions require the failsafe switch in order to execute. Be default changes to the APIC are not allowed. 
This capability is included to ensure that if the script is run accidently, no changes will be made.

Failsafe does not prevent a cookie from being obtained because 

.EXAMPLE 
This example will return a list of switches from 1.1.1.1 using the admin user and password. Verbose output will include the password provide.

.\aci-list-interface-stats.ps1 -apic 1.1.1.1 -user admin -password 'SomePassword' -verbose

.EXAMPLE
This example will return a list of switches from 1.1.1.1 without detailed output from the script.

.\aci-list-interface-stats.ps1 -apic 1.1.1.1 -user admin -password 'SomePassword'

.EXAMPLE
This example uses a domain reference to support remote authentication (LDAP or TACACs as examples) to the APIC.
The password in this case is requested seperately and is not passed as an argument. 

.\aci-list-interface-stats.ps1 -apic 1.1.1.1 -user SomeUser -domain SomeDomain

#>
[cmdletbinding(SupportsShouldProcess=$true)]

param(
    [parameter(mandatory=$true)] [string]$apic,
    [parameter(mandatory=$false)][string]$user='admin',   #If nothing is entered, admin is assumed
    [parameter(mandatory=$true)][SecureString]$password = (Read-Host -Prompt "Enter Password for $user" -AsSecureString ),
    [parameter(mandatory=$false)][string]$domain='',
    [parameter(mandatory=$false)][switch]$failsafe
)

$global:cookie = ''

function main {
    Param()
    #Request and validate that we have a cookie
    getCookie
    if ($Global:cookie -eq ''){
        write-host "Failed to get cookie. Script cannot continue. -Verbose may offer more information"
        exit
    }
    # Your Function Goes here.
    whatEverYouWantToDo
}


function whatEverYouWantToDo {
    param()
    Write-Host "When you put something here, it will do something here. :)"
    #Example line below so you know the format to send to getData
    #[xml]$returnedXML = getData -urlPath '/api/<YourpathintheAPI>.xml' -type Get
}

function getCookie{
    param()
    #Normalize user name if domain is not null
    if ($domain -ne ''){
        write-verbose "Domain Authentication detected - Converting username to remote authentication format"
        $user="apic:$($domain)\\$($user)"
    }
    else{
        write-verbose "Domain Authentication not detected, using local authentication"
    }

    $cookieResult = getData -data "<aaaUser name='$user' pwd='$([System.Net.NetworkCredential]::new('', $Password).Password)' />" -urlPath '/api/aaaLogin.xml' 
    if ($cookieResult.statusCode -eq 200) {
        write-verbose "Call to get cookie worked"
        Write-Verbose "Token`n$(([xml]$cookieResult.Content).ChildNodes.aaaLogin.token)"
        $Global:Cookie = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $tokenObj = New-Object System.Net.Cookie
        $tokenObj.Name = 'APIC-Cookie'
        $tokenObj.Value = ([xml]$cookieResult.Content).ChildNodes.aaaLogin.token
        $tokenObj.Domain = $apic
        $Global:Cookie.Cookies.add($tokenObj)
    }
    else{
        write-verbose "Call to get cookie failed"
        $cookieResult.content
    }
}

function urlFailure{
    param ()
    write-verbose "Failure detected to URL"
    write-debug -message "$($error[0])"
    if ($_.Exception.Response.StatusCode.Value__ -is [int]){
        switch ($_.Exception.Response.StatusCode.Value__){
            401 {
                "Access denied - Check host and credentials are correct"
                exit}
            Default{$_.Exception.Response.StatusCode.Value__}
    
        }
    }
    elseif ($_.exception){
        switch -Regex ($_.exception){
            "The operation has timed out" {
                "Host Address did not respond - check host address"
                exit
            }
            default {
                $_.exception
            }
        }
    }

}

function getData {
    param(
        [string   ]$data ='',
        [string   ]$urlPath,
        [string   ]$type='Post',
        [hashtable]$headers        = @{'Content-Type'='application/xml'},
        [int      ]$timeOutCounter =10
    )


    # Only visible when verbose is true 
    write-verbose "Calling APIC"
    write-verbose "`t`tAPIC:`t`t$apic"
    write-verbose "`t`tData:`t`t$data"
    write-verbose "`t`tURL:`t`t$urlPath"

    # Make sure we got a cookie and check for POST events
    if ($global:cookie -ne ''){
        if ($type.ToUpper() -eq "POST" -and $failsafe -eq $false){
            write-host "Cannot use post functions without failsafe. Script will exit"
            exit
        }
        $websession = $global:cookie
        write-verbose "Web Session Information is being used"
    }
    else{
        
    }

    # Make web call
    if ([int](get-host).version.major -le 5){
        # Ignore certificates that are unsigned and continue as supported in legacy powershell versions
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

        If ($Type.ToUpper() -eq "GET"){
            try {
                #Always requires a websession because you must have a token for this to be used.
                $result=Invoke-WebRequest -uri "https://$($apic)$($urlPath)" -method Get -TimeOutSec $timeOutCounter -WebSession $websession -headers $headers
            }
            catch{
                urlFailure
            }
        }
        elseif ($Type.ToUpper() -eq 'POST' -and $websession){
            try {
                #We use this exclusively once we have a taken because we need the websession variable to pass the token.
                $result=Invoke-WebRequest -uri "https://$($apic)$($urlPath)" -body "$($data)" -method Post -TimeOutSec $timeOutCounter -WebSession $websession -headers $headers
            }
            catch{
                urlFailure
            }
        }
        elseif ($type.ToUpper() -eq "POST" -and (-not $websession)){
            #Only used for getting the initial token. We use the result to extract the token.Cannot pass the websession because the token does not exist yet.
            try {
                $result=Invoke-WebRequest -uri "https://$($apic)$($urlPath)" -body "$($data)" -method Post -TimeOutSec $timeOutCounter -Headers $headers
            }
            catch{
                urlFailure
            }        
        }
    }
    else {
        #With version 7 or later we can use the a switch with Invoke-Webrequest to ensure self signed certificates do not impact connectivity.
        If ($Type.ToUpper() -eq "GET"){
            try {
                #Always requires a websession because you must have a token for this to be used.
                $result=Invoke-WebRequest -uri "https://$($apic)$($urlPath)" -method Get -TimeOutSec $timeOutCounter -WebSession $websession -headers $headers -SkipCertificateCheck
            }
            catch{
                urlFailure
            }
        }
        elseif ($Type.ToUpper() -eq 'POST' -and $websession){
            try {
                #We use this exclusively once we have a taken because we need the websession variable to pass the token.
                $result=Invoke-WebRequest -uri "https://$($apic)$($urlPath)" -body "$($data)" -method Post -TimeOutSec $timeOutCounter -WebSession $websession -headers $headers -SkipCertificateCheck
            }
            catch{
                urlFailure
            }
        }
        elseif ($type.ToUpper() -eq "POST" -and (-not $websession)){
            #Only used for getting the initial token. We use the result to extract the token.Cannot pass the websession because the token does not exist yet.
            try {
                $result=Invoke-WebRequest -uri "https://$($apic)$($urlPath)" -body "$($data)" -method Post -TimeOutSec $timeOutCounter -Headers $headers -SkipCertificateCheck
            }
            catch{
                urlFailure
            }        
        }
    }
    return $result
}

main