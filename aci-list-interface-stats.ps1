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

.PARAMETER rmonErrorReport
Produces a TSV formated report of interface errors for all interfaces in the fabric.

.PARAMETER interfaceReport
Procuces a TSV formated report of all interfaces in the fabric.

.PARAMETER ethernetStatsReport
Produces a TSV formated report of the ethernet statistics for each interface in the fabric

.EXAMPLE 
This example will return a list of interfaces from all leaf and spine switches from 1.1.1.1 using the admin user and password. Verbose output will include the password provide.

.\aci-list-interface-stats.ps1 -apic 1.1.1.1 -user admin -password 'SomePassword' -interfaceReport -verbose

.EXAMPLE
This example will return a list of interface errors from 1.1.1.1 without detailed output from the script.

.\aci-list-interface-stats.ps1 -apic 1.1.1.1 -user admin -password 'SomePassword' -rmonErrorReport

.EXAMPLE
This example uses a domain reference to support remote authentication (LDAP or TACACs as examples) to the APIC.
The password in this case is requested seperately and is not passed as an argument. 

.\aci-list-interface-stats.ps1 -apic 1.1.1.1 -user SomeUser -domain SomeDomain -interfaceReport

.EXAMPLE
Produces both the interface report and the ethernet statistics in TSV format for from apic 1.1.1.1

.\aci-list-interface-stats.ps1 -apic 1.1.1.1 -user SomeUser -domain SomeDomain -interfaceReport -ethernetStatsReport

#>
[cmdletbinding(SupportsShouldProcess=$true)]

param(
    [parameter(mandatory=$true)] [string]$apic,
    [parameter(mandatory=$false)][string]$user='admin',   #If nothing is entered, admin is assumed
    [parameter(mandatory=$false)] [string]$password = (Read-Host -Prompt "Enter Password for $user"),
    [parameter(mandatory=$false)][string]$domain='',
    [parameter(mandatory=$false)][string]$reportDirectory="Reports/",
    [parameter(mandatory=$false)][string]$tsvrmonErrorReportPath = "$($reportDirectory)$(get-date -format "yyyyMMdd-HHmmss")-rmonError-report.tsv",
    [parameter(mandatory=$false)][string]$tsvInterfaceReportPath = "$($reportDirectory)$(get-date -format "yyyyMMdd-HHmmss")-interface-report.tsv",
    [parameter(mandatory=$false)][string]$tsvEthernetStatsReportPath = "$($reportDirectory)$(get-date -format "yyyyMMdd-HHmmss")-EthernetStats-report.tsv",
    [parameter(mandatory=$false)][switch]$failsafe,
    [parameter(mandatory=$false)][switch]$rmonErrorReport,
    [parameter(mandatory=$false)][switch]$interfaceReport,
    [parameter(mandatory=$false)][switch]$ethernetStatsReport

)
# We change this at the top to make it obvious what is happening. We cannot pass a secure string to the script from an 
# argument, so we immidiately convert a string to a secure string to improve protection of the password during run time.
[securestring]$password = ($password | ConvertTo-SecureString -AsPlainText -force)

# We use this to authenticate once a cookie is obtained. By making it global we can use it anywhere. 
$global:cookie = ''

$global:rmonErrorReportOutput = @()
$global:interfaceReportOutput = @()
$global:ethernetStatsReportOutput = @()

function main {
    Param()
    # Make sure the report directory exists and create it if it doesn't
    reportDirectoryCheck
    #Request and validate that we have a cookie
    getCookie
    if ($Global:cookie -eq ''){
        write-host "Failed to get cookie. Script cannot continue. -Verbose may offer more information"
        exit
    }
    # Call function to return a list of 
    getAllLeafSwitches
    #Send generated reports to file as TSV files
    if ($global:rmonErrorReportOutput -ne '')     {$global:rmonErrorReportOutput     | ConvertTo-Csv -Delimiter "`t" | out-file $tsvrmonErrorReportPath     -force}
    if ($global:interfaceReportOutput -ne '')     {$global:interfaceReportOutput     | ConvertTo-Csv -Delimiter "`t" | Out-File $tsvInterfaceReportPath     -force}
    if ($global:ethernetStatsReportOutput -ne '') {$global:ethernetStatsReportOutput | ConvertTo-Csv -Delimiter "`t" | Out-File $tsvEthernetStatsReportPath -force}
}

function reportDirectoryCheck {
    param()
    $error.clear()
    if (test-path -Path $reportDirectory){
        write-verbose "Report Directory already exists."
    }
    else{
        write-verbose "Report Directory Does not exist. Creating directory"
        new-item -path $reportDirectory -ItemType Directory
        if ($error[0]){
            write-host "Failed to create diretory for reports. Script will exit"
            exit
        }
    }
}

function getAllLeafSwitches{
    param()
    [xml]$listOfSwitches = getData -urlPath '/api/node/class/fabricNode.xml' -type Get
    $listOfSwitches.imdata.fabricNode | Where-Object{$_.role -match "leaf|spine"} | sort-object dn | ForEach-Object{
        getInterfaces -currentSwitch $_
    }
}

function getInterfaces{
    param(
        $currentSwitch
    )
    $interfaceListResult = @()
    $listOfInterfaces = New-Object 'System.Collections.Generic.List[PSObject]'
    [xml]$interfaceList = (getData -urlPath "/api/node/mo/$($currentSwitch.dn)/sys.xml?query-target=children" -type Get).Content
    $interfaceList.imdata.l1PhysIf.dn | ForEach-Object {
        $thisInterface = $_  | Select-Object `
            @{name="Switch";Expression={[int](($_ -split("/sys/"))[0] -split('node-'))[1]}},    
            @{Name="Module";Expression={[int]((($_ -split('\['))[1] -replace('\]|\}','') -split('/'))[0] -replace('\D','')) }},
            @{Name="Port";Expression={[int](($_ -split('\['))[1] -replace('\]|\}','') -split('/'))[1] }},
            @{Name="DN";Expression={$_}}
        $listOfInterfaces += $thisInterface
    }
    $listOfInterfaces | sort-object "Switch",Module,Port | ForEach-Object{
        $interfaceListResult += (getInterfaceStats -currentInterfaceObj $_)
    }
    $interfaceListResult | format-table -AutoSize    
}

function getInterfaceStats {
    param(
        $currentInterfaceObj
    )
    write-verbose "Getting all stats from Interface $($currentInterfaceObj.dn)"
    $interfaceRequest= "/api/node/mo/$($_.dn).xml?query-target=children"
    write-verbose "`t$($interfaceRequest)"
    [xml]$interfaceStats = (getData -urlPath "$($interfaceRequest)" -type Get ).content
    $returnList = $InterfaceStats.imdata | Select-Object `
        @{Name="Switch";   Expression={$currentInterfaceObj.switch}},
        @{Name="Interface";Expression={($currentInterfaceObj.dn -split("phys-"))[1] -replace("\[|\]",'')}},
        @{Name="OperationalState";Expression={$_.ethpmPhysIf.operSt}},
        @{Name="OperationalSpeed";Expression={$_.ethpmPhysIf.operSpeed}},
        @{Name="Usage";Expression={$_.ethpmPhysIf.usage}},
        @{Name="CRCerrors";Expression={$_.rmonEtherStats.cRCAlignErrors}},
        @{Name="DropEvents";Expression={$_.rmonEtherStats.dropEvents}},
        @{Name="Collisions";Expression={$_.rmonEtherStats.collisions}},
        @{Name="UnderSizedPackets";Expression={$_.rmonEtherStats.undersizePkts}},
        @{Name="fragments";Expression={$_.rmonEtherStats.fragments}}
    if ($ethernetStatsReport){$global:ethernetStatsReportOutput += ($interfaceStats.imdata.rmonEtherStats | Select-Object `
        @{name='Switch';Expression={$currentInterfaceObj.switch}},
        @{Name="Interface";Expression={($currentInterfaceObj.dn -split("phys-"))[1] -replace("\[|\]",'')}},
        broadcastPkts,
        cRCAlignErrors,
        collisions,
        dropEvents,
        fragments,
        jabbers,
        multicastPkts,
        octets,
        oversizePkts,
        pkts,
        pkts1024to1518Octets,
        pkts128to255Octets,
        pkts256to511Octets,
        pkts512to1023Octets,
        pkts64Octets,
        pkts65to127Octets,
        rXNoErrors,
        rxGiantPkts,
        rxOversizePkts,
        tXNoErrors,
        txGiantPkts,
        txOversizePkts,
        undersizePkts
        )}
    if ($interfaceReport){$global:interfaceReportOutput += ($interfaceStats.imdata.ethpmPhysIf)}
    if ($rmonErrorReport){
        $global:rmonErrorReportOutput += ($interfaceStats.imdata.rmonDot3Stats | select-object `
            @{name='Switch';Expression={$currentInterfaceObj.switch}},
            @{name='Module';Expression={$currentInterfaceObj.module}},
            @{name='Port';Expression={$currentInterfaceObj.port}},
            alignmentErrors,
            carrierSenseErrors,
            childAction,
            clearTs,
            controlInUnknownOpcodes,
            deferredTransmissions,
            excessiveCollisions,
            fCSErrors,
            frameTooLongs,
            inLlfcFrames,
            inPauseFrames,
            inPri0PauseFrames,
            inPri1PauseFrames,
            inPri2PauseFrames,
            inPri3PauseFrames,
            inPri4PauseFrames,
            inPri5PauseFrames,
            inPri6PauseFrames,
            inPri7PauseFrames,
            inStandardPauseFrames,
            internalMacReceiveErrors,
            internalMacTransmitErrors,
            lateCollisions,
            modTs,
            multipleCollisionFrames,
            outLlfcFrames,
            outPauseFrames,
            outPri0PauseFrames,
            outPri1PauseFrames,
            outPri2PauseFrames,
            outPri3PauseFrames,
            outPri4PauseFrames,
            outPri5PauseFrames,
            outPri6PauseFrames,
            outPri7PauseFrames,
            singleCollisionFrames,
            sQETTestErrors,
            status,
            symbolErrors)
    } 
    return $returnList   
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