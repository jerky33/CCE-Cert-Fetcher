[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

#This script can be used to fetch all the certificates from CCE Servers and will also report if the certificates are expired or going to
#expire within the next 60 days.
#Note: This Script looks for a file name Servers.cvp (Required) in the same folder where the script is.
#region Initial Setup Vars
Set-Location -Path $PSScriptRoot
$InputServerList = ".\Servers.csv"
$ResultsFolder = "\CertFetch"
$global:ResultsPath = "$PSScriptRoot$($ResultsFolder)"
$global:HTMLFile = "CertFetchResult.htm"
$global:CsvFile = "CertFetchResult.csv"
$global:TodaysDate = Get-Date
$ShwResMsg = $true
$global:HTMLOuputStart = "<html><body><br><b>CCE Cert Fetch Results</b></body><html>
<html><body>"
$global:HTMLOuputEnd = "</body></html>"


#Write results to CSV, html file and PowerShell window
#To use function, send it the message status (Pass, Fail, Warning or Default) then the string to write to audit result to files
#and lastly the variable $ShwResMsg if you want the message status to be displayed at the end of the message line
Function WriteResults ($msgStatus,$String,$ShwResMsg){
    if ($msgStatus -eq "Pass") {$HtmlColor = "008000"; $ConsColor = "Green"}
    elseif ($msgStatus -eq "Fail") {$HtmlColor = "F00000"; $ConsColor = "Red"}
    elseif ($msgStatus -eq "Warning") {$HtmlColor = "FFC000"; $ConsColor = "Yellow"}
    else {$HtmlColor = "000000"; $ConsColor = "White"}
    if ($ShwResMsg) {
        if ($ConsColor -eq "White") {
            Add-Content "$ResultsPath\$HTMLFile" "<br><font color =`"#$HtmlColor`"></font>"
            Add-Content "$ResultsPath\$HTMLFile" "<br><font color =`"#$HtmlColor`">$String - $msgStatus</font>"
            Add-Content -Path "$ResultsPath\$CsvFile" ""
            Add-Content -Path "$ResultsPath\$CsvFile" "`'$String`',`'- $msgStatus`'"
            Write-Host -ForegroundColor $ConsColor "`n$String - $msgStatus"
        }else {
            Add-Content "$ResultsPath\$HTMLFile" "<br><font color =`"#$HtmlColor`">$String - $msgStatus</font>"
            Add-Content -Path "$ResultsPath\$CsvFile" "`'$String`',`'- $msgStatus`'"
            Write-Host -ForegroundColor $ConsColor "$String - $msgStatus"
        }
        
    }
    else {
        if ($ConsColor -eq "White") {
            Add-Content "$ResultsPath\$HTMLFile" "<br><font color =`"#$HtmlColor`"></font>"
            Add-Content "$ResultsPath\$HTMLFile" "<br><font color =`"#$HtmlColor`">$String</font>"
            Add-Content -Path "$ResultsPath\$CsvFile" ""
            Add-Content -Path "$ResultsPath\$CsvFile" "`'$String`',"
            Write-Host -ForegroundColor $ConsColor "`n$String"
        }else {
            Add-Content "$ResultsPath\$HTMLFile" "<br><font color =`"#$HtmlColor`">$String</font>"
            Add-Content -Path "$ResultsPath\$CsvFile" "`'$String`',"
            Write-Host -ForegroundColor $ConsColor "$String"
        }
    }
}

Function CloseHtml {
    Add-Content "$ResultsPath\$HTMLFile" $HTMLOuputEnd
}

Function Get-SSLCert ($URL, $FQDN, $CertType){
    <#$webRequest = [Net.WebRequest]::Create("https://www.outlook.com")
    try { $webRequest.GetResponse() } catch {}
    $cert = $webRequest.ServicePoint.Certificate
    $bytes = $cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    set-content -value $bytes -encod byte -path "$pwd\Outlook.Com.cer"ing
    #>
    $webRequest = [Net.WebRequest]::Create($URL)
    Try {$webResponse = $webRequest.GetResponse()
        if ($webResponse){
            WriteResults "Pass" "- $CertType Web request successful, continuing to fetch cert " $ShwResMsg
        }
    }
    Catch{
        WriteResults "Warning" "- $CertType Web request failed to open page, but attempting to read cert" $ShwResMsg
    }
    Try {$cert = $webRequest.ServicePoint.Certificate
        if ($cert){
            WriteResults "Pass" "- $CertType Cert found continuing with cert export" $ShwResMsg
            $bytes = $cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            set-content -value $bytes -encod byte -path "$ResultsPath\$FQDN`_$CertType.cer"
            $CertDir = "$PWD\CertFetch"
            $CRT = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 "$CertDir\$FQDN`_$CertType.cer"
            $DateExpire = $CRT.GetExpirationDateString()
            $ThirtyDaysOut = $TodaysDate.AddDays(30)
            $SixtyDaysOut = $TodaysDate.AddDays(60)
            $ValidDaysRemaining = New-TimeSpan -Start $TodaysDate -End $DateExpire | Select-Object -ExpandProperty Days
            if ($DateExpire -lt $SixtyDaysOut){
                WriteResults "Warning" "- - Certificate expiring within 60 days" $ShwResMsg
                WriteResults "Default" " "
            }
            elseif ($DateExpire -gt $SixtyDaysOut) {
                WriteResults "Pass" "- - Certificate valid for more than 60 days, $ValidDaysRemaining Days remaining" $ShwResMsg
                WriteResults "Default" " "
            }
        }
        else{
            WriteResults "Fail" "- Unable to fetch $CertType cert continuing to next server/cert" $ShwResMsg
            WriteResults "Default" " "
        }
    }
    Catch{
        WriteResults "Fail" "- Unable to fetch $CertType cert continuing to next server/cert" $ShwResMsg
        WriteResults "Default" " "
    }
}


Function CloseScript {
    CloseHtml
    Write-Host "Press Enter to close this script"
    $endvar = Read-Host
    Exit
}

#Check to see if the Cert Fetch Results folder is present
Write-Host "Checking to see if the Cert Fetch Results folder is present"
if (Test-Path -Path $ResultsPath){
    WriteResults "Pass" "- Cert Fetch Results folder found, proceeding" $ShwResMsg
}
else{
    Write-Host "Cert Fetch Results folder NOT Found, creating one"
    New-Item $ResultsPath -ItemType "Directory"
}

Set-Content -Path "$ResultsPath\$HTMLFile" $HTMLOuputStart
Set-Content -Path "$ResultsPath\$CsvFile" $null

#Check to see if the Server list is present
WriteResults "Default" "Checking to see if the Server list is present"
if (Test-Path -Path $InputServerList){
    WriteResults "Pass" "- Server list file found, proceeding" $ShwResMsg
    if (("" -eq ($global:TestServer = Get-Content $InputServerList))-or($null -eq ($global:TestServer = Get-Content $InputServerList))){
        WriteResults "Fail" "- No Servers in List File - Nothing to check." $ShwResMsg
        WriteResults "Fail" "- Exiting, press any key to exit script"
        CloseScript
    }
}

#region ---------------------------------------Start Cert Fetch---------------------------------------
WriteResults "Default" "Starting Audit Checks for list of servers"
$ServerList = Import-Csv $InputServerList
foreach ($ServerObj in $ServerList){
    #Write-Host $Server.ServerName $Server.ServerType
    $global:Server = $ServerObj.ServerName
    $global:UrlSuffix = $ServerObj.ThirdPartyUrlSuffix
    if (Test-Connection -Count 2 -Quiet $Server){
        WriteResults "Pass" "- Server `'$Server`' Online - Continuing with Cert Fetch Tasks" $ShwResMsg
        if ($ServerObj.ServerType -eq "cce"){
            WriteResults "Default" "$Server is a CCE server" $ShwResMsg
            Get-SSLCert https://$Server "$Server" cce-iis
            Get-SSLCert "https://$Server`:7890/icm-dp/DiagnosticPortal" "$Server" cce-dfp
        }
        elseif ($ServerObj.ServerType -eq "cvp"){
            WriteResults "Default" "$Server is a CVP server" $ShwResMsg
            Get-SSLCert "https://$Server`:8111" "$Server" cvpwsm
        }
        elseif ($ServerObj.ServerType -eq "cvpops"){
            WriteResults "Default" "$Server is a CVP Ops server" $ShwResMsg
            Get-SSLCert "https://$Server`:8111" "$Server" cvp-wsm
            Get-SSLCert "https://$Server`:9443" "$Server" cvp-oamp
        }
        elseif ($ServerObj.ServerType -eq "vvb"){
            WriteResults "Default" "$Server is a CVP server" $ShwResMsg
            Get-SSLCert "https://$Server/appadmin/main" "$Server" vvb
        }
        elseif ($ServerObj.ServerType -eq "3rdParty"){
            WriteResults "Default" "$Server is a 3rd Party server" $ShwResMsg
            Get-SSLCert "https://$Server$UrlSuffix" "$Server" 3rdParty
        }
    }
    else {
        WriteResults "Fail" "- Server `'$Server`' Offline - NOT Continuing with Cert Fetch Tasks" $ShwResMsg
    }
}

CloseScript