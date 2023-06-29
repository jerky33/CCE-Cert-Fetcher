[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}


#Note: This Script looks for two files, Servers.txt (Required) and Creds.csv (Optional) in the same folder where the script is.
#region Initial Setup Vars
Set-Location -Path $PSScriptRoot
$InputServerList = ".\Servers.txt"
$ResultsFolder = "\CertFecth"
$global:ResultsPath = "$PSScriptRoot$($ResultsFolder)"
$HTMLFile = "CertFetchResult.htm"
$CsvFile = "CertFetchResult.csv"
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
    $webRequest = [Net.WebRequest]::Create($URL)
    Try {$webResponse = $webRequest.GetResponse()
        if ($webResponse){
            WriteResults "Pass" "- $CertType Web request successful, continuing to fetch cert " $ShwResMsg
        }
    }
    Catch{
        WriteResults "Fail" "- $CertType Web request failed to open page, but attempting to read cert" $ShwResMsg
    }
    Try {$cert = $webRequest.ServicePoint.Certificate
        if ($cert){
            WriteResults "Pass" "- $CertType Cert found continuing swith cert export" $ShwResMsg
            $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
            $chain.build($cert) | Out-Null
            $chain.ChainElements.Certificate | ForEach-Object {set-content -value $($_.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)) -encoding byte -path "$ResultsPath\$FQDN`_$CertType.cer"}
        }
        else{
            WriteResults "Fail" "- Unable to fetch $CertType cert continuing to next server/cert" $ShwResMsg
        }
    }
    Catch{
        WriteResults "Fail" "- Unable to fetch $CertType cert continuing to next server/cert" $ShwResMsg
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

#Get-SSLCert https://labsprawler-12.lab.local "labsprawler-12.lab.local"

#region ---------------------------------------Start Audit---------------------------------------
WriteResults "Default" "Starting Audit Checks for list of servers"
Get-Content $InputServerList | ForEach-Object {
    #region Audit Setup vars and Check for Server
    #Setup Audit Vars
    $global:Server = $_
    $HTMLFile = "$Server.htm"
    $CsvFile = "$Server.csv"
    Set-Content -Path "$ResultsPath\$HTMLFile" $HTMLOuputStart
    Set-Content -Path "$ResultsPath\$CsvFile" $null

    #Write Server name to results
    WriteResults "Default" "Server - `'$Server`'"

    #Check that the server is reachable
    WriteResults "Default" "Checking to see if `'$Server`' is online"

    if (Test-Connection -Count 2 -Quiet $Server){
        WriteResults "Pass" "- Server `'$Server`' Online - Continuing with Cert Fetch Tasks" $ShwResMsg
        Get-SSLCert https://$Server "$Server" iis
        Get-SSLCert "https://$Server`:7890/icm-dp/DiagnosticPortal" "$Server" dfp

        <#
        Write-Host $PWD
        Set-Location $env:CCE_JAVA_HOME\bin
        Write-Host $PWD
        Set-Location $PSScriptRoot
        Write-Host $PWD #>

    }
    else {
        WriteResults "Fail" "- Server `'$Server`' Offline - NOT Continuing with Cert Fetch Tasks" $ShwResMsg
    }
}

CloseScript