####
##Functions
####
#http://jongurgul.com/blog/get-stringhash-get-filehash/
function Get-StringHash ([string]$String,$HashName = "MD5")
{
  $StringBuilder = New-Object System.Text.StringBuilder
  [System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String)) | ForEach-Object {
    [void]$StringBuilder.Append($_.ToString("x2"))
  }
  $StringBuilder.ToString()
}

function Export-sendMail
{
  $EmailLoginPassWord = ConvertTo-SecureString -String $EmailLoginPass -AsPlainText -Force
  $EmailLoginCredential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $EmailLoginUserName,$EmailLoginPassWord

  $EmailBodyText = Get-Content '.\assets\emailBody.html' -Raw
  $EmailBodyText = Invoke-Expression """$EmailBodyText"""
  $From = "connect@fire-light.us"
  $Cc = "webmaster@fire-light.us"
  $Subject = "AD\$SamAccountName New Account Instructions"

  $param = @{
    SmtpServer = 'smtp.zoho.com'
    Port = 587
    UseSsl = $true
    Credential = $EmailLoginCredential
    From = $From
    To = $UserEmailAddress
    Subject = $Subject
    Body = $EmailBodyText
    BodyAsHtml = $true
  }
  Send-MailMessage @param
}

function Get-UserVariables {
  #Initial User Variables

  $script:UserFirstName = Read-Host -Prompt 'Input User First Name'
  $script:UserMiddleInitial = Read-Host -Prompt 'Input User Middle Initial'
  $script:UserLastName = Read-Host -Prompt 'Input User last Name'
  $script:UserEmailAddress = Read-Host -Prompt 'Input User Email Address'
  $script:isInternalSwitch = Read-Host -Prompt "Is User Internal?`n[Y] Yes or [N] No"
  $script:isInternalSwitch = $isInternalSwitch.ToLower()



  $script:UserFirstInitial = $UserFirstName.Substring(0,1).ToLower()
  $script:UserMiddleInitialUpper = $UserMiddleInitial.ToUpper()
  $script:UserMiddleInitialLower = $UserMiddleInitial.ToLower()
  $script:UserLastNameLower = $UserLastName.ToLower()
  $script:UserFirstName = (Get-Culture).TextInfo.ToTitleCase($UserFirstName)
  $script:UserLastName = (Get-Culture).TextInfo.ToTitleCase($UserLastName)

  $script:DisplayName = "$UserLastName, $UserFirstName $UserMiddleInitialUpper."
  $script:DisplayNameEscaped = "$UserLastName\, $UserFirstName $UserMiddleInitialUpper."
  $script:SamAccountName = "$UserFirstInitial$UserMiddleInitialLower$UserLastNameLower"
  
  $script:Path = "CN=Users,DC=ad,DC=fire-light,DC=us"
  $script:Identity = "CN=$DisplayNameEscaped,$Path"

  if ($isInternalSwitch -eq 'yes' -or $isInternalSwitch -eq 'y') {
    $isInternal = $true
  } Else {
    $isInternal = $false
  }

  if ($isInternal -eq $true) {
    $script:networkShare = "\\winserver1\GUsers\"
    $script:PrimaryCN = "internal"
  } else {
    $script:networkShare = "\\winserver1\NGUsers\"
    $script:PrimaryCN = "externalUser"
  }

}

function Get-ConfigValues {
  Get-Content ".\settings.ini" | ForEach-Object -Begin { $settings = @{} } -Process { $k = [regex]::split($_,'='); if (($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("[") -ne $True)) { $settings.Add($k[0],$k[1]) } }
  $script:EmailLoginUserName = $settings.Get_Item("Username")
  $script:EmailLoginPass = $settings.Get_Item("Password")
  
  $script:UserPrincipalNameSuffix = $settings.Get_Item("UserPrincipalNameSuffix")
  $script:Server = $settings.Get_Item("UserPrincipalNameSuffix")
}

function Write-NewUserAccount

{


  New-ADUser -DisplayName:$DisplayName -GivenName:$UserFirstName -Initials:$UserMiddleInitialUpper -Surname:$UserLastName -Name:$DisplayName -Path:$path -SamAccountName:$SamAccountName -Server:$Server -Type:"user" -UserPrincipalName:"$SamAccountName@$UserPrincipalNameSuffix" -EmailAddress:$UserEmailAddress

  Set-ADAccountControl -AccountNotDelegated:$false -AllowReversiblePasswordEncryption:$false -CannotChangePassword:$false -DoesNotRequirePreAuth:$false -Identity:$Identity -PasswordNeverExpires:$false -Server:$Server -UseDESKeyOnly:$false

  Set-ADUser -ChangePasswordAtLogon:$true -Identity:$Identity -Server:$Server -SmartcardLogonRequired:$false

  Add-ADPrincipalGroupMembership -Identity:$Identity -MemberOf:"CN=Remote Desktop Users,CN=Builtin,DC=ad,DC=fire-light,DC=us","CN=$PrimaryCN,$Path" -Server:$Server
}

function Write-UserDirectory {
  #Setup user directory

  $script:UserGUID = Get-ADUser $SamAccountName | Select-Object -ExpandProperty ObjectGUID
  $script:UserSID = Get-ADUser $SamAccountName | Select-Object SID

  $script:UserFileDirectory = "$networkShare$SamAccountName"


  New-Item -ItemType directory -Path $UserFileDirectory

  $Acl = Get-Acl $UserFileDirectory

  $Ar = New-Object System.Security.AccessControl.FileSystemAccessRule ("AD\$SamAccountName","FullControl","ContainerInherit,ObjectInherit","None","Allow")

  $Acl.SetAccessRule($Ar)
  Set-Acl $UserFileDirectory $Acl
}

function Write-UserPassword {

  $UserSIDHash = Get-StringHash -String $UserSID -HashName "SHA1"
  $script:UserPassword = "@$UserSIDHash"

  $SecPaswd = ConvertTo-SecureString -String $UserPassword -AsPlainText -Force
  Set-ADAccountPassword -Reset -NewPassword $SecPaswd -Identity:$Identity
  Unlock-ADAccount -Identity:$Identity
  Set-ADUser -Identity:$Identity -ChangePasswordAtLogon $false
  

  Set-ADObject -Identity:$Identity -Replace:@{ "userAccountControl" = "8389120" } -Server:$Server
}

Get-UserVariables
Get-ConfigValues
Write-NewUserAccount
Write-UserDirectory
Write-UserPassword
Export-sendMail

