Set-StrictMode -Version Latest
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

# Assumes running on Windows 11+
# Assumes Yubikey Manager is already downloaded and installed. May need to add it's path to environment variables to call ykman.exe
# Assumes fido is reset already, this is a manual process. Use CMD line in admin and run ykman fido reset. Recommended to do this, even on newly purchased smart cards

function Disable-YubiKeyApplications
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$false)]
        [bool]$NFCType = $true
    )

    Write-Verbose "Disable-YubiKeyApplications | Disabling certain YubiKey applications for USB and all for NFC"

    $appsToDisable = @("OTP","U2F","OATH","OPENPGP") # Omitted are PIV,FIDO2, and HSMAUTH. HSMAUTH is not present on a non-NFC device

    if($NFCType)
    {
        ykman config nfc --disable-all --force > $null
        Write-Verbose "Disable-YubiKeyApplications | NFC: All apps disabled"

        ykman config usb --disable "HSMAUTH" --force > $null
        Write-Verbose "Disable-YubiKeyApplications | USB: HSMAUTH disabled"
    }

    foreach ($app in $appsToDisable)
    {
        ykman config usb --disable $app --force > $null
        Write-Verbose "Disable-YubiKeyApplications | USB: $app disabled"
    }
}

function Configure-YubiKey
{
    [byte]$pinRetries = 5 #byte max is 255, retires must be 1 or more
    [byte]$pukRetries = 3 #byte max is 255, retires must be 1 or more
    [System.String]$defaultPIN = "123456"
    [System.String]$defaultPUK = "12345678"
    [System.String]$managementKeyAlgo = "AES256"
    [System.String]$defaultManageKey = "010203040506070801020304050607080102030405060708"

    Write-Verbose "Configure-YubiKey | Resetting PIV"
    ykman piv reset --force > $null

    Write-Verbose "Configure-YubiKey | Setting PIV retry limits PIN:$pinRetries PUK:$pukRetries"
    # min:max retries are 1:255
    ykman piv access set-retries --pin $defaultPIN --management-key $defaultManageKey $pinRetries $pukRetries --force

    # Prompt user for new PIN and PUK
    # REMOVE in variable names is used for variable/memory cleanup for sensitive variables
    Write-Host "`nThe PIN is what is used to access systems and services. If the PIN is blocked from too many failed login attempts, the PUK will unblock the PIN."
    Write-Host "If the PUK is blocked from too many failed login attempts also, the whole PIV needs to be reset`n-----"
    Write-Host "The FIDO2/WebAuth PIN is used for WebAuth and other systems"
    $REMOVE_pin = Read-Host -AsSecureString "New PIV PIN (Don't Set to Default: $defaultPIN)"
    $REMOVE_puk = Read-Host -AsSecureString "New PIV PUK (Don't Set to Default: $defaultPUK)"
    $REMOVE_fido_pin = Read-Host -AsSecureString "New FIDO2/WebAuth PIN"

    try
    {
        # Convert secure strings to plaintext for CLI input
        $BSTR_pin = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($REMOVE_pin)
        $BSTR_puk = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($REMOVE_puk)
        $BSTR_fido_pin = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($REMOVE_pin)

        $REMOVE_plainPin = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR_pin)
        $REMOVE_plainPuk = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR_puk)
        $REMOVE_plainFidoPin = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR_fido_pin)

        ykman piv access change-pin --new-pin $REMOVE_plainPin --pin $defaultPIN
        ykman piv access change-puk --new-puk $REMOVE_plainPuk --puk $defaultPUK
        ykman fido access change-pin --new-pin $REMOVE_plainFidoPin

        # once the management key is set (random and protected on the Yubikey) to set retires or run other commands needing the management key in the future, we just need the PIN, as the Yubikey will decrypt the management key for us
        ykman piv access change-management-key --algorithm $managementKeyAlgo --protect --management-key $defaultManageKey --pin $REMOVE_plainPin --force
    }
    finally
    {
        # Cleanup memory
        Remove-Variable -Name REMOVE*
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR_pin)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR_puk)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR_fido_pin)

        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}

function Get-YubiKeyInfo
{
    $rawInfo = ykman info

    $infoHash = @{}

    foreach ($line in $rawInfo)
    {
        [System.Text.RegularExpressions.Regex]$regex = "^([^:]+):\s+(.+)$" # the details we are interested in are in a format of Key: Value, so get everything before the : and ignore any immedate spaces after, then grab the rest.
        if ($line -match $regex)
        {
            $key = $matches[1].Trim() -replace '\s+', '' # remove spaces from the key so it's easier to reference in object
            $value = $matches[2].Trim()
            $infoHash[$key] = $value
        }
    }

    return $infoHash
}

function Test-Yubikey
{
    [CmdletBinding()]
    param()

    Write-Verbose "Test-Yubikey | Checking that the Smart Card service is running"
    [bool]$serviceRunning = (Get-Service -Name SCardSvr).Status -eq 'Running'
    if (-not $serviceRunning)
    {
        throw "Smart Card service is not running. Please start the service and try again."
    }

    Write-Verbose "Test-Yubikey | Checking for a connected YubiKey"
    [System.Array]$ykmanList = ykman list
    if (-not $ykList)
    {
        throw "No YubiKey detected. Please connect your device."
    }
    Write-Verbose "Test-Yubikey | Checking that only 1 YubiKey is connected"
    if ($ykList.Count -gt 1)
    {
        throw "More than 1 YubiKey detected. Please disconnected other Yubikey devices."
    }

    Write-Verbose "Test-Yubikey | Getting YubiKey information"
    [System.Collections.Hashtable]$ykmanInfo = Get-YubiKeyInfo
    [System.String]$ykmanDeviceType = $ykmanInfo.Devicetype
    [bool]$NFCType = $ykmanDeviceType.Contains("NFC")

    Write-Verbose "Test-Yubikey | Checking YubiKey firmware version"
    [System.Version]$ykmanFirmwareVersion = $ykmanInfo.Firmwareversion
    [System.Version]$ykmanMinimalVersion = "5.4" #minimal version for commands, as described in yubico documentation
    if (-not ($ykmanFirmwareVersion -ge $ykmanMinimalVersion))
    {
        throw "Yubikey firmware version is not supported. Please use a device with a firmware version of $ykmanMinimalVersion or greater. Current Version: $ykmanFirmwareVersion"
    }
}

$verboseSet = $true
Test-Yubikey -Verbose:$verboseSet
Disable-YubiKeyApplications -NFCType $NFCType -Verbose:$verboseSet
Configure-YubiKey
