[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $SourcePath,

    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory,

    [ValidateRange(300, 172800)]
    [uint64] $ValiditySeconds = 86400
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$MaxSourceBytes = 2MB
$MaxPayloadBytes = 256KB
$MaxDevices = 4096
$MaxEntitlements = 32
$MaxEntitlementLength = 64
$P256Oid = "1.2.840.10045.3.1.7"

function Assert-ObjectShape
{
    param(
        [System.Text.Json.JsonElement] $Object,
        [string[]] $Expected,
        [string] $Path
    )

    if ($Object.ValueKind -ne [System.Text.Json.JsonValueKind]::Object)
    {
        throw "$Path must be an object."
    }

    $allowed = [System.Collections.Generic.HashSet[string]]::new(
        $Expected, [System.StringComparer]::Ordinal)
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($property in $Object.EnumerateObject())
    {
        if (!$allowed.Contains($property.Name))
        {
            throw "$Path contains unknown property '$($property.Name)'."
        }
        if (!$seen.Add($property.Name))
        {
            throw "$Path contains duplicate property '$($property.Name)'."
        }
    }

    foreach ($name in $Expected)
    {
        if (!$seen.Contains($name))
        {
            throw "$Path is missing property '$name'."
        }
    }
}

function Get-RequiredProperty
{
    param(
        [System.Text.Json.JsonElement] $Object,
        [string] $Name,
        [string] $Path
    )

    $value = [System.Text.Json.JsonElement]::new()
    if (!$Object.TryGetProperty($Name, [ref] $value))
    {
        throw "$Path is missing property '$Name'."
    }
    return $value
}

function Get-PositiveUInt64
{
    param(
        [System.Text.Json.JsonElement] $Element,
        [string] $Path
    )

    if ($Element.ValueKind -ne [System.Text.Json.JsonValueKind]::Number)
    {
        throw "$Path must be a positive unsigned integer."
    }

    [uint64] $value = 0
    if (!$Element.TryGetUInt64([ref] $value) -or $value -eq 0)
    {
        throw "$Path must be a positive unsigned integer."
    }
    return $value
}

function Get-Pkcs8Bytes
{
    param([string] $Pem)

    if ($Pem.Length -gt 16384)
    {
        throw "The signing key secret is unexpectedly large."
    }

    $pattern = "\A-----BEGIN PRIVATE KEY-----\r?\n(?<body>[A-Za-z0-9+/=\r\n]+)\r?\n-----END PRIVATE KEY-----\r?\n?\z"
    $match = [System.Text.RegularExpressions.Regex]::Match(
        $Pem, $pattern, [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (!$match.Success)
    {
        throw "AUTH_MANIFEST_SIGNING_KEY_PEM must contain one unencrypted PKCS#8 PRIVATE KEY PEM block."
    }

    $encoded = $match.Groups["body"].Value.Replace("`r", "").Replace("`n", "")
    try
    {
        [byte[]] $bytes = [System.Convert]::FromBase64String($encoded)
    }
    catch
    {
        throw "AUTH_MANIFEST_SIGNING_KEY_PEM contains invalid Base64."
    }

    if ([System.Convert]::ToBase64String($bytes) -cne $encoded)
    {
        [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)
        throw "AUTH_MANIFEST_SIGNING_KEY_PEM is not canonically encoded."
    }
    return $bytes
}

function Write-NewFile
{
    param(
        [string] $Path,
        [byte[]] $Bytes
    )

    $stream = $null
    try
    {
        $stream = [System.IO.FileStream]::new(
            $Path,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None)
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    }
    catch
    {
        if ($null -ne $stream)
        {
            $stream.Dispose()
            $stream = $null
        }
        if ([System.IO.File]::Exists($Path))
        {
            [System.IO.File]::Delete($Path)
        }
        throw
    }
    finally
    {
        if ($null -ne $stream)
        {
            $stream.Dispose()
        }
    }
}

$sourceFullPath = [System.IO.Path]::GetFullPath($SourcePath)
if (![System.IO.File]::Exists($sourceFullPath))
{
    throw "Authorization source file does not exist: $sourceFullPath"
}

$sourceLength = ([System.IO.FileInfo]::new($sourceFullPath)).Length
if ($sourceLength -le 0 -or $sourceLength -gt $MaxSourceBytes)
{
    throw "Authorization source file has an invalid size."
}

[byte[]] $sourceBytes = [System.IO.File]::ReadAllBytes($sourceFullPath)
$jsonOptions = [System.Text.Json.JsonDocumentOptions]::new()
$jsonOptions.AllowTrailingCommas = $false
$jsonOptions.CommentHandling = [System.Text.Json.JsonCommentHandling]::Disallow
$jsonOptions.MaxDepth = 16
$document = $null

try
{
    $document = [System.Text.Json.JsonDocument]::Parse(
        [System.ReadOnlyMemory[byte]]::new($sourceBytes), $jsonOptions)
    $root = $document.RootElement
    Assert-ObjectShape $root @("schema", "sequence", "minimum_build", "devices") "root"

    [uint64] $schema = Get-PositiveUInt64 (Get-RequiredProperty $root "schema" "root") "schema"
    if ($schema -ne 1)
    {
        throw "schema must be 1."
    }
    [uint64] $sequence = Get-PositiveUInt64 (Get-RequiredProperty $root "sequence" "root") "sequence"
    [uint64] $minimumBuild = Get-PositiveUInt64 (Get-RequiredProperty $root "minimum_build" "root") "minimum_build"

    $devicesElement = Get-RequiredProperty $root "devices" "root"
    if ($devicesElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Array)
    {
        throw "devices must be an array."
    }
    if ($devicesElement.GetArrayLength() -gt $MaxDevices)
    {
        throw "devices exceeds the $MaxDevices-device limit."
    }

    $devices = [System.Collections.Generic.SortedDictionary[string, object]]::new(
        [System.StringComparer]::Ordinal)
    $deviceIndex = 0
    foreach ($deviceElement in $devicesElement.EnumerateArray())
    {
        $devicePath = "devices[$deviceIndex]"
        Assert-ObjectShape $deviceElement @("id", "enabled", "expires_at", "entitlements") $devicePath

        $idElement = Get-RequiredProperty $deviceElement "id" $devicePath
        if ($idElement.ValueKind -ne [System.Text.Json.JsonValueKind]::String)
        {
            throw "$devicePath.id must be a string."
        }
        $id = $idElement.GetString()
        if ($null -eq $id -or $id -cnotmatch "\A[0-9a-f]{64}\z")
        {
            throw "$devicePath.id must be exactly 64 lowercase hexadecimal characters."
        }

        $enabledElement = Get-RequiredProperty $deviceElement "enabled" $devicePath
        if ($enabledElement.ValueKind -ne [System.Text.Json.JsonValueKind]::True -and
            $enabledElement.ValueKind -ne [System.Text.Json.JsonValueKind]::False)
        {
            throw "$devicePath.enabled must be a Boolean."
        }
        $enabled = $enabledElement.GetBoolean()
        [uint64] $expiresAt = Get-PositiveUInt64 (
            Get-RequiredProperty $deviceElement "expires_at" $devicePath) "$devicePath.expires_at"

        $entitlementsElement = Get-RequiredProperty $deviceElement "entitlements" $devicePath
        if ($entitlementsElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Array)
        {
            throw "$devicePath.entitlements must be an array."
        }
        if ($entitlementsElement.GetArrayLength() -gt $MaxEntitlements)
        {
            throw "$devicePath.entitlements exceeds the $MaxEntitlements-entry limit."
        }

        $entitlements = [System.Collections.Generic.List[string]]::new()
        $seenEntitlements = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $entitlementIndex = 0
        foreach ($entitlementElement in $entitlementsElement.EnumerateArray())
        {
            if ($entitlementElement.ValueKind -ne [System.Text.Json.JsonValueKind]::String)
            {
                throw "$devicePath.entitlements[$entitlementIndex] must be a string."
            }
            $entitlement = $entitlementElement.GetString()
            if ($null -eq $entitlement -or $entitlement.Length -eq 0 -or
                $entitlement.Length -gt $MaxEntitlementLength -or
                $entitlement -cnotmatch "\A[a-z][a-z0-9._-]*\z")
            {
                throw "$devicePath.entitlements[$entitlementIndex] has an invalid value."
            }
            if (!$seenEntitlements.Add($entitlement))
            {
                throw "$devicePath.entitlements contains duplicate value '$entitlement'."
            }
            $entitlements.Add($entitlement)
            $entitlementIndex++
        }
        $entitlements.Sort([System.StringComparer]::Ordinal)

        if ($devices.ContainsKey($id))
        {
            throw "devices contains duplicate id '$id'."
        }
        $devices.Add($id, [pscustomobject]@{
            Id = $id
            Enabled = $enabled
            ExpiresAt = $expiresAt
            Entitlements = [string[]] $entitlements.ToArray()
        })
        $deviceIndex++
    }

    [uint64] $generatedAt = [System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    [uint64] $manifestExpiresAt = $generatedAt + $ValiditySeconds
    $payloadBuffer = [System.Buffers.ArrayBufferWriter[byte]]::new()
    $writerOptions = [System.Text.Json.JsonWriterOptions]::new()
    $writerOptions.Indented = $false
    $writerOptions.SkipValidation = $false
    $writer = [System.Text.Json.Utf8JsonWriter]::new($payloadBuffer, $writerOptions)
    try
    {
        $writer.WriteStartObject()
        $writer.WriteNumber("schema", $schema)
        $writer.WriteNumber("sequence", $sequence)
        $writer.WriteNumber("generated_at", $generatedAt)
        $writer.WriteNumber("expires_at", $manifestExpiresAt)
        $writer.WriteNumber("minimum_build", $minimumBuild)
        $writer.WriteStartArray("devices")
        foreach ($device in $devices.Values)
        {
            $writer.WriteStartObject()
            $writer.WriteString("id", $device.Id)
            $writer.WriteBoolean("enabled", $device.Enabled)
            $writer.WriteNumber("expires_at", [uint64] $device.ExpiresAt)
            $writer.WriteStartArray("entitlements")
            foreach ($entitlement in $device.Entitlements)
            {
                $writer.WriteStringValue($entitlement)
            }
            $writer.WriteEndArray()
            $writer.WriteEndObject()
        }
        $writer.WriteEndArray()
        $writer.WriteEndObject()
        $writer.Flush()
    }
    finally
    {
        $writer.Dispose()
    }
    [byte[]] $payloadBytes = $payloadBuffer.WrittenMemory.ToArray()
    if ($payloadBytes.Length -le 0 -or $payloadBytes.Length -gt $MaxPayloadBytes)
    {
        throw "Generated authorization payload exceeds the client limit."
    }
}
finally
{
    if ($null -ne $document)
    {
        $document.Dispose()
    }
}

$keyPem = $env:AUTH_MANIFEST_SIGNING_KEY_PEM
$expectedFingerprint = $env:AUTH_MANIFEST_SIGNING_PUBLIC_KEY_SHA256
Remove-Item Env:AUTH_MANIFEST_SIGNING_KEY_PEM -ErrorAction SilentlyContinue
Remove-Item Env:AUTH_MANIFEST_SIGNING_PUBLIC_KEY_SHA256 -ErrorAction SilentlyContinue
if ([string]::IsNullOrWhiteSpace($keyPem))
{
    throw "AUTH_MANIFEST_SIGNING_KEY_PEM is not configured."
}
if ([string]::IsNullOrWhiteSpace($expectedFingerprint) -or
    $expectedFingerprint -cnotmatch "\A[0-9a-f]{64}\z")
{
    throw "AUTH_MANIFEST_SIGNING_PUBLIC_KEY_SHA256 must be 64 lowercase hexadecimal characters."
}

[byte[]] $privateKeyBytes = $null
$ecdsa = $null
[byte[]] $signature = $null
try
{
    $privateKeyBytes = Get-Pkcs8Bytes $keyPem
    $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
    $bytesRead = 0
    $ecdsa.ImportPkcs8PrivateKey($privateKeyBytes, [ref] $bytesRead)
    if ($bytesRead -ne $privateKeyBytes.Length)
    {
        throw "The signing key contains trailing data."
    }

    $parameters = $ecdsa.ExportParameters($false)
    if ($ecdsa.KeySize -ne 256 -or $parameters.Curve.Oid.Value -cne $P256Oid -or
        $parameters.Q.X.Length -ne 32 -or $parameters.Q.Y.Length -ne 32)
    {
        throw "The signing key must use the NIST P-256 curve."
    }

    [byte[]] $subjectPublicKeyInfo = $ecdsa.ExportSubjectPublicKeyInfo()
    [byte[]] $fingerprintBytes = [System.Security.Cryptography.SHA256]::HashData($subjectPublicKeyInfo)
    $actualFingerprint = [System.Convert]::ToHexString($fingerprintBytes).ToLowerInvariant()
    if (![System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
        [System.Text.Encoding]::ASCII.GetBytes($actualFingerprint),
        [System.Text.Encoding]::ASCII.GetBytes($expectedFingerprint)))
    {
        throw "The signing key does not match AUTH_MANIFEST_SIGNING_PUBLIC_KEY_SHA256."
    }

    $signatureFormat = [System.Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation
    $signature = $ecdsa.SignData(
        $payloadBytes,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        $signatureFormat)
    if ($signature.Length -ne 64 -or !$ecdsa.VerifyData(
        $payloadBytes,
        $signature,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        $signatureFormat))
    {
        throw "The generated signature failed verification."
    }

    $envelopeBuffer = [System.Buffers.ArrayBufferWriter[byte]]::new()
    $envelopeWriter = [System.Text.Json.Utf8JsonWriter]::new($envelopeBuffer, $writerOptions)
    try
    {
        $envelopeWriter.WriteStartObject()
        $envelopeWriter.WriteString("payload", [System.Convert]::ToBase64String($payloadBytes))
        $envelopeWriter.WriteString("signature", [System.Convert]::ToBase64String($signature))
        $envelopeWriter.WriteEndObject()
        $envelopeWriter.Flush()
    }
    finally
    {
        $envelopeWriter.Dispose()
    }
    [byte[]] $envelopeBytes = $envelopeBuffer.WrittenMemory.ToArray()

    $outputFullPath = [System.IO.Path]::GetFullPath($OutputDirectory)
    if ([System.IO.File]::Exists($outputFullPath))
    {
        throw "Output path is a file: $outputFullPath"
    }
    if ([System.IO.Directory]::Exists($outputFullPath))
    {
        $outputInfo = [System.IO.DirectoryInfo]::new($outputFullPath)
        if (($outputInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
        {
            throw "Output directory must not be a symbolic link or reparse point."
        }
        if ([System.IO.Directory]::EnumerateFileSystemEntries($outputFullPath).GetEnumerator().MoveNext())
        {
            throw "Output directory must be empty: $outputFullPath"
        }
    }
    else
    {
        [void] [System.IO.Directory]::CreateDirectory($outputFullPath)
    }

    $outputFile = [System.IO.Path]::Combine($outputFullPath, "authorization.json")
    Write-NewFile $outputFile $envelopeBytes
    Write-Host "Signed authorization sequence $sequence for $($devices.Count) device(s)."
}
finally
{
    if ($null -ne $privateKeyBytes)
    {
        [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($privateKeyBytes)
    }
    if ($null -ne $ecdsa)
    {
        $ecdsa.Dispose()
    }
    $keyPem = $null
}
