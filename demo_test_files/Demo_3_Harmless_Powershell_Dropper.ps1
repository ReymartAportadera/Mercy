# Harmless Demonstration of an Obfuscated PowerShell Loader Pattern
# (This script only prints a harmless test message)
$encodedPayload = 'V3JpdGUtSG9zdCAiW1NBTVBMRV0gSGFybWxlc3MgVGVzdCBFeGVjdXRpb24iIC1Gb3JlZ3JvdW5kQ29sb3IgR3JlZW4='
$decodedBytes = [System.Convert]::FromBase64String($encodedPayload)
$scriptCode = [System.Text.Encoding]::UTF8.GetString($decodedBytes)
Invoke-Expression $scriptCode
