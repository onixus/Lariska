param([Parameter(Mandatory=$true)][string]$Version, [string]$Binary = 'target\release\lariska.exe')
$ErrorActionPreference = 'Stop'
$destination = "dist\$Version"
New-Item -ItemType Directory -Force -Path $destination | Out-Null
$artifact = "$destination\lariska-$Version-x86_64-pc-windows-msvc.msi"
wix build -arch x64 -d "Version=$Version" -d "Binary=$Binary" -o $artifact packaging/windows/lariska.wxs
if ($LASTEXITCODE -ne 0) { throw 'WiX build failed' }
$signTool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe' | Sort-Object FullName | Select-Object -Last 1
& $signTool.FullName sign /fd SHA256 /f $env:LARISKA_SIGNING_P12 /p $env:LARISKA_WINDOWS_P12_PASSWORD $artifact
if ($LASTEXITCODE -ne 0) { throw 'MSI signing failed' }
$signature = Get-AuthenticodeSignature -LiteralPath $artifact
if ($signature.Status -ne 'Valid') { throw "MSI signature validation failed: $($signature.Status)" }
$trust = Get-Content packaging/trust/public-trust.json | ConvertFrom-Json
if ($signature.SignerCertificate.Thumbprint -ne $trust.certificates.windows.thumbprint) { throw 'MSI signer differs from local trust pin' }
