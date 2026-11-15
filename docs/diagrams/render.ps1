# Renders docs/diagrams/remediation_layer.py to "Neo — Remediation Layer.png" (1800x1680).
#
#   powershell -File docs/diagrams/render.ps1                      # writes to the repo root
#   powershell -File docs/diagrams/render.ps1 -Out C:\tmp\x.png -Font C:\fonts\inter.woff2
#
# Needs Python and Edge or Chrome. -Font is an optional Inter .woff2 (the diagrams use Inter);
# without it the system sans-serif is used and text widths shift slightly.
param(
    # The name has an em dash; build it from its code point so Windows PowerShell 5.1 (which reads
    # BOM-less UTF-8 as ANSI) cannot mangle this file.
    [string]$Out = (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) ("Neo " + [char]0x2014 + " Remediation Layer.png")),
    [string]$Font = "",
    [string]$Python = "python"
)
$ErrorActionPreference = "Stop"
$W, $H = 1800, 1680
$work = Join-Path ([IO.Path]::GetTempPath()) ("neo-diagram-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory $work | Out-Null

$browser = @(
    "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    "C:\Program Files\Google\Chrome\Application\chrome.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $browser) { throw "Edge or Chrome not found" }

$html = Join-Path $work "diagram.html"
$gen = @((Join-Path $PSScriptRoot "remediation_layer.py"), $html)
if ($Font) { $gen += ("file:///" + ((Resolve-Path $Font).Path -replace '\\', '/')) }
& $Python @gen
if ($LASTEXITCODE) { throw "generator failed" }

# A headless window reserves space for browser chrome, so render taller and crop to the page size.
$raw = Join-Path $work "raw.png"
$ErrorActionPreference = "Continue"   # Edge writes harmless errors to stderr; PS 5.1 would treat them as fatal
& $browser --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 `
    "--window-size=$W,$($H + 220)" --virtual-time-budget=4000 "--screenshot=$raw" `
    ("file:///" + ($html -replace '\\', '/')) 2>$null | Out-Null
$ErrorActionPreference = "Stop"
Start-Sleep -Seconds 2
if (-not (Test-Path $raw)) { throw "the browser produced no screenshot" }

Add-Type -AssemblyName System.Drawing
$src = [System.Drawing.Image]::FromFile($raw)
$dst = New-Object System.Drawing.Bitmap $W, $H
$g = [System.Drawing.Graphics]::FromImage($dst)
$rect = New-Object System.Drawing.Rectangle 0, 0, $W, $H
$g.DrawImage($src, $rect, $rect, [System.Drawing.GraphicsUnit]::Pixel)
$g.Dispose(); $src.Dispose()
$dst.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png); $dst.Dispose()
Remove-Item $work -Recurse -Force
"wrote $Out ($W x $H)"
