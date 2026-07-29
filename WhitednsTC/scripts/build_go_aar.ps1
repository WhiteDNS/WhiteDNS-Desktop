param(
    [string]$AndroidHome = $env:ANDROID_HOME,
    [string]$Output = "..\app\libs\tunnelengine.aar"
)

$ErrorActionPreference = "Stop"
if (-not $AndroidHome) {
    throw "ANDROID_HOME must point to the Android SDK."
}

Push-Location "$PSScriptRoot\..\engine"
try {
    go mod tidy
    gomobile init
    gomobile bind -target=android -androidapi 26 -o $Output .\tunnelengine
}
finally {
    Pop-Location
}
