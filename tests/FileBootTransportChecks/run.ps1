param(
    [string] $VcVars = 'C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars64.bat'
)

$ErrorActionPreference = 'Stop'
$repositoryPath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$sourcePath = Join-Path $PSScriptRoot 'main.c'
$outputDirectory = Join-Path $repositoryPath 'artifacts\file-boot-transport-checks'
$executablePath = Join-Path $outputDirectory 'FileBootTransportChecks.exe'
$objectPath = Join-Path $outputDirectory 'FileBootTransportChecks.obj'
$importLibraryPath = Join-Path $outputDirectory 'FileBootTransportChecks.lib'
$includePath = Join-Path $repositoryPath 'UF_FileFilterFactory\include'

if (-not (Test-Path -LiteralPath $VcVars -PathType Leaf)) {
    throw "MSVC 환경 설정 파일을 찾지 못했습니다: $VcVars"
}
[void](New-Item -Path $outputDirectory -ItemType Directory -Force)

# 통신을 메모리 모의 함수로 교체한 시험 실행 파일만 빌드한다.
$buildCommand = 'call "{0}" >nul && cl /nologo /W4 /WX /TC /utf-8 /MT /I"{1}" "{2}" /Fo"{3}" /Fe"{4}" /link /IMPLIB:"{5}" FltLib.lib Wintrust.lib Crypt32.lib Advapi32.lib User32.lib Ws2_32.lib' -f `
    $VcVars, $includePath, $sourcePath, $objectPath, $executablePath, $importLibraryPath
& $env:ComSpec /d /s /c $buildCommand
if ($LASTEXITCODE -ne 0) { throw "전송 모의 시험 빌드 실패: $LASTEXITCODE" }

# 관리자 권한·드라이버 연결·서비스 변경·원시 디스크 접근은 사용하지 않는다.
& $executablePath
if ($LASTEXITCODE -ne 0) { throw "전송 모의 시험 실패: $LASTEXITCODE" }
