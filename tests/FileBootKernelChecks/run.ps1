param(
    [string] $VcVars = 'C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars64.bat'
)

$ErrorActionPreference = 'Stop'
$repositoryPath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$outputDirectory = Join-Path $repositoryPath 'artifacts\file-boot-kernel-checks'
[void](New-Item -Path $outputDirectory -ItemType Directory -Force)
$sourcePath = Join-Path $PSScriptRoot 'main.c'
$objectPath = Join-Path $outputDirectory 'FileBootKernelChecks.obj'
$executablePath = Join-Path $outputDirectory 'FileBootKernelChecks.exe'

# 실제 커널 소스를 메모리 모의 API로 빌드하며 드라이버를 설치하거나 연결하지 않는다.
$buildCommand = 'call "{0}" >nul && cl /nologo /W4 /WX /TC /utf-8 /MT /I"{1}" "{2}" /Fo"{3}" /Fe"{4}"' -f `
    $VcVars, $PSScriptRoot, $sourcePath, $objectPath, $executablePath
& $env:ComSpec /d /s /c $buildCommand
if ($LASTEXITCODE -ne 0) { throw "커널 소스 모의 시험 빌드 실패: $LASTEXITCODE" }
& $executablePath
if ($LASTEXITCODE -ne 0) { throw "커널 소스 모의 시험 실패: $LASTEXITCODE" }
