# RansomUtilFactory

이 저장소에는 1단계 프로젝트인 Windows 파일시스템 미니필터 드라이버
`UF_FileFilterFactory`, 사용자 모드 통신 DLL `uf_fltwarp`, C 기반 시험 프로그램
`UF_FileFilterTest`와 WPF 개발 도구 `RansomUtilFactory.UI`가 들어 있습니다.

## 현재 구현된 동작

- 정규화된 NT 형식의 폴더 경로 여러 개를 하나의 정책으로 원자적으로 교체할 수 있습니다.
- `UfRuleMonitor` 규칙은 파일 열기 시도를 사용자 모드로 알립니다. 설정된 예외
  프로세스 이미지는 알림 대상에서 제외합니다.
- `UfRuleAllowList` 규칙은 허용 목록에 없는 프로세스 이미지의 파일 열기 시도를
  차단하고 해당 이벤트를 알립니다.
- 커널에서 시작된 입출력과 페이징 파일 열기는 감시하지 않습니다.
- 사용자 모드 클라이언트가 연결되지 않은 경우 감시 규칙은 입출력을 통과시킵니다.
  허용 목록 차단 규칙은 정책을 초기화하거나 드라이버를 언로드할 때까지 유지됩니다.
- 권한이 있는 사용자 모드 클라이언트 한 개만
  `\UF_FileFilterFactoryPort`에 연결할 수 있습니다.
- `uf_fltwarp.dll`은 C ABI로 연결, 정책 설정, 상태 조회, 경로 변환 및 비동기
  이벤트 수신 기능을 제공합니다.
- `UF_FileFilterTest.exe`로 DLL 자체 시험과 드라이버 통신 시험을 수행할 수 있습니다.

공유 통신 규약은
`UF_FileFilterFactory/include/uf_filefilter_protocol.h`에 정의되어 있습니다.
추후 제작할 `uf_fltwarp.dll`은 이 헤더를 포함하고
`FilterConnectCommunicationPort`, `FilterSendMessage`,
`FilterGetMessage`를 사용합니다.

## 빌드

필수 개발 환경:

- 데스크톱 C++ 및 .NET 데스크톱 개발 워크로드가 설치된 Visual Studio 2022 17.14 이상
- MSVC v143 x64/x86 빌드 도구
- Windows Driver Kit 10.0.28000.0
- x64 대상 플랫폼

Visual Studio 2022에서 솔루션 구성을 `Debug`, 플랫폼을 `x64`로 선택해 빌드합니다.
명령줄에서는 x64 개발자 PowerShell과 64비트 MSBuild를 사용합니다. WDK
10.0.28000.0에는 x86 `InfVerif.dll`이 없을 수 있습니다.

```powershell
& "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe" `
  .\RansomUtilFactory.sln /m /p:Configuration=Debug /p:Platform=x64
```

프로젝트는 WDK `10.0.28000.0`을 대상으로 설정되어 있습니다. 다른 WDK를
사용한다면 `WindowsTargetPlatformVersion` 값을 설치된 버전에 맞게 변경해야 합니다.

드라이버 C 소스는 Visual Studio 2022 x64 컴파일러와 WDK 10.0.28000 헤더를 사용하여
`/W4 /WX` 조건으로 컴파일 검증했습니다.

WDK 10.0.28000 설치에는 `Microsoft.DriverKit.Build.Tasks.17.0.dll`이 없고
`18.0.dll`만 포함될 수 있습니다. 드라이버 프로젝트는 VS2022에서 빌드할 때만
WDK 작업 버전을 18.0으로 선택하도록 호환 설정되어 있습니다.

각 프로젝트는 빌드 후 주요 결과물을 구성별 공용 폴더에 복사합니다. 앞으로
솔루션에 추가하는 신규 프로젝트에도 같은 규칙을 필수로 적용합니다.

```text
x64\Debug\bin
x64\Release\bin
```

공용 폴더에는 드라이버 SYS·INF·CAT, 네이티브 DLL, C 시험 프로그램 EXE와
WPF EXE·DLL·실행 구성 파일이 생성됩니다. PDB는 각 프로젝트의 원래 빌드 출력
폴더에만 유지하며 공용 `bin`에는 복사하지 않습니다.

커널 드라이버를 `Debug | x64`로 빌드하면 시험 서명에 사용하는
`UF_FileFilterFactory.cer`도 `x64\Debug\bin`에 복사됩니다. 테스트 인증서는
Release 공용 `bin`에는 포함하지 않습니다.

한국어 코드 주석을 코드 페이지 949 환경에서도 손실 없이 컴파일하도록 모든 C/C++
소스에 MSVC `/utf-8` 옵션을 적용합니다.

## 시험 환경

시험 서명을 사용하도록 설정한 일회용 Windows 가상 머신에서 스냅숏을 만든 후
시험하는 것을 권장합니다. 서명되지 않은 개발용 드라이버를 운영 장비에
로드하지 마십시오.

빌드 및 드라이버 패키지 설치 후 다음 명령으로 로드 상태를 확인할 수 있습니다.

```powershell
fltmc load UF_FileFilterFactory
fltmc filters
fltmc unload UF_FileFilterFactory
```

## 통신 시험 프로그램

드라이버를 요구하지 않는 경로 변환 자체 시험:

```powershell
.\x64\Debug\UF_FileFilterTest.exe --self-test
.\x64\Debug\UF_FileFilterTest.exe --convert C:\Test
```

시험용 VM에서 드라이버를 설치하고 로드한 후 사용할 수 있는 명령:

```powershell
.\x64\Debug\UF_FileFilterTest.exe --state
.\x64\Debug\UF_FileFilterTest.exe --clear
.\x64\Debug\UF_FileFilterTest.exe --monitor C:\감시폴더
.\x64\Debug\UF_FileFilterTest.exe --monitor C:\감시폴더 C:\도구\예외.exe
.\x64\Debug\UF_FileFilterTest.exe --protect C:\보호폴더 C:\도구\허용.exe
.\x64\Debug\UF_FileFilterTest.exe --listen 30
```

`--monitor`와 `--protect`는 현재 정책 전체를 각각 하나의 경로 규칙으로 교체합니다.
여러 경로와 보호 폴더별 허용 실행 파일은 WPF 개발 도구에서 V2 정책으로 편집할 수 있습니다.

## WPF 개발 도구

`RansomUtilFactory.UI`는 관리자 권한으로 실행되며 다음 화면을 제공합니다.

- `파일 제어`: 감시 폴더와 보호 폴더 추가·제거, 정책 적용·초기화, 실시간 이벤트 로그
- `파일 제어`: 보호 폴더별 허용 실행 파일 추가·제거 및 코드 서명 확인
- `파일 제어`: 파일 미니필터 설치·제거 및 연결 관리
- `연결`: INF로 미리 설치한 수동 시작 미니필터를 먼저 로드한 다음 통신 포트에 연결
- `프로세스 제어`: 설치·제거 버튼을 포함한 후속 구현용 자리 표시 탭

Debug 실행 파일:

```powershell
.\RansomUtilFactory.UI\bin\x64\Debug\net9.0-windows\RansomUtilFactory.UI.exe
```

보호 폴더의 허용 실행 파일은 정책 적용 전에 유효한 로컬 코드 서명을 확인합니다.
처음 접근할 때는 UI가 신뢰 요청 이벤트를 처리한 뒤 다음 접근부터 허용되므로, 첫 시도는
차단될 수 있습니다. 반드시 시험용 VM의 복구 가능한 폴더에서 검증하십시오.
감시 예외 프로그램 편집은 후속 UI 단계에서 추가합니다.

파일 드라이버 설치·제거 기능은 WPF 실행 폴더와
`Drivers\UF_FileFilterFactory`의 설치 패키지를 검색합니다. 전체 솔루션 빌드 시
공용 `x64\$(Configuration)\bin` 폴더에 INF, SYS와 CAT 파일이 자동 복사됩니다.
드라이버 설치·제거 및 로드 시험은 반드시 스냅숏이 있는 시험용 VM에서 수행하십시오.

## 주요 설계 사항

- 폴더 경로는 `C:\Protected` 형식이 아니라
  `\Device\HarddiskVolume3\Protected`와 같은 커널 정규화 경로를 사용합니다.
  DOS 경로를 NT 경로로 변환하는 기능은 추후 `uf_fltwarp.dll`에서 담당합니다.
- 프로세스 규칙은 현재 전체 이미지 경로를 대소문자 구분 없이 비교합니다.
- INF에 지정된 개발용 고도 값은 배포에 사용할 수 없습니다. 제품을 배포하기
  전에 Microsoft에서 미니필터 고도 값을 배정받아야 합니다.
- 현재 버전은 `IRP_MJ_CREATE` 접근을 처리합니다. 쓰기, 이름 변경, 삭제,
  섹션 매핑, 정책 영구 저장, 서명자 신원 확인 및 서비스 복구 기능은 이후
  강화 단계에서 구현합니다.

## 개발 문서

- 프로젝트 구현 순서, 구성 요소별 책임 및 완료 조건은
  [`docs/개발계획.md`](docs/개발계획.md)를 참고하십시오.
- 드라이버와 사용자 모드 DLL 사이의 구조체, 명령, 이벤트 및 오류 처리는
  [`docs/통신규약.md`](docs/통신규약.md)를 참고하십시오.
- Codex를 포함한 개발 도구가 따라야 할 언어, 구현, 검증 및 안전 규칙은
  [`AGENTS.md`](AGENTS.md)에 정의되어 있습니다.
