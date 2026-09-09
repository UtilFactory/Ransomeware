# RansomUtilFactory

이 저장소에는 Windows 파일시스템 미니필터 드라이버 `UF_FileFilterFactory`,
프로세스 생성·접근 감시 드라이버 `UF_ProcessFilterFactory`, 사용자 모드 통신 DLL
`uf_fltwarp`, C 기반 시험 프로그램 `UF_FileFilterTest`와 WPF 개발 도구
`RansomUtilFactory.UI`가 들어 있습니다.

## 현재 구현된 동작

- 정규화된 NT 형식의 폴더 경로 여러 개를 하나의 정책으로 원자적으로 교체할 수 있습니다.
- `UfRuleMonitor` 규칙은 파일 접근 이벤트를 사용자 모드로 알립니다. 설정된 예외
  프로세스 이미지는 알림 대상에서 제외합니다.
- V2의 `UfRuleProtected` 규칙은 보호 폴더별 허용 프로그램, 읽기·쓰기 권한과
  선택한 서명 조건에 따라 파일 접근을 판정하고 이벤트를 알립니다.
- 커널에서 시작된 입출력과 페이징 파일 열기는 감시하지 않습니다.
- 사용자 모드 클라이언트가 연결되지 않은 경우 감시 규칙은 입출력을 통과시킵니다.
  허용 목록 차단 규칙은 정책을 초기화하거나 드라이버를 언로드할 때까지 유지됩니다.
- 권한이 있는 사용자 모드 클라이언트 한 개만
  `\UF_FileFilterFactoryPort`에 연결할 수 있습니다.
- `uf_fltwarp.dll`은 C ABI로 연결, 정책 설정, 상태 조회, 경로 변환 및 비동기
  이벤트 수신 기능을 제공합니다.
- `UF_FileFilterTest.exe`로 DLL 자체 시험과 드라이버 통신 시험을 수행할 수 있습니다.
- `UF_ProcessFilterFactory.sys`는 프로세스 생성·종료와 다른 프로세스에 대한 사용자 모드
  핸들 생성·복제 요청을 감시하고, 등록된 이미지 규칙에 따라 프로세스 실행을 차단합니다.
- `uf_procwarp.dll`은 프로세스 정책 교체·초기화, 상태 조회 및 이벤트 수신 C ABI를
  제공합니다. `UF_ProcessControlTest.exe`로 정책 차단과 이벤트 수신을 시험할 수 있습니다.

파일 필터 공유 통신 규약은
`UF_FileFilterFactory/include/uf_filefilter_protocol.h`에, 프로세스 필터 공유 통신
규약은 `UF_ProcessFilterFactory/include/uf_processfilter_protocol.h`에 정의되어 있습니다.
`uf_fltwarp.dll`은 파일 필터 헤더를 포함하고
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

각 프로젝트는 빌드 후 주요 결과물을 구성별 공용 폴더에 복사합니다. 솔루션 파일을
통해 빌드해야 `$(SolutionDir)`가 저장소 루트로 설정되어 네이티브 DLL이 공용
폴더에 최신 상태로 복사됩니다. 프로젝트 파일 하나만 직접 빌드할 때는 다음처럼
`/p:SolutionDir=<저장소 루트>\\`를 지정하십시오. 앞으로
솔루션에 추가하는 신규 프로젝트에도 같은 규칙을 필수로 적용합니다.

```text
x64\Debug\bin
x64\Release\bin
```

공용 폴더에는 두 드라이버의 SYS·INF·CAT, 네이티브 DLL, C 시험 프로그램 EXE와
WPF EXE·DLL·실행 구성 파일이 생성됩니다. PDB는 각 프로젝트의 원래 빌드 출력
폴더에만 유지하며 공용 `bin`에는 복사하지 않습니다.

구성요소별 진단 로그는 실행 중인 UI·시험 프로그램의 실행 파일과 같은 위치의
`logs` 폴더에 기록됩니다. `uf_fltwarp.dll`도 DLL 경로가 아닌 호스트 프로세스의
실행 경로를 기준으로 기록하므로 세 로그를 한 폴더에서 확인할 수 있습니다.

- `uf_fltwarp.log`: `uf_fltwarp.dll`의 연결·정책·이벤트 처리 로그
- `uf_procwarp.log`: `uf_procwarp.dll`의 연결·IOCTL·정책 적용 단계 로그
- `UF_FileFilterTest.log`: C 시험 프로그램의 시작·명령·오류 로그
- `RansomUtilFactory.UI.log`: WPF UI의 초기화·버튼 동작·예외 로그
- `uf_fltwarp.bootstrap.log`: 네이티브 DLL 초기화가 멈출 때 단계 확인용 보조 로그

로그 파일은 실행할 때 자동으로 생성되며, 파일 내용이나 자격 증명은 기록하지
않습니다. 네이티브 DLL과 시험 프로그램은 정적 `log4cpp` 라이브러리를 빌드·연결하고,
UI 초기화 중 로깅 라이브러리 문제로 프로세스가 종료되지 않도록 Win32 파일 기록을
기본 경로로 사용합니다. WPF UI는 `log4net`을 사용합니다. `uf_fltwarp.bootstrap.log`는
`UfFltInitialize` 초기화 단계가 멈출 때만 확인하는 보조 파일입니다.

커널 드라이버를 `Debug | x64`로 빌드하면 시험 서명에 사용하는
`UF_FileFilterFactory.cer`와 `UF_ProcessFilterFactory.cer`도 `x64\Debug\bin`에
복사됩니다. 테스트 인증서는
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

프로세스 드라이버는 파일시스템 미니필터가 아니므로 시험용 VM에서 INF를 설치한 뒤
서비스 제어 관리자로 로드합니다.

```powershell
sc.exe start UF_ProcessFilterFactory
sc.exe query UF_ProcessFilterFactory
sc.exe stop UF_ProcessFilterFactory
```

커널 디버거 또는 DebugView의 커널 캡처에서 `[UF_ProcessFilterFactory]` 접두사의
`process-create`, `process-exit`, `process-access` 이벤트를 확인할 수 있습니다.

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

프로세스 드라이버를 시험 서명 VM에 설치·로드한 뒤 다음 명령으로 정책과 이벤트를
확인할 수 있습니다.

```powershell
.\x64\Debug\UF_ProcessControlTest.exe --state
.\x64\Debug\UF_ProcessControlTest.exe --block-name UF_ProcessBlockedProbe.exe
.\x64\Debug\UF_ProcessControlTest.exe --self-test
.\x64\Debug\UF_ProcessControlTest.exe --clear
.\x64\Debug\UF_ProcessControlTest.exe --listen 30
```

`--monitor`와 `--protect`는 현재 정책 전체를 각각 하나의 경로 규칙으로 교체합니다.
여러 경로와 보호 폴더별 허용 실행 파일은 WPF 개발 도구에서 V2 정책으로 편집할 수 있습니다.

## WPF 개발 도구

`RansomUtilFactory.UI`는 관리자 권한으로 실행되며 다음 화면을 제공합니다.

- `파일 제어`: 감시 폴더와 보호 폴더 추가·제거, 정책 적용·초기화, 실시간 이벤트 로그
- `파일 제어`: 보호 폴더별 허용 실행 파일 추가·제거, 읽기·쓰기 권한 및 코드 서명 확인
- `파일 제어`: 파일 미니필터 설치·제거 및 연결 관리
- `연결`: INF로 미리 설치한 수동 시작 미니필터를 먼저 로드한 다음 통신 포트에 연결
- `프로세스 제어`: 파일 이름별 실행 조건 편집, 전체 경로 일치·코드 서명 옵션,
  정책 적용·초기화 및 프로세스 드라이버 설치·로드·연결·제거
- `프로세스 제어`: 현재 UI에서 적용에 성공한 정책 이름의 실행 결과만 표시
  (`통과` 또는 `차단`). 미등록 실행·종료·다른 프로세스 접근 이벤트는 UI 목록에서 제외

폴더나 실행 파일을 목록에 추가하는 것만으로는 드라이버 정책이 바뀌지 않습니다.
각 탭에서 `정책 적용`을 누르고 완료 문구를 확인해야 합니다. 상단 초록색 상태는
드라이버 통신 연결을 나타내며 정책 적용 완료를 뜻하지 않습니다.
`로그 지우기`는 화면 기록만 지우고, `정책 초기화`는 드라이버의 적용 정책을 비웁니다.
프로세스 로그는 연결 해제·재연결 후에도 현재 UI에서 정책을 다시 적용해야 표시합니다.

Debug 실행 파일:

```powershell
.\RansomUtilFactory.UI\bin\x64\Debug\net9.0-windows\RansomUtilFactory.UI.exe
```

보호 폴더의 허용 실행 파일마다 `읽기`, `쓰기`, `코드 서명 확인`과 `전체 경로`·`프로세스 이름`
비교 방식을 각각 선택할 수 있습니다.
코드 서명을 선택한 실행 파일은 정책 적용 전에 유효한 로컬 코드 서명을 확인하고, 선택하지
않은 실행 파일은 선택한 비교 방식만 확인합니다. 읽기와 쓰기는 독립적으로 적용되며, 둘 다 해제한
프로세스는 정책에 포함할 수 없습니다. 코드 서명을 해제하면 실행 파일 교체를 인증서로
식별하지 못하므로 시험용 정책에서만 사용해야 합니다.
서명 확인이 필요한 경우 처음 접근할 때 UI가 신뢰 요청 이벤트를 처리한 뒤 다음 접근부터 허용하므로, 첫 시도는
차단될 수 있습니다. 반드시 시험용 VM의 복구 가능한 폴더에서 검증하십시오.
감시 예외 프로그램 편집은 후속 UI 단계에서 추가합니다.

파일 드라이버 설치·제거 기능은 WPF 실행 폴더와
`Drivers\UF_FileFilterFactory`의 설치 패키지를 검색합니다. 전체 솔루션 빌드 시
공용 `x64\$(Configuration)\bin` 폴더에 INF, SYS와 CAT 파일이 자동 복사됩니다.
드라이버 설치·제거 및 로드 시험은 반드시 스냅숏이 있는 시험용 VM에서 수행하십시오.

## 주요 설계 사항

- 폴더 경로는 `C:\Protected` 형식이 아니라
  `\Device\HarddiskVolume3\Protected`와 같은 커널 정규화 경로를 사용합니다.
  `uf_fltwarp.dll`이 정책의 DOS 경로를 NT 경로로 변환합니다.
- 보호 폴더의 허용 프로그램은 전체 이미지 경로 또는 파일 이름으로 비교합니다.
  프로세스 실행 정책은 이름을 기준으로 찾고 선택한 전체 경로·서명 조건을 검사합니다.
- INF에 지정된 개발용 고도 값은 배포에 사용할 수 없습니다. 제품을 배포하기
  전에 Microsoft에서 미니필터 고도 값을 배정받아야 합니다.
- 파일 드라이버는 생성·열기, 읽기·쓰기, 정보·보안 설정과 조회, 디렉터리 제어
  콜백을 등록합니다. 제공된 캡처의 로그만으로 개별 I/O 종류나 모든 경로의 차단을
  검증한 것은 아니며, 섹션 매핑 등 추가 경로와 복구 상황은 별도 시험이 필요합니다.
- 프로세스 드라이버는 `PsSetCreateProcessNotifyRoutineEx`와 `ObRegisterCallbacks`를
  사용합니다. 이름이 일치하는 정책의 경로·서명 조건을 만족하지 못하면
  프로세스 생성을 `STATUS_ACCESS_DENIED`로 차단하고,
  프로세스 핸들 권한은 관찰만 하며 변경하지 않습니다.

## 개발 문서

- 실제 실행 화면, 버튼별 기능 및 로그 해설은
  [`파일·프로세스 제어 사용 설명`](docs/포트폴리오/사용설명.md)과
  [15장 포트폴리오 PPT](docs/포트폴리오/RansomUtilFactory_파일·프로세스제어_포트폴리오_완성본.pptx)에 정리했습니다.
- 최근 수정 원인과 검증 범위는
  [`TSK-8 구현 현황`](docs/TSK-8_구현현황.md)을 참고하십시오.
- 프로젝트 구현 순서, 구성 요소별 책임 및 완료 조건은
  [`docs/개발계획.md`](docs/개발계획.md)를 참고하십시오.
- 드라이버와 사용자 모드 DLL 사이의 구조체, 명령, 이벤트 및 오류 처리는
  [`docs/통신규약.md`](docs/통신규약.md)를 참고하십시오.
- Codex를 포함한 개발 도구가 따라야 할 언어, 구현, 검증 및 안전 규칙은
  [`AGENTS.md`](AGENTS.md)에 정의되어 있습니다.
