# TSK-8 프로세스 필터 드라이버 구현 현황

## 1. 작업 범위

`UF_ProcessFilterFactory`는 Windows 커널에서 프로세스 생성·종료 시점과 프로세스 간
핸들 접근을 감지하는 WDM 드라이버이다. TSK-8의 1차 범위는 정책과 사용자 모드
통신을 추가하기 전의 안전한 콜백 기반을 만드는 것이다.

포함 범위:

- 프로세스 생성·종료 통지 등록
- 프로세스 핸들 생성·복제 사전 통지 등록
- 향후 실행 차단 정책을 연결할 평가 함수
- 커널 진단 로그
- 부분 초기화 실패와 언로드 정리
- INF 패키지와 Debug·Release 공용 산출물 복사

제외 범위:

- 실행 차단 정책 등록과 저장
- 프로세스 핸들 접근 권한 제거
- `uf_procwarp` 통신 DLL
- WPF 프로세스 제어 정책과 이벤트 UI

## 2. 콜백 설계

### 2.1 프로세스 생성·종료

`PsSetCreateProcessNotifyRoutineEx`로 `UfProcessNotify`를 등록한다.

- 생성 시 PID, 부모 PID, 생성 요청자 PID, 이미지 경로와 정책 평가 결과를 기록한다.
- 종료 시 PID를 기록한다.
- `UfEvaluateProcessCreation`은 후속 정책 구현을 위한 단일 평가 지점이다.
- 현재 구현은 항상 `STATUS_SUCCESS`를 반환하므로 프로세스 생성을 차단하지 않는다.
- 후속 구현에서 거부 상태를 반환하면 `PS_CREATE_NOTIFY_INFO.CreationStatus`에 적용한다.

### 2.2 프로세스 간 접근

`ObRegisterCallbacks`로 `PsProcessType`의 다음 동작을 등록한다.

- `OB_OPERATION_HANDLE_CREATE`
- `OB_OPERATION_HANDLE_DUPLICATE`

사전 콜백은 요청자 PID, 대상 PID, 원래 요청 접근 마스크와 실제 접근 마스크를
기록한다. 커널 핸들과 자기 자신에 대한 접근은 정책 입력으로 유용하지 않고 이벤트
양이 많으므로 제외한다. 현재 구현은 접근 마스크를 변경하지 않는다.

### 2.3 수명 주기

프로세스 통지를 먼저 등록하고 오브젝트 콜백을 등록한다. 두 번째 등록에 실패하면
프로세스 통지를 즉시 해제한다. 언로드에서는 오브젝트 콜백을 먼저 해제하고 프로세스
통지를 해제하여 드라이버 코드가 반환된 뒤 다시 호출되지 않도록 한다.

## 3. 보안 및 안정성 원칙

- 콜백에서 사용자 모드 응답을 기다리지 않는다.
- 콜백에서 페이지 가능한 파일 또는 네트워크 작업을 하지 않는다.
- 1차 단계에서 강제 차단을 하지 않아 필수 시스템 프로세스의 오차단을 방지한다.
- 오브젝트 콜백 등록 요구사항에 맞게 드라이버 링크에 `/INTEGRITYCHECK`를 적용한다.
- 개발용 오브젝트 콜백 고도 `370040.8`은 배포 전에 충돌 여부를 검토하고 제품용
  식별 값으로 확정해야 한다.
- 드라이버 로드와 Driver Verifier 시험은 스냅숏 복구 가능한 테스트 서명 VM에서만 한다.

## 4. 진단 이벤트

커널 진단 문자열은 `[UF_ProcessFilterFactory]` 접두사를 사용한다.

- `driver-loaded`, `driver-unloaded`
- `process-create`, `process-exit`
- `process-access`
- `process-notify-registration-failed`
- `object-callback-registration-failed`

이 진단 문자열은 개발 단계 관찰용이며 후속 `uf_procwarp` ABI 이벤트 형식을 대신하지 않는다.

## 5. 시험 항목

정적·빌드 시험:

- Debug x64 전체 솔루션 Rebuild
- Release x64 전체 솔루션 Rebuild
- 컴파일 경고와 오류 개수 확인
- 구성별 `x64\$(Configuration)\bin`의 SYS·INF·CAT 확인
- Debug CER 포함과 Release CER 미포함 확인
- INF 패키지 생성과 검증 결과 확인

전용 VM 동적 시험:

1. 테스트 인증서와 INF 패키지를 설치한다.
2. 드라이버를 시작하고 `driver-loaded` 로그를 확인한다.
3. 시험 프로그램을 시작·종료하여 생성·종료 PID와 이미지 경로를 확인한다.
4. `OpenProcess`와 `DuplicateHandle` 시험으로 프로세스 간 접근 로그를 확인한다.
5. 드라이버를 중지하고 `driver-unloaded` 로그를 확인한다.
6. 반복 로드·언로드와 Driver Verifier에서 충돌, 교착과 누수를 확인한다.

## 6. 후속 작업

2차 작업에서는 공유 ABI와 원자적 정책 교체를 먼저 정의한 뒤 다음 기능을 추가한다.

- 실행 차단 이미지 정책과 필수 시스템 예외
- `CreationStatus`를 통한 생성 차단
- 위험한 프로세스 핸들 권한의 선택적 제거
- `uf_procwarp` 비동기 이벤트 수신
- WPF 프로세스 정책 편집과 생성·접근 로그 UI

## 7. 2026-08-14 빌드 결과

- `Debug | x64` 전체 솔루션 Rebuild 성공: 오류 0개, 경고 0개
- `Release | x64` 전체 솔루션 Rebuild 성공: 오류 0개, 경고 0개
- WDK 패키지 서명 가능성 시험 성공: 오류 0개, 경고 0개
- Debug 공용 폴더: SYS·INF·CAT·CER 포함, PDB 미포함
- Release 공용 폴더: SYS·INF·CAT 포함, CER·PDB 미포함
- Debug SYS PE 특성에서 `Check integrity` 적용 확인

32비트 MSBuild는 설치된 WDK에 없는 `x86\InfVerif.dll`을 요구하여 실패하므로,
README에 명시된 64비트 MSBuild 실행 파일을 사용했다. 이는 소스 또는 INF 검증 실패가
아니며 64비트 MSBuild의 전체 Rebuild에서는 INF 검증과 패키지 생성이 성공했다.

## 8. 2026-08-16 Win11 VM 동적 시험 결과

시험 환경:

- Hyper-V VM: `Win11`
- 게스트 OS: Windows 11 Pro `10.0.26200.0`
- 시험 전 체크포인트: `TSK-8 ProcessDriver BeforeTest 20260816`
- 테스트 서명 모드 활성화, Secure Boot 비활성화
- Debug 패키지의 SYS·CAT 서명 상태 `Valid`
- INF 설치 성공: 게시 이름 `oem7.inf`
- 원본 커널 로그: VM의
  `C:\RansomUtilFactory\TSK-8\process_driver_kernel.log`

콜백 동작 시험:

- 드라이버 시작과 중지 성공: `sc.exe` 종료 코드 각각 0
- `driver-loaded` 1건, `driver-unloaded` 1건
- `process-create` 14건, `process-exit` 10건
- 프로세스 핸들 생성 접근 1,896건, 복제 접근 70건
- 20초 캡처 전체 이벤트 1,992건
- 시험 대상 PowerShell PID 6200(`0x1838`) 관련 이벤트 54건
- 대상 프로세스의 생성, `OpenProcess`, `DuplicateHandle`, 종료 이벤트 확인
- 사용자 모드 시험에서 `OpenProcessSucceeded=True`,
  `DuplicateHandleSucceeded=True` 확인

Driver Verifier 시험:

- 기존 활성 설정이 없음을 확인한 뒤 `UF_ProcessFilterFactory.sys`만 대상으로 표준
  규칙 `0x001209bb` 적용
- Verifier 활성 상태에서 드라이버 로드·프로세스 핸들 접근·언로드 3회 반복 성공
- 세 번 모두 시작·중지 종료 코드 0, 핸들 접근 성공
- BugCheck와 새 Minidump·`MEMORY.DMP` 없음
- Hyper-V 강제 재시작 시각의 Kernel-Power 41 이벤트 1건은 시험 절차상 전원 이벤트이며
  드라이버 검증 위반이 아님
- 시험 후 Verifier를 해제하고 정상 재부팅하여 플래그 `0x00000000`, 검증 대상 0개 확인
- 최종 상태: VM 실행 중, 드라이버 서비스 `Stopped`, 시작 유형 `Manual`
- 시험 결과 반영 후 `Debug | x64`, `Release | x64` 전체 솔루션 Rebuild 성공:
  오류 0개, 경고 0개
- Debug 공용 폴더의 SYS·INF·CAT·CER와 Release 공용 폴더의 SYS·INF·CAT 확인
- 두 공용 폴더에 PDB가 없고 Release 공용 폴더에 CER가 없음을 확인

관찰 사항:

- 필터 없이 모든 프로세스 핸들 접근을 진단 출력하면 20초에 약 2천 건이 발생한다.
- 2차 사용자 모드 이벤트 경로에서는 정책 관련 이벤트 선별, 큐 크기 제한, 손실 카운터,
  속도 제한 또는 집계를 ABI 설계에 포함해야 한다.
