# 실제 부트 검사 소스의 사용자 모드 회귀 시험

`main.c`는 제품의 `UF_FileFilterFactory/src/boot_guard.c`를 직접 포함한다.
판정 알고리즘을 시험 프로젝트에 복제하지 않는다. `fltKernel.h`는 이 프로젝트에서만
사용하는 메모리 모의 API이며 실제 커널·필터 관리자 함수를 호출하지 않는다.
드라이버 설치/로드, 관리자 권한, 원시 디스크 열기/쓰기, 악성코드 실행은 필요하지 않다.

## 검사 범위

- 비페이징 KernelMode 및 PID 0/4 변경 쓰기 차단, 커널 페이징/관리 클라이언트 예외.
- 정지 상태·일반 파일·범위 밖 쓰기의 기존 통과 동작.
- 실제 worker의 선두 바이트 비교, 동일 바이트 허용과 변경 바이트 차단.
- 문맥·참조·MDL·메모리·작업 큐·대상 검증·재열기·읽기 실패 주입.
- 읽기 실패 등의 Action 7 차단과 검사·차단·실패 카운터, Action 5 내용 변경 차단 구분.
- 1 MiB 쓰기 및 16개 보류 상한 초과 차단. 활성 상태에서 rundown 획득 실패 차단.
- 검사 중 정지 및 관리 클라이언트 변경 시 새 차단 취소.
- 비동기 사후 콜백까지 스냅숏 수명 유지, 원래 사용자 버퍼 변경과 승인 버퍼 분리.
- 모든 시험 이후 메모리·MDL·읽기 핸들·파일 객체·프로세스·볼륨·인스턴스 참조 균형.
- 선두 마지막 바이트, 비영점 위치, 범위 밖 변경, 정확히 1 MiB 크기 등의 경계.

메모리 모의 함수는 큐에 넣은 worker를 결정적 순서로 실행한다. 실제 스레드 경합,
장치 지연, Windows 파일시스템/저장장치 경로, 볼륨 잠금의 실제 NTSTATUS, 정식 커널
MDL 소유권과 Driver Verifier는 검증하지 않는다. 실제 `driver.c`의 콜백 등록·호출
순서는 별도 코드 검토 대상이다. 테스트 통과를 VM 실방어 검증으로 표현하지 않는다.
특히 빈 이름의 장치 신원을 얻지 못한 요청은 확인된 원시 대상에 포함되지 않는다는
현행 제한을 명시적으로 검사한다. 모든 직접 물리 디스크 경로를 보호한다는 뜻은 아니다.

## 실행

개발자 PowerShell에서 다음을 실행한다. 실행 정책 때문에 서명되지 않은 스크립트를
실행할 수 없다면 정책을 바꾸지 않고 아래 동일 컴파일 명령을 개발자 명령 프롬프트에서
사용할 수 있다.

```powershell
& G:\GitCode\Ransomeware\tests\FileBootKernelChecks\run.ps1
```

```bat
cl /nologo /W4 /WX /TC /utf-8 /MT /I"G:\GitCode\Ransomeware\tests\FileBootKernelChecks" "G:\GitCode\Ransomeware\tests\FileBootKernelChecks\main.c" /Fo"G:\GitCode\Ransomeware\artifacts\file-boot-kernel-checks\FileBootKernelChecks.obj" /Fe"G:\GitCode\Ransomeware\artifacts\file-boot-kernel-checks\FileBootKernelChecks.exe"
G:\GitCode\Ransomeware\artifacts\file-boot-kernel-checks\FileBootKernelChecks.exe
```

`artifacts\file-boot-kernel-checks` 출력 폴더를 먼저 준비해야 한다. 실행 파일과 모의 헤더는
제품 배포용 `bin`에 복사하지 않는다. 테스트 실행 결과의 검사 개수/실패 개수는 표준 출력으로
확인한다.
