# 외부 구성요소

이 디렉터리에는 프로젝트에서 사용하는 외부 구성요소가 들어 있습니다.

## `log4cpp`

`uf_fltwarp.dll`과 `UF_FileFilterTest.exe`의 파일 로그를 위해 `log4cpp` 소스를
정적 라이브러리로 빌드합니다. 빌드 프로젝트는
[`log4cpp.vcxproj`](log4cpp/log4cpp.vcxproj)이며 Debug·Release x64 구성에서
`log4cpp_static.lib`를 생성합니다.

원본 소스와 라이선스 전문은 `third_party/log4cpp` 아래에 보존합니다. 외부
소스의 주석과 README는 원본 저작물의 일부이므로 임의로 번역하거나 수정하지
않습니다.
