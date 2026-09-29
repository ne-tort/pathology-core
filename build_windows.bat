@echo off
setlocal EnableExtensions
cd /d "%~dp0"
set GOOS=windows
set GOARCH=amd64
set CGO_ENABLED=1

REM TAGS from build_tags.txt (single source of truth)
set "TAGS="
for /f "usebackq eol=# tokens=* delims=" %%i in ("%~dp0build_tags.txt") do (
  if not defined TAGS set "TAGS=%%i"
)
if not defined TAGS (
  echo Error: could not read TAGS from build_tags.txt
  exit /b 1
)

if not exist bin mkdir bin
if not exist bin\libcronet.dll (
  echo Extracting libcronet.dll from go.mod-pinned module...
  go mod download github.com/sagernet/cronet-go/lib/windows_amd64
  if errorlevel 1 exit /b 1
  for /f "delims=" %%D in ('go list -m -f "{{.Dir}}" github.com/sagernet/cronet-go/lib/windows_amd64') do (
    copy /Y "%%D\libcronet.dll" bin\libcronet.dll >nul
  )
  if not exist bin\libcronet.dll (
    echo Error: libcronet.dll not found after go mod download
    exit /b 1
  )
)

echo Building pathology-core.dll...
echo Tags: %TAGS%
go build -trimpath -tags %TAGS%,with_purego -buildmode=c-shared -ldflags="-w -s -checklinkname=0" -o bin/pathology-core.dll ./platform/desktop
if errorlevel 1 exit /b 1

echo Building PathologyCli.exe...
go install -mod=readonly github.com/akavel/rsrc@latest
if errorlevel 1 (
  echo Error: could not install rsrc
  exit /b 1
)
for /f "delims=" %%G in ('go env GOPATH') do set "GOPATH=%%G"
"%GOPATH%\bin\rsrc.exe" -ico "%~dp0assets\pathology-cli.ico" -o "%~dp0cmd\bydll\cli.syso"
if errorlevel 1 (
  echo Error: rsrc failed to embed assets\pathology-cli.ico into cmd\bydll\cli.syso
  exit /b 1
)
copy /Y bin\pathology-core.dll pathology-core.dll >nul
set CGO_LDFLAGS=pathology-core.dll
go build -trimpath -tags %TAGS%,with_purego -ldflags="-w -s -checklinkname=0" -o bin/PathologyCli.exe ./cmd/bydll
set CGO_LDFLAGS=
del pathology-core.dll 2>nul

if not exist bin\pathology-core.dll (
  echo Error: bin\pathology-core.dll not built
  exit /b 1
)
if not exist bin\PathologyCli.exe (
  echo Error: bin\PathologyCli.exe not built
  exit /b 1
)
echo OK: bin\pathology-core.dll bin\PathologyCli.exe bin\libcronet.dll
