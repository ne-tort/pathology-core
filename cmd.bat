@echo off
REM TAGS from build_tags.txt (single source of truth)
setlocal EnableExtensions
set "TAGS="
for /f "usebackq eol=# tokens=* delims=" %%i in ("%~dp0build_tags.txt") do (
  if not defined TAGS set "TAGS=%%i"
)
if not defined TAGS (
  echo Error: could not read TAGS from build_tags.txt
  exit /b 1
)
go run --tags %TAGS% ./cmd/main %*
