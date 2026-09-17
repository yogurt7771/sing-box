@echo off
setlocal EnableDelayedExpansion

%~d0
cd /d "%~dp0"

set "BUILD_TAGS=with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_naive_outbound,with_purego,badlinkname,tfogo_checklinkname0"
set "VERSION=unknown"

for /f "usebackq delims=" %%V in (`go run ./cmd/internal/read_tag 2^>nul`) do (
    set "VERSION=%%V"
)

if not exist dist mkdir dist

set "CGO_ENABLED=0"
set "GOOS=windows"
set "GOARCH=amd64"

go build -v -trimpath ^
  -o "dist\sing-box.exe" ^
  -tags "%BUILD_TAGS%" ^
  -ldflags "-s -buildid= -X github.com/sagernet/sing-box/constant.Version=!VERSION! -X internal/godebug.defaultGODEBUG=multipathtcp=0 -checklinkname=0" ^
  ./cmd/sing-box

if errorlevel 1 exit /b 1

echo Built dist\sing-box.exe ^(windows/amd64, version=!VERSION!^)
echo Note: CI additionally packages libcronet.dll for naive outbound runtime.