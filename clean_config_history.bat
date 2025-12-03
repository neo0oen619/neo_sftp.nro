@echo off
setlocal ENABLEDELAYEDEXPANSION

REM =====================================================================
REM  clean_config_history.bat
REM ---------------------------------------------------------------------
REM  This script removes build/config.ini from ALL git history using
REM  git-filter-repo and force-pushes the cleaned history back to GitHub.
REM
REM  WARNING:
REM    - This rewrites the repository history.
REM    - All commit SHAs will change.
REM    - You should treat any secrets that were in build/config.ini as
REM      compromised and rotate/revoke them BEFORE running this.
REM =====================================================================

echo [INFO] This will rewrite git history to remove build/config.ini
echo        from ALL commits and force-push the result.
echo.
echo  * Make sure you have already revoked/rotated any secrets in that file.
echo  * Anyone with a clone will need to re-sync or reclone after this.
echo.
set /p CONFIRM=Type YES to continue, anything else to abort: 
if /I not "%CONFIRM%"=="YES" (
    echo [INFO] Aborted by user.
    pause
    exit /b 0
)

REM ---------------------------------------------------------------------
REM Figure out the origin URL from the current repo
REM ---------------------------------------------------------------------
if not exist ".git" (
    echo [ERROR] No .git directory found. Run this from inside a git repo.
    pause
    exit /b 1
)

for /f "usebackq delims=" %%R in (`git remote get-url origin`) do (
    set REPO_URL=%%R
)

if "%REPO_URL%"=="" (
    echo [ERROR] Could not determine origin URL.
    pause
    exit /b 1
)

echo.
echo [INFO] Origin URL detected: %REPO_URL%

REM ---------------------------------------------------------------------
REM Check for git-filter-repo availability
REM ---------------------------------------------------------------------
echo.
echo [INFO] Checking for git-filter-repo...
git-filter-repo --help >NUL 2>&1
if errorlevel 1 (
    echo [ERROR] git-filter-repo does not appear to be installed or on PATH.
    echo         Install it first, for example:
    echo           pip install git-filter-repo
    echo         or follow GitHub docs:
    echo           https://github.com/newren/git-filter-repo
    pause
    exit /b 1
)

REM ---------------------------------------------------------------------
REM Create a temporary mirror clone
REM ---------------------------------------------------------------------
set MIRROR_DIR=%TEMP%\repo_mirror_%RANDOM%%RANDOM%
echo.
echo [INFO] Creating mirror clone at: "%MIRROR_DIR%"
git clone --mirror "%REPO_URL%" "%MIRROR_DIR%"
if errorlevel 1 (
    echo [ERROR] git clone --mirror failed.
    pause
    exit /b 1
)

pushd "%MIRROR_DIR%"

REM ---------------------------------------------------------------------
REM Run git-filter-repo to remove build/config.ini from all history
REM ---------------------------------------------------------------------
echo.
echo [INFO] Running git filter-repo to strip build/config.ini from history...
git-filter-repo --invert-paths --path build/config.ini
if errorlevel 1 (
    echo [ERROR] git filter-repo failed.
    popd
    pause
    exit /b 1
)

REM ---------------------------------------------------------------------
REM Force-push cleaned history back to origin
REM ---------------------------------------------------------------------
echo.
echo [INFO] Force-pushing cleaned history back to origin...
git push --force --mirror origin
if errorlevel 1 (
    echo [ERROR] Force-push failed.
    popd
    pause
    exit /b 1
)

popd

echo.
echo [INFO] Done. The remote history has been rewritten without build/config.ini.
echo.
echo IMPORTANT:
echo  - All clone(s) of this repo should now either:
echo      * git fetch && git reset --hard origin/master   (or origin/main), OR
echo      * delete the local directory and clone fresh.
echo  - Any forks will still have the old history unless their owners also
echo    clean or recreate them.
echo.
pause
endlocal
exit /b 0
