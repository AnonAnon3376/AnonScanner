@echo off
chcp 65001 >nul
echo ========================================
echo    修复Maven SSL问题（HTTP方案）
echo ========================================
echo.

echo [警告] 此方案使用HTTP协议（不加密）
echo 仅在HTTPS方案失败时使用
echo.
pause

echo [1/3] 创建Maven配置目录...
if not exist "%USERPROFILE%\.m2" mkdir "%USERPROFILE%\.m2"
echo [✓] 目录已创建
echo.

echo [2/3] 创建Maven配置文件（HTTP版本）...

(
echo ^<?xml version="1.0" encoding="UTF-8"?^>
echo ^<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
echo           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
echo           xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 
echo           http://maven.apache.org/xsd/settings-1.0.0.xsd"^>
echo.
echo     ^<mirrors^>
echo         ^<mirror^>
echo             ^<id^>aliyun-http^</id^>
echo             ^<mirrorOf^>*^</mirrorOf^>
echo             ^<name^>Aliyun Maven HTTP^</name^>
echo             ^<url^>http://maven.aliyun.com/nexus/content/groups/public^</url^>
echo         ^</mirror^>
echo     ^</mirrors^>
echo.
echo ^</settings^>
) > "%USERPROFILE%\.m2\settings.xml"

echo [✓] 配置文件已创建
echo.

echo [3/3] 验证配置...
if exist "%USERPROFILE%\.m2\settings.xml" (
    echo [✓] 配置文件存在
) else (
    echo [错误] 配置文件不存在！
    pause
    exit /b 1
)
echo.

echo ========================================
echo    ✅ 修复完成！
echo ========================================
echo.
echo 已配置HTTP镜像（绕过SSL验证）
echo.
echo 下一步: 重新运行 build.bat
echo.

pause
