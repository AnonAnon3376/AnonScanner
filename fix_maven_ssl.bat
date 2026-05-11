@echo off
chcp 65001 >nul
echo ========================================
echo    修复Maven SSL证书问题
echo ========================================
echo.

echo [1/3] 创建Maven配置目录...
if not exist "%USERPROFILE%\.m2" mkdir "%USERPROFILE%\.m2"
echo [✓] 目录已创建: %USERPROFILE%\.m2
echo.

echo [2/3] 创建Maven配置文件...
echo 正在写入配置到: %USERPROFILE%\.m2\settings.xml
echo.

(
echo ^<?xml version="1.0" encoding="UTF-8"?^>
echo ^<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
echo           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
echo           xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 
echo           http://maven.apache.org/xsd/settings-1.0.0.xsd"^>
echo.
echo     ^<mirrors^>
echo         ^<!-- 阿里云Maven镜像 --^>
echo         ^<mirror^>
echo             ^<id^>aliyun-central^</id^>
echo             ^<mirrorOf^>central^</mirrorOf^>
echo             ^<name^>Aliyun Maven Central^</name^>
echo             ^<url^>https://maven.aliyun.com/repository/central^</url^>
echo         ^</mirror^>
echo.
echo         ^<mirror^>
echo             ^<id^>aliyun-public^</id^>
echo             ^<mirrorOf^>*^</mirrorOf^>
echo             ^<name^>Aliyun Maven Public^</name^>
echo             ^<url^>https://maven.aliyun.com/repository/public^</url^>
echo         ^</mirror^>
echo     ^</mirrors^>
echo.
echo     ^<profiles^>
echo         ^<profile^>
echo             ^<id^>aliyun^</id^>
echo             ^<repositories^>
echo                 ^<repository^>
echo                     ^<id^>aliyun-central^</id^>
echo                     ^<url^>https://maven.aliyun.com/repository/central^</url^>
echo                     ^<releases^>
echo                         ^<enabled^>true^</enabled^>
echo                     ^</releases^>
echo                     ^<snapshots^>
echo                         ^<enabled^>false^</enabled^>
echo                     ^</snapshots^>
echo                 ^</repository^>
echo                 ^<repository^>
echo                     ^<id^>aliyun-public^</id^>
echo                     ^<url^>https://maven.aliyun.com/repository/public^</url^>
echo                     ^<releases^>
echo                         ^<enabled^>true^</enabled^>
echo                     ^</releases^>
echo                     ^<snapshots^>
echo                         ^<enabled^>false^</enabled^>
echo                     ^</snapshots^>
echo                 ^</repository^>
echo             ^</repositories^>
echo             ^<pluginRepositories^>
echo                 ^<pluginRepository^>
echo                     ^<id^>aliyun-plugin^</id^>
echo                     ^<url^>https://maven.aliyun.com/repository/public^</url^>
echo                     ^<releases^>
echo                         ^<enabled^>true^</enabled^>
echo                     ^</releases^>
echo                     ^<snapshots^>
echo                         ^<enabled^>false^</enabled^>
echo                     ^</snapshots^>
echo                 ^</pluginRepository^>
echo             ^</pluginRepositories^>
echo         ^</profile^>
echo     ^</profiles^>
echo.
echo     ^<activeProfiles^>
echo         ^<activeProfile^>aliyun^</activeProfile^>
echo     ^</activeProfiles^>
echo.
echo ^</settings^>
) > "%USERPROFILE%\.m2\settings.xml"

if %errorlevel% neq 0 (
    echo [错误] 配置文件创建失败！
    pause
    exit /b 1
)

echo [✓] 配置文件已创建
echo.

echo [3/3] 验证配置...
if exist "%USERPROFILE%\.m2\settings.xml" (
    echo [✓] 配置文件存在: %USERPROFILE%\.m2\settings.xml
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
echo 已配置阿里云Maven镜像，解决SSL证书问题
echo.
echo 配置文件位置:
echo %USERPROFILE%\.m2\settings.xml
echo.
echo 下一步:
echo 1. 重新运行编译: build.bat
echo 2. 或手动执行: mvn clean package
echo.
echo 提示: 阿里云镜像速度更快，下载依赖更稳定
echo.

pause
