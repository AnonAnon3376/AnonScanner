@echo off
chcp 65001 >nul
echo ========================================
echo    Burp AI Security Scanner 编译脚本
echo ========================================
echo.

echo [1/4] 检查Java环境...
java -version >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未检测到Java，请先安装JDK 11+
    echo 下载地址: https://adoptium.net/
    pause
    exit /b 1
)

REM 检查Java版本
for /f "tokens=3" %%g in ('java -version 2^>^&1 ^| findstr /i "version"') do (
    set JAVA_VERSION=%%g
)
set JAVA_VERSION=%JAVA_VERSION:"=%

echo [✓] Java已安装
java -version

REM 检查是否是Java 8
echo %JAVA_VERSION% | findstr /C:"1.8." >nul
if %errorlevel%==0 (
    echo.
    echo [警告] 检测到Java 8，但项目需要Java 11+
    echo.
    echo 解决方案:
    echo 1. 运行 set_java21.bat 切换到Java 21
    echo 2. 或配置JAVA_HOME环境变量指向Java 11+
    echo.
    pause
    exit /b 1
)

echo.

echo [2/4] 检查Maven环境...
mvn --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [警告] 未检测到Maven！
    echo.
    echo 请选择:
    echo 1. 查看Maven安装教程
    echo 2. 退出（手动安装Maven后重试）
    echo.
    set /p choice="请输入选择 (1/2): "
    
    if "%choice%"=="1" (
        echo.
        echo ========================================
        echo    Maven 安装教程
        echo ========================================
        echo.
        echo 方法1: 自动安装（推荐）
        echo   运行: install_maven.bat
        echo.
        echo 方法2: 手动安装
        echo   1. 访问: https://maven.apache.org/download.cgi
        echo   2. 下载: apache-maven-3.9.6-bin.zip
        echo   3. 解压到: C:\Program Files\Apache\maven
        echo   4. 添加环境变量:
        echo      MAVEN_HOME = C:\Program Files\Apache\maven
        echo      Path += %%MAVEN_HOME%%\bin
        echo   5. 重启命令行窗口
        echo   6. 重新运行 build.bat
        echo.
        echo 详细说明请查看: 编译指南.md
        echo.
        pause
        exit /b 1
    ) else (
        echo 已取消编译
        pause
        exit /b 0
    )
)
echo [✓] Maven已安装
mvn --version
echo.

echo [3/4] 开始编译...
echo 提示: 首次编译需要下载依赖，可能需要几分钟...
echo.
call mvn clean package -DskipTests
if %errorlevel% neq 0 (
    echo.
    echo [错误] 编译失败！
    echo.
    echo 常见问题:
    echo 1. 网络问题导致依赖下载失败
    echo    解决: 配置阿里云Maven镜像（见编译指南.md）
    echo 2. Java版本不对
    echo    解决: 确保使用JDK 11+
    echo 3. 代码文件不完整
    echo    解决: 检查所有Java文件是否存在
    echo.
    pause
    exit /b 1
)
echo.

echo [4/4] 验证编译结果...
if exist "target\burp-ai-sec-scanner-1.0.0.jar" (
    echo [✓] 编译成功！
) else (
    echo [错误] 未找到编译输出文件！
    pause
    exit /b 1
)
echo.

echo ========================================
echo    🎉 编译成功！
echo ========================================
echo.
echo 输出文件: target\burp-ai-sec-scanner-1.0.0.jar
echo 文件大小: 
for %%A in ("target\burp-ai-sec-scanner-1.0.0.jar") do echo %%~zA 字节
echo.
echo 📝 下一步操作:
echo.
echo 1. 安装到Burp Suite:
echo    - 打开Burp Suite
echo    - Extender → Extensions → Add
echo    - 选择 target\burp-ai-sec-scanner-1.0.0.jar
echo    - 点击 Next
echo.
echo 2. 配置AI模型:
echo    - 点击 "AI Security Scanner" 标签
echo    - 选择AI提供商（阿里千问/DeepSeek/智谱AI等）
echo    - 填写API Key
echo    - 测试连接并保存
echo.
echo 3. 开始使用:
echo    - 右键点击HTTP请求
echo    - 选择 "Send to AI Security Scanner"
echo    - 查看扫描结果
echo.
echo 📚 详细文档:
echo    - README.md - 完整使用说明
echo    - AI_MODELS.md - AI模型选择指南
echo    - QUICKSTART.md - 快速开始
echo    - 编译指南.md - 编译问题解决
echo.

pause
