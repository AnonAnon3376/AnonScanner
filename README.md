# Anon Scanner

🤖 AI驱动的Burp Suite安全扫描插件，专注于检测高危Web漏洞。

## ✨ 核心特性

🤖 **多AI模型支持** - 支持阿里千问、DeepSeek、智谱AI、字节豆包、OpenAI等8+主流AI模型  
🔌 **开放式架构** - 支持任意兼容OpenAI格式的自定义API端点  
🎯 **智能检测** - AI驱动的漏洞分析，覆盖7大类高危漏洞  
🛠️ **手动+被动** - 支持右键手动扫描和被动自动监控  
📊 **任务管理** - 类似Burp风格的任务列表，高亮显示漏洞风险  
💰 **成本控制** - 内置扫描频率限制，防止API成本过高  

## 🎯 支持的漏洞类型

### 反序列化漏洞
- FastJson (1.2.24-1.2.80全版本)
- Jackson、XStream、SnakeYAML、Hessian
- Java原生反序列化

### 命令执行漏洞  
- Log4j2 RCE (CVE-2021-44228)
- Spring4Shell (CVE-2022-22965)
- Struts2系列漏洞
- Weblogic T3/IIOP、Shiro反序列化

### SQL注入
- MySQL/PostgreSQL/Oracle/MSSQL
- MongoDB NoSQL注入

### XXE漏洞
- 标准XXE、Blind XXE
- XXE via SVG/XLSX/DOCX

### 模板注入 (SSTI)
- Freemarker/Velocity/Thymeleaf/Jinja2

### 其他高危漏洞
- SSRF、文件上传、任意文件读取、目录遍历

## 🤖 支持的AI模型

| AI提供商 | 推荐模型 | Base URL |
|---------|---------|----------|
| 阿里千问 | qwen-plus, qwen-max | `https://dashscope.aliyuncs.com/compatible-mode/v1` |
| DeepSeek | deepseek-chat, deepseek-coder | `https://api.deepseek.com/v1` |
| 智谱AI | glm-4, glm-4-flash | `https://open.bigmodel.cn/api/paas/v4` |
| 字节豆包 | doubao-pro-32k | `https://ark.cn-beijing.volces.com/api/v3` |
| OpenAI | gpt-4o, gpt-4o-mini | `https://api.openai.com/v1` |
| 月之暗面 | moonshot-v1-8k | `https://api.moonshot.cn/v1` |
| 百川智能 | Baichuan2-Turbo | `https://api.baichuan-ai.com/v1` |
| 零一万物 | yi-large, yi-medium | `https://api.lingyiwanwu.com/v1` |
| 自定义 | 任意兼容OpenAI格式的API | 手动填写 |

## 🚀 快速开始

### 1. 编译插件

**前置要求：**
- JDK 11+
- Maven 3.6+

```bash
# 克隆项目
git clone https://github.com/yizhouliao/AnonScanner.git
cd AnonScanner

# 编译打包
mvn clean package

# 生成的jar文件：target/burp-ai-sec-scanner-1.0.0.jar
```

### 2. 安装到Burp Suite

1. 打开Burp Suite
2. 进入 **Extender** → **Extensions**
3. 点击 **Add**
4. Extension type: 选择 **Java**
5. Extension file: 选择 `burp-ai-sec-scanner-1.0.0.jar`
6. 点击 **Next**

### 3. 配置AI API

1. 点击 **Anon Scanner** 标签页
2. 进入 **配置** 子标签
3. 选择AI提供商或选择"自定义"
4. 填写API配置并测试连接
5. 保存配置

### 4. 开始扫描

**手动扫描：**
1. 右键点击HTTP请求
2. 选择 **Send to Anon Scanner**

**被动扫描：**
1. 在配置中启用"被动扫描"
2. 自动监控POST/PUT/DELETE/PATCH请求

## 📋 界面说明

### 配置页面
- **AI模型配置**：选择提供商、填写API Key
- **扫描选项**：深度分析、生成Payload、风险评估
- **自动验证**：混合模式，AI分析+自动验证
- **被动扫描**：自动监控HTTP/HTTPS流量
- **成本控制**：每日/每小时/并发扫描限制

### 任务管理页面 ⭐
- **任务列表**：类似Burp风格的表格展示
- **高亮显示**：
  - 🔴 高危漏洞 - 红色背景
  - 🟠 中危漏洞 - 橙色背景  
  - 🟡 低危漏洞 - 黄色背景
  - 🔵 扫描中 - 蓝色背景
- **实时统计**：总计/今日/本小时/运行中任务数
- **自动刷新**：每2秒更新任务状态

### 扫描结果页面
- **历史记录**：所有扫描历史
- **详细结果**：AI分析报告
- **导出功能**：支持复制和导出

## 🔧 自定义API配置

如果你使用的是自定义API或其他兼容OpenAI格式的服务：

1. **选择提供商**：自定义
2. **Base URL**：你的API端点地址
   ```
   示例：https://your-api.com/v1
   ```
3. **API Key**：你的API密钥
4. **Model**：模型名称
   ```
   示例：gpt-3.5-turbo 或 your-custom-model
   ```

**常见自定义API：**
- OpenAI兼容的本地部署
- 第三方API代理服务
- 企业内部AI服务

## 🛡️ 被动扫描

### 支持HTTPS
✅ **完全支持HTTPS流量监控**
- Burp代理自动解密HTTPS
- 插件接收明文请求进行分析
- 无需额外配置

### 监控范围
**✅ 会扫描：**
- POST/PUT/DELETE/PATCH请求
- 包含JSON/XML/Form数据的请求
- 有参数的请求

**❌ 会过滤：**
- GET/HEAD/OPTIONS请求
- 静态资源(.css, .js, .png等)
- 静态路径(/static/, /images/等)

### 成本控制
- **每日限制**：默认100次扫描
- **每小时限制**：默认20次扫描  
- **并发限制**：默认3个同时扫描
- 达到限制自动停止，防止API成本过高

## 💡 使用技巧

### 1. API成本优化
```
推荐配置：
- DeepSeek: 性价比最高 (¥0.001/千tokens)
- 阿里千问: 中文效果好 (¥0.004/千tokens)
- 智谱AI: 代码理解强 (¥0.005/千tokens)
```

### 2. 扫描策略
- **手动扫描**：针对重点接口，精准分析
- **被动扫描**：全面监控，自动发现
- **混合模式**：AI分析+自动验证，提高准确率

### 3. 结果分析
- 查看**任务管理**页面的高亮显示
- 重点关注红色(高危)和橙色(中危)的请求
- 复制AI生成的Payload进行手动验证

## ❓ 常见问题

### Q: 自定义API连接失败？
**A: 检查以下配置：**
1. **Base URL格式**：确保以 `/v1` 结尾
   ```
   正确：https://api.example.com/v1
   错误：https://api.example.com
   ```
2. **API Key格式**：确保包含正确的前缀
   ```
   OpenAI格式：sk-xxxxxxxx
   其他格式：按提供商要求
   ```
3. **Model名称**：确保模型名称正确
4. **网络连接**：确保能访问API地址

### Q: 被动扫描没反应？
**A: 检查以下设置：**
1. 配置页面是否启用"被动扫描"
2. 是否有POST/PUT/DELETE/PATCH请求通过代理
3. 查看Burp的 **Extender** → **Output** 控制台日志
4. 检查是否达到扫描限制

### Q: HTTPS请求能监控吗？
**A: 完全可以！**
- Burp代理会自动解密HTTPS流量
- 插件接收到的是明文请求
- 需要在浏览器中安装Burp CA证书

### Q: 如何降低API成本？
**A: 几种方法：**
1. 选择便宜的AI模型（如DeepSeek）
2. 调整成本控制限制
3. 关闭被动扫描，只用手动扫描
4. 减少Max Tokens设置

## 📊 项目结构

```
AnonScanner/
├── pom.xml                     # Maven配置
├── README.md                   # 项目说明
├── build.bat                   # Windows编译脚本
└── src/main/java/com/security/burp/
    ├── BurpExtender.java       # 主扩展类
    ├── config/
    │   └── PluginConfig.java   # 配置管理
    ├── ai/
    │   └── QianwenAIClient.java # AI客户端
    ├── scanner/
    │   ├── AISecurityScanner.java      # 主扫描器
    │   ├── ScanTask.java               # 扫描任务
    │   ├── ScanTaskManager.java        # 任务管理器
    │   └── PassiveScanEngine.java      # 被动扫描引擎
    ├── ui/
    │   ├── ConfigPanel.java            # 配置界面
    │   ├── TaskManagerPanel.java       # 任务管理界面
    │   └── ResultPanel.java            # 结果展示界面
    ├── verifier/
    │   └── VulnerabilityVerifier.java  # 漏洞验证器
    └── dnslog/
        └── DnsLogClient.java           # DNS日志客户端
```

## 🔄 更新日志

### v1.0.0 (2025-05-11)
- ✨ 支持8+主流AI模型
- ✨ 新增任务管理页面，高亮显示漏洞
- ✨ 支持被动扫描，自动监控HTTP/HTTPS流量
- ✨ 支持混合模式（AI分析+自动验证）
- ✨ 内置成本控制，防止API费用过高
- ✨ 支持自定义API端点
- ✨ 界面优化，支持滚动显示

## ⚠️ 免责声明

本工具仅供安全研究和授权渗透测试使用。使用者应当：

1. 仅在获得明确授权的系统上使用
2. 遵守当地法律法规
3. 对使用本工具产生的任何后果负责
4. 妥善保管API密钥，防止泄露

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

1. Fork 本项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 📞 联系方式

- GitHub: [@AnonAnon3376 ](https://github.com/AnonAnon3376 )
- 项目链接: [https://github.com/AnonAnon3376 /AnonScanner](https://github.com/yizhouliao/AnonScanner)

---

⭐ 如果这个项目对你有帮助，请给个Star支持一下！
