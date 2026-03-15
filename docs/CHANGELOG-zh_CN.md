# 📋 AWStats 版本更新发布记录

*基于官方文档、SourceForge 记录和作者历史资料整理*

⚠️ **AWStats 8.0 将是原作者（Laurent Destailleur）维护的最后一个版本，后续版本由社区维护。**



## 🚀 8.x 系列 (2024-latest)

### 8.1 - 2026-03-10
- 📱 采用 HTML5 标准，支持响应式设计
- 🌙 新增深色/浅色主题切换功能
- 🧭 新增导航菜单，网站部署人员可使用本土化语言查看官方文档
- 📖 新增文档查看器（iframe），点击菜单链接在页面内查看文档，支持关闭按钮
- ♻️ 重构英文硬编码文档，用户可根据语言喜好阅读文档，基于官方文档利用 [deepseek](https://www.deepseek.com) 翻译。如有错误翻译，欢迎反馈至 [hestiacn@tuta.io](mailto:hestiacn@tuta.io)
- 🚀 语言文件从 GBK 编码的 .txt 格式，改为全新现代的 UTF-8 编码的 .po 格式，基于 gettext 标准，便于维护和翻译
- 🛡️ 默认添加安全响应头：X-Content-Type-Options, X-Frame-Options, Referrer-Policy
- 🌐 若未加载任何 GeoIP 插件，自动启用 geoipfree 插件
- ⬆️ 最低 Perl 版本要求从 5.007 提升至 5.020
- 🔧 启用 use warnings 和 use utf8，统一 UTF-8 编码输出
- 🎨 使用 CSS 变量定义主题颜色，支持一键切换
- 📊 表格样式现代化：圆角、悬停效果
- 😊 图标全面替换为 emoji
- ⚡ 优化 DNS 缓存机制，减少重复解析
- 🔄 改进 try/catch 异常处理，避免 JSON 解析崩溃
- 📡 增强对 IPv6 和 CloudFlare 真实 IP 头部的支持
- 📚 帮助信息更新，增加生成中文报告等示例
- 📋 新增版本更新历史页面 awstats_changelog.html，按版本分类展示
- 🐛 修复未声明变量 $lang 和 $dir_attr 导致的编译错误
- 🔨 修正 Try::Tiny 语法错误，确保 try/catch 正确解析
- 📐 单独控制 IP 和机器人列表表格第一列宽度，避免布局变形
- 🚪 文档查看器不再默认占用空白区域，点击链接后显示并增加关闭按钮
- 🌏 修正语言加载逻辑，auto 模式下正确回退到英文
- 📅 版权年份根据当前年份自动更新
- 🧹 移除过时的 PrintCLIHelp，统一使用 print_help

### 8.0 - 2025-08-26
- 👋 *这是开发者（Laurent Destailleur）维护的最后一个版本*
- 🔄 改进 CSS 样式表
- 📋 更新 robots.pm 数据库
- 🌍 修复 #248
- 📖 将繁体中文翻译迁移到 UTF-8 编码
- 🌳 排序树：检查键是否存在，不关心其值
- 📋 支持处理 JSON 格式日志
- 🔧 修复 NotPageList 的默认设置
- 📋 添加请求时间报告
- 📋 修复文档中的错误链接
- 🗑️ 从 robots.pm 中移除原生 Android 和原生 iOS/OSX 浏览器的 User Agent
- 🔧 修复 robots.pm 中 GPTBot 识别错误的问题
- 🔧 修复乌克兰语翻译的编码问题

---

## 📦 7.x 系列 (2011-2023)

### 7.9 - 2023-01-17
- 🪟 添加 Windows 11 和 Android 13 操作系统检测
- 🇭🇺 更新匈牙利语翻译并迁移到 UTF-8
- 🛡️ 修复跨站脚本漏洞 (CVE-2020-35176)
- 🔧 将硬编码文本替换为 $Message 变量（月、日、小时）
- 📱 添加 Android 11/12、macOS 11/12 检测
- 🇩🇪 更新德语翻译
- 🔄 改进换行符替换逻辑，同时支持 HTML 和 XHTML
- 🤖 添加一些新机器人和手机浏览器，修复 robots.pm 中的错误
- 📂 仅在专用的 awstats 目录中查找配置
- 📧 处理 SRS 邮件地址
- 🔒 修复 #195/CVE-2020-35176
- 🌍 修复 geoip2_country 插件问题
- 🖥️ 添加 HaikuOS 和基于 Safari 的 WebPositive 浏览器支持
- 🔨 添加缺失的 td 标签
- 🇹🇯 添加塔吉克语支持

### 7.8 - 2020-04-30
- 🗄️ 新增 DatabaseBreak 模式选择：月、日、小时
- 📋 更新 HTTP 状态码
- 📁 添加更多文件类型
- 📖 更新 README.md
- 🌍 修复 geoip2 格式化问题
- 🔍 修复 search_engines.pm 中的错误条目
- 🪟 修复 Windows 下的 geoip2 插件
- 🤖 更新 robots.pm，添加多个新机器人：PiplBot、um-IC/um-LN、arcemedia、bit.ly、bidswitchbot、bnf.fr_bot、contxbot、flamingo、getintent、laserlikebot、mappy、mojeek、serendeputy、trendiction、yak、zoominfobot
- 🔨 修复 #104
- 📝 改进 Markdown 可读性
- 📅 更新版权年份
- 🔒 改用 https 链接
- 🔗 修复 Perl 下载链接
- ⏱️ 新增 %time6 标签，支持某些 IIS 日志格式
- 📊 修复 geoip2 表格格式错误
- 🍏 添加 macOS DMG 和 PKG 文件支持
- 🖥️ 修复 HTTP 206 状态码的浏览器检测
- 💻 支持 macOS 10.13/10.14，改进图标图片压缩
- 📈 使用前 5 名作为图表基准
- 🧹 清理 geoip2 和 geoip2 city 模块：正确转换 DNS 名称、仅查询公网 IP、HTML 转义输出、代码改进
- 🗜️ 无损压缩 PNG 图片约 33%
- 🤖 添加机器人：The Knowledge AI
- 🔄 修复 RobotsSearchIDOrder_listx 记录数不一致错误
- ⚡ 优化 OptimizeArray 函数
- ⏰ 添加 UptimeRobot
- ⚙️ 修复配置文件中的语法错误
- 📏 忽略超过 80 字符的搜索短语
- 🔧 修复 404 详情页不更新问题
- 🔤 解码 RFC 3986 未保留字符
- 🔨 修复 #80
- ⚠️ 禁用 Perl > 5.6 的嵌套包含警告
- 🌐 更新 domains.pm
- 🔍 修复 search_engines.pm 中的两个无效条目
- 💾 TB 单位格式化
- ➗ 修复除以零错误
- 🔨 修复 #79
- 🛠️ 改进 awstats_buildstaticpages.pl 的错误处理
- 🔨 修复 #90
- 🚫 排除私有 IP 地址（GeoIP2::Reader 不支持）
- 🧹 仅清除已保存部分的数据
- 🏙️ 改进城市插件功能
- 📊 修复 ShowHost 部分的问题
- 🌍 初步实现 GeoIP2 City 查询
- 🇮🇱 更新希伯来语文件
- 🔍 改进雅虎检测
- 📱 在 awstats_misc_tracker.js 中添加设备像素比
- 🤖 基于 7.7 版本的 robots.pm 添加 37 个新机器人
- 🔄 移动 oBot 条目以避免被错误识别
- 🏁 缺失 Sint Maarten 旗帜
- 🌍 修复 #76 - 国家名称错误
- 📝 修复 UTF BOM 文件
- 🛡️ 修复 cPanel 安全团队报告的漏洞
- 🧪 添加更多测试

### 7.7 - 2018-01-07
- 🛡️ 安全修复：CVE-2017-1000501
- 🔒 安全修复：参数清理缺失
- 🔧 修复包含空格的 URL 的 LogFormat=4
- 🪟 修复外部引荐网站链接的 window.opener 漏洞
- 📝 添加 methodurlprot 定义日志格式
- 🔄 添加动态 DNS 查找
- 🌐 修复 Edge 支持

### 7.6 - 2016-12-07
- 🛡️ 安全修复：DirLang 参数不允许使用 |
- 🔒 安全修复：更严格的 AWSTATS_ENABLE_CONFIG_DIR 使用规则
- 🤖 更新 robots 数据库
- 💻 修复 OS 数据库
- 📚 更新/修复文档
- 🏁 添加缺失的 el 国家旗帜
- 📁 部分支持 pure-ftpd 统计格式
- 🍏 添加对 macOS Sierra 的支持
- 🔤 将 Web 字体添加到默认 NotPageList，支持 GPX 和 JSON 文件

### 7.5 - 2016-04-29
- 🐪 兼容 Perl 5.22
- 🌐 支持 Edge 浏览器版本检测
- 🤖 更新 robots 数据库
- 🔤 将 eot/woff/woff2 添加到 mime.pm 作为字体
- 🖼️ 将 .svgz 添加到图片列表
- 🚫 从搜索引擎中排除 groups.google
- ⏱️ 添加 %time5 标签，支持带时区的 ISO 时间格式
- 🔄 添加 DynamicDNSLookup 选项，在输出时进行 DNS 查找而非日志分析时
- 📊 增加 MaxRowsInHTMLOutput 默认值

### 7.4 - 2015-11-11
- 🌍 添加 geoip6 插件，支持 IPv4 和 IPv6
- ☁️ 支持 Amazon AWS 日志文件（使用 %time5 标签）
- 🔧 修复某些 .pl 脚本的权限问题
- 🔨 修复 #205：GetResolvedIP_ipv6 不删除尾部点
- ⚠️ 修复 #496：工具脚本应将警告和错误输出到 STDERR
- 🔗 修复 #919：引荐未被跟踪的问题
- 📝 修复 #921：geoip_generator.pl 帮助文本错误
- 🐛 修复 #909：awstats_buildstaticpages.pl 调试输出过多
- 💥 修复 #680：传递给 Time::Local 的无效数据导致全局销毁
- 🛡️ 修复 CVE-2006-2237

### 7.3 - 2015-11-11
- 📌 添加命令行选项 -version
- 🌍 改进 geoip 模块的错误管理
- 🗄️ 更新 domains、robots 和 search engines 数据库
- 📱 #877：AWStats 支持 Windows 8 和 iOS
- 🪟 检测 IE11 和 Windows 8.1
- 🔗 修复使用 builddate 选项时静态链接错误
- 🌐 恢复 Opera 浏览器版本检测
- 🏙️ #838：GeoIP Cities 页面无法工作
- 🖼️ 添加缺失的图标
- 🔒 #881：避免 graphgooglechartapi 模块的 http/https 混合警告
- 🔧 #918：HTMLShowLogins 中使用 $MinHit{'Host'} 而非 $MinHit{'Login'}
- 📦 将版本系统迁移到 SourceForge Git

### 7.2 - 2013-07-09
- ⚖️ 升级许可证到 GPL v3+
- 📚 更新文档
- ☁️ 支持 modCloudFlareIIS
- 🖥️ 修复 Webmin 1.53 的布局问题
- 🔗 更新 maxmind 的失效链接

### 7.1.1 - 2013-03-08
- 🪟 添加 Windows 8 检测
- ⏱️ 支持 ISO 日期时间的 %time5
- 🐪 修复 Perl 5.14 的问题

### 7.1 - 2012-12-20
- 🌍 更新翻译
- 🌐 更新浏览器列表
- 🔧 添加 nginx 配置示例
- 📦 添加 Debian 包的一些补丁
- 📛 将文档域名重命名为 awstats.org
- 🔑 awredir.pl 可以不使用 md5 密钥参数
- 📊 awstats_buildstaticpages.pl 支持 databasebreak 选项
- 🔗 添加 rel=nofollow 链接
- 🧩 添加 AddLinkToExternalCGIWrapper 选项
- 🛡️ 修复 awredir.pl 的安全问题
- 🇬🇧 修复 googlechart api 中 uk 的大小写问题
- 🐪 修复与最新 Perl 版本的兼容性

### 7.0 - 2011-01-08
- 🪟 检测 Windows 7
- 🔢 根据语言格式化数字
- 📁 更多 MIME 类型
- 🌍 添加 geoip_asn_maxmind 插件
- 🗺️ GeoIP Maxmind 城市插件支持覆盖文件
- 📊 添加 graphgooglechartapi 使用在线 Google Chart API 生成图表
- 🗺️ 可显示国家地图
- 🧹 代码清理和优化
- 🚫 添加参数忽略缺失的日志文件
- 🤖 更新 robots 数据库
- 📥 添加下载跟踪功能
- 🧩 WrapperScript 参数支持带参数的包装器
- 🏢 支持在 Dolibarr ERP/CRM 插件中使用 AWStats
- 🖥️ 修复 Webmin 模块与新版本的兼容性
- 🛡️ 安全修复（LoadPlugin 目录遍历）
- 🔒 安全修复（限制配置目录访问）

---

## ⚙️ 6.x 系列 (2004-2009)

### 6.95 - 2009-10-28
- 🛡️ 修复 awredir.pl 安全问题，默认添加安全密钥
- 🧹 增强参数清理功能
- 📋 在数据文件头中添加配置文件名
- 🌐 添加 Chrome、Opera、Safari、Konqueror 浏览器的版本详情
- 📱 添加 AdobeAir 检测
- 🤖 大幅更新浏览器、机器人和搜索引擎数据库（包括 Bing）
- 🔍 大幅提升机器人检测能力
- 🇫🇷 添加布列塔尼语
- 🖥️ 改进 Safari 版本检测
- 🗺️ 为 geoip maxmind 模块添加子页面
- 🇵🇱 修复波兰语文件中的拼写错误
- ⚠️ 修复 geoipfree 的警告
- 🔧 修复机器人检测问题

### 6.9 - 2008-12-28
- 📧 maillogconvert.pl 支持 DSN，避免重复计数
- 📊 logresolvemerge.pl 支持 FreeRADIUS 日志
- 🛑 添加 stoponfirsteof 选项
- 🔄 添加 host_proxy 标签支持
- ⭐ 重命名为 Add to favourites
- 🤖 更新机器人和搜索引擎数据库（添加 Chrome、改进 Vista、WII 检测等）
- 🌍 更新语言文件
- 🗺️ 修复 maxmind citi、org 和 isp 插件
- 🛡️ 修复多个安全问题
- 🖼️ 添加缺失的图标
- 🐪 *需要 Perl 5.007 或更高版本*

### 6.8 - 2008-07-20
- 👥 添加 OnlyUsers 选项
- 📡 支持 RPC 请求跟踪
- 📝 HTMLHeadSection 支持换行符
- 🤖 添加 MetaRobot 选项
- 🔍 大幅提升机器人检测能力
- 🪟 改进 Windows 操作系统检测
- ➕ 在额外部分中添加 HOSTINLOG 条件
- 📄 修复 XML 输出的问题
- 🐛 修复 awstats_configure.pl 脚本的 bug

### 6.7 - 2007-07-07
- 📅 完全支持 -day 选项，可为每天构建不同的报告
- 🏷️ 添加 virtualenamequot 标签
- 🚫 添加 NotPageList 选项
- 🌐 添加 .jobs 和 .mobi 域名
- 🐛 修复 awstats_configure.pl 的次要 bug
- 🌍 更新语言文件
- 🌐 更新浏览器数据库

### 6.6 - 2006-12-24
- 🐪 所有 geoip 插件支持 PurePerl 版本
- ➕ 可在 extra 部分使用 vhost
- 🌐 AllowAccessFromWebToFollowingIPAddresses 参数支持 IPv6
- 🗂️ 添加 svn 系列到浏览器检测
- 🌍 支持 IE7
- 🔇 移除一些 Perl 警告
- 🛡️ 修复 XSS 攻击漏洞
- 🌏 更新语言文件
- 🌐 更新浏览器数据库

### 6.5 - 2005-12-24
- ⚡ logresolvemerge.pl 合并大量日志文件时速度提升 30 倍
- 🐧 添加 Linux 和 BSD 发行版检测
- 🚫 添加 SkipReferrersBlackList 选项排除垃圾引荐
- 📰 在机器人数据库中添加 RSS 订阅器/阅读器
- 🗄️ 添加 databasebreak 选项
- 🗺️ geoip_cities 插件在有数据时报告地区
- 📱 LevelForBrowsersDetection 可接受 allphones 值
- 🔄 LogFormat=2 可动态检测日志格式变化
- 📋 添加 SectionsToBeSaved 选项
- 🌐 添加 Epiphany 浏览器检测
- 🔗 awredir 支持 ftp、https 等协议
- 📧 修复 Gmail 点击计数问题
- 🔨 修复多个 bug 和 XSS 问题
- 🛡️ 修复 XSS 问题

### 6.4 - 2005-02-25
- 📊 添加 ShowSummary 选项
- 🌍 启用 GeoIP 插件时在主机报告中添加列
- 🔄 LogFormat=2 自动检测日志格式变化
- 🔓 修复安全漏洞（可读取日志文件内容）
- 🛡️ 修复可能的 DoS 攻击漏洞
- 🎥 修复媒体服务器分析的错误
- 🪟 修复 Windows 服务器上的 configdir 选项问题
- 🏁 添加缺失的巴斯克语旗帜图标

### 6.3 - 2005-02-25
- 🌍 添加 geoip_isp_maxmind 和 geoip_org_maxmind 插件
- 🦊 显示 Firefox 版本详情
- 🔍 支持检测在 URL 中存储搜索关键词的搜索引擎
- 🔓 移除两个安全漏洞
- 🗺️ 修复 geoip_city_maxmind 插件问题
- 📁 修复文件类型表格的显示
- 🌐 修复翻译词条损坏问题
- 📄 修复 XML 解析错误

### 6.2 - 2004-11-06
- ⚙️ awstats_updateall.pl 添加 -excludeconf 选项
- ➕ 允许插件在菜单中添加条目
- 🔄 允许插件在更新过程中编译数据
- 🗺️ 添加 geoip_region_maxmind 和 geoip_city_maxmind 插件
- 📧 maillogconvert.pl 支持 postfix 2.1
- ⚡ 小幅速度提升
- 🚫 统计 JavaScript 禁用的浏览器
- 🏷️ 支持在日志格式中使用 %extraX 标签
- 📁 分析 FTP 日志时支持 put 方法
- 🔨 修复多个 bug

### 6.1 - 2004-05-15
- 📄 BuildHistoryFormat 支持 XML 格式
- ⏱️ 添加 %time4 标签支持 Unix 时间戳
- 🦊 在浏览器数据库中添加 Firefox
- 🔗 添加 IncludeInternalLinksInOriginSection 参数
- 📑 PDF 检测支持 PDF 6
- 📧 maillogconvert.pl 自动调整年份
- 💡 为邮件报告添加工具提示
- ❌ 在摘要中添加失败邮件数
- 🔤 AllowAccessFromWebToFollowingAuthenticatedUsers 不再区分大小写
- 🌐 添加 Camino 浏览器检测
- 🔨 修复多个 bug

### 6.0 - 2004-01-25
- ⚡ 速度提升 10-20%
- 🐛 添加蠕虫报告
- 📄 支持 XML 输出
- 🔤 添加 decodeUTFkeys 插件
- ⚙️ 添加 configure.pl 脚本
- 🔄 代码重写，更易理解和维护
- 🔍 新的搜索引擎数据库，支持多个匹配 ID
- ➕ 支持在 ExtraSection 中使用 UA 和 HOST 字段
- 🔁 支持从右到左的语言
- 📊 添加文件类型百分比列
- 🔨 修复多个 bug

---

## 🔧 5.x 系列 (2002-2003)

### 5.9 - 2003-09-22
- 🖥️ Webmin 模块更新到 1.1
- 📅 添加 AllowFullYearView 参数
- 🌍 年份条目在组合框中显示本地化文本
- 📧 maillogconvert.pl 支持一些交换格式
- ⚙️ awstats_buildstaticpages.pl 的 -noloadplugin 选项可接受逗号分隔列表
- 📨 支持 qmail 日志的错误记录
- 🔨 修复多个 bug

### 5.8 - 2003-09-16
- 🔧 修复 mod_deflate 压缩报告
- 📊 修复主机图表中其他行的列数错误
- 🔍 修复 uabracket 和 refererquot 的解析问题
- 🖥️ 添加 Webmin 模块
- ➕ 增强 Extra 功能，添加 ExtraSectionFirstColumnFormatX 等参数
- 🏷️ 添加 %lognamequot 标签
- 👥 添加 OnlyUserAgents 参数
- 🛠️ 添加 awredir.pl 工具
- 📊 添加集群报告

### 5.7 - 2003-08-23
- 📝 添加 rawlog 插件
- 🔍 在完整列表报告页添加动态排除过滤器
- 📧 添加 maillogconvert.pl 用于分析邮件日志
- ➕ logresolvemerge.pl 添加 -addfilenum 选项
- ⏱️ 添加 -updatefor 选项限制每次更新的行数
- 🎥 支持 Darwin 流媒体服务器
- 🔥 添加 Firebird 浏览器检测
- 📄 awstats_buildstaticpages.pl 可构建 PDF 文件
- ⚙️ 改进插件加载失败的处理
- 🏷️ 添加 LogType 参数

### 5.6 - 2003-06-28
- 🗜️ 支持 mod_deflate 压缩报告
- 🌐 改进浏览器检测
- 🔣 可为列表参数添加正则表达式值
- 🎨 StyleSheet 参数完全生效
- 🤖 添加 meta 标签 robots noindex,nofollow
- 📊 添加杂项图表，报告浏览器对 Java、Flash、Real、QuickTime、WMA、PDF 的支持
- ⚡ 改进更新过程，速度更快
- 🦊 改进在 Netscape/Mozilla 浏览器上的显示

### 5.5 - 2003-05-25
- 📱 添加屏幕尺寸报告
- 💻 按系列分组操作系统，添加详细版本图表
- 🔍 改进 404 错误管理
- 🌍 添加 geoipfree 插件
- 👤 添加 userinfo 插件
- 📅 月份参数可接受 -month=D 格式
- ⚡ 优化代码大小和 HTML 输出
- 🌐 添加 ipv6 插件
- 📊 拆分月份摘要和月份天数图表为两个独立图表
- 🔗 添加 -staticlinksext 选项
- 📧 支持 QMail

### 5.4 - 2003-02-23
- 🌍 Lang 参数接受 auto 值
- 🎥 部分支持 realmedia 服务器
- 🛠️ 添加 urlaliasbuilder.pl 工具
- 🔗 ExtraSection 第一列支持 URL
- #️⃣ 添加 URLWithAnchor 参数
- 💡 将工具提示功能导出为插件
- ⏱️ 在访问时长报告中添加平均时长和百分比
- 📦 logresolvemerge.pl 可读取 .gz 或 .bz2 文件
- 📁 为文件类型报告添加图标和 MIME 标签
- ➕ 添加多个数据数组参数
- 🪟 Whois 信息显示在居中弹出窗口
- 🎨 改进浏览器报告的外观

### 5.3 - 2003-01-02
- 📤 添加 awstats_exportlib.pl 工具
- 🌍 为域名/国家报告添加完整列表视图
- 📧 为邮件发送者/接收者图表添加完整列表和最后访问视图
- ⚡ 为 GeoIP 插件添加内存缓存
- 🔤 添加 AuthenticatedUsersNotCaseSensitive 参数
- 🚀 使用 ExtraSection 时速度提升
- 🔄 更新机器人、操作系统、浏览器、搜索引擎数据库
- 🖥️ 添加 X11 为未知 Unix 操作系统，添加 Atari 操作系统

### 5.2 - 2002-12-03
- 🔗 添加 urlalias 插件
- 🌍 添加 geoip 插件
- 📧 支持 postfix 邮件日志
- 📊 在日期数据数组底部添加总计和平均行
- 🔍 在主机和引荐者页面添加动态过滤器
- 🚫 移除值为 0 时的 Bytes 文本
- 📦 减小主页大小
- 👥 添加 OnlyHosts 参数
- ⚠️ 添加 ErrorMessages 参数
- 🐛 添加 DebugMessages 参数
- 🔣 添加 URLQuerySeparators 参数
- 🔒 添加 UseHTTPSLinkForUrl 参数
- 🇦🇱 添加阿尔巴尼亚语
- 🇧🇬 添加保加利亚语
- 🏴󠁧󠁢󠁷󠁬󠁳󠁿 添加威尔士语
- 🇸🇨 添加塞舌尔旗帜

### 5.1 - 2002-10-26
- 📁 改进对 FTP 日志文件的支持
- 📧 改进对邮件日志文件的支持
- 🎥 可分析流媒体日志文件（Windows Media Server）
- 📅 在 CGI 模式下添加月份和年份选择框
- 📊 月份和天数的数据值直接显示在主页图表下方
- 🔧 ShowxxxStats 参数可接受代码决定显示哪些列
- 🚫 添加 SkipUserAgents 参数
- 🔤 添加 URLNotCaseSensitive 参数
- 🔗 添加 URLWithQueryWithoutFollowingParameters 参数
- 🔄 添加 URLReferrerWithquery 参数
- 🏷️ 添加多个日期标签
- 🛡️ 修复日志文件中包含二进制字符时的分析停止问题

### 5.0 - 2002-10-06
- 🔄 完全重写更新过程和历史文件读/写代码
- 🔄 与之前版本（3.x 或 4.x）兼容
- ⚡ 可通过 -migrate 命令迁移旧历史文件以获得速度提升
- 🔧 修复使用不同偏移标签时的错误
- 🔐 CreateDataDirIfNotExists 创建的目录权限从 0666 改为 0766
- 🌐 跟踪浏览器的详细主次版本
- 🤖 为机器人和错误添加带宽报告
- 📦 支持 DNS 缓存文件进行 DNS 查找
- 🧩 添加插件支持和多个工作插件
- 🖼️ 使用框架报告（UseFramesWhenCGI 参数）
- 📉 减少全局变量数量
- 📄 DefaultFile 参数可接受多个值
- 🤖 添加所有机器人和最后机器人完整列表报告
- 👤 添加所有登录和最后登录完整列表报告
- 🚪 添加 URL 入口和出口完整列表报告
- 🛡️ 添加 AllowAccessFromWebToFollowingIPAddresses 参数
- 🔣 添加 LogSeparator 参数
- 🔒 添加 EnableLockForUpdate 参数
- 🔤 添加 DecodeUA 参数
- 🏷️ 添加 %WY 标签

---

## 📊 4.x 系列 (2002)

### 4.1 - 2002-07-09
- ⌨️ -logfile 选项可在命令行任意位置使用，支持文件名中的空格
- 🧠 修复 logresolvemerge.pl 的内存泄漏问题
- 📉 减少对非完全排序日志文件的丢弃记录数
- 🏷️ 添加 %virtualname 标签，可共享同一日志文件用于多个虚拟服务器
- 🔧 LogFile 参数中可使用管道
- 🔗 添加引荐搜索引擎和引荐页面的完整列表
- 🔍 同时报告关键词和关键短语
- 🚪 报告出口页面
- ⏱️ 报告访问时长
- 📁 awstats_buildstaticpages.pl 添加 -dir 选项

### 4.0 - 2002-04-21
- ⚠️ *警告：与旧历史文件不兼容*
- ⚡ 提高速度，减少大型网站的内存使用
- 🌐 未解析的 IP 现在像已解析的一样处理
- 🖼️ 在浏览器图表中添加图标
- 📋 个性化日志格式也支持制表符分隔
- 🔒 新的安全/隐私管理方式和参数
- 🤖 在浏览器图表中标记抓取器浏览器
- 📊 在页面/URL 报告图表中添加平均文件大小
- ⚙️ 可在配置文件中使用动态环境变量
- 📝 关键短语列表可完整查看
- 🧩 添加 WrapperScript 参数
- 📁 添加 CreateDirDataIfNotExists 参数
- ✅ 添加 ValidHTTPCodes 参数
- 📏 添加 MaxRowsInHTMLOutput 参数
- 🔗 添加 ShowLinksToWhoIs 参数
- 🔗 添加 LinksToWhoIs 参数
- 🎨 添加 StyleSheet 参数
- 🔗 添加 -staticlinks 选项
- 🛠️ 添加 common2combined.pl 工具
- 🛠️ 添加 awstats_buildstaticpages.pl 工具

---

## 🎨 3.x 系列 (2001)

### 3.2 - 2001-12-29
- ⚡ 速度提升 19%
- 🔧 修复历史文件损坏问题
- 🛡️ 安全修复：当 AllowToUpdateStatsFromBrowser 关闭时，无法通过 URL 更新
- 🏷️ 添加各种标签用于动态日志文件名
- 🚫 添加 NotPageList 参数
- 💾 添加 KeepBackupOfHistoricFiles 选项
- 📊 访问次数在天数统计中可见
- 📅 添加星期统计
- 📁 添加文件类型统计
- 🚪 添加入口页面统计
- 🗜️ 添加 Web 压缩统计（mod_gzip）
- 👤 添加认证用户/登录统计
- 📋 添加参数选择主页中显示的报表
- 🔗 添加 URLWithQuery 选项
- 🏁 ShowFlagLinks 可接受所有需要的旗帜列表
- 🖥️ 支持标准 ISA 服务器日志格式
- 🛠️ 添加 logresolvemerge 工具
- 📝 添加 HTMLHeadSection 参数
- 🔢 添加 NbOfLinesForCorruptedLog 参数

### 3.1 - 2001-09
- ⚡ 大幅提高更新速度
- ⚡ 大幅提高浏览器查看统计的速度
- 🧠 减少内存使用
- 📂 AWStats 在多个目录中搜索配置文件
- 📄 可分析 NCSA common 日志文件
- 🕒 最后访问列表
- 📊 URL 分数的完整列表
- 📅 日期格式可根据国家选择
- 🌍 添加 DirLang 参数
- ⏱️ 添加 Expires 参数
- 🔗 添加 LogoLink 参数
- 🎨 添加 color_weekend 选项
- ⚙️ 添加 -update 和 -output 选项
- 🔍 添加 -showsteps 选项
- 🔧 修复操作系统检测
- 📱 添加 WAP 浏览器到数据库

### 3.0 - 2001-07-22
- 🎨 全新外观
- 📅 添加每日页面、点击和字节报告
- 🔄 AWStats 可使用自己的转换数组进行反向 DNS 查找
- 🚫 添加 SkipDNSLookupFor 选项
- 📁 添加 OnlyFiles 选项
- 📋 支持个性化日志格式
- ⚡ 默认不在浏览器读取统计时更新，添加立即更新按钮
- 💡 工具提示现在也适用于 Netscape 6、Opera 等浏览器
- 🌐 更新浏览器数据库，添加音频浏览器
- 💻 更新操作系统数据库
- 🤖 更新机器人数据库
- 🌍 支持新域名
- 🏁 添加缺失的旗帜图标
- 🔧 重写 UnescapeURL 函数
- 📊 字节自动缩放
- 🎨 修复样式问题
- 🌐 添加新语言

---

## 🔄 2.x 系列 (2001)

### 2.24 - 2001-03-09
- ⏱️ 可在 LogFile 参数中动态包含当前年月日时
- ⌨️ 命令行也可选择月份、年份和语言
- 🔒 https 请求正确报告
- ⚙️ 初始化参数以避免 mod_perl 的缓存问题
- 🛡️ 修复参数检查以避免 XSS 攻击
- 🏁 添加多个国家旗帜
- 🔍 新的关键词检测算法
- 📝 添加报告关键词为独立词或完整搜索字符串的选项
- 🇬🇷 添加希腊语
- 🇨🇿 添加捷克语
- 🇵🇹 添加葡萄牙语翻译
- ⚡ 更快的配置文件解析
- 🪟 区分 Windows NT 和 Windows 2000
- 🌐 添加 OmniWeb 和 iCab 浏览器

### 2.23 - 2001-02-10
- ⚙️ 使用配置文件
- 📁 可处理旧日志文件
- 📅 按月统计现在正常工作
- 📅 旧年份也可从 AWStats 报告页面查看
- 📂 可选择工作目录
- 🗑️ 添加 PurgeLogFile 选项
- 📝 awstats.pl 可重命名为 awstats.plx 并仍正常工作
- 🔗 命令行生成的统计页面链接正确
- 📅 添加选择全年视图的链接
- 📊 域名和页面报告按页面排序
- 🔄 自动禁用已完成的 DNS 查找
- ➕ 可在 awstats 末尾添加自定义 HTML 代码
- 🇮🇹 添加意大利语
- 🇩🇪 添加德语
- 🇵🇱 添加波兰语

### 2.1 - 2001-01-01
- 🔄 AWStats 将 myserver 和 www.myserver 视为相同
- 🔧 修复唯一访问者计数器过高的问题
- 📦 添加 ArchiveLog 参数
- ❓ 区分未知浏览器和未知操作系统
- 🤖 机器人统计与访问者分开
- 🔍 改进的关键词检测算法
- 🕒 添加每个主机的最后连接时间
- 📋 添加 HTTP 404 错误的 URL 列表
- 📊 添加页面、点击和 KB 统计
- 🎨 添加颜色和链接
- 🪟 支持 IIS
- ⚡ 代码更清晰、更快
- 🖼️ 图像为 .png 格式
- 🌐 4 种语言

---

## 🌟 1.x 系列 (2000)

### 1.0 - 2000-05-02
- 🎉 首次在 SourceForge 公开发布 1.0 版本
- 📄 支持 Apache 日志格式
- 📊 基本统计功能：访问量、页面数、文件数

---

## 📜 早期开发阶段 (1995-1999)

### 1999 - 开源前夜
- 🚀 标准化架构，引入 lang/ 字典系统（初步确立 GBK/ISO 编码规范），以适应不同服务器环境，完成从个人工具向标准化产品的最后蜕变
- 🔍 识别增强：大幅扩充爬虫识别库
- 🎯 模式固定：完善 CGI 脚本运行模式
- 👥 社区内测：在小范围同行中进行测试，根据反馈完成代码清理和文档撰写

### 1998 - 功能深耕
- ⚙️ 进入高频内部私有迭代
- 🔄 确立“增量更新”架构，引入中间数据库文件，确保大数据量下统计不占用服务器实时资源
- 💻 新增操作系统、浏览器类型及 HTTP 状态码识别能力
- 🔌 利用 Perl 跨平台特性，测试 Unix/Linux 和 Windows 环境兼容性

### 1997 - 项目元年
- 🌟 官方文档公认起点，从零散脚本向分析引擎质变
- 📊 确立静态报告生成模式，首次将分析结果输出为带图形界面的 HTML 页面
- 🔍 开始建立搜索引擎与机器人识别规则库
- 📈 受益于 Common Log Format 标准化，脚本开始具备通用化基础

### 1995-1996 - 概念萌芽
- 💡 应对 Apache HTTP Server 流行后的 access.log 分析需求
- 🧪 尚无正式项目名称，为作者 Laurent Destailleur 的实验性代码片段
- 🐪 基于 Perl 5 编写，利用复杂哈希结构实现基础正则匹配，用于统计总点击量及简单文件类型过滤
- 📊 仅用于作者个人网站（cdr）的内部流量观测