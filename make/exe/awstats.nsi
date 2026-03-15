;===============================================================================
; AWStats 现代安装脚本
; 支持多语言 (中文/英文)
;===============================================================================
Unicode true
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "WinVer.nsh"
!include "FileFunc.nsh"
!include "WordFunc.nsh"

;===============================================================================
; 安装程序属性
;===============================================================================
Name "AWStats"
OutFile "..\awstats.exe"
InstallDir "$PROGRAMFILES64\AWStats"
InstallDirRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AWStats" "InstallLocation"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
SetCompressorDictSize 32
XPStyle on
CRCCheck on

;===============================================================================
; 版本信息
;===============================================================================
!define VERSION "8.1"
!define PRODUCT_NAME "AWStats"
!define PRODUCT_PUBLISHER "Laurent Destailleur"
!define PRODUCT_WEB_SITE "https://www.awstats.org"
!define PRODUCT_COPYRIGHT "Copyright © 2000-2026 Laurent Destailleur"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"

VIProductVersion "${VERSION}.0.0"
VIAddVersionKey "ProductName" "${PRODUCT_NAME}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "${PRODUCT_COPYRIGHT}"
VIAddVersionKey "FileDescription" "${PRODUCT_NAME} Web Log Analyzer"
VIAddVersionKey "ProductVersion" "${VERSION}"

;===============================================================================
; 界面设置 - 现代风格
;===============================================================================
!define MUI_ICON "..\..\docs\images\favicon.pub\favicon.ico"
!define MUI_UNICON "..\..\docs\images\favicon.pub\favicon.ico"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "..\..\docs\images\favicon.pub\header.bmp"
!define MUI_HEADERIMAGE_RIGHT
!define MUI_WELCOMEFINISHPAGE_BITMAP "..\..\docs\images\favicon.pub\welcome.bmp"
!define MUI_ABORTWARNING
!define MUI_UNABORTWARNING
!define MUI_LANGDLL_ALLLANGUAGES

; 字体设置 - 使用系统默认中文字体
!define MUI_FONT_HEADER "Microsoft YaHei"
!define MUI_FONT_TITLE "Microsoft YaHei"
!define MUI_FONT_BOLD "Microsoft YaHei Bold"

; 界面颜色 (深色主题)
!define MUI_BGCOLOR 2D2D2D
!define MUI_TEXTCOLOR FFFFFF
!define MUI_WELCOMEPAGE_BGCOLOR 2D2D2D
!define MUI_WELCOMEPAGE_TEXTCOLOR FFFFFF
!define MUI_LICENSEPAGE_BGCOLOR 1E1E1E
!define MUI_LICENSEPAGE_TEXTCOLOR FFFFFF
;===============================================================================
; 多语言支持 - 先定义语言文件
;===============================================================================

; 加载NSIS内置语言
!insertmacro MUI_LANGUAGE "SimpChinese"
!insertmacro MUI_LANGUAGE "English"

;===============================================================================
; 自定义字符串定义
;===============================================================================

; 简体中文
LangString WelcomeText ${LANG_SIMPCHINESE} "欢迎使用 AWStats 安装程序$\r$\n$\r$\nAWStats 是一个功能强大的 Web 日志分析工具。$\r$\n$\r$\n本安装程序将引导您完成 AWStats 的安装过程。$\r$\n$\r$\n点击“下一步”继续。"
LangString LicenseTextTop ${LANG_SIMPCHINESE} "请阅读以下许可协议。使用滚轮或 Page Down 键查看全文。"
LangString LicenseTextBottom ${LANG_SIMPCHINESE} "如果您接受协议条款，请勾选“我接受”并点击“下一步”。"
LangString DirectoryTextTop ${LANG_SIMPCHINESE} "选择 AWStats 的安装目录。$\r$\n$\r$\n建议安装在非系统盘。"
LangString DirectoryTextDestination ${LANG_SIMPCHINESE} "目标文件夹"
LangString InstallFinishHeader ${LANG_SIMPCHINESE} "安装完成"
LangString InstallFinishSubtext ${LANG_SIMPCHINESE} "AWStats 已成功安装到您的计算机。"
LangString FinishText ${LANG_SIMPCHINESE} "AWStats 安装完成。$\r$\n$\r$\n感谢您选择 AWStats！"
LangString FinishRunText ${LANG_SIMPCHINESE} "运行 AWStats"
LangString FinishReadmeText ${LANG_SIMPCHINESE} "查看说明文档"
LangString FinishLinkText ${LANG_SIMPCHINESE} "访问 AWStats 官网"
LangString SectionMain ${LANG_SIMPCHINESE} "安装核心文件"
LangString SectionDesktop ${LANG_SIMPCHINESE} "创建桌面快捷方式"
LangString SectionStartMenu ${LANG_SIMPCHINESE} "创建开始菜单快捷方式"
LangString DescMain ${LANG_SIMPCHINESE} "安装 AWStats 核心程序、文档和工具"
LangString DescDesktop ${LANG_SIMPCHINESE} "在桌面创建 AWStats 快捷方式"
LangString DescStartMenu ${LANG_SIMPCHINESE} "在开始菜单创建 AWStats 快捷方式"
LangString RemoveConfig ${LANG_SIMPCHINESE} "$(^Name) 配置文件要保留吗？$\r$\n选择“是”保留配置，选择“否”删除配置。"

; 英文
LangString WelcomeText ${LANG_ENGLISH} "Welcome to the AWStats Setup Wizard$\r$\n$\r$\nAWStats is a powerful web log analyzer.$\r$\n$\r$\nThis wizard will guide you through the installation of AWStats.$\r$\n$\r$\nClick 'Next' to continue."
LangString LicenseTextTop ${LANG_ENGLISH} "Please review the license terms before installing AWStats. Use scroll wheel or Page Down to view the rest of the agreement."
LangString LicenseTextBottom ${LANG_ENGLISH} "If you accept the terms of the agreement, check 'I accept' and click 'Next'."
LangString DirectoryTextTop ${LANG_ENGLISH} "Choose the installation directory for AWStats.$\r$\n$\r$\nIt is recommended to install on a non-system drive."
LangString DirectoryTextDestination ${LANG_ENGLISH} "Destination Folder"
LangString InstallFinishHeader ${LANG_ENGLISH} "Installation Complete"
LangString InstallFinishSubtext ${LANG_ENGLISH} "AWStats has been successfully installed on your computer."
LangString FinishText ${LANG_ENGLISH} "AWStats installation is complete.$\r$\n$\r$\nThank you for choosing AWStats!"
LangString FinishRunText ${LANG_ENGLISH} "Run AWStats"
LangString FinishReadmeText ${LANG_ENGLISH} "View Readme"
LangString FinishLinkText ${LANG_ENGLISH} "Visit AWStats Website"
LangString SectionMain ${LANG_ENGLISH} "Core Files"
LangString SectionDesktop ${LANG_ENGLISH} "Desktop Shortcut"
LangString SectionStartMenu ${LANG_ENGLISH} "Start Menu Shortcut"
LangString DescMain ${LANG_ENGLISH} "Install AWStats core files, documentation and tools"
LangString DescDesktop ${LANG_ENGLISH} "Create AWStats shortcut on desktop"
LangString DescStartMenu ${LANG_ENGLISH} "Create AWStats shortcut in Start Menu"
LangString RemoveConfig ${LANG_ENGLISH} "Do you want to keep $(^Name) configuration files?$\r$\nSelect Yes to keep, No to remove."

;===============================================================================
; 页面配置
;===============================================================================

; 欢迎页
!define MUI_WELCOMEPAGE_TITLE_3LINES
!define MUI_WELCOMEPAGE_TEXT "$(WelcomeText)"

; 许可证页
!define MUI_LICENSEPAGE_TEXT_TOP "$(LicenseTextTop)"
!define MUI_LICENSEPAGE_TEXT_BOTTOM "$(LicenseTextBottom)"

; 目录选择页
!define MUI_DIRECTORYPAGE_TEXT_TOP "$(DirectoryTextTop)"
!define MUI_DIRECTORYPAGE_TEXT_DESTINATION "$(DirectoryTextDestination)"

; 安装进度页
!define MUI_INSTFILESPAGE_COLORS "FFFFFF 2D2D2D"
!define MUI_INSTFILESPAGE_PROGRESSBAR "smooth"
!define MUI_INSTFILESPAGE_FINISHHEADER_TEXT "$(InstallFinishHeader)"
!define MUI_INSTFILESPAGE_FINISHHEADER_SUBTEXT "$(InstallFinishSubtext)"

; 完成页
!define MUI_FINISHPAGE_TITLE_3LINES
!define MUI_FINISHPAGE_TEXT "$(FinishText)"
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "$(FinishRunText)"
!define MUI_FINISHPAGE_RUN_FUNCTION "RunAWStats"
!define MUI_FINISHPAGE_SHOWREADME
!define MUI_FINISHPAGE_SHOWREADME_TEXT "$(FinishReadmeText)"
!define MUI_FINISHPAGE_SHOWREADME_FUNCTION "ShowReadme"
!define MUI_FINISHPAGE_LINK "$(FinishLinkText)"
!define MUI_FINISHPAGE_LINK_LOCATION "https://www.awstats.org"

;===============================================================================
; 页面插入
;===============================================================================
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\..\docs\LICENSE.txt"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

;===============================================================================
; 卸载页面
;===============================================================================
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

;===============================================================================
; 语言选择页面
;===============================================================================
Function .onInit
  !insertmacro MUI_LANGDLL_DISPLAY
FunctionEnd

;===============================================================================
; 安装部分
;===============================================================================

; 主安装部分
Section "$(SectionMain)" SEC_MAIN
  SectionIn RO
  
  SetOutPath "$INSTDIR"
  
  ; 复制核心文件
  File /r "..\..\wwwroot\*"
  File /r "..\..\docs\*"
  File /r "..\..\tools\*"
  File "..\..\README.md"
  File "..\..\docs\LICENSE.txt"
  
  ; 创建配置文件目录
  CreateDirectory "$APPDATA\AWStats"
  
  ; 复制默认配置文件
  IfFileExists "$INSTDIR\wwwroot\cgi-bin\awstats.model.conf" 0 +2
    CopyFiles "$INSTDIR\wwwroot\cgi-bin\awstats.model.conf" "$APPDATA\AWStats\awstats.conf"
  
  ; 写入卸载信息
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  
  ; 写入注册表卸载信息
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\awstats.ico"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
  WriteRegDWORD HKLM "${PRODUCT_UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${PRODUCT_UNINST_KEY}" "NoRepair" 1
  
  ; 计算安装大小
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "${PRODUCT_UNINST_KEY}" "EstimatedSize" "$0"
SectionEnd

; 桌面快捷方式
Section "$(SectionDesktop)" SEC_DESKTOP
  CreateShortCut "$DESKTOP\AWStats.lnk" "$INSTDIR\wwwroot\cgi-bin\awstats.pl" \
    "" "$INSTDIR\awstats.ico" 0 SW_SHOWMINIMIZED
SectionEnd

; 开始菜单快捷方式
Section "$(SectionStartMenu)" SEC_STARTMENU
  CreateDirectory "$SMPROGRAMS\AWStats"
  CreateShortCut "$SMPROGRAMS\AWStats\AWStats.lnk" "$INSTDIR\wwwroot\cgi-bin\awstats.pl" \
    "" "$INSTDIR\awstats.ico" 0 SW_SHOWMINIMIZED
  CreateShortCut "$SMPROGRAMS\AWStats\Uninstall.lnk" "$INSTDIR\Uninstall.exe" \
    "" "$INSTDIR\Uninstall.exe" 0
  CreateShortCut "$SMPROGRAMS\AWStats\Documentation.lnk" "$INSTDIR\docs\index.html"
  CreateShortCut "$SMPROGRAMS\AWStats\Configuration.lnk" "$APPDATA\AWStats"
SectionEnd

;===============================================================================
; 组件描述
;===============================================================================
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC_MAIN} "$(DescMain)"
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC_DESKTOP} "$(DescDesktop)"
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC_STARTMENU} "$(DescStartMenu)"
!insertmacro MUI_FUNCTION_DESCRIPTION_END

;===============================================================================
; 卸载部分
;===============================================================================
Section "Uninstall"
  ; 删除文件
  RMDir /r "$INSTDIR"
  
  ; 删除快捷方式
  Delete "$DESKTOP\AWStats.lnk"
  RMDir /r "$SMPROGRAMS\AWStats"
  
  ; 询问是否删除配置文件
  MessageBox MB_YESNO|MB_ICONQUESTION "$(RemoveConfig)" IDYES KeepConfig
    RMDir /r "$APPDATA\AWStats"
  KeepConfig:
  
  ; 删除注册表项
  DeleteRegKey HKLM "${PRODUCT_UNINST_KEY}"
SectionEnd

;===============================================================================
; 辅助函数
;===============================================================================
Function RunAWStats
  ExecShell "open" "$INSTDIR\wwwroot\cgi-bin\awstats.pl"
FunctionEnd

Function ShowReadme
  ExecShell "open" "$INSTDIR\docs\index.html"
FunctionEnd