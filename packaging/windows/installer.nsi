; --------------------------------------------------
; Connect Hub Windows 安装向导脚本 (NSIS)
; --------------------------------------------------

Unicode True
SetCompressor /SOLID lzma

!include "MUI2.nsh"
!include "FileFunc.nsh"

; 常量定义
!define PRODUCT_NAME "Connect Hub"
!define PRODUCT_PUBLISHER "Connect Hub Contributors"
!define PRODUCT_WEB_SITE "https://github.com/ehZyiL/aTrustHub"
!define MAIN_EXE "connect-hub.exe"
!define UNINST_EXE "Uninstall.exe"
!define UNINST_REG_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\ConnectHub"

Name "${PRODUCT_NAME}"
OutFile "..\..\build\connect-hub-setup-windows-amd64.exe"
InstallDir "$LOCALAPPDATA\Programs\ConnectHub"
InstallDirRegKey HKCU "Software\ConnectHub" "InstallPath"
RequestExecutionLevel user

; 图标设置
!define MUI_ICON "..\..\resources\icon.ico"
!define MUI_UNICON "..\..\resources\icon.ico"
!define MUI_ABORTWARNING

; 安装向导页面
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\${MAIN_EXE}"
!define MUI_FINISHPAGE_RUN_TEXT "运行 Connect Hub"
!insertmacro MUI_PAGE_FINISH

; 卸载向导页面
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; 语言支持（简体中文）
!insertmacro MUI_LANGUAGE "SimpChinese"

; 安装段
Section "MainSection" SEC01
    SetOutPath "$INSTDIR"
    SetOverwrite on

    ; 释放构建好的全部应用文件及 core 目录
    File /r "..\..\build\connect-hub-windows-amd64\*.*"

    ; 生成卸载器
    WriteUninstaller "$INSTDIR\${UNINST_EXE}"

    ; 写入安装路径记录
    WriteRegStr HKCU "Software\ConnectHub" "InstallPath" "$INSTDIR"

    ; 写入 Windows 控制面板“卸载或更改程序”注册表项
    WriteRegStr HKCU "${UNINST_REG_KEY}" "DisplayName" "${PRODUCT_NAME}"
    WriteRegStr HKCU "${UNINST_REG_KEY}" "UninstallString" '"$INSTDIR\${UNINST_EXE}"'
    WriteRegStr HKCU "${UNINST_REG_KEY}" "QuietUninstallString" '"$INSTDIR\${UNINST_EXE}" /S'
    WriteRegStr HKCU "${UNINST_REG_KEY}" "InstallLocation" "$INSTDIR"
    WriteRegStr HKCU "${UNINST_REG_KEY}" "DisplayIcon" "$INSTDIR\${MAIN_EXE}"
    WriteRegStr HKCU "${UNINST_REG_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
    WriteRegStr HKCU "${UNINST_REG_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
    WriteRegDWORD HKCU "${UNINST_REG_KEY}" "NoModify" 1
    WriteRegDWORD HKCU "${UNINST_REG_KEY}" "NoRepair" 1

    ; 计算安装大小写入注册表
    ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
    IntFmt $0 "0x%08X" $0
    WriteRegDWORD HKCU "${UNINST_REG_KEY}" "EstimatedSize" "$0"

    ; 创建桌面快捷方式
    CreateShortCut "$DESKTOP\Connect Hub.lnk" "$INSTDIR\${MAIN_EXE}" "" "$INSTDIR\${MAIN_EXE}" 0

    ; 创建开始菜单项
    CreateDirectory "$SMPROGRAMS\Connect Hub"
    CreateShortCut "$SMPROGRAMS\Connect Hub\Connect Hub.lnk" "$INSTDIR\${MAIN_EXE}" "" "$INSTDIR\${MAIN_EXE}" 0
    CreateShortCut "$SMPROGRAMS\Connect Hub\卸载 Connect Hub.lnk" "$INSTDIR\${UNINST_EXE}" "" "$INSTDIR\${UNINST_EXE}" 0
SectionEnd

; 卸载段
Section "Uninstall"
    ; 删除快捷方式
    Delete "$DESKTOP\Connect Hub.lnk"
    Delete "$SMPROGRAMS\Connect Hub\Connect Hub.lnk"
    Delete "$SMPROGRAMS\Connect Hub\卸载 Connect Hub.lnk"
    RMDir "$SMPROGRAMS\Connect Hub"

    ; 删除安装目录文件
    RMDir /r "$INSTDIR"

    ; 清理注册表
    DeleteRegKey HKCU "${UNINST_REG_KEY}"
    DeleteRegKey HKCU "Software\ConnectHub"
SectionEnd
