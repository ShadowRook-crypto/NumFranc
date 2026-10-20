; Installeur Windows de NumFranc (NSIS). Sans droits administrateur : tout va dans le dossier de l'utilisateur.
;   makensis -DVERSION=1.1.0 -DPROGRAMME=numfranc.exe -DICONE=numfranc.ico -DSORTIE=NumFranc-installation.exe windows.nsi
Unicode true
!include "MUI2.nsh"

Name "NumFranc"
OutFile "${SORTIE}"
InstallDir "$LOCALAPPDATA\Programs\NumFranc"
RequestExecutionLevel user
SetCompressor /SOLID lzma
BrandingText "NumFranc ${VERSION}"

!define MUI_ICON "${ICONE}"
!define MUI_UNICON "${ICONE}"
!define MUI_FINISHPAGE_RUN "$INSTDIR\NumFranc.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Lancer NumFranc / Start NumFranc"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "French"
!insertmacro MUI_LANGUAGE "English"

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "NumFranc"
VIAddVersionKey "FileDescription" "Installeur NumFranc"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "ShadowRook - licence MIT"

Section "NumFranc"
  SetOutPath "$INSTDIR"
  ; « Toujours allumé » : on arrête NumFranc (gardien et arrière-plan) pour pouvoir remplacer le programme.
  nsExec::Exec '"$SYSDIR\taskkill.exe" /F /IM NumFranc.exe'
  Sleep 1500
  ; Si NumFranc est ouvert pendant une mise à jour, on laisse l'ancien fichier se remplacer au prochain redémarrage.
  SetOverwrite try
  File "/oname=NumFranc.exe" "${PROGRAMME}"
  File "/oname=numfranc.ico" "${ICONE}"
  WriteUninstaller "$INSTDIR\Desinstaller.exe"
  ; Menu Démarrer
  CreateShortcut "$SMPROGRAMS\NumFranc.lnk" "$INSTDIR\NumFranc.exe" "" "$INSTDIR\numfranc.ico" 0
  ; Liens de paiement nfr:... (registre de l'utilisateur uniquement)
  WriteRegStr HKCU "Software\Classes\nfr" "" "URL:NumFranc"
  WriteRegStr HKCU "Software\Classes\nfr" "URL Protocol" ""
  WriteRegStr HKCU "Software\Classes\nfr\DefaultIcon" "" "$INSTDIR\NumFranc.exe,0"
  WriteRegStr HKCU "Software\Classes\nfr\shell\open\command" "" '"$INSTDIR\NumFranc.exe" "%1"'
  ; Liste « Applications installées » de Windows
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NumFranc" "DisplayName" "NumFranc"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NumFranc" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NumFranc" "Publisher" "ShadowRook"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NumFranc" "DisplayIcon" "$INSTDIR\numfranc.ico"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NumFranc" "UninstallString" '"$INSTDIR\Desinstaller.exe"'
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NumFranc" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NumFranc" "NoRepair" 1
  ; Si « Toujours allumé » était activé, on relance tout de suite le gardien (nouvelle version).
  ReadRegStr $0 HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "NumFranc gardien"
  StrCmp $0 "" +2
  Exec '$0'
SectionEnd

; La désinstallation retire le programme, le raccourci et le lien nfr: ;
; elle NE touche JAMAIS au portefeuille ni à la chaîne (dossier %APPDATA%\NumFranc).
Section "Uninstall"
  nsExec::Exec '"$SYSDIR\taskkill.exe" /F /IM NumFranc.exe'
  Sleep 1500
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "NumFranc gardien"
  Delete "$INSTDIR\NumFranc.exe"
  Delete "$INSTDIR\numfranc.ico"
  Delete "$INSTDIR\Desinstaller.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\NumFranc.lnk"
  DeleteRegKey HKCU "Software\Classes\nfr"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NumFranc"
SectionEnd
