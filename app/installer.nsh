; Registers the VPN service with Windows, and removes it again.

!macro NSIS_HOOK_PREINSTALL
  ; An older service must stop before its files can be replaced. Fails harmlessly if absent.
  ExecWait '"$INSTDIR\ripsec-service.exe" uninstall'
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ExecWait '"$INSTDIR\ripsec-service.exe" install' $0
  StrCmp $0 "0" +2
    MessageBox MB_OK|MB_ICONEXCLAMATION "The Ripsec VPN service could not be installed. Install into Program Files and run the installer again."
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ExecWait '"$INSTDIR\ripsec-service.exe" uninstall'
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; The stored profile holds a secret, so it does not stay behind. Updates keep it.
  StrCmp $UpdateMode "1" +2
    RMDir /r "$INSTDIR\data"
  RMDir "$INSTDIR"
!macroend
