ContainGo Interactive V10

1. Extract this ZIP over your existing C:\Projects\ContainGo-Interactive folder.
2. Allow Windows to replace all files.
3. Run from PowerShell:

   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\RUN-CONTAINGO.ps1

The launcher reuses the healthy kind, Calico and SPIRE installation, redeploys only changed application images, and runs a targeted end-to-end smoke test before opening http://127.0.0.1:8060.
   
   
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\STOP-CONTAINGO.ps1