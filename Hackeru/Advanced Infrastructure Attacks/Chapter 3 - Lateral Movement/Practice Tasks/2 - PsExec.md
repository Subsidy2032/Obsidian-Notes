1. Download PsExec - https://docs.microsoft.com/en-us/sysinternals/downloads/psexec
2. Run cmd using administrator privileges
3. Activate local NT Authority privileges via PsExec - psexec.exe -s cmd.exe
4. Achieve NT Authority privileges on a remote computer - psexec.exe -u ["user"] -p ["password"] -s \\[ip] cmd.exe