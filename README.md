# protonvpn-change-server-patcher

Removes the free-tier **"Change Server" cooldown** from the Proton VPN Windows
client by rewriting one method so it always returns `true`. Designed to
**survive client updates**.

## What it changes

The cooldown (45 s between switches, 10 min after 4 switches — values pushed by
Proton's API) is enforced only in the client UI by
`ChangeServerModerator.CanChangeServer()` in
`ProtonVPN.Client.Logic.Connection.dll`. This tool rewrites that method body to
`ldc.i4.1; ret` ("return true"), so the Change Server button is never gated.

Everything else — connecting, disconnecting, the VPN service — is untouched.

## Why it survives updates

Every client update installs into a **new `v*` folder** under
`C:\Program Files\Proton\VPN\`, so any one-time patch is abandoned. Instead of
patching bytes at fixed offsets, this tool:

1. **Finds the newest `v*` folder** the same way the launcher does.
2. **Locates the method by name** through the assembly's CLI metadata (a
   dependency-free ECMA-335 parser — never by byte offset), as long as Proton
   keeps the `ChangeServerModerator` / `CanChangeServer` names.
3. **Re-applies automatically** via a scheduled task (at logon and every
   30 minutes), so an updated install is patched on its next run.
4. **Backs up** the original assembly (per client version) before the first
   patch, verifies the return type is `bool` before touching anything, refuses
   unknown method layouts, and can restore the original at any time.

If a future client renames the method or changes its shape, the patcher fails
loudly (logged, no modification) instead of corrupting the assembly.

## Install

From an elevated PowerShell (or let it self-elevate):

```powershell
.\Install.ps1
```

This copies the patcher to `%LOCALAPPDATA%\ProtonChangeServerPatcher`,
registers the scheduled task **ProtonVPN ChangeServer Patcher**, and applies
the patch immediately. Restart the Proton VPN client afterwards (a running
client locks its DLL; the next task run patches it once the lock is gone).

## Uninstall

```powershell
.\Uninstall.ps1 -Restore   # removes the task and restores the original DLL
.\Uninstall.ps1            # removes the task only
```

## Manual use

```powershell
.\Set-ProtonChangeServerPatch.ps1 -Action Status    # read-only report
.\Set-ProtonChangeServerPatch.ps1 -Action Patch     # requires elevation
.\Set-ProtonChangeServerPatch.ps1 -Action Restore   # requires elevation
```

Backups live in `%LOCALAPPDATA%\ProtonChangeServerPatcher\Backups\<version>\`,
logs in `%LOCALAPPDATA%\ProtonChangeServerPatcher\patcher.log`.

## Requirements

- Proton VPN Windows client v5.x (the WinUI 3 client with
  `ProtonVPN.Client.Logic.Connection.dll`)
- Windows PowerShell 5.1+ (no other dependencies)
- Elevation only for `Patch` / `Restore` (they write into Program Files)

## Notes and caveats

- The cooldown is Proton's deliberate free-tier anti-abuse mechanism; working
  around it may conflict with Proton's terms of service.
- Values and enforcement live client-side today, but Proton can change either
  at any time.
- Use at your own risk. MIT licensed.
