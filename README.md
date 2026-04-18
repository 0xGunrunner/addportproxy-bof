# addportproxy-bof

A Beacon Object File (BOF) for adding IPv4 port proxy rules without spawning `netsh.exe`.

Supports AdaptixC2, Cobalt Strike, and any C2 framework that implements the BOF specification.

---

## How It Works

`netsh interface portproxy` is purely a registry frontend. The actual portproxy configuration lives at:

```
HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp
  Value name : <listenaddress>/<listenport>     (e.g. 0.0.0.0/443)
  Value data : <connectaddress>/<connectport>   (e.g. 192.168.1.10/443)
```

This BOF writes directly to that registry key and signals the IP Helper service (`iphlpsvc`) via `SERVICE_CONTROL_PARAMCHANGE` to reload its configuration — no `netsh.exe` process spawn, no `cmd.exe`, no command-line event log entry.

**Network telemetry note:** When the listen address is set to `127.0.0.1`, the egress traffic is attributed to `SYSTEM`/`svchost.exe` (iphlpsvc), which generates significant false positives and is rarely investigated. This makes it useful for routing C2 callback traffic through a portproxy while keeping the beacon itself communicating only with localhost.

---

## OPSEC Comparison

| Method | Process Spawn | Command Line Logging | Noise Level |
|--------|--------------|---------------------|-------------|
| `netsh` via shell | `cmd.exe` + `netsh.exe` | Yes — full command visible in event logs | High |
| This BOF | None | No | Low |

Detection surface: registry write to `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\` — detectable by EDR registry monitoring. Palo Alto Cortex XDR specifically has a rule for "Unusual Netsh PortProxy rule" which triggers on the registry key regardless of how it was written.

---

## Usage

### AdaptixC2

```
addportproxy <listenaddr> <listenport> <connectaddr> <connectport>
```

```
addportproxy 0.0.0.0 443 192.168.1.10 443
addportproxy 127.0.0.1 443 192.168.1.10 443
```

### Cobalt Strike (inline-execute)

```
inline-execute addportproxy.x64.o <listenaddr> <listenport> <connectaddr> <connectport>
```

---

## Build

Requires `mingw-w64`:

```bash
# x64
x86_64-w64-mingw32-gcc -o addportproxy.x64.o -c addportproxy.c -masm=intel

# x86
i686-w64-mingw32-gcc -o addportproxy.x86.o -c addportproxy.c -masm=intel
```

Place the compiled `.o` files in your extension's `_bin/` directory.

---

## AdaptixC2 Extension Integration

Add the following to your `.axs` extension file:

```javascript
var cmd_portproxy = ax.create_command("addportproxy", "Add a portproxy rule via registry (no netsh)", "addportproxy 0.0.0.0 443 192.168.250.22 443");
cmd_portproxy.addArgString("listenaddr", true, "Listen address (e.g. 0.0.0.0 or 127.0.0.1)");
cmd_portproxy.addArgString("listenport", true, "Listen port");
cmd_portproxy.addArgString("connectaddr", true, "Connect address");
cmd_portproxy.addArgString("connectport", true, "Connect port");
cmd_portproxy.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let listenaddr  = parsed_json["listenaddr"];
    let listenport  = parsed_json["listenport"];
    let connectaddr = parsed_json["connectaddr"];
    let connectport = parsed_json["connectport"];

    let bof_params = ax.bof_pack("wstr,wstr,wstr,wstr", [listenaddr, listenport, connectaddr, connectport]);
    let bof_path = ax.script_dir() + "_bin/addportproxy." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: Add portproxy rule");
});
```

---

## Verify Rule Was Written

From a beacon shell or WinRM session:

```
reg query HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp
```

Or from Kali:

```bash
proxychains reg.py DOMAIN/user@target query -keyName 'HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp'
```

---

## Remove a Rule

The BOF currently supports adding rules only. To remove a rule, delete the registry value:

```
reg delete HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp /v "0.0.0.0/443" /f
```

A `deleteportproxy` BOF companion may be added in a future release.

---

## Dependencies

- `beacon.h` — [Cobalt Strike BOF template](https://github.com/Cobalt-Strike/bof_template) or [Adaptix Extension-Kit](https://github.com/Adaptix-Framework/Extension-Kit)
- `ADVAPI32` — registry and SCM functions
- `MSVCRT` — `swprintf`, `wcslen`

---

## Disclaimer

This tool is intended for authorized security assessments, penetration testing, and red team engagements only. Usage against systems without explicit written permission from the system owner is illegal and unethical.

The author assumes no liability for misuse or damage caused by this tool. Use responsibly.

---

## References

- [Adaptix-Framework/Extension-Kit](https://github.com/Adaptix-Framework/Extension-Kit)
- [Microsoft: IPv4-to-IPv4 Port Proxying](https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-interface-portproxy)
- Portproxy loopback OPSEC technique — credit to philomath213
