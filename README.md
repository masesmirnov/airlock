# Airlock

Airlock isolates one Claude Desktop account on a Windows PC. It runs the app under a separate local Windows account, pins that account's traffic with WFP filters bound to its SID, injects a small MinHook DLL into the app's processes, and lets it reach the internet only through a SOCKS5 or HTTP proxy that is checked before use.

`Airlock.exe` is the portable tray panel. `airlock.exe` is the console build with the installer and service commands (run it without arguments to list them). Both need administrator rights. The proxy is entered at runtime and stored encrypted on the machine; nothing is baked into the binary.

## Build

Windows amd64, Go 1.26:

```
go vet .
go build -o build/airlock.exe .
go build -ldflags "-H windowsgui" -o build/dist/Airlock.exe .
```

`hook/airlockhook.dll` is embedded into the binary; its source is `hook/airlockhook.c` with MinHook in `hook/minhook`.

## License

No license file yet. MinHook is under its own license in `hook/minhook/LICENSE.txt`.
