# SOARProbe Windows IPv4 service

Local Starlette ASGI service for the SOAR userscript. v1.3.0 replaces FastAPI/Pydantic with strict Python standard-library request validation and removes `_pydantic_core` from both Windows release layouts. The API v1 contract, persistent configuration and probe engine remain compatible.

Only public IPv4 targets are eligible. Private/special addresses, default safety rules, DNS servers, known CDN/WAF networks and custom exclusions are skipped. Domains try the system resolver, 8.8.8.8, then 223.5.5.5 only when resolution fails or has no IPv4 answers. Allowed answers receive Ping and TCP checks after filtering. Explicit domain ports are checked alone; domains without a port use TCP 80 and 443. IPv4 literals without a port receive Ping only. Explicitly associated source and destination TCP ports are checked even when Ping fails.

Download [the Windows release](https://github.com/en0th/Windows_probe_service/releases/latest). The recommended `SOARProbe-Windows-x64-portable.zip` runs without installing Python, dependencies or a Telnet client. Extract the entire ZIP to a new directory and double-click `SOARProbe/Start-SOARProbe.cmd`; keep its `_internal` directory. Do not mix old runtime files into a new release. Press C to copy the pairing token, L to open logs and Q to quit. Configuration, token and logs remain in `%LOCALAPPDATA%\SOARProbe` across upgrades. A single-file EXE and its ZIP are also supplied.

Removing the blocked dependency does not establish Smart App Control trust for the remaining EXE/DLL/PYD files. There is no guaranteed SAC approval or trusted signing claim. Windows CI does not reproduce the user's SAC policy, and the launcher does not change security settings. Microsoft does not currently offer per-app SAC exclusions: [Smart App Control FAQ](https://support.microsoft.com/en-us/windows/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003).

[GitHub Actions](https://github.com/en0th/Windows_probe_service/actions/workflows/build-windows-probe.yml) runs offline tests, builds both Windows x64 layouts, checks frozen resources and the absence of the removed dependencies, then starts the actual EXE for loopback health/authentication checks without target probes. The final portable ZIP is extracted to a path with spaces and checked again. Leave `release_tag` blank for an artifact-only build or enter the matching service version, such as `v1.3.0`, to publish a Release only after all assets have been uploaded to a draft.

[Chinese installation and build guide](windows_probe_service/README.md) · [release notes](RELEASE_NOTES.md)

CDN data: ProjectDiscovery/cdncheck; see [license](windows_probe_service/LICENSE.cdncheck.md). The supplied CDN database has finite coverage and supports updates and custom rules.
