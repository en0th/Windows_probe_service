# SOARProbe Windows IPv4 service

Standalone local FastAPI probe service for the SOAR userscript. Only public IPv4 targets are eligible; private/special addresses, default safety rules, DNS servers, known CDN/WAF networks and custom exclusions are skipped. Domains use system DNS, then 8.8.8.8 and 223.5.5.5 only if resolution fails. Allowed IPv4 answers receive Ping and TCP checks after filtering. An explicit domain port is checked alone; domains without a port use TCP 80 and 443. IPv4 literals without a port receive Ping only. Explicitly associated source and destination TCP ports are checked even when Ping fails.

The Windows release runs without Python or dependency installation. Double-click `SOARProbe.exe`; press C to copy the pairing token, L to open logs, Q to quit. Settings remain in `%LOCALAPPDATA%\SOARProbe`.

Download the ready-to-run [Windows release](https://github.com/en0th/Windows_probe_service/releases/latest): `SOARProbe.exe` or the complete `SOARProbe-Windows-x64.zip`. No Python or dependency installation is needed.

Build with [GitHub Actions](https://github.com/en0th/Windows_probe_service/actions/workflows/build-windows-probe.yml); leave `release_tag` blank for an artifact-only build, or enter the matching service version (for example `v1.2.0`) to publish a Release. The workflow runs offline tests, checks PE x64 and frozen resources, and starts the bundled service for loopback health/authentication checks without target probes. Release publishing uses a separate job and publishes only after the complete assets have been uploaded to a draft.

[Chinese installation and build guide](windows_probe_service/README.md)

CDN data: ProjectDiscovery/cdncheck; see [license](windows_probe_service/LICENSE.cdncheck.md). The supplied CDN database has finite coverage and supports updates and custom rules.
