# SOARProbe Windows IPv4 service

Standalone local FastAPI probe service for the SOAR userscript. Only public IPv4 targets are eligible; private/special addresses, DNS servers, known CDN/WAF networks and custom exclusions are skipped.

The Windows release runs without Python or dependency installation. Double-click `SOARProbe.exe`; press C to copy the pairing token, L to open logs, Q to quit. Settings remain in `%LOCALAPPDATA%\SOARProbe`.

Build the verified EXE with [GitHub Actions](https://github.com/en0th/Windows_probe_service/actions/workflows/build-windows-probe.yml), then download the `SOARProbe-Windows-x64` artifact. The workflow runs offline tests, checks PE x64 and frozen resources, and starts the bundled service for loopback health/authentication checks without target probes.

[Chinese installation and build guide](windows_probe_service/README.md)

CDN data: ProjectDiscovery/cdncheck; see [license](windows_probe_service/LICENSE.cdncheck.md). The supplied CDN database has finite coverage and supports updates and custom rules.
