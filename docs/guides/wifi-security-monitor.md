# Wi-Fi security monitoring: encryption, local devices, and router checks

Sentinel reads reported Wi-Fi authentication/cipher information and provides optional bounded local discovery. It shows available metadata rather than independently certifying the network's security.

1. Open the dashboard and read **Wi-Fi health**. Weak reported modes such as open/WEP/TKIP need attention; WPA2/WPA3 reporting is not a comprehensive security audit.
2. When authorized to assess that network, select **Discover local devices**.
3. Review responding hosts versus cached neighbor entries and the nine selected router TCP ports.

Discovery requires a verified connected Wi-Fi interface and a private IPv4 route. It is limited to the connected local /24 and source-bound probes. The product avoids substituting VPN/Ethernet routes for verified Wi-Fi. Silent hosts, client isolation, stale neighbor caches, larger networks, and missing permissions can reduce visibility.

It does not test passwords, firmware vulnerabilities, wireless handshakes, packet contents, WAN exposure, or malware on another device. TCP service reachability is not an exploit result. If a saved discovery belongs to another Wi-Fi network, the dashboard asks for a current discovery instead of silently presenting it as fresh.

Windows uses native Wi-Fi metadata; Linux uses available NetworkManager/iproute2 information; macOS privacy restrictions can hide details. WSL normally has no physical Wi-Fi interface. Native hardware validation is separate from mocked tests. [Platform coverage](../PLATFORMS.md).

All public screenshots and examples use fictional network names and documentation addresses. Never attach your actual SSID, MAC/IP inventory, raw network report, or system screenshot to a public issue. [Privacy policy](../../SECURITY.md).
