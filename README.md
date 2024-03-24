# [Narrowlink](https://narrowlink.com/docs/intro)
<p align="center"><img src="https://raw.githubusercontent.com/narrowlink/homepage/main/static/img/NarrowLink-888.svg" alt="Narrowlink Logo" width="50%"></p>
Narrowlink is a self-hosted platform that allows you to establish secure remote connections between devices within a network that may be hindered by network address translation (NAT) or firewalls. Whether you need to access a home computer from your laptop, share internet access with remote devices, or publish a local web server on the internet, Narrowlink provides the solution.



## Example of Narrowlink Use Cases and Scenarios

- **[Sharing Network Access](https://narrowlink.com/docs/extended-tutorial/share-network-access-socks5)** - If you need to work from home and access your company's internal network, which only allows access from within the network, you can install the Narrowlink agent on a computer located within your company's premises. This will enable you to utilize its internet access[^1] without depending on the company's remote access tools.

- **[Access to Devices Without VPN Support](https://narrowlink.com/docs/category/extended-tutorial/)** - Suppose you have a device that does not support VPN, such as an IoT sensor, CCTV camera, or smart TV, and you want to access them from your laptop on a different network that cannot directly reach the device. In this case, you can install the Narrowlink agent on a device within the same network as these devices. Then, you can connect using your laptop through Narrowlink from anywhere.

- **[Using Native Services like RDP/SSH Across Different Networks](https://narrowlink.com/docs/extended-tutorial/ssh-integration/)** - You can use Narrowlink to access your computer's native services like RDP (Remote Desktop) or SSH directly, without relying on third-party services. This is especially useful when both machines cannot reach each other directly, and neither has a public IP address. Narrowlink allows you to use your SSH or RDP client (e.g., OpenSSH client or Microsoft Remote Desktop) without the need for any modifications or additional software to connect to your computer. The connection can even be established directly using peer-to-peer functionality.

- **[Publishing a Local Webserver](https://narrowlink.com/docs/extended-tutorial/webserver-publish)** - Suppose you have a webserver running on your local network that you want to make accessible on the internet. If your ISP doesn't provide you with a public IP address or you wish to let others publish their webservers on your public IP address from their local networks, Narrowlink can help you publish your webserver to the internet.
    

## Key Features

-   **Covert Communications:** Narrowlink disguises traffic as regular web browsing using the WebSocket over HTTP/S protocol, enhancing privacy and bypassing firewalls.
    
-   **Peer to Peer Connectivity:** Establish direct, peer-to-peer connections between clients and agents (when possible) using the QUIC protocol to increase performance by avoiding traffic routing through the gateway.
    
-   **Fine-Grained Access Control:** Control access to agents and services based on IP addresses, domains, and agent names, allowing you to implement zero trust network access (ZTNA) policies.
    
-   **End-to-End Encryption:** Secure your communications with end-to-end encryption using the Xchacha20-Poly1305 cipher and HMAC-SHA256 for tamper-proofing.
    
-   **User Management:** Create different user spaces with individual access control policies, providing services to multiple users with a single gateway.
    
-   **Automatic Certificate Provisioning:** Automatic generation and management of TLS certificates for published services using the ACME protocol.
    
-   **SNI Proxy:** Prevent the gateway from decrypting your TLS traffic by handling it on the agent's server with your certificate.
    
-   **CDN Compatibility:** Set up the gateway behind CDN services to enhance the performance of your services.
    
-   **Flexibility:** Orchestrate Narrowlink with other tools like SSH or sing-box to add more functionalities.
    
-   **Cross-Platform and Lightweight:** Written in Rust, Narrowlink is lightweight, fast, and cross-platform, supporting major desktop and mobile operating systems.
    
## Architecture

Narrowlink's architecture consists of three main components: the Gateway, Agents, and Clients. The Gateway serves as the central hub, routing packets between agents, clients, and browsers. Agents act as proxies, forwarding packets to or from targeted hosts within the local network. Clients send and receive packets to and from agents, facilitating communication with the Agent component. The Token Generator is responsible for generating tokens used for authentication and configuration within the Narrowlink network.

<p align="center"><img src="https://raw.githubusercontent.com/narrowlink/homepage/main/static/img/Diagram.svg" alt="Narrowlink Logo" width="80%"></p>

## Getting Started

<a href="https://repology.org/project/narrowlink/versions">
    <img src="https://repology.org/badge/vertical-allrepos/narrowlink.svg" alt="Packaging status" align="right">
</a>


To get started with Narrowlink, please refer to the [documentation](https://narrowlink.com/docs/intro)  page. This page provides two guides: Basic and Extended, which will help you learn more about the platform and walk you through the process of setting up a Narrowlink network and configuring your agents and clients.

## Contributing

We welcome contributions to the Narrowlink project. To contribute, please read the [Contribution Guidelines](CONTRIBUTING.md) and follow the code of conduct.

## License

Narrowlink is released under the MPL-V2 and AGPL-3.0 licenses. Please see the [LICENSE](LICENSE.md) file for more details.


[^1]: Please ensure you have permission from your company and comply with your company's security policies before sharing internet access using Narrowlink. Narrowlink is not responsible for any misuse of the software.
