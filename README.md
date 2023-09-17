# Narrowlink
<p align="center"><img src="https://raw.githubusercontent.com/narrowlink/homepage/main/static/img/NarrowLink-888.svg" alt="Narrowlink Logo" width="50%"></p>
Narrowlink is a self-hosted platform that allows you to establish secure remote connections between devices within a network that may be hindered by network address translation (NAT) or firewalls. Whether you need to access a home computer from your laptop, share internet access with remote devices, or publish a local web server on the internet, Narrowlink provides the solution.


## Use Cases

-   **Port Forwarding without a Public IP Address:** Access devices within your home network from external locations without public IP addresses.
    
-   **Sharing Internet Access:** Enable remote devices to access the internet through your network.
    
-   **Publishing Your Local Webserver:** Make your local webserver accessible on the internet, even without a public IP address.
    

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

To get started with Narrowlink, please refer to the [documentation](https://narrowlink.com/docs/intro)  page. This page provides two guides: Basic and Extended, which will help you learn more about the platform and walk you through the process of setting up a Narrowlink network and configuring your agents and clients.

## Contributing

We welcome contributions to the Narrowlink project. To contribute, please read the [Contribution Guidelines](CONTRIBUTING.md) and follow the code of conduct.

## License

Narrowlink is released under the MPL-V2 and AGPL-3.0 licenses. Please see the [LICENSE](LICENSE.md) file for more details.
