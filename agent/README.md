# Narrowlink Agent
<p align="center">
<img src="https://github.com/narrowlink/docs/blob/main/docs/assets/NarrowLink-888.svg" width="50%" height="50%" alt="Narrowlink Logo">
</p>

## Introduction

Agent runs on your target devices that you want to access remotely. It is responsible for forwarding requests to the gateway and receiving responses from the gateway. The agent handles encryption and decryption of requests and responses. Currently, it supports websockets over HTTP and HTTPS protocols as the transport layer. Additionally, the agent can be configured to publish a webserver to the gateway without intervention from the client. In this case, when the gateway receives a request for the published domain name, it will forward the request to the agent, and the agent will further forward the request to the webserver. The agent also supports optional end-to-end encryption for requests and responses.
## Getting Started

Follow the [Documentation](https://narrowlink.com/docs/intro) to set up Narrowlink, or check the [Agent](https://narrowlink.com/docs/agent) page in the documentation for more information.

## Disclaimer

This software is provided as-is and without warranty. Use at your own risk.
