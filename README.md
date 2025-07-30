# Security Monitoring for AI Agents and MCP
A practical guide to building an observable Phishing Triage Assistant with MCP and structured logging

**TLDR:** We show structured logging of AI Agents with MCP to tackle Phishing Triage, allowing continuous security monitoring in a SIEM and automated remediation in a SOAR.

This code is a companion to our technical blog post, published by [Realm.Security](https://realm.security/).

TODO: Add link to blog post
TODO: Add graphic

## Contents

- `mcp_server.py` provides the MCP server using FastMCP, instrumented with client-side logging
- `agent_client.py` provides the AI agent using LangGraph, with structured logging across both agent and tools

## Usage

Ensure [uv is installed](https://docs.astral.sh/uv/getting-started/installation/) to manage the Python dependencies.

Run the MCP server:
```shell
uv run -- python mcp_server.py
```

Then, in a separate terminal, run the AI agent.
```shell
uv run -- python agent_client.py
```

The agent requires access to a Large Language Model (LLM), and is set up
to use Anthropic Claude Sonnet 3.7 through AWS Bedrock by default. Ensure
your access credentials are available to the LangChain API.