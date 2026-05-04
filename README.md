## Security Notes

This project is intended for local, authorized research workflows.

# Browser/Proxy MCP Runtime

A lightweight MCP runtime that connects an LLM agent to a browser and proxy observation pipeline.

This project provides a Python-based MCP server with optional browser automation, proxy capture, session parsing, and LLM bridge components. It is designed for local security research workflows where browser/network telemetry needs to be reduced into compact, useful observations for an agent.

## Features

- MCP server entrypoint
- Browser bridge integration
- Playwright client wrapper
- Proxy control client
- mitmproxy addon support
- Session parser for compact observations
- LLM bridge for OpenAI-compatible local/remote models
- Handler-based tool organization

## Project structure

```text
.
├── browser_bridge/        # Browser-side bridge/runtime components
├── handlers/              # MCP tool handlers
├── controller.py          # Main orchestration/controller layer
├── mcp_server.py          # MCP server entrypoint
├── playwright_client.py   # Playwright client integration
├── proxy_client.py        # Proxy control client
├── mitm_addon_v2.py       # mitmproxy addon for traffic capture/control
├── session_parser.py      # Session/event parsing and reduction
├── llm_bridge.py          # LLM endpoint adapter
└── requirements.txt

## Installation

Create and activate a Python virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

If using the browser bridge, install Node.js dependencies inside the browser bridge directory:

```bash
cd browser_bridge
npm install
cd ..
```

If using Playwright from the Node worker, install the browser runtime:

```bash
npx playwright install chromium
```

If using proxy capture, install and run mitmproxy with the provided addon:

```bash
mitmproxy -s mitm_addon_v2.py
```

## MCP Client Configuration

Example MCP client configuration:

```json
{
  "mcpServers": {
    "local_host": {
      "command": "/absolute/path/to/python",
      "args": ["/absolute/path/to/mcp_python/mcp_server.py"],
      "cwd": "/absolute/path/to/mcp_python/"
    }
  }
}
```

Example local configuration:

```json
{
  "mcpServers": {
    "local_host": {
      "command": "/home/your_name/python-dirty/bin/python",
      "args": ["/home/your_name/mcp_python/mcp_server.py"],
      "cwd": "/home/your_name/mcp_python/"
    }
  }
}
```

## Environment Variables

Create a `.env` file based on `.env.example`.

```env
LLM_BASE_URL=http://127.0.0.1:8080/v1
LLM_MODEL=local-model
MITM_CONTROL_URL=http://127.0.0.1:8765
MITM_PROXY_SERVER=http://127.0.0.1:8080
PW_BROWSER=chromium
PW_HEADLESS=false
PW_IGNORE_HTTPS_ERRORS=true
```

## Running

Start the MCP server:

```bash
python mcp_server.py
```

Start mitmproxy with the addon, if proxy capture is needed:

```bash
mitmproxy -s mitm_addon_v2.py
```

The MCP client should then launch this server using the configured Python interpreter and working directory.

## Main Components

- `mcp_server.py`: MCP server entrypoint.
- `controller.py`: Coordinates browser, proxy, session parsing, and LLM components.
- `playwright_client.py`: Client wrapper for the Playwright worker.
- `proxy_client.py`: Client wrapper for the proxy control interface.
- `mitm_addon_v2.py`: mitmproxy addon for HTTP traffic capture/control.
- `session_parser.py`: Reduces browser/proxy events into compact session observations.
- `llm_bridge.py`: OpenAI-compatible LLM bridge.
- `handlers/`: MCP tool handlers.
- `browser_bridge/`: Browser-side worker/runtime code.



## Status

Experimental research tooling.

The goal of this repository is to provide a compact runtime layer for browser/proxy/LLM workflows without exposing target-specific logic or private research data.
