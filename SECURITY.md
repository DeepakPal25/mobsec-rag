# Security policy

## Reporting a vulnerability in mobsec-rag

Please do not open a public issue for security problems in the tool itself (for example a crafted APK/IPA
that causes code execution, path traversal during extraction, or prompt injection that changes results).
Use GitHub's private vulnerability reporting ("Security" tab → "Report a vulnerability") and include a
minimal reproducer. We aim to respond within 7 days.

## Handling untrusted apps

mobsec-rag parses untrusted binaries. It never executes app code, extracts archives with zip-slip
protection, caps file sizes, and treats all app content as data in LLM prompts. Still, scan unknown apps
in a container (see the Dockerfile) and keep the web UI bound to localhost unless you add authentication.

## Data sent to LLM providers

With `--llm anthropic` or `--llm openai`, code snippets, class names and strings from the scanned app are
sent to that provider. Use `--llm ollama` (local model) or `--llm none` for confidential apps.

## Responsible use

Only scan applications you own or are explicitly authorised to test.
