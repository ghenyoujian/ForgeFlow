# Native provider UI journey boundary

The Bot Room is a controlled entry point for DSH/Claude conversations. It reads
the same workspace and Agent Registry identity as the control plane and keeps
`NOT_RUN`, `UNKNOWN`, and `UNSUPPORTED` visible until a current provider
receipt is available.

The UI does not treat an online indicator, a message ACK, or a local process
exit as a completed task. A qualification run must bind a source SHA, provider
authorization, execution envelope, message receipt, cost ledger, verification
result, and Git evidence. Until those facts are captured by the native
qualification runner, the dual-provider journey remains `NOT_RUN`.
