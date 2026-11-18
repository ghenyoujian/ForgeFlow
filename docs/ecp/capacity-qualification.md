# Capacity and soak campaign

`benchmarks/ecp/capacity_campaign.py` is the bounded real-API runner for the
Phase 6 capacity slice. It creates real PostgreSQL conversations and threads,
sends bounded messages through the control plane, records latency and failures,
and never invokes a model. Use `--run` only with a disposable deployment and
source-bound credentials.

The scale profile is 1/4/10/32/64/128 channels. The final ECP target is 128
channels for 60 minutes; the separate soak wrapper records the 72-hour target
and leaves resource observation and qualification as `NOT_RUN` until an
independent observer is attached.
