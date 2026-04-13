# Migration Samples

This directory contains sample services for testing live migration in Junction.

## counter_service

A simple stateful TCP service that maintains an integer counter. It accepts two commands:

- `INC\n` — increments the counter, responds `OK`
- `GET\n` — returns the current counter value as `COUNT <n>`

It is used to demonstrate stop-and-copy live migration: the counter state is
preserved across migration to a new node.

## Stop-and-Copy Migration Test

This test migrates `counter_service` from one Junction instance to another using
`scripts/migrate.py`. It requires three roles, each run from a separate node (or terminal).

### Prerequisites

- Build Junction: `scripts/build.sh`
- The iokerneld scheduler must already be running on each node (see the top-level README)
- Node IPs are configured in `CMakeLists.txt`:
  - Source (sender): `10.10.1.1`
  - Destination (receiver): `10.10.1.2`
- The initiator must be able to reach both IPs (e.g. run from a third node on the same subnet)

### Step 1 — Start the sender (node-0)

```shell
scripts/migrate.py sender 8080
```

Wait for `Sender ready.` to appear before proceeding.

### Step 2 — Start the receiver (node-1)

```shell
scripts/migrate.py receiver
```

### Step 3 — Trigger migration (initiator node)

```shell
scripts/migrate.py initiator 8080
```

The initiator will:
1. Send 3 `INC` requests to the source and print the counter
2. Trigger migration of the process to the destination
3. Verify the source is no longer serving
4. Confirm the counter state is preserved on the destination
5. Send 3 more `INC` requests to the destination to verify it continues working
