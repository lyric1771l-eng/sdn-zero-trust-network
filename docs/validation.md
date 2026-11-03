# Validation guide

The original group project was run and validated in a Linux VM hosted in UTM, as confirmed by Yan Liang. The [group project website](https://sites.google.com/view/2026t2ztrust-mini-project) accompanies the project.

Portfolio preparation date: 2026-11-03. Six offline regression tests and Python syntax checks passed. The portfolio edition corrects source-host filtering in the verification script; that specific revision has not been rerun in Mininet. Original project validation and validation of this later revision are separate. The following steps are provided for reproduction, not as a requirement to repeat the already completed group project.

## Capture the environment

In the original UTM Linux VM, record:

```bash
uname -a
python3 --version
mn --version
ovs-vsctl --version
ryu-manager --version
python3 -m pip freeze
```

Record the working package versions before attempting upgrades. No dependency lock file is supplied because the original environment has not yet been captured.

## Expected checks

Start a fresh controller and topology for each suite as described in the README.

| Check | Expected evidence |
|---|---|
| Operations to Core Web | HTTP 200 |
| Guest to Core Web | No HTTP response |
| Scanner probes five destinations | First same-pod target reachable; probes recorded |
| First offence | Source-specific `0x400` flow; same-pod ping works |
| Repeat offence | Source-specific `0x300` flow; same-pod ping fails |
| Other Operations client | Core Web remains reachable |
| Clean host probes four destinations | No enforcement for that host |
| Exempt host probes five destinations | No enforcement for that host |
| Scanner after reputation decay | Four targets no longer trigger enforcement |

These are expected outcomes, not recorded passes. Keep the complete controller log, PASS/FAIL summaries, switch-table dumps, meter configuration and meter statistics with the date and environment versions. Measure throughput separately before claiming rate-limit performance.

An HTTP timeout alone does not prove a deny policy if the service is down; the positive Operations control is essential. Short sleeps may be sensitive to a heavily loaded VM. Investigate failed checks rather than changing the expected result.
