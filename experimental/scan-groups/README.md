# Experimental multi-target scan groups with credential overrides

This companion controller drives one logical GSA task across selected source
targets. It resolves saved per-asset credentials, groups concrete hosts by
**source target and full effective credential set**, and creates one scanner
target and child task per group. Six hosts across two targets therefore make
two scans without overrides, or three when one host differs. The logical task
appears as a normal gvmd task record; a completed run publishes a combined
report while retaining source reports.

The service uses python-gvm and a Unix gvmd socket. Run it only behind the
GSAD-authenticated reverse proxy in the matching experimental GSAD branch.
The `TRUST_GSA_PROXY=1` mode assumes the proxy alone can reach port 8080.
Persistent group and override state lives in `REVIEW_DB` (SQLite).

`test_controller.py` covers partitioning, child creation, override routing,
and combined report publication. The 9443 review stack runs this exact source.

This is a separate experimental controller. Native gvmd multi-target storage,
launch, resume, and report aggregation are not implemented by this directory.
