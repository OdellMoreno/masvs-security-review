# MASVS Quick Map

Primary dataset:
- `references/OWASP_MASVS.v2.0.0.json`

Domain overview (`24` controls total):
- `MASVS-STORAGE` (2): local sensitive data storage and leakage prevention.
- `MASVS-CRYPTO` (2): cryptography and key management.
- `MASVS-AUTH` (3): authn/authz and step-up auth for sensitive operations.
- `MASVS-NETWORK` (2): secure transport and endpoint pinning.
- `MASVS-PLATFORM` (3): IPC, WebView, and UI data exposure controls.
- `MASVS-CODE` (4): platform/app updates, vulnerable deps, input validation.
- `MASVS-RESILIENCE` (4): platform integrity, anti-tamper, anti-analysis.
- `MASVS-PRIVACY` (4): minimization, unlinkability, transparency, user control.

Prioritization tips:
- Handling credentials/tokens/PII: start with `MASVS-STORAGE`, `MASVS-CRYPTO`, `MASVS-AUTH`, `MASVS-PRIVACY`.
- Heavy API traffic: prioritize `MASVS-NETWORK`, `MASVS-AUTH`, `MASVS-CODE`.
- WebView/deep links/intents/custom URL schemes: prioritize `MASVS-PLATFORM`, then `MASVS-CODE`.
- High tampering/repackaging risk: prioritize `MASVS-RESILIENCE` plus `MASVS-CODE`.

Profile notes:
- MASVS v2 removed per-control legacy levels from the core controls dataset.
- Use MAS profiles (`MAS-L1`, `MAS-L2`, `MAS-R`) as threat-model context, not as strict control filters.
- Practical exception: `MAS-R` aligns strongly with `MASVS-RESILIENCE` controls.
