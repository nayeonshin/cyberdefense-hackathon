# Ramp dashboard rollout evidence

Verified October 9, 2026. Image `e940bebe6ddb283c697ef19da69525900f626830`; digest `sha256:91714aed78a3d7a056a255ad102faea5715274425dd4ba408a77a6ad4a074c35`.

- [Live dashboard](https://e98drk9q2591r5c0pgkbalcshg.ingress.akash-palmito.org/)
- [Replacement deployment](https://console.akash.network/deployments/1791577874883)
- [Successful Linux validation](https://github.com/nayeonshin/cyberdefense-hackathon/actions/runs/37987379983)
- 48 tests passed locally and in Linux CI. The real ClickHouse / Semgrep / Actor container run completed in 12.649 seconds. A volume-preserving container restart retained one SENT receipt and produced a fresh confirmation.
- Desktop and 390px narrow layouts checked in the browser. Row click and arrow keys followed by Shift+Space select the event. Selection survives refresh, reorder and new arrivals; deep links and disappearance fallback have regression coverage.
- Pending, negative, detected, scan failure, dispatch failure, submitted, saved test and historical confirmation states checked. Evidence remains escaped; invalid proof URLs are not linked. Dependency failures retain the last snapshot with a visible error; worker failures remain visible.
- Bundled Inter Regular; captions retain full opacity, 12px minimum and regular weight. Browser console contained no frontend errors after reconnect.

## Replacement and persistence boundary

The previous deployment `1791574764504` was already **closed by provider**. The user authorized replacement hosting using sponsor credits only. Akash's redeploy flow did not expose volume recovery. This is a **fresh controlled run on a new 1 GiB persistent volume**, retaining the configured run ID `akash-controlled-001`; it is not a migration of the previous ledger. Prior deployment evidence remains in `DEPLOYMENT_EVIDENCE.md` as historical evidence.

Akash Palmito hosts deployment `1791577874883` with 2 CPUs, 4 GiB RAM, 5 GiB ephemeral storage and one replica. The quote is $5.38/month, approximately $0.18 for the enabled 24-hour runtime limit. Existing sponsor credits only; no payment method was added. Runtime ends approximately October 10 at 1:34 PM PDT.

The new autonomous run ingested at 20:33:56 UTC, scanned with actual Semgrep at 20:34:00, submitted mock ticket T-0001 at 20:34:02, and confirmed HTTP 410 at 20:34:08. The acceptance probe measured **12.271 seconds**. Browser refresh/reconnect retained exactly **one submitted action** and three distinct receipts (submitted, saved test message, confirmed unavailability). External reporting remains disabled. Cloud data is files; ClickHouse is separately verified in CI and Guild AI evidence remains pending.

## Rollback

Previous image: `ghcr.io/nayeonshin/cyberdefense-hackathon:2ae9e2d4308f230f4c24b482170535f9634004a5`

Previous digest: `sha256:c5e0766119b291edff48ee0d790b082815432128d549025a7767f3f31b26130e`

To roll back the active replacement, change only its image in Akash's Update tab, retaining `RUN_ID=akash-controlled-001` and its `/data` persistent volume. Never recreate hosting as an ordinary image rollback.
