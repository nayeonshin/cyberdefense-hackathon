# Ramp dashboard rollout evidence

Verified October 9, 2026. Image `e940bebe6ddb283c697ef19da69525900f626830`; digest `sha256:91714aed78a3d7a056a255ad102faea5715274425dd4ba408a77a6ad4a074c35`.

- [Live dashboard](https://rlts1sj4jhcur9q89cjbfn8omk.ingress.h6i-dedicated.eu-se-1.digitalfrontier.so/)
- [Replacement deployment](https://console.akash.network/deployments/1791578237742)
- [Successful Linux validation](https://github.com/nayeonshin/cyberdefense-hackathon/actions/runs/37987379983)
- 48 tests passed locally and in Linux CI. The real ClickHouse / Semgrep / Actor container run completed in 12.649 seconds. A volume-preserving container restart retained one SENT receipt and produced a fresh confirmation.
- Desktop and 390px narrow layouts checked in the browser. Row click and arrow keys followed by Shift+Space select the event. Selection survives refresh, reorder and new arrivals; deep links and disappearance fallback have regression coverage.
- Pending, negative, detected, scan failure, dispatch failure, submitted, saved test and historical confirmation states checked. Evidence remains escaped; invalid proof URLs are not linked. Dependency failures retain the last snapshot with a visible error; worker failures remain visible.
- Bundled Inter Regular; captions retain full opacity, 12px minimum and regular weight. Browser console contained no frontend errors after reconnect.

## Replacement and persistence boundary

The previous deployment `1791574764504` was already **closed by provider**. The user authorized replacement hosting using sponsor credits only. Akash's redeploy flow did not expose volume recovery. This is a **fresh controlled run on a new 1 GiB persistent volume**, retaining the configured run ID `akash-controlled-001`; it is not a migration of the previous ledger. Prior deployment evidence remains in `DEPLOYMENT_EVIDENCE.md` as historical evidence.

Digital Frontier (`provider.h6i-dedicated.eu-se-1.digitalfrontier.so`) hosts deployment `1791578237742` with 2 CPUs, 4 GiB RAM, 5 GiB ephemeral storage and one replica. The quote is $5.18/month, approximately $0.17 for the enabled 24-hour runtime limit. Existing sponsor credits only; no payment method was added. Runtime ends approximately October 10 at 1:39 PM PDT.

The new autonomous run ingested at 20:39:07 UTC, scanned with actual Semgrep at 20:39:14, submitted mock ticket T-0001 at 20:39:15, and confirmed HTTP 410 at 20:39:22. The acceptance probe measured **15.054 seconds**. Browser refresh/reconnect retained exactly **one submitted action** and three distinct receipts (submitted, saved test message, confirmed unavailability). External reporting remains disabled. Cloud data is files; ClickHouse is separately verified in CI and Guild AI evidence remains pending.

The first replacement on Palmito (`1791577874883`) completed a 12.271-second controlled run but was then also closed by the provider. The final deployment uses Digital Frontier. No cause for provider closure was established.

A local backup, `outputs/akash-controlled-001-backup.tar.gz`, contains the current ledger, registrar state, attempts, event, scan findings, capture and saved test message. Archive contents were listed successfully. A restoration from this backup has not been exercised.

## Rollback

Previous image: `ghcr.io/nayeonshin/cyberdefense-hackathon:2ae9e2d4308f230f4c24b482170535f9634004a5`

Previous digest: `sha256:c5e0766119b291edff48ee0d790b082815432128d549025a7767f3f31b26130e`

To roll back the active replacement, change only its image in Akash's Update tab, retaining `RUN_ID=akash-controlled-001` and its `/data` persistent volume. Never recreate hosting as an ordinary image rollback.
