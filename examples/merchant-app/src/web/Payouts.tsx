import { useState } from 'react';
import { useNapSession } from '@imani/nap-react';

/**
 * The one action in this app that is not satisfied by being signed in.
 *
 * `stripe:manage` is declared `stepUp: true` in the registry, so the guard
 * wants an `X-Step-Up-Token` as well as a session. The token comes from
 * `session.stepUp()`, which re-runs the whole init/complete exchange — a fresh
 * signature, and therefore a fresh prompt from the extension or bunker.
 *
 * What that proves is **present key control**, and nothing more. A NIP-46
 * bunker with the permission pre-granted answers it without asking anybody.
 * Do not read a step-up as consent; see tutorial 06.
 */
export function Payouts() {
  const { session, permissions } = useNapSession();
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (!permissions.includes('stripe:manage')) {
    return <p>Your account cannot change payout settings.</p>;
  }

  const post = (stepUpToken?: string) =>
    fetch('/api/payouts', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'content-type': 'application/json',
        ...(stepUpToken ? { 'x-step-up-token': stepUpToken } : {}),
      },
      body: JSON.stringify({}),
    });

  async function save() {
    setBusy(true);
    setStatus(null);
    try {
      // Try without a step-up first, deliberately. The registry can change,
      // the permission can stop being `stepUp: true`, and a client that
      // decides for itself when to prompt will keep prompting after the
      // server has stopped asking. Let the 403 be the thing that asks.
      let res = await post();

      if (res.status === 403) {
        // Only a step-up refusal is retryable. A plain 403 means the role does
        // not carry the permission, and no number of signatures fixes that.
        const body = (await res.json().catch(() => ({}))) as { message?: string };
        if (body.message !== 'step-up required') {
          setStatus('You are not allowed to change payout settings.');
          return;
        }

        // Costs a signature. In cookie mode this also replaces the session
        // cookie, because a step-up mints a new session rather than upgrading
        // the old one — which is why the retry below just works.
        res = await post(await session.stepUp());
      }

      setStatus(res.ok ? 'Payout settings updated.' : 'Could not update payout settings.');
    } catch {
      // Declining the signature lands here, and it is an ordinary outcome
      // rather than an error state to shout about.
      setStatus('Payout settings unchanged.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <h2>Payouts</h2>
      <button disabled={busy} onClick={() => void save()}>
        Update payout settings
      </button>
      {status ? <p role="status">{status}</p> : null}
    </section>
  );
}
