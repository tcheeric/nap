import { useEffect, useState } from 'react';
import { useNapSession } from '@imani/nap-react';

interface Voucher {
  id: string;
  code: string;
  amountCents: number;
  issuedBy: string;
}

/**
 * Hiding a button is not protecting a route.
 *
 * Everything this component does with `permissions` is affordance: it stops the
 * user reaching for something that would be refused. The refusal itself comes
 * from `requirePermission()` on the server, and it happens whether or not this
 * file exists. Delete every check below and the app is exactly as secure — only
 * ruder.
 */
export function Vouchers() {
  const { permissions } = useNapSession();
  const [vouchers, setVouchers] = useState<Voucher[] | null>(null);
  const [amount, setAmount] = useState('25.00');
  const [error, setError] = useState<string | null>(null);

  const canRead = permissions.includes('merchant:read');
  const canCreate = permissions.includes('voucher:create');

  useEffect(() => {
    if (!canRead) return;
    void refresh();
  }, [canRead]);

  async function refresh() {
    // `credentials: 'include'` on every call you make yourself. NAP's own
    // client sets it; your fetches are your own problem, and the failure is a
    // 401 indistinguishable from an expired session.
    const res = await fetch('/api/vouchers', { credentials: 'include' });
    if (res.ok) setVouchers(((await res.json()) as { vouchers: Voucher[] }).vouchers);
  }

  async function create() {
    setError(null);
    const res = await fetch('/api/vouchers', {
      method: 'POST',
      credentials: 'include',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ amount_cents: Math.round(Number(amount) * 100) }),
    });

    if (res.status === 403) {
      // Reachable even with the button hidden — a stale snapshot, a revoked
      // role, a second tab. The server is the one that decides.
      setError('You are not allowed to issue vouchers.');
      return;
    }
    if (!res.ok) {
      setError('Could not issue that voucher.');
      return;
    }
    await refresh();
  }

  if (!canRead) {
    return <p>Your account cannot see vouchers.</p>;
  }

  return (
    <section>
      <h2>Vouchers</h2>
      <ul>
        {(vouchers ?? []).map((voucher) => (
          <li key={voucher.id}>
            <code>{voucher.code}</code> — {(voucher.amountCents / 100).toFixed(2)}
          </li>
        ))}
      </ul>
      {vouchers?.length === 0 ? <p>None yet.</p> : null}

      {canCreate ? (
        <p>
          <label>
            Amount{' '}
            <input value={amount} onChange={(event) => setAmount(event.target.value)} />
          </label>{' '}
          <button onClick={() => void create()}>Issue voucher</button>
        </p>
      ) : null}

      {error ? <p role="alert">{error}</p> : null}
    </section>
  );
}
