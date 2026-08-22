# NAP and OAuth 2.0

**Who this is for:** an architect deciding whether NAP replaces the OAuth
2.0 / OIDC setup they already run, supplements it, or is simply answering a
different question.

Start with the two questions, because most of the confusion is here:

> OAuth answers "can this app act on behalf of this user at that service?"
> NAP answers "does this user control this Nostr key right now?"
>
> — `docs/NAP-v2-RFC.md`, Appendix D.5

## They are not substitutes

NAP is **authentication**. It has no delegation model at all — Appendix D's
delegation row reads "Not supported — single-party authentication only", and
that is a scope decision, not a gap waiting to be filled. If your requirement is
"app A reaches resource B on behalf of user C", OAuth is the answer and NAP has
nothing to offer you.

The case where they genuinely compete is narrower: **OAuth (usually OIDC) used
purely as a login mechanism**, where the authorization server exists so that a
third party vouches for who the user is, and the delegation machinery is
overhead you tolerate rather than capability you use. That is the comparison
Appendix D makes, and for that case NAP replaces the authorization server with a
signature your own server verifies.

If you run both — a Nostr login for users who have a key, an IdP login for
everyone else — that is a normal outcome, not a failure to choose.

---

## The comparison proper

**[`docs/NAP-v2-RFC.md` Appendix D — NAP vs OAuth 2.0](../NAP-v2-RFC.md)** is
the comparison, and this page deliberately does not restate it. It covers:

| | |
| --- | --- |
| D.1 | Structural comparison — flow shape, identity verification, third-party authorization server, redirects, token types and transport, scopes, refresh, revocation, delegation |
| D.2 | Trust model |
| D.3 | Complexity, and why NAP has one flow with two endpoints |
| D.4 | When to prefer each, as two lists of conditions |
| D.5 | The one-sentence summary quoted above |

Read that first. Everything below assumes you have, and covers only what it does
not: what adopting NAP looks like when OAuth is already running in production.

---

## You have OAuth today

`docs/NAP-INTEGRATION-GUIDE.md` §10 gives a five-phase migration path, written
for a reader whose incumbent scheme is bare NIP-98. The phases transfer to an
OAuth incumbent unchanged in shape; what changes is what "the old path" means at
each one.

### Phase 0 — mount NAP, guard nothing

Add the router and stores. Do not put a NAP guard on a single existing route
yet, and verify the flow with `curl` before touching anything else.

Two things bite here regardless of what your incumbent is:

- **Exclude `/auth/**` from your existing global auth filter.** `/auth/init` is
  by definition called without credentials. A global "require a valid bearer
  token" middleware 401s it before NAP ever sees it. This is the single most
  common integration failure.
- **Watch body-parser ordering.** A global `express.json()` above the NAP router
  breaks every completion, because the NIP-98 `payload` tag is
  `sha256(rawBody)`. Guide §5.2 has the fix.

### Phase 1 — dual auth, one principal

Make the NAP session an *additional* way to authenticate, checked first, falling
through to your OAuth token validation. Guide §10's Phase 1 middleware is the
template; the branch you fall through to is your existing introspection or JWT
verification instead of a NIP-98 check.

The design point that matters is the same one: **both paths must populate the
same principal object**, so that no controller, service, or authorization check
downstream can tell which happened. Get this right and Phase 4 is deleting an
`else`.

**This is where an OAuth incumbent costs more than a NIP-98 one.** Your
principal is almost certainly keyed on an IdP subject identifier — a `sub`
claim, a provider user id — and a NAP session gives you
`session.principal_pubkey`, a hex Nostr pubkey. Nothing in NAP maps one to the
other, and nothing will. Before Phase 1 is useful you need to decide:

- **Account linking** — an authenticated OAuth user proves control of a Nostr
  key once, and you store the pubkey against the existing account. NAP logins
  then resolve to accounts that already exist. This is yours to build; NAP has
  no enrollment ceremony to hang it on.
- **Or separate accounts** — a NAP login creates a new account keyed on the
  pubkey. Simpler, and correct if your Nostr users are a new audience rather
  than your existing one wearing a different credential.

Pick one before you write the middleware. Discovering halfway through that two
identifiers refer to the same person is expensive.

### Phase 2 — opt-in on the client

Feature-detect rather than ship a config flag: attempt `POST /auth/init` and
fall back to the existing flow on 404. Frontend and backend then deploy
independently, and a backend rollback needs no frontend release. Guide §10 has
the snippet.

Behind an OAuth incumbent this also means your login screen now offers two
buttons, and the Nostr one only makes sense for users who have a signer.
[Tutorial 02](../tutorials/02-logging-in-from-a-browser.md) covers detecting a
NIP-07 extension, and [tutorial 07](../tutorials/07-nip46.md) covers the NIP-46
path for users who do not have one.

### Phase 3 — the ACL, and what happens to your scopes

OAuth carries scopes **in the token**, granted at authorization time. NAP
resolves roles and permissions **server-side at login**, and freezes them into
the session — the snapshot semantics in guide §3.4. Two consequences:

- There is no NAP equivalent of "the client requests these scopes". The server
  decides what the principal gets, from its own tables. If your scope set is
  really a per-user permission set, that translates directly. If it is really a
  per-*client* grant — this app may read, that app may write — that is
  delegation, and NAP does not model it.
- A permission change does not reach a live session. Pair every grant or
  suspension with `sessionStore.revokeByPrincipal(pubkey, nowSeconds())` or the
  change appears to do nothing until the session expires. See
  [tutorial 03](../tutorials/03-roles-and-permissions.md).

If you already have an authorization model, implement `AclResolver` over your
existing tables and skip NAP's registry entirely — it is one method, and your
current checks keep working unchanged.

### Phase 4 — retire the old path, or don't

Instrument the fall-through in the Phase 1 middleware; when the OAuth branch is
cold, delete it. Unlike the NIP-98 case, there is a good chance it never goes
cold, and that is fine. An IdP login is not something NAP asks you to remove.

---

## What you give up

Worth being explicit, because an authorization server is doing more for you than
issuing tokens:

- **Account recovery.** Your IdP has a password reset flow, a verified email, a
  support path. NAP has none: the key is the account, and a user who loses it
  loses access. Anything better is something your application builds.
- **MFA and step-up as consent.** NAP's step-up proves key control at a moment,
  not that a human approved anything — RFC §10.3 is explicit, and it is not a
  consent control. If your OAuth provider is enforcing MFA today, NAP does not
  carry that forward.
- **Provider-side audit and account lifecycle.** Suspension, deprovisioning, and
  the audit trail that goes with them move to your side.

None of these are arguments against NAP. They are line items to budget, and they
are the reason "run both" is a reasonable end state.

---

## Where to go next

- **[Tutorial 01](../tutorials/01-a-server-you-can-curl.md)** — the whole
  exchange by hand, no frontend. About twenty minutes, and it makes the
  structural comparison concrete.
- **`docs/NAP-INTEGRATION-GUIDE.md` §10** — the migration path in full, with the
  code for each phase.
- **`docs/NAP-v2-RFC.md` Appendix D** — the comparison proper, again.
