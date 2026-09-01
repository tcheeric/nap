/**
 * The app's actual domain, such as it is. An in-memory list of vouchers, so the
 * tutorials have something worth guarding that is not itself about auth.
 */
export interface Voucher {
  id: string;
  code: string;
  amountCents: number;
  issuedBy: string;
  issuedAt: number;
}

export interface VoucherStore {
  list(): Voucher[];
  create(input: { amountCents: number; issuedBy: string; now: number }): Voucher;
}

export function createVoucherStore(): VoucherStore {
  const vouchers: Voucher[] = [];
  let counter = 0;

  return {
    list() {
      return [...vouchers];
    },
    create({ amountCents, issuedBy, now }) {
      counter += 1;
      const voucher: Voucher = {
        id: `vch_${counter}`,
        code: `MERCHANT-${String(counter).padStart(4, '0')}`,
        amountCents,
        issuedBy,
        issuedAt: now,
      };
      vouchers.push(voucher);
      return voucher;
    },
  };
}
