import { NextRequest, NextResponse } from "next/server";
import { getStripe } from "@/lib/stripe";

// One-time unlock only, on purpose — a low-commitment purchase for a
// first-time stranger. No subscription offering at this time.
export async function POST(req: NextRequest) {
  const { origin } = (await req.json()) as { origin: string };

  const priceId = process.env.STRIPE_PRICE_ONE_TIME;
  if (!priceId) {
    return NextResponse.json(
      { error: "Missing STRIPE_PRICE_ONE_TIME env var" },
      { status: 500 }
    );
  }

  const stripe = getStripe();
  const session = await stripe.checkout.sessions.create({
    mode: "payment",
    line_items: [{ price: priceId, quantity: 1 }],
    success_url: `${origin}/?session_id={CHECKOUT_SESSION_ID}#results`,
    cancel_url: `${origin}/#results`,
  });

  return NextResponse.json({ url: session.url });
}
