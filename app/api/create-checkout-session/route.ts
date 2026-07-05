import { NextRequest, NextResponse } from "next/server";
import { getStripe } from "@/lib/stripe";

// Two price points on purpose: a low-commitment one-time unlock for a
// first-time stranger, and a subscription for anyone convinced by the
// "your AI keeps shipping new code, recheck after every session" story.
// Neither price ID exists until a real Stripe account is created — see
// README.md for the one remaining manual step.
export async function POST(req: NextRequest) {
  const { plan, origin } = (await req.json()) as {
    plan: "one_time" | "subscription";
    origin: string;
  };

  const priceId =
    plan === "subscription"
      ? process.env.STRIPE_PRICE_SUBSCRIPTION
      : process.env.STRIPE_PRICE_ONE_TIME;

  if (!priceId) {
    return NextResponse.json(
      { error: `Missing price ID env var for plan "${plan}"` },
      { status: 500 }
    );
  }

  const stripe = getStripe();
  const session = await stripe.checkout.sessions.create({
    mode: plan === "subscription" ? "subscription" : "payment",
    line_items: [{ price: priceId, quantity: 1 }],
    success_url: `${origin}/?session_id={CHECKOUT_SESSION_ID}#results`,
    cancel_url: `${origin}/#results`,
  });

  return NextResponse.json({ url: session.url });
}
