import { NextRequest, NextResponse } from "next/server";
import { getStripe } from "@/lib/stripe";

// Confirms a completed Stripe Checkout session so the browser can unlock
// the already-computed report. Note what this route does NOT do: it never
// receives or stores the user's scan data — that stays entirely
// client-side. This endpoint only ever sees a Stripe session id.
export async function GET(req: NextRequest) {
  const sessionId = req.nextUrl.searchParams.get("session_id");
  if (!sessionId) {
    return NextResponse.json({ error: "session_id required" }, { status: 400 });
  }

  const stripe = getStripe();
  const session = await stripe.checkout.sessions.retrieve(sessionId);

  const paid =
    session.payment_status === "paid" ||
    session.status === "complete";

  return NextResponse.json({ paid });
}
