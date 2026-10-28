// One-off seed for the new caption_context table (2026-10-28). Run once
// locally against the live DB via the service key already in .env.
const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

const PERFORMANCE_LEARNINGS = `General research (vendor data, not platform-official -- directionally solid, not gospel):
- The first ~2 seconds decide whether someone keeps watching. Bold claims, questions, and "did you know" framing outperform generic openers.
- Watch time and completion are the top-weighted ranking signals on both Instagram and TikTok -- not likes. Shares/saves outweigh likes too.
- Short wins: most high performers land in the 20-40s range.
- Animated word-level captions show up disproportionately in top performers.
- For trades content specifically: real crew/jobsite footage consistently beats anything polished or stock; before-and-afters and problem-then-fix narratives perform well.

811 Assist's own Instagram, reviewed directly:
- Current format is a tight, repeatable template: numbered-list hook ("5 Things That Actually Cause a Missed Locate Ticket"), real B-roll of actual people/jobsites, white text boxes with the key word bolded in red, matching emoji per line, same CTA every time ("Check the caption for the full breakdown").
- Hook-writing is the strongest part of the current content -- specific and curiosity-driven.
- Real tension found: posts run ~6s with zero voiceover, so the hook never resolves on-screen -- the payoff is "go read the caption," which fights against watch-time/completion being the top ranking signal.
- Standing recommendation: keep the strong numbered-list hook style, but test resolving at least one point on-screen before sending people to the caption, and consider an 8-10s cut instead of 6s to ease the reading pace.`;

const EIGHT_ELEVEN_PLAN = `811 Assist sells certainty that you're covered, not ticket-management software -- the relief of not getting blamed or billed for something that wasn't your fault because you can prove what you knew and when.
The hook/content should be written to the field crew (the emotional subject -- the person with hands on the bucket), even though the actual buyer is the business owner/office manager. Content stays aimed at the crew's fear because that's what gets attention and shares.
Every piece should close by pointing at the lead magnet concept ("The 3-Question Check: Are You Actually Covered to Dig?") or the tripwire ("try it on your next ticket for $1.99"), never straight at a hard sell.
Strong hook angles already validated: numbered-list/root-cause hooks (e.g. "86% of damage has the same 3 causes"), the $83 billion industry-cost stat made personal, and honest AM Underground case-study framing (same owner, real customer).
Compliance: nothing here becomes actual paid ad copy without a platform ad-policy check first -- zero account-ban risk is the standing rule.`;

const AXION_PEPT_PLAN = `Axion Pept content must stay strictly in "for laboratory research only" framing at all times -- no human-use, dosing-for-consumer, or therapeutic/performance claims, no exceptions.
Differentiation angle: name and lean on Axion's real third-party HPLC/mass-spec testing and published Certificates of Analysis -- naming the specific independent lab (not just "third-party tested") is what makes a testing claim credible in this category.
Safer organic angle found in research: non-coded, non-hyped community presence (being talked about where researchers already are) rather than TikTok-affiliate-style promotion, which is explicitly what's drawing FDA attention in this category.
Good content angles: "The Questions a Real Lab Answers in an Hour" (responsiveness as proof), "Why 'Third-Party Tested' Means Nothing Without This" (teaches the verification gap), and a named-lab/lot-number walkthrough once the branded testing program has a name.
Tone: educational, "help them verify, don't just talk about yourself" -- even when the content is inherently about Axion's own process.`;

(async () => {
    const { error: e1 } = await supabase.from("caption_context").insert({
        client_id: null,
        category: "performance_learnings",
        content: PERFORMANCE_LEARNINGS,
    });
    console.log("global performance_learnings:", e1 ? e1.message : "OK");

    const { data: clients } = await supabase.from("clients").select("id, slug");
    const eightEleven = clients.find(c => c.slug === "811-assist");
    const axion = clients.find(c => c.slug === "axion-pept");

    const { error: e2 } = await supabase.from("caption_context").insert({
        client_id: eightEleven.id,
        category: "marketing_plan",
        content: EIGHT_ELEVEN_PLAN,
    });
    console.log("811 Assist marketing_plan:", e2 ? e2.message : "OK");

    const { error: e3 } = await supabase.from("caption_context").insert({
        client_id: axion.id,
        category: "marketing_plan",
        content: AXION_PEPT_PLAN,
    });
    console.log("Axion Pept marketing_plan:", e3 ? e3.message : "OK");
})();
