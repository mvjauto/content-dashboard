const path = require("path");
const fs = require("fs");
const os = require("os");
const crypto = require("crypto");
const { execFile } = require("child_process");
const { promisify } = require("util");
const execFileAsync = promisify(execFile);
const express = require("express");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const multer = require("multer");
const { createClient } = require("@supabase/supabase-js");

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

// Sessions used to live in plain server memory (express-session's default
// store) -- fine on a laptop, broken here: Render's free plan spins the
// service down after 15 min idle, and every manual deploy (constant, since
// there's still no GitHub webhook) restarts the process too. Either one
// wiped every logged-in session with no warning. Backing sessions with the
// same Supabase Postgres database already in use fixes that -- logins now
// survive restarts and deploys. Same pooler connection run-migration.js uses.
const sessionPool = new Pool({
    host: "aws-0-us-east-1.pooler.supabase.com",
    port: 6543,
    user: "postgres.bfutcalcoegtdtbnpysy",
    password: process.env.DB_PASS,
    database: "postgres",
    ssl: { rejectUnauthorized: false },
});

// ffmpeg-full specifically, not the system "ffmpeg" -- the plain Homebrew
// ffmpeg formula doesn't ship libfreetype, so it has no drawtext filter.
// Full path so this doesn't depend on PATH or on Josh's own shell setup.
// Real bug found 2026-10-19: this was hardcoded to the Homebrew path that
// only exists on Josh's own Mac, so every trim/crop/finish call has been
// silently crashing (spawn ENOENT) on the actual deployed Render site this
// whole time -- every test that ever "worked" was against localhost, never
// against production. Render's own Node environment ships ffmpeg/ffprobe on
// PATH already (confirmed, not assumed -- see the deploy log check after
// this fix), so resolve by platform instead of hardcoding one machine's path.
const FFMPEG_BIN = process.platform === "darwin" ? "/opt/homebrew/opt/ffmpeg-full/bin/ffmpeg" : "ffmpeg";
const FFPROBE_BIN = process.platform === "darwin" ? "/opt/homebrew/opt/ffmpeg-full/bin/ffprobe" : "ffprobe";

const app = express();
// Render (and most host platforms) terminate TLS at their own proxy and
// forward to this app over plain HTTP -- without this, Express thinks every
// request is insecure and silently refuses to set the secure session
// cookie, so nobody could ever actually stay logged in once deployed.
app.set("trust proxy", 1);
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(session({
    store: new pgSession({ pool: sessionPool, createTableIfMissing: true }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: process.env.NODE_ENV === "production" },
}));

function requireLogin(req, res, next) {
    if (!req.session.user) return res.status(401).json({ error: "not logged in" });
    next();
}

function requireOwner(req, res, next) {
    if (!req.session.user || req.session.user.role !== "owner") return res.status(403).json({ error: "owner only" });
    next();
}

// A user sees every client if they're an owner, otherwise only the ones
// listed in user_client_access -- enforced here, not left to the client.
async function clientsVisibleTo(user) {
    if (user.role === "owner") {
        const { data } = await supabase.from("clients").select("*");
        return data || [];
    }
    const { data } = await supabase
        .from("user_client_access")
        .select("clients(*)")
        .eq("user_id", user.id);
    return (data || []).map(row => row.clients);
}

app.get("/health", (req, res) => res.json({ ok: true }));

app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;
    const { data: user } = await supabase.from("users").select("*").eq("email", email).single();
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
        return res.status(401).json({ error: "invalid email or password" });
    }
    req.session.user = { id: user.id, email: user.email, name: user.name, role: user.role };
    res.json({ ok: true, user: req.session.user });
});

app.post("/api/logout", (req, res) => {
    req.session.destroy(() => res.json({ ok: true }));
});

app.post("/api/change-password", requireLogin, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!newPassword || newPassword.length < 8) {
        return res.status(400).json({ error: "new password must be at least 8 characters" });
    }

    const { data: user } = await supabase.from("users").select("*").eq("id", req.session.user.id).single();
    if (!user || !(await bcrypt.compare(currentPassword || "", user.password_hash))) {
        return res.status(401).json({ error: "current password is wrong" });
    }

    const hash = await bcrypt.hash(newPassword, 10);
    const { error } = await supabase.from("users").update({ password_hash: hash }).eq("id", user.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
});

app.get("/api/me", requireLogin, (req, res) => res.json(req.session.user));

app.get("/api/clients", requireLogin, async (req, res) => {
    res.json(await clientsVisibleTo(req.session.user));
});

// Owner-only team management -- lets Josh add people himself instead of
// coming to Jarvis every time. Generates a real random temp password,
// returned once in the response (never stored in plaintext, never logged)
// for Josh to relay. No auto-email yet -- that needs an SMTP credential
// that doesn't exist here yet, flagged honestly rather than faked.
app.get("/api/users", requireOwner, async (req, res) => {
    const { data: users, error } = await supabase.from("users").select("id, email, name, role, created_at");
    if (error) return res.status(500).json({ error: error.message });

    const { data: access } = await supabase.from("user_client_access").select("user_id, clients(slug, name)");
    const withAccess = users.map(u => ({
        ...u,
        clients: u.role === "owner" ? "all" : (access || []).filter(a => a.user_id === u.id).map(a => a.clients),
    }));
    res.json(withAccess);
});

app.post("/api/users", requireOwner, async (req, res) => {
    const { email, name, clientSlugs } = req.body;
    if (!email || !name || !Array.isArray(clientSlugs) || !clientSlugs.length) {
        return res.status(400).json({ error: "email, name, and at least one client are required" });
    }

    const tempPassword = crypto.randomBytes(9).toString("base64").replace(/[+/=]/g, "").slice(0, 12);
    const hash = await bcrypt.hash(tempPassword, 10);

    const { data: user, error: userErr } = await supabase.from("users").insert({
        email, name, role: "staff", password_hash: hash,
    }).select().single();
    if (userErr) return res.status(500).json({ error: userErr.message });

    const { data: clients } = await supabase.from("clients").select("id, slug").in("slug", clientSlugs);
    const accessRows = clients.map(c => ({ user_id: user.id, client_id: c.id }));
    const { error: accessErr } = await supabase.from("user_client_access").insert(accessRows);
    if (accessErr) return res.status(500).json({ error: accessErr.message });

    res.json({ ok: true, user, tempPassword });
});

// Replaces a staff member's whole set of company access in one shot --
// Josh checks/unchecks boxes for that person and hits save, this just makes
// the database match exactly what's checked. Owners aren't editable here --
// their role already sees everything regardless of this table.
app.put("/api/users/:id/access", requireOwner, async (req, res) => {
    const { clientSlugs } = req.body;
    if (!Array.isArray(clientSlugs)) return res.status(400).json({ error: "clientSlugs must be an array" });

    const { data: targetUser } = await supabase.from("users").select("id, role").eq("id", req.params.id).single();
    if (!targetUser) return res.status(404).json({ error: "not found" });
    if (targetUser.role === "owner") return res.status(400).json({ error: "owners already see everything" });

    const { error: delErr } = await supabase.from("user_client_access").delete().eq("user_id", targetUser.id);
    if (delErr) return res.status(500).json({ error: delErr.message });

    if (clientSlugs.length) {
        const { data: clients } = await supabase.from("clients").select("id, slug").in("slug", clientSlugs);
        const accessRows = clients.map(c => ({ user_id: targetUser.id, client_id: c.id }));
        const { error: insErr } = await supabase.from("user_client_access").insert(accessRows);
        if (insErr) return res.status(500).json({ error: insErr.message });
    }

    res.json({ ok: true });
});

// Owner-triggered reset for someone who lost/never got their temp password --
// doesn't need the old password, unlike the self-service change-password route.
app.post("/api/users/:id/reset-password", requireOwner, async (req, res) => {
    const { data: targetUser } = await supabase.from("users").select("id, email").eq("id", req.params.id).single();
    if (!targetUser) return res.status(404).json({ error: "not found" });

    const tempPassword = crypto.randomBytes(9).toString("base64").replace(/[+/=]/g, "").slice(0, 12);
    const hash = await bcrypt.hash(tempPassword, 10);
    const { error } = await supabase.from("users").update({ password_hash: hash }).eq("id", targetUser.id);
    if (error) return res.status(500).json({ error: error.message });

    res.json({ ok: true, tempPassword });
});

// Raw B-roll waiting for someone to turn it into a post, scoped to clients
// this user can actually see. Lightweight -- just how many per client, for
// the clickable client cards on the main page; the full list with playable
// video lives behind /api/clients/:slug/raw-media below.
app.get("/api/raw-media", requireLogin, async (req, res) => {
    const clients = await clientsVisibleTo(req.session.user);
    const clientIds = clients.map(c => c.id);
    const { data, error } = await supabase
        .from("raw_media")
        .select("client_id, clients(name, slug)")
        .in("client_id", clientIds);
    if (error) return res.status(500).json({ error: error.message });
    const counts = {};
    for (const row of data) {
        const slug = row.clients.slug;
        if (!counts[slug]) counts[slug] = { slug, name: row.clients.name, count: 0 };
        counts[slug].count++;
    }
    res.json(Object.values(counts));
});

// Full B-roll list for one client, with a signed URL per item so the video
// is actually playable -- the bucket is private, so a bare storage_path
// isn't a usable link on its own.
app.get("/api/clients/:slug/raw-media", requireLogin, async (req, res) => {
    const clients = await clientsVisibleTo(req.session.user);
    const client = clients.find(c => c.slug === req.params.slug);
    if (!client) return res.status(403).json({ error: "no access to this client" });

    const { data, error } = await supabase
        .from("raw_media")
        .select("*")
        .eq("client_id", client.id)
        .order("received_at", { ascending: false });
    if (error) return res.status(500).json({ error: error.message });

    const withUrls = await Promise.all(data.map(async (row) => {
        const { data: signed } = await supabase.storage
            .from("raw-media")
            .createSignedUrl(row.storage_path, 3600);
        return { ...row, url: signed ? signed.signedUrl : null };
    }));
    res.json({ client, media: withUrls });
});

// Deletes a raw B-roll clip for real -- the Storage file and the row both,
// not just hiding it. Re-checks client access on the row itself (not just
// trusting the slug in the URL) so a user can't delete footage for a client
// they aren't actually scoped to.
app.delete("/api/raw-media/:id", requireLogin, async (req, res) => {
    const clients = await clientsVisibleTo(req.session.user);
    const clientIds = clients.map(c => c.id);

    const { data: row, error: findErr } = await supabase
        .from("raw_media").select("*").eq("id", req.params.id).single();
    if (findErr || !row) return res.status(404).json({ error: "not found" });
    if (!clientIds.includes(row.client_id)) return res.status(403).json({ error: "no access to this client" });

    const { error: storageErr } = await supabase.storage.from("raw-media").remove([row.storage_path]);
    if (storageErr) return res.status(500).json({ error: "couldn't delete file: " + storageErr.message });

    const { error: dbErr } = await supabase.from("raw_media").delete().eq("id", row.id);
    if (dbErr) return res.status(500).json({ error: "couldn't delete record: " + dbErr.message });

    res.json({ ok: true });
});

// Turns a raw B-roll clip into an actual reviewable post. Generic across
// every client and every media type on purpose -- Josh was explicit that
// trim/crop/etc. have to be the same tool everywhere, not special-cased per
// company. No platform_account_id yet (nullable) since publishing is parked
// for now -- a post can sit in review before any platform is connected.
app.post("/api/raw-media/:id/create-post", requireLogin, async (req, res) => {
    const clients = await clientsVisibleTo(req.session.user);
    const clientIds = clients.map(c => c.id);

    const { data: row, error: findErr } = await supabase
        .from("raw_media").select("*").eq("id", req.params.id).single();
    if (findErr || !row) return res.status(404).json({ error: "not found" });
    if (!clientIds.includes(row.client_id)) return res.status(403).json({ error: "no access to this client" });

    const { data: post, error: insertErr } = await supabase.from("posts").insert({
        client_id: row.client_id,
        raw_media_id: row.id,
        caption_draft: null,
        status: "needs_review",
    }).select().single();
    if (insertErr) return res.status(500).json({ error: insertErr.message });

    res.json({ ok: true, post });
});

// The approval queue -- nothing here publishes until a human flips it to approved.
app.get("/api/posts", requireLogin, async (req, res) => {
    const clients = await clientsVisibleTo(req.session.user);
    const clientIds = clients.map(c => c.id);
    const { data, error } = await supabase
        .from("posts")
        .select("*, raw_media(storage_path, media_type), clients(name)")
        .in("client_id", clientIds)
        .order("created_at", { ascending: false });
    if (error) return res.status(500).json({ error: error.message });

    // A caption without the clip it goes with isn't reviewable -- sign the
    // URL here so the approval card can actually show the footage. Once a
    // post has a human-trimmed cut, that's what shows -- never the raw clip.
    const withUrls = await Promise.all(data.map(async (post) => {
        const showPath = post.finished_media_path || post.edited_media_path || (post.raw_media && post.raw_media.storage_path);
        if (!showPath) return post;
        const { data: signed } = await supabase.storage
            .from("raw-media")
            .createSignedUrl(showPath, 3600);
        return { ...post, media_url: signed ? signed.signedUrl : null };
    }));
    res.json(withUrls);
});

// Approve a draft -- logs who approved it, flips status, still doesn't
// publish on its own; the scheduler/publisher is a separate follow-up piece.
app.post("/api/posts/:id/approve", requireLogin, async (req, res) => {
    const { error } = await supabase
        .from("posts")
        .update({ status: "approved", approved_by: req.session.user.id })
        .eq("id", req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
});

// The human-judgment step: picking the section of raw footage that's
// actually usable, and cropping it, happens here -- before any automated
// overlay/hook work touches the clip. Trims via ffmpeg (already installed,
// no extra dependency), writes the cut to its own path so the original raw
// clip is never overwritten, and points the post at the cut via
// edited_media_path.
app.post("/api/posts/:id/trim", requireLogin, async (req, res) => {
    const { start, end, crop } = req.body; // start/end in seconds; crop: {x,y,w,h} in pixels, optional
    if (typeof start !== "number" || typeof end !== "number" || end <= start) {
        return res.status(400).json({ error: "start and end (seconds) are required, end must be after start" });
    }

    const { data: post, error: postErr } = await supabase
        .from("posts").select("*, raw_media(storage_path)").eq("id", req.params.id).single();
    if (postErr || !post) return res.status(404).json({ error: "post not found" });

    const { data: fileBlob, error: dlErr } = await supabase.storage
        .from("raw-media").download(post.raw_media.storage_path);
    if (dlErr) return res.status(500).json({ error: "couldn't fetch source clip: " + dlErr.message });

    const tmpIn = path.join(os.tmpdir(), `trim-in-${Date.now()}.mp4`);
    const tmpOut = path.join(os.tmpdir(), `trim-out-${Date.now()}.mp4`);
    fs.writeFileSync(tmpIn, Buffer.from(await fileBlob.arrayBuffer()));

    const args = ["-y", "-i", tmpIn, "-ss", String(start), "-to", String(end)];
    if (crop && crop.w && crop.h) {
        args.push("-vf", `crop=${crop.w}:${crop.h}:${crop.x || 0}:${crop.y || 0}`);
    }
    args.push("-c:v", "libx264", "-c:a", "aac", tmpOut);

    try {
        await execFileAsync(FFMPEG_BIN, args);
    } catch (e) {
        fs.unlinkSync(tmpIn);
        return res.status(500).json({ error: "ffmpeg failed: " + e.message });
    }

    const editedPath = `${post.client_id}/edited/${post.id}.mp4`;
    const { error: upErr } = await supabase.storage
        .from("raw-media").upload(editedPath, fs.readFileSync(tmpOut), { upsert: true });
    fs.unlinkSync(tmpIn);
    fs.unlinkSync(tmpOut);
    if (upErr) return res.status(500).json({ error: "upload failed: " + upErr.message });

    await supabase.from("posts").update({ edited_media_path: editedPath }).eq("id", post.id);

    const { data: signed } = await supabase.storage.from("raw-media").createSignedUrl(editedPath, 3600);
    res.json({ ok: true, url: signed ? signed.signedUrl : null });
});

// The photo equivalent of trim, above -- same human-picks-the-section idea,
// just spatial instead of time-based. Generic across every client, same as
// trim: this is the one tool every image post uses, not an Axion-Pept-only
// feature. Uses the same ffmpeg binary rather than a separate image library.
app.post("/api/posts/:id/crop-image", requireLogin, async (req, res) => {
    const { x, y, w, h } = req.body;
    if ([x, y, w, h].some(v => typeof v !== "number") || w <= 0 || h <= 0) {
        return res.status(400).json({ error: "x, y, w, h (all numbers) are required" });
    }

    const { data: post, error: postErr } = await supabase
        .from("posts").select("*, raw_media(storage_path, media_type)").eq("id", req.params.id).single();
    if (postErr || !post) return res.status(404).json({ error: "post not found" });
    if (post.raw_media.media_type !== "image") return res.status(400).json({ error: "this post's media isn't an image" });

    const { data: fileBlob, error: dlErr } = await supabase.storage
        .from("raw-media").download(post.raw_media.storage_path);
    if (dlErr) return res.status(500).json({ error: "couldn't fetch source image: " + dlErr.message });

    const tmpIn = path.join(os.tmpdir(), `crop-in-${Date.now()}.jpg`);
    const tmpOut = path.join(os.tmpdir(), `crop-out-${Date.now()}.jpg`);
    fs.writeFileSync(tmpIn, Buffer.from(await fileBlob.arrayBuffer()));

    try {
        await execFileAsync(FFMPEG_BIN, ["-y", "-i", tmpIn, "-vf", `crop=${w}:${h}:${x}:${y}`, tmpOut]);
    } catch (e) {
        fs.unlinkSync(tmpIn);
        return res.status(500).json({ error: "ffmpeg failed: " + e.message });
    }

    const editedPath = `${post.client_id}/edited/${post.id}.jpg`;
    const { error: upErr } = await supabase.storage
        .from("raw-media").upload(editedPath, fs.readFileSync(tmpOut), { upsert: true });
    fs.unlinkSync(tmpIn);
    fs.unlinkSync(tmpOut);
    if (upErr) return res.status(500).json({ error: "upload failed: " + upErr.message });

    await supabase.from("posts").update({ edited_media_path: editedPath }).eq("id", post.id);

    const { data: signed } = await supabase.storage.from("raw-media").createSignedUrl(editedPath, 3600);
    res.json({ ok: true, url: signed ? signed.signedUrl : null });
});

// Escapes a string for ffmpeg's drawtext filter, which treats \, : and '
// as control characters in the filter graph syntax -- not shell escaping,
// this is a different, narrower rule.
function escapeDrawtext(text) {
    return text.replace(/\\/g, "\\\\").replace(/:/g, "\\:").replace(/'/g, "\u2019");
}

const HOOK_FONT = "/System/Library/Fonts/Supplemental/Arial Bold.ttf";

// Greedy word-wrap so the hook text actually fits the frame instead of
// running off both edges -- the bug seen on the first real test. maxChars
// is an estimate (bold sans-serif averages ~0.58x fontsize px per char).
function wrapText(text, maxChars) {
    const words = text.split(" ");
    const lines = [];
    let line = "";
    for (const w of words) {
        const candidate = line ? `${line} ${w}` : w;
        if (candidate.length > maxChars && line) {
            lines.push(line);
            line = w;
        } else {
            line = candidate;
        }
    }
    if (line) lines.push(line);
    return lines;
}

// Burns the hook line onto the clip for real -- the automated step Josh
// asked for, picking up wherever the human-trim step (above) left off.
// Operates on edited_media_path if a trim exists, otherwise the raw clip.
// mute (boolean, Josh's per-post choice, not a hardcoded default) strips
// audio when true; false keeps the clip's original audio track.
app.post("/api/posts/:id/finish", requireLogin, async (req, res) => {
    const { overlayText, mute, backgroundAudioExampleId } = req.body;
    if (!overlayText || !overlayText.trim()) return res.status(400).json({ error: "overlayText is required" });

    const { data: post, error: postErr } = await supabase
        .from("posts").select("*, raw_media(storage_path)").eq("id", req.params.id).single();
    if (postErr || !post) return res.status(404).json({ error: "post not found" });

    // Optional licensed background music, mixed in via ffmpeg -- the track
    // itself just needs to be sitting in the Learning library (Josh uploads
    // his own properly-licensed files there, e.g. from Artlist). Scoped to
    // clients this user can see, same access rule as every other Learning
    // read, and must actually be an audio-type example, not a video/image/text one.
    let bgAudioTmp = null;
    if (backgroundAudioExampleId) {
        const clients = await clientsVisibleTo(req.session.user);
        const clientIds = clients.map(c => c.id);
        const { data: audioEx, error: audioErr } = await supabase
            .from("example_media").select("*").eq("id", backgroundAudioExampleId).single();
        if (audioErr || !audioEx) return res.status(404).json({ error: "background audio not found" });
        if (audioEx.media_type !== "audio") return res.status(400).json({ error: "that Learning item isn't an audio file" });
        if (!clientIds.includes(audioEx.client_id)) return res.status(403).json({ error: "no access to that company's Learning library" });

        const { data: audioBlob, error: dlAudioErr } = await supabase.storage.from("learning-examples").download(audioEx.storage_path);
        if (dlAudioErr) return res.status(500).json({ error: "couldn't fetch background audio: " + dlAudioErr.message });
        bgAudioTmp = path.join(os.tmpdir(), `finish-bgaudio-${Date.now()}.mp3`);
        fs.writeFileSync(bgAudioTmp, Buffer.from(await audioBlob.arrayBuffer()));
    }

    const sourcePath = post.edited_media_path || post.raw_media.storage_path;
    const { data: fileBlob, error: dlErr } = await supabase.storage.from("raw-media").download(sourcePath);
    if (dlErr) {
        if (bgAudioTmp) fs.unlinkSync(bgAudioTmp);
        return res.status(500).json({ error: "couldn't fetch source clip: " + dlErr.message });
    }

    const tmpIn = path.join(os.tmpdir(), `finish-in-${Date.now()}.mp4`);
    const tmpOut = path.join(os.tmpdir(), `finish-out-${Date.now()}.mp4`);
    fs.writeFileSync(tmpIn, Buffer.from(await fileBlob.arrayBuffer()));

    // Phone video frequently carries a rotation tag (e.g. shot in portrait,
    // stored as landscape pixels with rotate=-90) -- ffmpeg auto-rotates on
    // decode, so drawtext actually draws onto the DISPLAYED frame, not the
    // coded one. Reading just stream=width here was the root cause of the
    // real overflow bug: a 1024x576-coded, rotate=-90 clip displays at
    // 576 wide, but the naive probe reported 1024 and sized text for that.
    const { stdout: probeOut } = await execFileAsync(FFPROBE_BIN,
        ["-v", "error", "-select_streams", "v:0",
         "-show_entries", "stream=width,height,duration:stream_side_data=rotation:format=duration",
         "-of", "json", tmpIn]);
    const probeData = JSON.parse(probeOut);
    const stream = probeData.streams[0];
    const rotation = stream.side_data_list && stream.side_data_list[0] ? stream.side_data_list[0].rotation : 0;
    const rotated90 = Math.abs(rotation) === 90 || Math.abs(rotation) === 270;
    const width = (rotated90 ? stream.height : stream.width) || 1080;
    // Stream-level duration is sometimes missing (container-dependent) --
    // fall back to the format-level one, which is always present.
    const videoDuration = parseFloat(stream.duration || probeData.format.duration);

    const fontsize = Math.max(22, Math.min(48, Math.round(width / 16)));
    const maxChars = Math.floor(width / (fontsize * 0.58));
    const wrapped = wrapText(overlayText.trim(), maxChars).join("\n");

    // Held for the full video now, per Josh 2026-10-19 -- was originally
    // just the first 2.5s matching the reel concepts' "hook, first 2 seconds"
    // spec, but he wants the text staying up the whole time instead.
    //
    // Style redesigned 2026-10-12 per Josh ("not just a black box, something
    // that stands out") and real research on what actually reads on short-form
    // video: white fill is the safest universal contrast, but a flat box read
    // as generic. Swapped the box for a thick colored stroke (construction
    // orange -- fits this content specifically) plus a drop shadow, which is
    // the most consistently recommended "produced" look across sources and
    // still passes the "readable on the worst frame" test a flat box can fail.
    const HOOK_ACCENT_COLOR = "0xFF6A00"; // construction-cone orange
    const drawtext = `drawtext=fontfile='${HOOK_FONT}':text='${escapeDrawtext(wrapped)}':`
        + `fontsize=${fontsize}:fontcolor=white:bordercolor=${HOOK_ACCENT_COLOR}:borderw=5:`
        + `shadowcolor=black@0.7:shadowx=2:shadowy=2:line_spacing=8:`
        + `x=(w-text_w)/2:y=h*0.12`;

    // Four real cases: with/without a background track, muted or not. Once a
    // second input (the background track) is involved, drawtext has to move
    // into a -filter_complex graph with explicit labeled outputs -- can't mix
    // a plain -vf with a second -i the simple way the no-track case used.
    let ffmpegArgs;
    if (bgAudioTmp) {
        const audioGraph = mute
            // Muted original + background track as the only audio.
            ? `[1:a]anull[aout]`
            // Original audio kept, background mixed in underneath at reduced
            // volume so it doesn't bury spoken audio -- duration=first stops
            // the mix at the video's own length rather than running the full
            // length of the music track.
            : `[1:a]volume=0.2[bg];[0:a][bg]amix=inputs=2:duration=first:dropout_transition=2[aout]`;
        // -shortest doesn't reliably stop the mux here -- the background
        // track's audio pad (anull/amix) never gets an EOF tied to the video
        // stream, so it was encoding the FULL track length regardless of how
        // long the video actually is. -t with the real probed duration is
        // the hard, deterministic cutoff; -shortest stays as a backstop.
        ffmpegArgs = [
            "-y", "-i", tmpIn, "-i", bgAudioTmp,
            "-filter_complex", `[0:v]${drawtext}[vout];${audioGraph}`,
            "-map", "[vout]", "-map", "[aout]",
            "-c:v", "libx264", "-c:a", "aac", "-t", String(videoDuration), "-shortest", tmpOut,
        ];
    } else {
        const audioArgs = mute ? ["-an"] : ["-c:a", "aac"];
        ffmpegArgs = ["-y", "-i", tmpIn, "-vf", drawtext, "-c:v", "libx264", ...audioArgs, tmpOut];
    }

    try {
        await execFileAsync(FFMPEG_BIN, ffmpegArgs);
    } catch (e) {
        fs.unlinkSync(tmpIn);
        if (bgAudioTmp) fs.unlinkSync(bgAudioTmp);
        return res.status(500).json({ error: "ffmpeg failed: " + e.message });
    }
    if (bgAudioTmp) fs.unlinkSync(bgAudioTmp);

    const finishedPath = `${post.client_id}/finished/${post.id}.mp4`;
    const { error: upErr } = await supabase.storage
        .from("raw-media").upload(finishedPath, fs.readFileSync(tmpOut), { upsert: true });
    fs.unlinkSync(tmpIn);
    fs.unlinkSync(tmpOut);
    if (upErr) return res.status(500).json({ error: "upload failed: " + upErr.message });

    await supabase.from("posts")
        .update({ finished_media_path: finishedPath, overlay_text: overlayText.trim(), background_audio_example_id: backgroundAudioExampleId || null })
        .eq("id", post.id);

    const { data: signed } = await supabase.storage.from("raw-media").createSignedUrl(finishedPath, 3600);
    res.json({ ok: true, url: signed ? signed.signedUrl : null });
});

// Learning examples -- reference/inspiration videos Josh uploads for Jarvis
// to actually study (frames + audio), not tied to any one client. Separate
// bucket and table from raw_media on purpose: this isn't footage to post,
// it's material to learn from, visible to every logged-in user regardless
// of which clients they're scoped to.
const exampleUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 500 * 1024 * 1024 } });

app.get("/api/examples", requireLogin, async (req, res) => {
    const clients = await clientsVisibleTo(req.session.user);
    const clientIds = clients.map(c => c.id);

    const { data, error } = await supabase
        .from("example_media").select("*, clients(name, slug)")
        .in("client_id", clientIds)
        .order("uploaded_at", { ascending: false });
    if (error) return res.status(500).json({ error: error.message });

    const withUrls = await Promise.all(data.map(async (row) => {
        if (!row.storage_path) return { ...row, url: null };
        const { data: signed } = await supabase.storage
            .from("learning-examples").createSignedUrl(row.storage_path, 3600);
        return { ...row, url: signed ? signed.signedUrl : null };
    }));
    res.json(withUrls);
});

// Checks the posted clientId against clients THIS user can actually see --
// never trust a slug/id from the request body alone, same pattern as every
// other client-scoped route in this file.
async function resolveAllowedClient(user, clientId) {
    const clients = await clientsVisibleTo(user);
    return clients.find(c => c.id === clientId) || null;
}

app.post("/api/examples/upload", requireLogin, exampleUpload.single("file"), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "no file uploaded" });
    const client = await resolveAllowedClient(req.session.user, req.body.clientId);
    if (!client) return res.status(400).json({ error: "pick a valid company" });

    const isVideo = req.file.mimetype.startsWith("video/");
    const isImage = req.file.mimetype.startsWith("image/");
    const isAudio = req.file.mimetype.startsWith("audio/");
    if (!isVideo && !isImage && !isAudio) return res.status(400).json({ error: "only video, image, or audio files" });

    const ext = path.extname(req.file.originalname) || (isVideo ? ".mp4" : isAudio ? ".m4a" : ".jpg");
    const storagePath = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}${ext}`;

    const { error: upErr } = await supabase.storage
        .from("learning-examples").upload(storagePath, req.file.buffer, { contentType: req.file.mimetype });
    if (upErr) return res.status(500).json({ error: "upload failed: " + upErr.message });

    const { data: row, error: dbErr } = await supabase.from("example_media").insert({
        client_id: client.id,
        storage_path: storagePath,
        media_type: isVideo ? "video" : isAudio ? "audio" : "image",
        original_filename: req.file.originalname,
        uploaded_by: req.session.user.id,
    }).select().single();
    if (dbErr) return res.status(500).json({ error: dbErr.message });

    res.json({ ok: true, example: row });
});

// Standing instructions typed directly in -- "use this logo," "stop doing X."
// No file, so reviewed_at is set immediately: there's nothing for Jarvis to
// study, the typed text already IS the directive. draftCaption() below pulls
// every one of these in on every single caption draft, unconditionally.
app.post("/api/examples/text-note", requireLogin, async (req, res) => {
    const text = (req.body.text || "").trim();
    if (!text) return res.status(400).json({ error: "no text provided" });
    const client = await resolveAllowedClient(req.session.user, req.body.clientId);
    if (!client) return res.status(400).json({ error: "pick a valid company" });

    const { data: row, error: dbErr } = await supabase.from("example_media").insert({
        client_id: client.id,
        media_type: "text",
        instruction_text: text,
        uploaded_by: req.session.user.id,
        reviewed_at: new Date().toISOString(),
    }).select().single();
    if (dbErr) return res.status(500).json({ error: dbErr.message });

    res.json({ ok: true, example: row });
});

app.post("/api/examples/:id/notes", requireLogin, async (req, res) => {
    const { notes } = req.body;
    const { error } = await supabase.from("example_media")
        .update({ notes, reviewed_at: new Date().toISOString() })
        .eq("id", req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
});

app.delete("/api/examples/:id", requireLogin, async (req, res) => {
    const { data: row, error: findErr } = await supabase
        .from("example_media").select("*").eq("id", req.params.id).single();
    if (findErr || !row) return res.status(404).json({ error: "not found" });

    if (row.storage_path) {
        const { error: storageErr } = await supabase.storage.from("learning-examples").remove([row.storage_path]);
        if (storageErr) return res.status(500).json({ error: "couldn't delete file: " + storageErr.message });
    }

    const { error: dbErr } = await supabase.from("example_media").delete().eq("id", row.id);
    if (dbErr) return res.status(500).json({ error: dbErr.message });
    res.json({ ok: true });
});

// Concepts -- hook/video ideas, scoped per company like Learning. A concept
// can get a video attached two ways: Josh uploads one himself (a screen
// recording, a found clip, whatever), or -- once a stock-footage API key
// exists -- Jarvis searches a real royalty-free library and Josh picks a
// result. No API key configured yet; find-footage is wired to say so plainly
// rather than pretend to work.
const conceptUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 500 * 1024 * 1024 } });

app.get("/api/concepts", requireLogin, async (req, res) => {
    const clients = await clientsVisibleTo(req.session.user);
    const clientIds = clients.map(c => c.id);

    const { data, error } = await supabase
        .from("concepts").select("*, clients(name, slug)")
        .in("client_id", clientIds)
        .order("created_at", { ascending: false });
    if (error) return res.status(500).json({ error: error.message });

    const withUrls = await Promise.all(data.map(async (row) => {
        if (!row.matched_video_path) return { ...row, url: null };
        const { data: signed } = await supabase.storage
            .from("concept-media").createSignedUrl(row.matched_video_path, 3600);
        return { ...row, url: signed ? signed.signedUrl : null };
    }));
    res.json(withUrls);
});

app.post("/api/concepts", requireLogin, async (req, res) => {
    const text = (req.body.text || "").trim();
    if (!text) return res.status(400).json({ error: "no text provided" });
    const client = await resolveAllowedClient(req.session.user, req.body.clientId);
    if (!client) return res.status(400).json({ error: "pick a valid company" });

    const { data: row, error: dbErr } = await supabase.from("concepts").insert({
        client_id: client.id,
        text,
        created_by: req.session.user.id,
    }).select().single();
    if (dbErr) return res.status(500).json({ error: dbErr.message });

    res.json({ ok: true, concept: row });
});

// Record-and-transcribe: Josh talks instead of typing. Audio never gets
// Shared by /api/concepts/record and /api/transcribe-only below. Runs
// through OpenAI's hosted Whisper API, not a local model -- the local
// mlx-whisper path (same one the WhatsApp bot uses) only exists on Josh's
// own Mac, so it hard-failed for anyone using the deployed site from
// anywhere else (confirmed with a real test against production: ENOENT).
// Audio is sent for transcription only, never written to Storage or kept.
async function transcribeAudioBuffer(buffer) {
    const form = new FormData();
    form.append("file", new Blob([buffer]), "recording.webm");
    form.append("model", "whisper-1");
    const resp = await fetch("https://api.openai.com/v1/audio/transcriptions", {
        method: "POST",
        headers: { "Authorization": `Bearer ${process.env.OPENAI_API_KEY}` },
        body: form,
    });
    const data = await resp.json();
    if (data.error) throw new Error(data.error.message);
    return data.text;
}

app.post("/api/concepts/record", requireLogin, conceptUpload.single("file"), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "no audio uploaded" });
    const client = await resolveAllowedClient(req.session.user, req.body.clientId);
    if (!client) return res.status(400).json({ error: "pick a valid company" });

    let text;
    try {
        text = await transcribeAudioBuffer(req.file.buffer);
    } catch (e) {
        return res.status(500).json({ error: "transcription failed: " + e.message });
    }
    if (!text || !text.trim()) return res.status(400).json({ error: "couldn't make out any speech in that recording" });

    const { data: row, error: dbErr } = await supabase.from("concepts").insert({
        client_id: client.id,
        text: text.trim(),
        created_by: req.session.user.id,
    }).select().single();
    if (dbErr) return res.status(500).json({ error: dbErr.message });

    res.json({ ok: true, concept: row });
});

// Used by the "find footage" search box's mic button -- just returns text,
// doesn't create anything. Reuses the same transcription path as above.
app.post("/api/transcribe-only", requireLogin, conceptUpload.single("file"), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "no audio uploaded" });
    let text;
    try {
        text = await transcribeAudioBuffer(req.file.buffer);
    } catch (e) {
        return res.status(500).json({ error: "transcription failed: " + e.message });
    }
    if (!text || !text.trim()) return res.status(400).json({ error: "couldn't make out any speech in that recording" });
    res.json({ text: text.trim() });
});

app.post("/api/concepts/:id/upload-video", requireLogin, conceptUpload.single("file"), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "no file uploaded" });
    if (!req.file.mimetype.startsWith("video/")) return res.status(400).json({ error: "video files only" });

    const clients = await clientsVisibleTo(req.session.user);
    const clientIds = clients.map(c => c.id);
    const { data: concept, error: findErr } = await supabase
        .from("concepts").select("*").eq("id", req.params.id).single();
    if (findErr || !concept) return res.status(404).json({ error: "not found" });
    if (!clientIds.includes(concept.client_id)) return res.status(403).json({ error: "no access to this company" });

    const ext = path.extname(req.file.originalname) || ".mp4";
    const storagePath = `${concept.id}-${Date.now()}${ext}`;
    const { error: upErr } = await supabase.storage
        .from("concept-media").upload(storagePath, req.file.buffer, { contentType: req.file.mimetype, upsert: true });
    if (upErr) return res.status(500).json({ error: "upload failed: " + upErr.message });

    const { error: dbErr } = await supabase.from("concepts")
        .update({ matched_video_path: storagePath, matched_media_type: "video", matched_video_source: "upload" })
        .eq("id", concept.id);
    if (dbErr) return res.status(500).json({ error: dbErr.message });

    res.json({ ok: true });
});

// Attaches an existing B-roll clip (already sitting in raw_media from
// WhatsApp intake) to a concept instead of uploading something new. Copies
// the file into concept-media rather than just pointing at raw_media's
// path, same reasoning as everywhere else in this build: if the original
// raw_media item later gets deleted, the concept's copy is unaffected.
app.post("/api/concepts/:id/attach-raw-media", requireLogin, async (req, res) => {
    const { rawMediaId } = req.body;
    if (!rawMediaId) return res.status(400).json({ error: "rawMediaId required" });

    const clients = await clientsVisibleTo(req.session.user);
    const clientIds = clients.map(c => c.id);

    const { data: concept, error: cErr } = await supabase
        .from("concepts").select("*").eq("id", req.params.id).single();
    if (cErr || !concept) return res.status(404).json({ error: "concept not found" });
    if (!clientIds.includes(concept.client_id)) return res.status(403).json({ error: "no access to this company" });

    const { data: raw, error: rErr } = await supabase
        .from("raw_media").select("*").eq("id", rawMediaId).single();
    if (rErr || !raw) return res.status(404).json({ error: "raw media not found" });
    if (raw.client_id !== concept.client_id) return res.status(400).json({ error: "that clip belongs to a different company than this concept" });

    const { data: fileBlob, error: dlErr } = await supabase.storage.from("raw-media").download(raw.storage_path);
    if (dlErr) return res.status(500).json({ error: "couldn't pull the clip: " + dlErr.message });

    const ext = path.extname(raw.storage_path) || (raw.media_type === "video" ? ".mp4" : ".jpg");
    const storagePath = `${concept.id}-${Date.now()}${ext}`;
    const buffer = Buffer.from(await fileBlob.arrayBuffer());
    const { error: upErr } = await supabase.storage
        .from("concept-media").upload(storagePath, buffer, { contentType: fileBlob.type, upsert: true });
    if (upErr) return res.status(500).json({ error: "upload failed: " + upErr.message });

    const { error: dbErr } = await supabase.from("concepts")
        .update({ matched_video_path: storagePath, matched_media_type: raw.media_type, matched_video_source: "raw-media" })
        .eq("id", concept.id);
    if (dbErr) return res.status(500).json({ error: dbErr.message });

    res.json({ ok: true });
});

// Turns a concept's hook text (often a narrative headline, not a literal
// visual description -- "The Locate Ticket That Never Got Called" isn't
// something a stock library can search on) into real search keywords.
// Same claude-CLI pattern as the WhatsApp bot's translation, cheap tier.
async function deriveSearchKeywords(conceptText) {
    const prompt = `Extract 3-6 concise, literal, visual search keywords for finding stock video footage that matches this video concept. Think about what would actually be ON SCREEN, not the headline/angle. Respond with ONLY the keywords, space-separated, nothing else -- no explanation, no punctuation beyond spaces.

Concept: "${conceptText}"`;
    try {
        const { stdout } = await execFileAsync("claude", [
            "-p", prompt, "--output-format", "json", "--permission-prompts", "none", "--model", "claude-haiku-5-5",
        ], { cwd: "/Users/h/my-agent", encoding: "utf8", maxBuffer: 2 * 1024 * 1024, timeout: 20000 });
        const parsed = JSON.parse(stdout.trim().split("\n").pop());
        return (parsed.result || "").trim();
    } catch (e) {
        return conceptText; // fall back to the raw text rather than fail the whole search
    }
}

// Search only -- returns candidates, doesn't download or attach anything.
// Picking happens separately via pick-footage, same human-approval pattern
// as everything else in this dashboard (nothing gets attached without a
// deliberate click).
app.post("/api/concepts/:id/find-footage", requireLogin, async (req, res) => {
    if (!process.env.PIXABAY_API_KEY) {
        return res.status(501).json({ error: "No Pixabay API key configured on the server yet." });
    }
    const clients = await clientsVisibleTo(req.session.user);
    const clientIds = clients.map(c => c.id);
    const { data: concept, error: cErr } = await supabase
        .from("concepts").select("*").eq("id", req.params.id).single();
    if (cErr || !concept) return res.status(404).json({ error: "not found" });
    if (!clientIds.includes(concept.client_id)) return res.status(403).json({ error: "no access to this company" });

    const typedQuery = (req.body.query || "").trim();
    const query = typedQuery || await deriveSearchKeywords(concept.text);

    const url = `https://pixabay.com/api/videos/?key=${process.env.PIXABAY_API_KEY}&q=${encodeURIComponent(query)}&per_page=8&safesearch=true`;
    let pixabayData;
    try {
        const resp = await fetch(url);
        pixabayData = await resp.json();
    } catch (e) {
        return res.status(500).json({ error: "search request failed: " + e.message });
    }
    if (pixabayData.error) return res.status(500).json({ error: "Pixabay error: " + pixabayData.error });

    const results = (pixabayData.hits || []).map(h => ({
        id: h.id,
        tags: h.tags,
        thumbnail: h.videos.tiny.thumbnail,
        previewUrl: h.videos.tiny.url,
        downloadUrl: h.videos.medium ? h.videos.medium.url : h.videos.small.url,
    }));
    res.json({ query, results });
});

// The actual attach step -- downloads the picked Pixabay clip and copies it
// into concept-media, same pattern as upload and attach-raw-media.
app.post("/api/concepts/:id/pick-footage", requireLogin, async (req, res) => {
    const { downloadUrl, pixabayId } = req.body;
    if (!downloadUrl) return res.status(400).json({ error: "downloadUrl required" });

    const clients = await clientsVisibleTo(req.session.user);
    const clientIds = clients.map(c => c.id);
    const { data: concept, error: cErr } = await supabase
        .from("concepts").select("*").eq("id", req.params.id).single();
    if (cErr || !concept) return res.status(404).json({ error: "not found" });
    if (!clientIds.includes(concept.client_id)) return res.status(403).json({ error: "no access to this company" });

    let buffer;
    try {
        const resp = await fetch(downloadUrl);
        buffer = Buffer.from(await resp.arrayBuffer());
    } catch (e) {
        return res.status(500).json({ error: "couldn't download the clip: " + e.message });
    }

    const storagePath = `${concept.id}-${Date.now()}-pixabay${pixabayId || ""}.mp4`;
    const { error: upErr } = await supabase.storage
        .from("concept-media").upload(storagePath, buffer, { contentType: "video/mp4", upsert: true });
    if (upErr) return res.status(500).json({ error: "upload failed: " + upErr.message });

    const { error: dbErr } = await supabase.from("concepts")
        .update({ matched_video_path: storagePath, matched_media_type: "video", matched_video_source: "pixabay" })
        .eq("id", concept.id);
    if (dbErr) return res.status(500).json({ error: dbErr.message });

    res.json({ ok: true });
});

// Durable context baked into the deployed code rather than read from Josh's
// vault -- the vault only exists on his own Mac, Render can't see it (same
// lesson as the transcription bug). These are condensed, faithful copies of
// what's already written in the vault's research notes; update both places
// together if the source material changes.
const SHARED_PERFORMANCE_LEARNINGS = `The first ~2 seconds decide whether someone keeps watching -- bold claims, questions, and "did you know" framing outperform generic openers. Watch time and completion are the top-weighted ranking signals on Instagram and TikTok, not likes -- shares/saves outweigh likes too. Short wins: most high performers land in the 20-40s range. For trades content specifically: real crew/jobsite footage consistently beats anything polished or stock, before-and-afters and problem-then-fix narratives perform well. Numbered-list hooks ("5 Things That Actually Cause X") are a strong, proven format for this account -- but a hook that never resolves on-screen (pure "check the caption" payoff) fights against watch-time being the top signal.`;

const CLIENT_MARKETING_CONTEXT = {
    "811-assist": `811 Assist sells certainty that you're covered, not ticket-management software -- the relief of being able to prove what you knew and when, so a crew member isn't eating the cost of an unmarked line. Emotional subject of content: the field crew. Actual buyer: the business owner/office manager worried about liability exposure. Real angles already validated: cost-of-damage stats (CGA's $83B/year figure made personal), the "86% of damage has 3 root causes" DIRT data (no ticket / invalid ticket / incorrect ticket), industry-neglect framing (conference spending vs. tool spending), and honest case-study angles. Always point toward the idea of proof/certainty, never generic "sign up" language.`,
    "axion-pept": `Axion Pept sells trust and verification in a category where generic "third-party tested" claims are common and often thin. Real validated angles: named-lab, lot-number-specific COA verification (the actual differentiator competitors lack), responsiveness to verification requests, and the loyalty/subscription gap nobody in the category has filled. HARD COMPLIANCE RULE, never break it: research-use framing only -- zero dosing-for-consumer language, zero before/after claims, zero therapeutic or performance claims, nothing implying human use. This is the single biggest compliance risk in this category (FDA attention specifically targets coded consumer-use language), so every concept must read as "how to evaluate a supplier," never "what this does for you."`,
};

// Pulls durable context (above) + this client's standing Learning
// instructions (database, so it works from Render regardless of who's
// logged in) + existing concepts (to avoid writing duplicates), then asks
// Claude for N new ones and inserts them for real -- same automated
// pattern as translation and the email check, cheap Haiku tier.
app.post("/api/concepts/generate", requireLogin, async (req, res) => {
    const client = await resolveAllowedClient(req.session.user, req.body.clientId);
    if (!client) return res.status(400).json({ error: "pick a valid company" });
    const count = Math.min(Math.max(parseInt(req.body.count, 10) || 5, 1), 12);

    const { data: instructions } = await supabase.from("example_media")
        .select("instruction_text").eq("client_id", client.id).eq("media_type", "text");
    const { data: existing } = await supabase.from("concepts")
        .select("text").eq("client_id", client.id);

    const marketingContext = CLIENT_MARKETING_CONTEXT[client.slug] || "(no dedicated marketing plan written yet for this company -- stay general and factual.)";
    const standingInstructions = (instructions || []).map(i => `- ${i.instruction_text}`).join("\n") || "(none yet)";
    const existingHooks = (existing || []).map(c => `- ${c.text.slice(0, 80)}`).join("\n") || "(none yet)";

    const prompt = `You're writing ${count} new short-form video hook/concept ideas for ${client.name}'s social content. Each one should be a single paragraph: a specific, curiosity-driven hook line plus a one-sentence description of the concept/angle. Ground every idea in the real context below -- don't invent generic marketing fluff.

What's proven to work on social generally:
${SHARED_PERFORMANCE_LEARNINGS}

This company's actual marketing/brand context:
${marketingContext}

Standing rules this company has set (never violate these):
${standingInstructions}

Hooks that already exist -- do NOT repeat these angles, write genuinely different ones:
${existingHooks}

Respond with ONLY the ${count} new concepts, one per line, nothing else -- no numbering, no headers, no explanation.`;

    let lines;
    try {
        const { stdout } = await execFileAsync("claude", [
            "-p", prompt, "--output-format", "json", "--permission-prompts", "none", "--model", "claude-haiku-5-5",
        ], { cwd: "/Users/h/my-agent", encoding: "utf8", maxBuffer: 2 * 1024 * 1024, timeout: 45000 });
        const parsed = JSON.parse(stdout.trim().split("\n").pop());
        lines = (parsed.result || "").trim().split("\n").map(l => l.trim()).filter(Boolean);
    } catch (e) {
        return res.status(500).json({ error: "generation failed: " + e.message });
    }

    const inserted = [];
    for (const text of lines) {
        const { data: row, error } = await supabase.from("concepts").insert({
            client_id: client.id, text, created_by: req.session.user.id,
        }).select().single();
        if (!error) inserted.push(row);
    }
    res.json({ ok: true, concepts: inserted });
});

app.put("/api/concepts/:id", requireLogin, async (req, res) => {
    const text = (req.body.text || "").trim();
    if (!text) return res.status(400).json({ error: "text can't be empty" });

    const clients = await clientsVisibleTo(req.session.user);
    const clientIds = clients.map(c => c.id);
    const { data: concept, error: findErr } = await supabase
        .from("concepts").select("*").eq("id", req.params.id).single();
    if (findErr || !concept) return res.status(404).json({ error: "not found" });
    if (!clientIds.includes(concept.client_id)) return res.status(403).json({ error: "no access to this company" });

    const { error: dbErr } = await supabase.from("concepts").update({ text }).eq("id", concept.id);
    if (dbErr) return res.status(500).json({ error: dbErr.message });
    res.json({ ok: true });
});

app.delete("/api/concepts/:id", requireLogin, async (req, res) => {
    const clients = await clientsVisibleTo(req.session.user);
    const clientIds = clients.map(c => c.id);
    const { data: concept, error: findErr } = await supabase
        .from("concepts").select("*").eq("id", req.params.id).single();
    if (findErr || !concept) return res.status(404).json({ error: "not found" });
    if (!clientIds.includes(concept.client_id)) return res.status(403).json({ error: "no access to this company" });

    if (concept.matched_video_path) {
        await supabase.storage.from("concept-media").remove([concept.matched_video_path]);
    }
    const { error: dbErr } = await supabase.from("concepts").delete().eq("id", concept.id);
    if (dbErr) return res.status(500).json({ error: dbErr.message });
    res.json({ ok: true });
});

// Calendar -- scheduling, not publishing. A post (already approved/finished)
// gets a date, a time, and a set of platforms checked -- one row per
// platform, matching the real-world shape of a multi-platform publish job
// even though the actual publish step itself is still parked.
app.get("/api/scheduled-posts", requireLogin, async (req, res) => {
    const clients = await clientsVisibleTo(req.session.user);
    const clientIds = clients.map(c => c.id);

    const { data, error } = await supabase
        .from("scheduled_posts")
        .select("*, clients(name, slug), posts(caption_draft, caption_final, finished_media_path, edited_media_path, raw_media_id)")
        .in("client_id", clientIds)
        .order("scheduled_date", { ascending: true });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

app.post("/api/scheduled-posts", requireLogin, async (req, res) => {
    const { postId, date, time, platforms } = req.body;
    if (!postId || !date || !time || !Array.isArray(platforms) || !platforms.length) {
        return res.status(400).json({ error: "postId, date, time, and at least one platform are required" });
    }

    const { data: post, error: postErr } = await supabase
        .from("posts").select("id, client_id").eq("id", postId).single();
    if (postErr || !post) return res.status(404).json({ error: "post not found" });

    const clients = await clientsVisibleTo(req.session.user);
    const clientIds = clients.map(c => c.id);
    if (!clientIds.includes(post.client_id)) return res.status(403).json({ error: "no access to this company" });

    const rows = platforms.map(platform => ({
        post_id: post.id, client_id: post.client_id, scheduled_date: date,
        scheduled_time: time, platform, created_by: req.session.user.id,
    }));
    const { data, error } = await supabase.from("scheduled_posts").insert(rows).select();
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true, scheduled: data });
});

app.delete("/api/scheduled-posts/:id", requireLogin, async (req, res) => {
    const clients = await clientsVisibleTo(req.session.user);
    const clientIds = clients.map(c => c.id);
    const { data: row, error: findErr } = await supabase
        .from("scheduled_posts").select("*").eq("id", req.params.id).single();
    if (findErr || !row) return res.status(404).json({ error: "not found" });
    if (!clientIds.includes(row.client_id)) return res.status(403).json({ error: "no access to this company" });

    const { error } = await supabase.from("scheduled_posts").delete().eq("id", row.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
});

// Organic social publishing via upload-post.com -- the actual "post it live"
// step that was parked since day one of this build. Built against their
// real API per their documented behavior, but genuinely untested end to end:
// there's no UPLOAD_POST_API_KEY configured yet, and none of this can be
// verified without Josh's own account + a real connected platform profile.
//
// Deliberately scheduling-only, never immediate-publish: per upload-post's
// own documented findings, TikTok specifically can land as a live public
// post OR a private inbox draft on the exact same clean file, totally
// unpredictably, with NO API takedown if it goes live wrong. scheduled_date
// is the one mechanism confirmed to reliably hold rather than fire -- so
// this route requires one, it will not publish anything the moment it's
// called. Josh said explicitly tonight: nothing posts without him seeing it
// land correctly first.
app.post("/api/scheduled-posts/:id/send-to-upload-post", requireLogin, async (req, res) => {
    if (!process.env.UPLOAD_POST_API_KEY) {
        return res.status(501).json({ error: "No upload-post.com API key configured yet -- Josh needs to create an account there and hand over a key before this can run for real." });
    }

    const clients = await clientsVisibleTo(req.session.user);
    const clientIds = clients.map(c => c.id);
    const { data: sched, error: sErr } = await supabase
        .from("scheduled_posts").select("*, posts(finished_media_path, edited_media_path, caption_draft, caption_final, raw_media_id)")
        .eq("id", req.params.id).single();
    if (sErr || !sched) return res.status(404).json({ error: "not found" });
    if (!clientIds.includes(sched.client_id)) return res.status(403).json({ error: "no access to this company" });

    const mediaPath = sched.posts.finished_media_path || sched.posts.edited_media_path;
    if (!mediaPath) return res.status(400).json({ error: "this post has no finished video yet -- trim/crop + Finish it first" });

    const { data: account } = await supabase
        .from("platform_accounts").select("*")
        .eq("client_id", sched.client_id).eq("platform", sched.platform).maybeSingle();
    if (!account || !account.upload_post_profile) {
        return res.status(400).json({ error: `No upload-post profile connected yet for this company's ${sched.platform}. That's a one-time human OAuth step Josh has to do in a browser -- can't be automated.` });
    }

    const { data: fileBlob, error: dlErr } = await supabase.storage.from("raw-media").download(mediaPath);
    if (dlErr) return res.status(500).json({ error: "couldn't pull the finished video: " + dlErr.message });

    const caption = sched.posts.caption_final || sched.posts.caption_draft || "";
    const form = new FormData();
    form.append("user", account.upload_post_profile);
    form.append("platform[]", sched.platform);
    form.append("video", fileBlob, "post.mp4");
    form.append("title", caption);
    form.append("scheduled_date", `${sched.scheduled_date}T${sched.scheduled_time}:00`);
    form.append("timezone", "America/Chicago");

    let result;
    try {
        const resp = await fetch("https://api.upload-post.com/api/upload", {
            method: "POST",
            headers: { "Authorization": `Apikey ${process.env.UPLOAD_POST_API_KEY}` },
            body: form,
        });
        result = await resp.json();
    } catch (e) {
        return res.status(500).json({ error: "upload-post request failed: " + e.message });
    }

    if (result.error) {
        await supabase.from("scheduled_posts").update({ upload_post_status: "failed", upload_post_error: result.error }).eq("id", sched.id);
        return res.status(500).json({ error: result.error });
    }

    await supabase.from("scheduled_posts")
        .update({ upload_post_job_id: result.request_id || null, upload_post_status: "scheduled" })
        .eq("id", sched.id);
    res.json({ ok: true, result });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`content-dashboard listening on ${port}`));
