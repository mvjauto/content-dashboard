const path = require("path");
const fs = require("fs");
const os = require("os");
const { execFile } = require("child_process");
const { promisify } = require("util");
const execFileAsync = promisify(execFile);
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const { createClient } = require("@supabase/supabase-js");

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

// ffmpeg-full specifically, not the system "ffmpeg" -- the plain Homebrew
// ffmpeg formula doesn't ship libfreetype, so it has no drawtext filter.
// Full path so this doesn't depend on PATH or on Josh's own shell setup.
const FFMPEG_BIN = "/opt/homebrew/opt/ffmpeg-full/bin/ffmpeg";

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: process.env.NODE_ENV === "production" },
}));

function requireLogin(req, res, next) {
    if (!req.session.user) return res.status(401).json({ error: "not logged in" });
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

app.get("/api/me", requireLogin, (req, res) => res.json(req.session.user));

app.get("/api/clients", requireLogin, async (req, res) => {
    res.json(await clientsVisibleTo(req.session.user));
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
    const { overlayText, mute } = req.body;
    if (!overlayText || !overlayText.trim()) return res.status(400).json({ error: "overlayText is required" });

    const { data: post, error: postErr } = await supabase
        .from("posts").select("*, raw_media(storage_path)").eq("id", req.params.id).single();
    if (postErr || !post) return res.status(404).json({ error: "post not found" });

    const sourcePath = post.edited_media_path || post.raw_media.storage_path;
    const { data: fileBlob, error: dlErr } = await supabase.storage.from("raw-media").download(sourcePath);
    if (dlErr) return res.status(500).json({ error: "couldn't fetch source clip: " + dlErr.message });

    const tmpIn = path.join(os.tmpdir(), `finish-in-${Date.now()}.mp4`);
    const tmpOut = path.join(os.tmpdir(), `finish-out-${Date.now()}.mp4`);
    fs.writeFileSync(tmpIn, Buffer.from(await fileBlob.arrayBuffer()));

    // Phone video frequently carries a rotation tag (e.g. shot in portrait,
    // stored as landscape pixels with rotate=-90) -- ffmpeg auto-rotates on
    // decode, so drawtext actually draws onto the DISPLAYED frame, not the
    // coded one. Reading just stream=width here was the root cause of the
    // real overflow bug: a 1024x576-coded, rotate=-90 clip displays at
    // 576 wide, but the naive probe reported 1024 and sized text for that.
    const { stdout: probeOut } = await execFileAsync("/opt/homebrew/opt/ffmpeg-full/bin/ffprobe",
        ["-v", "error", "-select_streams", "v:0",
         "-show_entries", "stream=width,height:stream_side_data=rotation",
         "-of", "json", tmpIn]);
    const probeData = JSON.parse(probeOut);
    const stream = probeData.streams[0];
    const rotation = stream.side_data_list && stream.side_data_list[0] ? stream.side_data_list[0].rotation : 0;
    const rotated90 = Math.abs(rotation) === 90 || Math.abs(rotation) === 270;
    const width = (rotated90 ? stream.height : stream.width) || 1080;

    const fontsize = Math.max(22, Math.min(48, Math.round(width / 16)));
    const maxChars = Math.floor(width / (fontsize * 0.58));
    const wrapped = wrapText(overlayText.trim(), maxChars).join("\n");

    // Held for the first 2.5s, matching the reel concepts' "hook, first 2
    // seconds" spec -- a beat longer so it's actually readable, not a flash.
    const drawtext = `drawtext=fontfile='${HOOK_FONT}':text='${escapeDrawtext(wrapped)}':`
        + `fontsize=${fontsize}:fontcolor=white:box=1:boxcolor=black@0.55:boxborderw=14:line_spacing=6:`
        + `x=(w-text_w)/2:y=h*0.12:enable='lt(t,2.5)'`;

    const audioArgs = mute ? ["-an"] : ["-c:a", "aac"];
    try {
        await execFileAsync(FFMPEG_BIN, ["-y", "-i", tmpIn, "-vf", drawtext, "-c:v", "libx264", ...audioArgs, tmpOut]);
    } catch (e) {
        fs.unlinkSync(tmpIn);
        return res.status(500).json({ error: "ffmpeg failed: " + e.message });
    }

    const finishedPath = `${post.client_id}/finished/${post.id}.mp4`;
    const { error: upErr } = await supabase.storage
        .from("raw-media").upload(finishedPath, fs.readFileSync(tmpOut), { upsert: true });
    fs.unlinkSync(tmpIn);
    fs.unlinkSync(tmpOut);
    if (upErr) return res.status(500).json({ error: "upload failed: " + upErr.message });

    await supabase.from("posts")
        .update({ finished_media_path: finishedPath, overlay_text: overlayText.trim() })
        .eq("id", post.id);

    const { data: signed } = await supabase.storage.from("raw-media").createSignedUrl(finishedPath, 3600);
    res.json({ ok: true, url: signed ? signed.signedUrl : null });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`content-dashboard listening on ${port}`));
