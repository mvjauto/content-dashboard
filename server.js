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

// The approval queue -- nothing here publishes until a human flips it to approved.
app.get("/api/posts", requireLogin, async (req, res) => {
    const clients = await clientsVisibleTo(req.session.user);
    const clientIds = clients.map(c => c.id);
    const { data, error } = await supabase
        .from("posts")
        .select("*, raw_media(storage_path, media_type)")
        .in("client_id", clientIds)
        .order("created_at", { ascending: false });
    if (error) return res.status(500).json({ error: error.message });

    // A caption without the clip it goes with isn't reviewable -- sign the
    // URL here so the approval card can actually show the footage. Once a
    // post has a human-trimmed cut, that's what shows -- never the raw clip.
    const withUrls = await Promise.all(data.map(async (post) => {
        const showPath = post.edited_media_path || (post.raw_media && post.raw_media.storage_path);
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
        await execFileAsync("ffmpeg", args);
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

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`content-dashboard listening on ${port}`));
