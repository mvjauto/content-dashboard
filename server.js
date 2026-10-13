const path = require("path");
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
// this user can actually see.
app.get("/api/raw-media", requireLogin, async (req, res) => {
    const clients = await clientsVisibleTo(req.session.user);
    const clientIds = clients.map(c => c.id);
    const { data, error } = await supabase
        .from("raw_media")
        .select("*")
        .in("client_id", clientIds)
        .order("received_at", { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

// The approval queue -- nothing here publishes until a human flips it to approved.
app.get("/api/posts", requireLogin, async (req, res) => {
    const clients = await clientsVisibleTo(req.session.user);
    const clientIds = clients.map(c => c.id);
    const { data, error } = await supabase
        .from("posts")
        .select("*")
        .in("client_id", clientIds)
        .order("created_at", { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
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

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`content-dashboard listening on ${port}`));
