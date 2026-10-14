-- Content Dashboard schema.
-- Four clients at launch: 811-assist, axion-pept, am-underground (active),
-- mvj-auto-sales (placeholder, no platform rows until it's actually operating).

create table clients (
  id uuid primary key default gen_random_uuid(),
  slug text unique not null,
  name text not null,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

-- One row per connected account. A client can have more than one account on
-- the same platform (811 Assist has two TikToks) -- platform is not unique
-- per client on its own, (client_id, platform, account_label) is.
create table platform_accounts (
  id uuid primary key default gen_random_uuid(),
  client_id uuid not null references clients(id) on delete cascade,
  platform text not null check (platform in ('instagram','facebook','tiktok','youtube','linkedin')),
  account_label text not null,          -- e.g. "main", "crew account"
  external_account_id text,             -- platform's own account/page id
  access_token_ref text,                -- Keychain/secret-store key name, never the token itself
  status text not null default 'pending' check (status in ('pending','connected','needs_review','disabled')),
  created_at timestamptz not null default now(),
  unique (client_id, platform, account_label)
);

-- Raw footage landing from the per-client WhatsApp group. Separate from
-- posts on purpose -- this is the reusable B-roll bin, not a draft.
create table raw_media (
  id uuid primary key default gen_random_uuid(),
  client_id uuid not null references clients(id) on delete cascade,
  storage_path text not null,           -- path in the Supabase Storage bucket
  media_type text not null check (media_type in ('video','image')),
  source text not null default 'whatsapp',
  whatsapp_group_jid text,
  sender text,
  caption_raw text,                     -- whatever text came with it, unedited
  received_at timestamptz not null default now()
);

create table posts (
  id uuid primary key default gen_random_uuid(),
  client_id uuid not null references clients(id) on delete cascade,
  platform_account_id uuid references platform_accounts(id) on delete cascade,  -- nullable: a post can exist in review before a platform is connected
  raw_media_id uuid references raw_media(id) on delete set null,
  caption_draft text,                   -- Jarvis's draft
  caption_final text,                   -- what actually gets posted (may equal the draft)
  status text not null default 'needs_review'
    check (status in ('needs_review','approved','scheduled','published','failed')),
  scheduled_for timestamptz,
  published_at timestamptz,
  external_post_id text,                -- id returned by the platform once published
  approved_by uuid,                     -- references users(id); nullable until approved
  edited_media_path text,               -- the human-trimmed/cropped cut, once one exists
  finished_media_path text,             -- the trimmed cut with the hook text burned in, once rendered
  overlay_text text,                    -- the exact on-screen hook line used for the burn-in
  created_at timestamptz not null default now()
);

-- Every edit a human makes to Jarvis's draft -- the learning-loop feedback
-- signal described in the Content Dashboard scope. Append-only, never updated.
create table caption_edits (
  id uuid primary key default gen_random_uuid(),
  post_id uuid not null references posts(id) on delete cascade,
  ai_draft text not null,
  human_final text not null,
  edited_by uuid,                       -- references users(id)
  edited_at timestamptz not null default now()
);

create table users (
  id uuid primary key default gen_random_uuid(),
  email text unique not null,
  name text not null,
  role text not null default 'staff' check (role in ('owner','staff')),
  password_hash text not null,
  created_at timestamptz not null default now()
);

-- Per-person, per-client scoping -- a staff user may see one client, several,
-- or (if role = 'owner') everything regardless of rows here.
create table user_client_access (
  user_id uuid not null references users(id) on delete cascade,
  client_id uuid not null references clients(id) on delete cascade,
  primary key (user_id, client_id)
);

-- Reference/inspiration videos Josh uploads for Jarvis to study -- NOT
-- client B-roll, not tied to any one client's footage. Jarvis extracts
-- frames + audio from the file in Storage and writes findings into `notes`.
create table example_media (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references clients(id),  -- which company this learning applies to -- learning is NOT shared across companies, Josh was explicit
  storage_path text,                    -- path in the "learning-examples" bucket; null for text instructions (no file)
  media_type text not null check (media_type in ('video','image','audio','text')),
  original_filename text,
  instruction_text text,                -- for media_type='text' -- a standing directive typed directly in ("use this logo", "stop doing X"), not Jarvis's own analysis
  uploaded_by uuid references users(id),
  notes text,                           -- Jarvis's analysis once reviewed (video/image/audio only)
  reviewed_at timestamptz,              -- null until Jarvis has actually looked at it; set immediately for text instructions, nothing to study
  uploaded_at timestamptz not null default now()
);

insert into clients (slug, name, active) values
  ('811-assist', '811 Assist', true),
  ('axion-pept', 'Axion Pept', true),
  ('am-underground', 'AM Underground', true),
  ('mvj-auto-sales', 'MVJ Auto Sales', false);
