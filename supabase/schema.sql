-- ── Tables ─────────────────────────────────────────────────────────────────

create table blocked_events (
  id         bigserial primary key,
  created_at timestamptz default now(),
  source_ip  text        not null,
  dest_port  int,
  event_type smallint    not null,  -- 1=blacklist  2=ping  3=web
  interface  text
);

create table blacklist_rules (
  id         bigserial primary key,
  created_at timestamptz default now(),
  ip_address text        unique not null,
  reason     text,
  created_by text        default 'admin',
  is_active  boolean     default true,
  hit_count  bigint      default 0
);

-- ── Realtime ────────────────────────────────────────────────────────────────

alter publication supabase_realtime add table blocked_events;
alter publication supabase_realtime add table blacklist_rules;

-- ── Row-Level Security (open for dev — tighten before prod) ─────────────────

alter table blocked_events  enable row level security;
alter table blacklist_rules enable row level security;

create policy "anon read events"     on blocked_events  for select using (true);
create policy "anon read blacklist"  on blacklist_rules for select using (true);
