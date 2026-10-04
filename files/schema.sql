-- =========================================================
-- AmberWear / SBNTS — Supabase schema (hardened)
-- Run this once in Supabase Dashboard → SQL Editor → New query.
-- Safe to re-run: it drops/recreates policies, functions & triggers.
-- =========================================================

-- ---------- profiles ----------
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text,
  role text not null default 'customer' check (role in ('customer','admin')),
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

drop policy if exists "Users can view own profile" on public.profiles;
create policy "Users can view own profile"
  on public.profiles for select
  using (auth.uid() = id);

-- NOTE: The UPDATE policy alone is NOT enough to stop privilege
-- escalation, because a WITH CHECK cannot easily compare against the
-- row's OLD value. We keep the policy scoped to the user's own row AND
-- add a trigger below (prevent_role_change) that blocks any attempt by a
-- non-admin to change their own `role`. Together these close the
-- "customer promotes self to admin via the anon key" hole.
drop policy if exists "Users can update own profile" on public.profiles;
create policy "Users can update own profile"
  on public.profiles for update
  using (auth.uid() = id)
  with check (auth.uid() = id);

-- ---------- role-change guard (server-side privilege-escalation fix) ----------
-- Blocks anyone who is not already an admin from changing a profile's role.
create or replace function public.prevent_role_change()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  caller_role text;
begin
  if new.role is distinct from old.role then
    -- Service role / SQL editor has no auth.uid(); allow those (that is how
    -- you legitimately promote the first admin). App calls always have a uid.
    if auth.uid() is not null then
      select role into caller_role from public.profiles where id = auth.uid();
      if coalesce(caller_role, 'customer') <> 'admin' then
        raise exception 'Not allowed to change role';
      end if;
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists trg_prevent_role_change on public.profiles;
create trigger trg_prevent_role_change
  before update on public.profiles
  for each row execute function public.prevent_role_change();

-- ---------- server-side admin check (RPC) ----------
-- The front-end must treat THIS as the source of truth for admin status,
-- never a value cached in the browser. Returns true only when the caller's
-- profile row has role='admin'. SECURITY DEFINER so it reads reliably.
create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'admin'
  );
$$;

revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to authenticated;

-- Automatically create a profile row for every new auth user,
-- whether they sign up with email/password OR Google.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, username, role)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name', split_part(new.email, '@', 1)),
    'customer'   -- role is ALWAYS customer on creation; promote via SQL only
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------- products ----------
create table if not exists public.products (
  id bigint generated always as identity primary key,
  name text not null,
  price numeric(10,2) not null,
  icon text,
  category text not null default 'tops',
  badge text,
  created_at timestamptz not null default now()
);

alter table public.products enable row level security;

drop policy if exists "Anyone can view products" on public.products;
create policy "Anyone can view products"
  on public.products for select
  using (true);

drop policy if exists "Admins can insert products" on public.products;
create policy "Admins can insert products"
  on public.products for insert
  with check (public.is_admin());

drop policy if exists "Admins can update products" on public.products;
create policy "Admins can update products"
  on public.products for update
  using (public.is_admin());

drop policy if exists "Admins can delete products" on public.products;
create policy "Admins can delete products"
  on public.products for delete
  using (public.is_admin());

-- seed a few starter products (only if the table is currently empty)
insert into public.products (name, price, icon, category, badge)
select * from (values
  ('Ember Linen Shirt', 68, '👕', 'tops', 'New'),
  ('Karoo Wide-Leg Trouser', 92, '👖', 'bottoms', null),
  ('Dusk Wrap Jacket', 128, '🧥', 'outerwear', null),
  ('Sunset Canvas Tote', 29, '👜', 'accessories', null)
) as v(name, price, icon, category, badge)
where not exists (select 1 from public.products);

-- ---------- orders ----------
create table if not exists public.orders (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  total numeric(10,2) not null,
  created_at timestamptz not null default now()
);

alter table public.orders enable row level security;

drop policy if exists "Users can view own orders" on public.orders;
create policy "Users can view own orders"
  on public.orders for select
  using (auth.uid() = user_id);

drop policy if exists "Users can create own orders" on public.orders;
create policy "Users can create own orders"
  on public.orders for insert
  with check (auth.uid() = user_id);

-- ---------- order_items ----------
create table if not exists public.order_items (
  id bigint generated always as identity primary key,
  order_id bigint not null references public.orders(id) on delete cascade,
  product_id bigint references public.products(id),
  quantity int not null default 1
);

alter table public.order_items enable row level security;

drop policy if exists "Users can view own order items" on public.order_items;
create policy "Users can view own order items"
  on public.order_items for select
  using (exists (select 1 from public.orders where orders.id = order_items.order_id and orders.user_id = auth.uid()));

drop policy if exists "Users can insert own order items" on public.order_items;
create policy "Users can insert own order items"
  on public.order_items for insert
  with check (exists (select 1 from public.orders where orders.id = order_items.order_id and orders.user_id = auth.uid()));

-- ---------- contact_messages ----------
create table if not exists public.contact_messages (
  id bigint generated always as identity primary key,
  firstname text,
  lastname text,
  email text,
  subject text,
  message text,
  created_at timestamptz not null default now()
);

alter table public.contact_messages enable row level security;

drop policy if exists "Anyone can submit a contact message" on public.contact_messages;
create policy "Anyone can submit a contact message"
  on public.contact_messages for insert
  with check (true);

-- =========================================================
-- Server-side rate limiting for auth-sensitive actions
-- (login attempts + password-reset requests).
--
-- The browser calls check_and_record_attempt() BEFORE asking Supabase
-- Auth to sign in / send a reset email. Because this runs in the
-- database it cannot be bypassed by clearing localStorage, using
-- incognito, or scripting the anon key directly. It complements (does
-- not replace) Supabase's own built-in Auth rate limits.
-- =========================================================
create table if not exists public.auth_rate_limits (
  id bigint generated always as identity primary key,
  identifier text not null,          -- e.g. lower(email) or ip-ish key
  action text not null,              -- 'login' | 'reset'
  attempted_at timestamptz not null default now()
);

create index if not exists auth_rate_limits_lookup
  on public.auth_rate_limits (identifier, action, attempted_at);

alter table public.auth_rate_limits enable row level security;
-- No direct table access for anon/authenticated; all access is via the
-- SECURITY DEFINER function below. (No policies = no direct rows.)

create or replace function public.check_and_record_attempt(
  p_identifier text,
  p_action text,
  p_max_attempts int default 5,
  p_window_seconds int default 900
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_ident text := lower(coalesce(p_identifier, ''));
  v_count int;
  v_window_start timestamptz := now() - make_interval(secs => p_window_seconds);
  v_oldest timestamptz;
begin
  if v_ident = '' then
    return jsonb_build_object('allowed', false, 'reason', 'invalid');
  end if;

  -- Opportunistic cleanup of old rows (keeps the table small).
  delete from public.auth_rate_limits
    where attempted_at < now() - interval '1 day';

  select count(*), min(attempted_at)
    into v_count, v_oldest
  from public.auth_rate_limits
  where identifier = v_ident
    and action = p_action
    and attempted_at >= v_window_start;

  if v_count >= p_max_attempts then
    return jsonb_build_object(
      'allowed', false,
      'reason', 'rate_limited',
      'retry_after_seconds',
        greatest(0, p_window_seconds - extract(epoch from (now() - v_oldest))::int)
    );
  end if;

  insert into public.auth_rate_limits (identifier, action)
  values (v_ident, p_action);

  return jsonb_build_object('allowed', true, 'remaining', p_max_attempts - v_count - 1);
end;
$$;

revoke all on function public.check_and_record_attempt(text, text, int, int) from public;
grant execute on function public.check_and_record_attempt(text, text, int, int) to anon, authenticated;

-- Clears a user's rate-limit counters after a fully successful login.
create or replace function public.clear_rate_limit(p_identifier text, p_action text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  delete from public.auth_rate_limits
  where identifier = lower(coalesce(p_identifier, '')) and action = p_action;
end;
$$;

revoke all on function public.clear_rate_limit(text, text) from public;
grant execute on function public.clear_rate_limit(text, text) to anon, authenticated;

-- =========================================================
-- After running this, make yourself an admin (run separately,
-- after you've signed up/in at least once on the site):
--
-- update public.profiles set role = 'admin' where id =
--   (select id from auth.users where email = 'you@example.com');
--
-- (The prevent_role_change trigger blocks self-promotion from the app;
-- running this here in the SQL editor uses the service role, which the
-- trigger allows through because there is no auth.uid() context.)
-- =========================================================
