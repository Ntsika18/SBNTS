-- =========================================================
-- AmberWear — Supabase schema
-- Run this once in Supabase Dashboard → SQL Editor → New query
-- =========================================================

-- ---------- profiles ----------
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text,
  role text not null default 'customer' check (role in ('customer','admin')),
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

create policy "Users can view own profile"
  on public.profiles for select
  using (auth.uid() = id);

create policy "Users can update own profile"
  on public.profiles for update
  using (auth.uid() = id);

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
    'customer'
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

create policy "Anyone can view products"
  on public.products for select
  using (true);

create policy "Admins can insert products"
  on public.products for insert
  with check (exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'));

create policy "Admins can update products"
  on public.products for update
  using (exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'));

create policy "Admins can delete products"
  on public.products for delete
  using (exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'));

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

create policy "Users can view own orders"
  on public.orders for select
  using (auth.uid() = user_id);

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

create policy "Users can view own order items"
  on public.order_items for select
  using (exists (select 1 from public.orders where orders.id = order_items.order_id and orders.user_id = auth.uid()));

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

create policy "Anyone can submit a contact message"
  on public.contact_messages for insert
  with check (true);

-- =========================================================
-- After running this, make yourself an admin (run separately,
-- after you've signed up/in at least once on the site):
--
-- update public.profiles set role = 'admin' where id =
--   (select id from auth.users where email = 'you@example.com');
-- =========================================================
