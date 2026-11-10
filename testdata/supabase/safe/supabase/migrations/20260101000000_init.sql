create table public.profiles (
  id uuid primary key,
  name text
);
alter table public.profiles enable row level security;
create policy "own profile" on public.profiles for select using (auth.uid() = id);
