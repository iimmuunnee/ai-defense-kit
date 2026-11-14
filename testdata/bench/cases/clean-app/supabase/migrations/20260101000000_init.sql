create table public.orders (
  id uuid primary key,
  user_id uuid not null references auth.users (id),
  total integer
);

alter table public.orders enable row level security;

create policy "본인 주문만 읽기" on public.orders
  for select using (auth.uid() = user_id);
