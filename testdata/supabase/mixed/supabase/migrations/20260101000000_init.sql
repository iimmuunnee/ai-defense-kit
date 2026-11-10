create table public.orders (id bigint primary key);
create table public.notes (id bigint primary key);
create table private.audit (id bigint primary key);
alter table public.orders enable row level security;
