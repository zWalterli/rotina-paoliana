-- Rotina do Faturamento da Paoliana: banco no Supabase
-- Cole tudo no SQL Editor do Supabase e rode UMA vez.
-- O PIN é criado no primeiro acesso ao site e fica guardado só como hash; ninguém lê o PIN de volta.
-- Para trocar o PIN depois: delete from public.rotina_config; e abra o site para criar outro.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.rotina_config (
  id int primary key default 1 check (id = 1),
  pin_hash text not null
);

create table if not exists public.rotina_marcas (
  dia text primary key,
  ids text[] not null default '{}',
  atualizado timestamptz not null default now()
);

create table if not exists public.rotina_tarefas (
  id uuid primary key default gen_random_uuid(),
  t text not null check (char_length(t) between 1 and 120),
  d text check (char_length(d) <= 200),
  quando text not null check (quando in ('data', 'sempre', 'diario', 'especifico')),
  data text check (data is null or data ~ '^\d{4}-\d{2}-\d{2}$'),
  periodo text not null check (periodo in ('manha', 'tarde', 'extra')),
  ini text check (ini is null or ini ~ '^\d{2}:\d{2}$'),
  fim text check (fim is null or fim ~ '^\d{2}:\d{2}$'),
  criado_em timestamptz not null default now()
);

-- Ninguém acessa as tabelas direto: só pelas funções abaixo, que conferem o PIN.
alter table public.rotina_config enable row level security;
alter table public.rotina_marcas enable row level security;
alter table public.rotina_tarefas enable row level security;
revoke all on table public.rotina_config, public.rotina_marcas, public.rotina_tarefas from anon, authenticated;

create or replace function public.rotina_pin_ok(p text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if p is null or not exists (select 1 from rotina_config where pin_hash = crypt(p, pin_hash)) then
    perform pg_sleep(1);
    raise exception 'PIN incorreto' using errcode = '28P01';
  end if;
end $$;

create or replace function public.rotina_dados(p text) returns json
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform rotina_pin_ok(p);
  return json_build_object(
    'marcas', coalesce((select json_object_agg(dia, ids) from rotina_marcas), '{}'::json),
    'tarefas', coalesce((select json_agg(json_build_object(
        'docId', id, 't', t, 'd', d, 'quando', quando, 'data', data,
        'periodo', periodo, 'ini', ini, 'fim', fim) order by criado_em) from rotina_tarefas), '[]'::json)
  );
end $$;

create or replace function public.rotina_set_marcas(p text, p_dia text, p_ids text[]) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform rotina_pin_ok(p);
  if p_dia !~ '^\d{4}-\d{2}-\d{2}$' or coalesce(array_length(p_ids, 1), 0) > 60 then
    raise exception 'dados inválidos' using errcode = '22023';
  end if;
  insert into rotina_marcas (dia, ids, atualizado) values (p_dia, coalesce(p_ids, '{}'), now())
  on conflict (dia) do update set ids = excluded.ids, atualizado = now();
end $$;

create or replace function public.rotina_add_tarefa(p text, p_t jsonb) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare novo uuid;
begin
  perform rotina_pin_ok(p);
  if (select count(*) from rotina_tarefas) >= 500 then
    raise exception 'limite de atividades atingido' using errcode = '54000';
  end if;
  insert into rotina_tarefas (t, d, quando, data, periodo, ini, fim)
  values (p_t->>'t', nullif(p_t->>'d', ''), p_t->>'quando', nullif(p_t->>'data', ''),
          p_t->>'periodo', nullif(p_t->>'ini', ''), nullif(p_t->>'fim', ''))
  returning id into novo;
  return novo;
end $$;

create or replace function public.rotina_del_tarefa(p text, p_id uuid) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform rotina_pin_ok(p);
  delete from rotina_tarefas where id = p_id;
end $$;

create or replace function public.rotina_tem_pin() returns boolean
language sql security definer set search_path = public, extensions as $$
  select exists (select 1 from rotina_config);
$$;

-- Só funciona enquanto nenhum PIN existe (primeiro acesso).
create or replace function public.rotina_criar_pin(p text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if p is null or p !~ '^\d{6,12}$' then
    raise exception 'O PIN precisa ter de 6 a 12 números' using errcode = '22023';
  end if;
  insert into rotina_config (id, pin_hash) values (1, crypt(p, gen_salt('bf')))
  on conflict (id) do nothing;
  if not found then
    raise exception 'O PIN já foi criado' using errcode = '42710';
  end if;
end $$;

revoke execute on function public.rotina_pin_ok(text) from public, anon, authenticated;
revoke execute on function public.rotina_dados(text), public.rotina_set_marcas(text, text, text[]),
  public.rotina_add_tarefa(text, jsonb), public.rotina_del_tarefa(text, uuid),
  public.rotina_tem_pin(), public.rotina_criar_pin(text) from public;
grant execute on function public.rotina_dados(text), public.rotina_set_marcas(text, text, text[]),
  public.rotina_add_tarefa(text, jsonb), public.rotina_del_tarefa(text, uuid),
  public.rotina_tem_pin(), public.rotina_criar_pin(text) to anon;
