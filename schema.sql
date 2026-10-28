-- =====================================================================
-- Schema para a app Familiar Finance (finanças de casal)
-- Colar no Supabase: SQL Editor > New query > Run
-- Seguro para correr mais do que uma vez.
--
-- O que cria:
--   families         -> a "família" (o casal) e o código de convite
--   family_members   -> quem pertence a cada família
--   family_records   -> os dados da app (chave/valor), um registo por chave
--   create_family()  -> cria a família e junta quem a criou
--   join_family()    -> entra numa família com o código de convite
--
-- Segurança: RLS ativa em todas as tabelas. Só membros da família
-- conseguem ler/escrever os dados dessa família. O role "anon"
-- (visitantes sem login) não tem acesso a nada.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. Tabelas
-- ---------------------------------------------------------------------

create table if not exists public.families (
  id          uuid primary key default gen_random_uuid(),
  name        text not null default 'A nossa família',
  invite_code text not null unique
              default upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 10)),
  created_by  uuid references auth.users (id) on delete set null,
  created_at  timestamptz not null default now()
);

create table if not exists public.family_members (
  family_id  uuid not null references public.families (id) on delete cascade,
  user_id    uuid not null references auth.users (id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (family_id, user_id),
  -- cada utilizador só pode pertencer a uma família (a app assume isto)
  unique (user_id)
);

create table if not exists public.family_records (
  family_id  uuid not null references public.families (id) on delete cascade,
  key        text not null check (char_length(key) between 1 and 200),
  value      text not null,
  updated_by uuid references auth.users (id) on delete set null,
  updated_at timestamptz not null default now(),
  primary key (family_id, key)
);

-- atualiza updated_at automaticamente em cada alteração
create or replace function public.touch_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists family_records_touch on public.family_records;
create trigger family_records_touch
  before update on public.family_records
  for each row execute function public.touch_updated_at();

-- ---------------------------------------------------------------------
-- 2. Função auxiliar para as regras de acesso
--    (security definer evita recursão nas políticas RLS)
-- ---------------------------------------------------------------------

create or replace function public.is_family_member(fid uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.family_members m
    where m.family_id = fid
      and m.user_id = (select auth.uid())
  );
$$;

-- ---------------------------------------------------------------------
-- 3. Row Level Security
-- ---------------------------------------------------------------------

alter table public.families       enable row level security;
alter table public.family_members enable row level security;
alter table public.family_records enable row level security;

-- families: membros podem ver a sua família (inclui o código de convite).
-- Não há políticas de insert/update/delete: só as funções abaixo criam famílias.
drop policy if exists "membros veem a sua familia" on public.families;
create policy "membros veem a sua familia"
  on public.families for select
  to authenticated
  using (public.is_family_member(id));

-- family_members: cada utilizador só vê a sua própria associação.
-- Também sem insert/update/delete direto: só create_family / join_family.
drop policy if exists "ver a propria associacao" on public.family_members;
create policy "ver a propria associacao"
  on public.family_members for select
  to authenticated
  using (user_id = (select auth.uid()));

-- family_records: membros leem e escrevem os dados da sua família.
drop policy if exists "membros leem registos" on public.family_records;
create policy "membros leem registos"
  on public.family_records for select
  to authenticated
  using (public.is_family_member(family_id));

drop policy if exists "membros criam registos" on public.family_records;
create policy "membros criam registos"
  on public.family_records for insert
  to authenticated
  with check (
    public.is_family_member(family_id)
    and updated_by = (select auth.uid())
  );

drop policy if exists "membros atualizam registos" on public.family_records;
create policy "membros atualizam registos"
  on public.family_records for update
  to authenticated
  using (public.is_family_member(family_id))
  with check (
    public.is_family_member(family_id)
    and updated_by = (select auth.uid())
  );

drop policy if exists "membros apagam registos" on public.family_records;
create policy "membros apagam registos"
  on public.family_records for delete
  to authenticated
  using (public.is_family_member(family_id));

-- ---------------------------------------------------------------------
-- 4. Funções chamadas pela app
-- ---------------------------------------------------------------------

-- Cria uma família nova e junta quem a criou.
create or replace function public.create_family(family_name text default 'A nossa família')
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  uid uuid := (select auth.uid());
  new_id uuid;
begin
  if uid is null then
    raise exception 'É preciso iniciar sessão.';
  end if;

  if exists (select 1 from public.family_members where user_id = uid) then
    raise exception 'Esta conta já pertence a uma família.';
  end if;

  insert into public.families (name, created_by)
  values (coalesce(nullif(btrim(family_name), ''), 'A nossa família'), uid)
  returning id into new_id;

  insert into public.family_members (family_id, user_id)
  values (new_id, uid);

  return new_id;
end;
$$;

-- Entra numa família existente com o código de convite.
-- Limite de membros por família: altera max_members se precisares.
create or replace function public.join_family(invite_token text)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  uid uuid := (select auth.uid());
  fid uuid;
  max_members constant int := 2;
begin
  if uid is null then
    raise exception 'É preciso iniciar sessão.';
  end if;

  if exists (select 1 from public.family_members where user_id = uid) then
    raise exception 'Esta conta já pertence a uma família.';
  end if;

  select f.id into fid
  from public.families f
  where f.invite_code = upper(btrim(invite_token));

  if fid is null then
    raise exception 'Código de convite inválido.';
  end if;

  if (select count(*) from public.family_members where family_id = fid) >= max_members then
    raise exception 'Esta família já atingiu o número máximo de membros.';
  end if;

  insert into public.family_members (family_id, user_id)
  values (fid, uid);

  return fid;
end;
$$;

-- ---------------------------------------------------------------------
-- 5. Permissões: visitantes sem login (anon) não têm acesso a nada
-- ---------------------------------------------------------------------

revoke all on public.families       from anon;
revoke all on public.family_members from anon;
revoke all on public.family_records from anon;

grant select                         on public.families       to authenticated;
grant select                         on public.family_members to authenticated;
grant select, insert, update, delete on public.family_records to authenticated;

revoke all on function public.is_family_member(uuid)  from public, anon;
revoke all on function public.create_family(text)     from public, anon;
revoke all on function public.join_family(text)       from public, anon;
revoke all on function public.touch_updated_at()      from public, anon;

grant execute on function public.is_family_member(uuid) to authenticated;
grant execute on function public.create_family(text)    to authenticated;
grant execute on function public.join_family(text)      to authenticated;
