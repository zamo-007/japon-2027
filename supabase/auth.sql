-- Comptes individuels : code PIN par voyageur, sessions de 24 h d'inactivité, droits côté serveur.
create extension if not exists pgcrypto with schema extensions;

alter table public.trips add column if not exists admin_id text;

create table if not exists public.members(
  trip_id uuid not null references public.trips(id),
  traveler_id text not null,
  pin_hash text,
  failed int not null default 0,
  locked_until timestamptz,
  pin_set_at timestamptz,
  primary key(trip_id, traveler_id)
);
create table if not exists public.sessions(
  token_hash text primary key,
  trip_id uuid not null references public.trips(id),
  traveler_id text not null,
  created_at timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  revoked boolean not null default false
);
create index if not exists sessions_trav on public.sessions(trip_id, traveler_id);
alter table public.members enable row level security;
alter table public.sessions enable row level security;
revoke all on public.members, public.sessions from anon, authenticated;


create or replace function public._tid(p_code text) returns uuid language plpgsql stable security definer set search_path=public as $$
declare tid uuid := public.trip_from_code(p_code);
begin
  if tid is null then raise exception 'code invalide' using errcode = '28000'; end if;
  return tid;
end $$;

create or replace function public._hash(p_token text) returns text language sql immutable set search_path=public,extensions as $$
  select encode(extensions.digest(coalesce(p_token,''),'sha256'),'hex')
$$;

-- Vérifie la session (24 h d'inactivité max) et renvoie le voyageur connecté.
create or replace function public._sess(p_code text, p_token text, out tid uuid, out me text, out is_admin boolean)
language plpgsql security definer set search_path=public as $$
declare s public.sessions;
begin
  tid := public._tid(p_code);
  select * into s from public.sessions where token_hash = public._hash(p_token) and trip_id = tid;
  if s.token_hash is null or s.revoked or s.last_seen < now() - interval '24 hours' then
    raise exception 'session expiree' using errcode = '28P01';
  end if;
  if s.last_seen < now() - interval '1 minute' then
    update public.sessions set last_seen = now() where token_hash = s.token_hash;
  end if;
  me := s.traveler_id;
  is_admin := coalesce((select admin_id from public.trips where id = tid) = me, false);
end $$;

create or replace function public._new_session(tid uuid, trav text) returns json language plpgsql security definer set search_path=public,extensions as $$
declare tok text := encode(extensions.gen_random_bytes(32),'hex');
begin
  insert into public.sessions(token_hash, trip_id, traveler_id) values (public._hash(tok), tid, trav);
  return json_build_object('ok', true, 'token', tok, 'me', trav,
    'admin', coalesce((select admin_id from public.trips where id = tid) = trav, false));
end $$;

create or replace function public._traveler_exists(tid uuid, trav text) returns boolean language sql stable security definer set search_path=public as $$
  select exists(select 1 from public.items where trip_id = tid and col = 'travelers' and id = trav and not (data ? '_deleted'))
$$;

create or replace function public._pin_ok(p text) returns boolean language sql immutable as $$
  select coalesce(p ~ '^[0-9]{4,6}$', false)
$$;

-- Liste publique des prénoms (écran de connexion) : jamais de données privées.
create or replace function public.list_travelers(p_code text) returns json language plpgsql stable security definer set search_path=public as $$
declare tid uuid := public._tid(p_code);
begin
  return coalesce((select json_agg(json_build_object('id', i.id, 'name', i.data->>'name', 'color', i.data->>'color',
      'order', i.data->'order', 'has_pin', m.pin_hash is not null) order by (i.data->>'order')::numeric nulls last)
    from public.items i left join public.members m on m.trip_id = i.trip_id and m.traveler_id = i.id
    where i.trip_id = tid and i.col = 'travelers' and not (i.data ? '_deleted')), '[]'::json);
end $$;

-- Première connexion (ou après réinitialisation) : le voyageur choisit lui-même son PIN.
create or replace function public.set_first_pin(p_code text, p_traveler text, p_pin text) returns json language plpgsql security definer set search_path=public,extensions as $$
declare tid uuid := public._tid(p_code); m public.members; n int;
begin
  if not public._pin_ok(p_pin) then return json_build_object('ok', false, 'error', 'format'); end if;
  if not public._traveler_exists(tid, p_traveler) then return json_build_object('ok', false, 'error', 'unknown'); end if;
  select * into m from public.members where trip_id = tid and traveler_id = p_traveler for update;
  if m.pin_hash is not null then return json_build_object('ok', false, 'error', 'already'); end if;
  insert into public.members(trip_id, traveler_id, pin_hash, failed, locked_until, pin_set_at)
    values (tid, p_traveler, extensions.crypt(p_pin, extensions.gen_salt('bf', 8)), 0, null, now())
    on conflict (trip_id, traveler_id) do update set pin_hash = excluded.pin_hash, failed = 0, locked_until = null, pin_set_at = now()
    where public.members.pin_hash is null;
  get diagnostics n = row_count;
  if n = 0 then return json_build_object('ok', false, 'error', 'already'); end if;
  return public._new_session(tid, p_traveler);
end $$;

-- Connexion avec le PIN : 5 essais, puis blocage de 10 minutes.
create or replace function public.login_pin(p_code text, p_traveler text, p_pin text) returns json language plpgsql security definer set search_path=public,extensions as $$
declare tid uuid := public._tid(p_code); m public.members;
begin
  select * into m from public.members where trip_id = tid and traveler_id = p_traveler for update;
  if m.pin_hash is null or not public._traveler_exists(tid, p_traveler) then return json_build_object('ok', false, 'error', 'nopin'); end if;
  if m.locked_until is not null and m.locked_until > now() then
    return json_build_object('ok', false, 'error', 'locked', 'wait', ceil(extract(epoch from m.locked_until - now())));
  end if;
  if m.pin_hash = extensions.crypt(coalesce(p_pin,''), m.pin_hash) then
    update public.members set failed = 0, locked_until = null where trip_id = tid and traveler_id = p_traveler;
    return public._new_session(tid, p_traveler);
  end if;
  if m.failed + 1 >= 5 then
    update public.members set failed = 0, locked_until = now() + interval '10 minutes' where trip_id = tid and traveler_id = p_traveler;
    return json_build_object('ok', false, 'error', 'locked', 'wait', 600);
  end if;
  update public.members set failed = m.failed + 1 where trip_id = tid and traveler_id = p_traveler;
  return json_build_object('ok', false, 'error', 'wrong', 'left', 5 - (m.failed + 1));
end $$;

-- Nouveau voyageur : prénom + PIN, compte créé côté serveur.
create or replace function public.join_trip(p_code text, p_name text, p_color text, p_pin text) returns json language plpgsql security definer set search_path=public,extensions as $$
declare tid uuid := public._tid(p_code); n text := left(btrim(coalesce(p_name,'')), 24); nid text; ord int;
begin
  if n = '' then return json_build_object('ok', false, 'error', 'name'); end if;
  if not public._pin_ok(p_pin) then return json_build_object('ok', false, 'error', 'format'); end if;
  if exists(select 1 from public.items where trip_id = tid and col = 'travelers' and not (data ? '_deleted') and lower(data->>'name') = lower(n)) then
    return json_build_object('ok', false, 'error', 'exists');
  end if;
  nid := 'p' || encode(extensions.gen_random_bytes(6),'hex');
  select count(*) + 1 into ord from public.items where trip_id = tid and col = 'travelers';
  insert into public.items(trip_id, col, id, data, updated_at) values (tid, 'travelers', nid,
    jsonb_build_object('name', n, 'color', coalesce(nullif(left(p_color, 9), ''), '#E9A93F'), 'order', ord, 'createdAt', to_char(now() at time zone 'utc','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')), now());
  insert into public.members(trip_id, traveler_id, pin_hash, pin_set_at) values (tid, nid, extensions.crypt(p_pin, extensions.gen_salt('bf', 8)), now());
  return public._new_session(tid, nid);
end $$;

create or replace function public.whoami(p_code text, p_token text) returns json language plpgsql security definer set search_path=public as $$
declare s record;
begin
  select * into s from public._sess(p_code, p_token);
  return json_build_object('me', s.me, 'admin', s.is_admin);
end $$;

create or replace function public.logout(p_code text, p_token text) returns void language plpgsql security definer set search_path=public as $$
begin
  update public.sessions set revoked = true where token_hash = public._hash(p_token) and trip_id = public._tid(p_code);
end $$;

create or replace function public.change_pin(p_code text, p_token text, p_old text, p_new text) returns json language plpgsql security definer set search_path=public,extensions as $$
declare s record; m public.members;
begin
  select * into s from public._sess(p_code, p_token);
  if not public._pin_ok(p_new) then return json_build_object('ok', false, 'error', 'format'); end if;
  select * into m from public.members where trip_id = s.tid and traveler_id = s.me for update;
  if m.locked_until is not null and m.locked_until > now() then return json_build_object('ok', false, 'error', 'locked'); end if;
  if m.pin_hash is null or m.pin_hash <> extensions.crypt(coalesce(p_old,''), m.pin_hash) then
    update public.members set failed = case when m.failed + 1 >= 5 then 0 else m.failed + 1 end,
      locked_until = case when m.failed + 1 >= 5 then now() + interval '10 minutes' else null end
      where trip_id = s.tid and traveler_id = s.me;
    return json_build_object('ok', false, 'error', 'wrong');
  end if;
  update public.members set pin_hash = extensions.crypt(p_new, extensions.gen_salt('bf', 8)), failed = 0, locked_until = null, pin_set_at = now()
    where trip_id = s.tid and traveler_id = s.me;
  -- Les autres appareils devront ressaisir le nouveau PIN.
  update public.sessions set revoked = true where trip_id = s.tid and traveler_id = s.me and token_hash <> public._hash(p_token);
  return json_build_object('ok', true);
end $$;

-- Lecture : les éléments « perso » des autres ne quittent jamais le serveur.
create or replace function public.get_items(p_code text, p_token text) returns json language plpgsql security definer set search_path=public as $$
declare s record;
begin
  select * into s from public._sess(p_code, p_token);
  return coalesce((select json_agg(json_build_object('col', col, 'id', id, 'data', data, 'updated_at', updated_at))
    from public.items where trip_id = s.tid and not (data ? '_deleted')
      and (data->>'owner' is null or data->>'owner' = s.me)), '[]'::json);
end $$;

-- Règles d'écriture communes à put/patch.
create or replace function public._guard(s_me text, p_col text, old jsonb, fin jsonb) returns jsonb language plpgsql stable as $$
declare k text; m jsonb; mine jsonb;
begin
  if p_col = 'travelers' then
    raise exception 'interdit' using errcode = '42501';
  end if;
  if old is not null and old->>'owner' is not null and old->>'owner' <> s_me then
    raise exception 'interdit' using errcode = '42501';
  end if;
  if fin->>'owner' is not null and fin->>'owner' <> s_me then
    raise exception 'interdit' using errcode = '42501';
  end if;
  -- Coches individuelles : chacun ne modifie que sa propre case.
  foreach k in array array['done','joined','amounts'] loop
    if (fin ? k) or (old is not null and old ? k) then
      m := case when old is not null and jsonb_typeof(old->k) = 'object' then (old->k) - s_me else '{}'::jsonb end;
      mine := case when jsonb_typeof(fin->k) = 'object' then fin->k->s_me end;
      if mine is not null then m := m || jsonb_build_object(s_me, mine); end if;
      if fin ? k or m <> '{}'::jsonb then fin := fin || jsonb_build_object(k, m); end if;
    end if;
  end loop;
  return fin;
end $$;

create or replace function public.put_item(p_code text, p_token text, p_col text, p_id text, p_data jsonb) returns void language plpgsql security definer set search_path=public as $$
declare s record; old jsonb; fin jsonb;
begin
  select * into s from public._sess(p_code, p_token);
  if p_col = 'travelers' and p_id = s.me then
    select data into old from public.items where trip_id = s.tid and col = p_col and id = p_id;
    if old is null or (p_data ? '_deleted') then raise exception 'interdit' using errcode = '42501'; end if;
    update public.items set data = p_data, updated_at = now() where trip_id = s.tid and col = p_col and id = p_id;
    return;
  end if;
  select data into old from public.items where trip_id = s.tid and col = p_col and id = p_id for update;
  fin := public._guard(s.me, p_col, old, p_data);
  insert into public.items(trip_id, col, id, data, updated_at) values (s.tid, p_col, p_id, fin, now())
  on conflict (trip_id, col, id) do update set data = excluded.data, updated_at = now();
end $$;

create or replace function public.patch_item(p_code text, p_token text, p_col text, p_id text, p_patch jsonb) returns void language plpgsql security definer set search_path=public as $$
declare s record; old jsonb; fin jsonb;
begin
  select * into s from public._sess(p_code, p_token);
  select data into old from public.items where trip_id = s.tid and col = p_col and id = p_id for update;
  if p_col = 'travelers' then
    if p_id <> s.me or old is null or (p_patch ? '_deleted') then raise exception 'interdit' using errcode = '42501'; end if;
    update public.items set data = public.jsonb_deep_merge(old, p_patch), updated_at = now() where trip_id = s.tid and col = p_col and id = p_id;
    return;
  end if;
  fin := public._guard(s.me, p_col, old, public.jsonb_deep_merge(old, p_patch));
  insert into public.items(trip_id, col, id, data, updated_at) values (s.tid, p_col, p_id, fin, now())
  on conflict (trip_id, col, id) do update set data = excluded.data, updated_at = now();
end $$;

-- Organisateur : réinitialiser un PIN (le voyageur en choisira un nouveau), retirer un voyageur.
create or replace function public.admin_reset_pin(p_code text, p_token text, p_traveler text) returns json language plpgsql security definer set search_path=public as $$
declare s record;
begin
  select * into s from public._sess(p_code, p_token);
  if not s.is_admin then raise exception 'interdit' using errcode = '42501'; end if;
  update public.members set pin_hash = null, failed = 0, locked_until = null, pin_set_at = null where trip_id = s.tid and traveler_id = p_traveler;
  update public.sessions set revoked = true where trip_id = s.tid and traveler_id = p_traveler;
  return json_build_object('ok', true);
end $$;

create or replace function public.admin_remove_traveler(p_code text, p_token text, p_traveler text) returns json language plpgsql security definer set search_path=public as $$
declare s record;
begin
  select * into s from public._sess(p_code, p_token);
  if not s.is_admin or p_traveler = s.me then raise exception 'interdit' using errcode = '42501'; end if;
  update public.items set data = data || '{"_deleted":true}'::jsonb, updated_at = now() where trip_id = s.tid and col = 'travelers' and id = p_traveler;
  update public.members set pin_hash = null, failed = 0, locked_until = null where trip_id = s.tid and traveler_id = p_traveler;
  update public.sessions set revoked = true where trip_id = s.tid and traveler_id = p_traveler;
  return json_build_object('ok', true);
end $$;

-- Pour les fonctions photos/push (clé de service) : session ou null, sans erreur.
create or replace function public.session_info(p_code text, p_token text) returns json language plpgsql security definer set search_path=public as $$
declare s record;
begin
  select * into s from public._sess(p_code, p_token);
  return json_build_object('trip_id', s.tid, 'me', s.me, 'admin', s.is_admin);
exception when others then return null;
end $$;

revoke all on function public._tid(text), public._hash(text), public._sess(text,text), public._new_session(uuid,text),
  public._traveler_exists(uuid,text), public._pin_ok(text), public._guard(text,text,jsonb,jsonb), public.session_info(text,text) from public, anon, authenticated;
grant execute on function public.session_info(text,text) to service_role;
revoke all on function public.list_travelers(text), public.set_first_pin(text,text,text), public.login_pin(text,text,text), public.join_trip(text,text,text,text),
  public.whoami(text,text), public.logout(text,text), public.change_pin(text,text,text,text), public.get_items(text,text),
  public.put_item(text,text,text,text,jsonb), public.patch_item(text,text,text,text,jsonb), public.admin_reset_pin(text,text,text),
  public.admin_remove_traveler(text,text,text) from public;
grant execute on function public.list_travelers(text), public.set_first_pin(text,text,text), public.login_pin(text,text,text), public.join_trip(text,text,text,text),
  public.whoami(text,text), public.logout(text,text), public.change_pin(text,text,text,text), public.get_items(text,text),
  public.put_item(text,text,text,text,jsonb), public.patch_item(text,text,text,text,jsonb), public.admin_reset_pin(text,text,text),
  public.admin_remove_traveler(text,text,text) to anon, authenticated;

-- Fonctions historiques sans session : neutralisées (les anciennes versions de l'appli reçoivent « session expirée »).
create or replace function public.get_items(p_code text) returns json language plpgsql security definer set search_path=public as $$
begin raise exception 'session expiree' using errcode = '28P01'; end $$;
create or replace function public.put_item(p_code text, p_col text, p_id text, p_data jsonb) returns void language plpgsql security definer set search_path=public as $$
begin raise exception 'session expiree' using errcode = '28P01'; end $$;
create or replace function public.patch_item(p_code text, p_col text, p_id text, p_patch jsonb) returns void language plpgsql security definer set search_path=public as $$
begin raise exception 'session expiree' using errcode = '28P01'; end $$;
alter function public._pin_ok(text) set search_path = public;
alter function public._guard(text,text,jsonb,jsonb) set search_path = public;
