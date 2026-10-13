-- Durcissement de sécurité du 13/10/2026 (audit).
-- 1) Validation par l'organisateur : tout nouveau voyageur et toute première création de PIN restent « en attente ».
-- 2) Verrouillage progressif du PIN (10 min, 30 min, 1 h 30, … jusqu'à 24 h).
-- 3) Les voyageurs en attente ne voient rien et n'apparaissent pas chez les autres.

alter table public.members add column if not exists approved boolean not null default true;
alter table public.members add column if not exists lock_level int not null default 0;
alter table public.members add column if not exists pending_since timestamptz;

create or replace function public._lock_for(lvl int) returns interval language sql immutable set search_path=public as $$
  select least(interval '24 hours', interval '10 minutes' * power(3, greatest(lvl,0)))
$$;

create or replace function public._is_pending(tid uuid, trav text) returns boolean language sql stable security definer set search_path=public as $$
  select coalesce((select not approved from public.members where trip_id = tid and traveler_id = trav), false)
$$;

-- Session valide ET voyageur validé par l'organisateur.
create or replace function public._sess(p_code text, p_token text, out tid uuid, out me text, out is_admin boolean)
language plpgsql security definer set search_path=public as $$
declare s public.sessions;
begin
  tid := public._tid(p_code);
  select * into s from public.sessions where token_hash = public._hash(p_token) and trip_id = tid;
  if s.token_hash is null or s.revoked or s.last_seen < now() - interval '24 hours' then
    raise exception 'session expiree' using errcode = '28P01';
  end if;
  if public._is_pending(tid, s.traveler_id) then
    raise exception 'en attente' using errcode = '28P02';
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
  return json_build_object('ok', true, 'token', tok, 'me', trav, 'pending', public._is_pending(tid, trav),
    'admin', coalesce((select admin_id from public.trips where id = tid) = trav, false));
end $$;

-- whoami : distingue « en attente » d'une session expirée.
create or replace function public.whoami(p_code text, p_token text) returns json language plpgsql security definer set search_path=public as $$
declare tid uuid := public._tid(p_code); s public.sessions;
begin
  select * into s from public.sessions where token_hash = public._hash(p_token) and trip_id = tid;
  if s.token_hash is null or s.revoked or s.last_seen < now() - interval '24 hours' then
    raise exception 'session expiree' using errcode = '28P01';
  end if;
  if public._is_pending(tid, s.traveler_id) then
    return json_build_object('me', s.traveler_id, 'admin', false, 'pending', true);
  end if;
  update public.sessions set last_seen = now() where token_hash = s.token_hash;
  return json_build_object('me', s.traveler_id, 'pending', false,
    'admin', coalesce((select admin_id from public.trips where id = tid) = s.traveler_id, false));
end $$;

create or replace function public.list_travelers(p_code text) returns json language plpgsql stable security definer set search_path=public as $$
declare tid uuid := public._tid(p_code);
begin
  return coalesce((select json_agg(json_build_object('id', i.id, 'name', i.data->>'name', 'color', i.data->>'color',
      'order', i.data->'order', 'has_pin', m.pin_hash is not null) order by (i.data->>'order')::numeric nulls last)
    from public.items i left join public.members m on m.trip_id = i.trip_id and m.traveler_id = i.id
    where i.trip_id = tid and i.col = 'travelers' and not (i.data ? '_deleted') and coalesce(m.approved, true)), '[]'::json);
end $$;

create or replace function public.set_first_pin(p_code text, p_traveler text, p_pin text) returns json language plpgsql security definer set search_path=public,extensions as $$
declare tid uuid := public._tid(p_code); m public.members; n int;
begin
  if not public._pin_ok(p_pin) then return json_build_object('ok', false, 'error', 'format'); end if;
  if not public._traveler_exists(tid, p_traveler) then return json_build_object('ok', false, 'error', 'unknown'); end if;
  select * into m from public.members where trip_id = tid and traveler_id = p_traveler for update;
  if m.pin_hash is not null then return json_build_object('ok', false, 'error', 'already'); end if;
  insert into public.members(trip_id, traveler_id, pin_hash, failed, locked_until, pin_set_at, approved, pending_since)
    values (tid, p_traveler, extensions.crypt(p_pin, extensions.gen_salt('bf', 8)), 0, null, now(), false, now())
    on conflict (trip_id, traveler_id) do update set pin_hash = excluded.pin_hash, failed = 0, locked_until = null, pin_set_at = now(),
      approved = false, pending_since = now()
    where public.members.pin_hash is null;
  get diagnostics n = row_count;
  if n = 0 then return json_build_object('ok', false, 'error', 'already'); end if;
  return public._new_session(tid, p_traveler);
end $$;

create or replace function public.join_trip(p_code text, p_name text, p_color text, p_pin text) returns json language plpgsql security definer set search_path=public,extensions as $$
declare tid uuid := public._tid(p_code); n text := left(btrim(coalesce(p_name,'')), 24); nid text; ord int; v_col text;
begin
  if n = '' then return json_build_object('ok', false, 'error', 'name'); end if;
  if not public._pin_ok(p_pin) then return json_build_object('ok', false, 'error', 'format'); end if;
  if exists(select 1 from public.items where trip_id = tid and col = 'travelers' and not (data ? '_deleted') and lower(data->>'name') = lower(n)) then
    return json_build_object('ok', false, 'error', 'exists');
  end if;
  if (select count(*) from public.members where trip_id = tid and not approved) >= 10 then
    return json_build_object('ok', false, 'error', 'busy');
  end if;
  v_col := case when coalesce(p_color,'') ~ '^#[0-9A-Fa-f]{6}$' then p_color else '#E9A93F' end;
  nid := 'p' || encode(extensions.gen_random_bytes(6),'hex');
  select count(*) + 1 into ord from public.items where trip_id = tid and col = 'travelers';
  insert into public.items(trip_id, col, id, data, updated_at) values (tid, 'travelers', nid,
    jsonb_build_object('name', n, 'color', v_col, 'order', ord, 'createdAt', to_char(now() at time zone 'utc','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')), now());
  insert into public.members(trip_id, traveler_id, pin_hash, pin_set_at, approved, pending_since)
    values (tid, nid, extensions.crypt(p_pin, extensions.gen_salt('bf', 8)), now(), false, now());
  return public._new_session(tid, nid);
end $$;

create or replace function public.login_pin(p_code text, p_traveler text, p_pin text) returns json language plpgsql security definer set search_path=public,extensions as $$
declare tid uuid := public._tid(p_code); m public.members; w interval;
begin
  select * into m from public.members where trip_id = tid and traveler_id = p_traveler for update;
  if m.pin_hash is null or not public._traveler_exists(tid, p_traveler) then return json_build_object('ok', false, 'error', 'nopin'); end if;
  if m.locked_until is not null and m.locked_until > now() then
    return json_build_object('ok', false, 'error', 'locked', 'wait', ceil(extract(epoch from m.locked_until - now())));
  end if;
  if m.pin_hash = extensions.crypt(coalesce(p_pin,''), m.pin_hash) then
    update public.members set failed = 0, locked_until = null, lock_level = 0 where trip_id = tid and traveler_id = p_traveler;
    return public._new_session(tid, p_traveler);
  end if;
  if m.failed + 1 >= 5 then
    w := public._lock_for(m.lock_level);
    update public.members set failed = 0, locked_until = now() + w, lock_level = m.lock_level + 1 where trip_id = tid and traveler_id = p_traveler;
    return json_build_object('ok', false, 'error', 'locked', 'wait', ceil(extract(epoch from w)));
  end if;
  update public.members set failed = m.failed + 1 where trip_id = tid and traveler_id = p_traveler;
  return json_build_object('ok', false, 'error', 'wrong', 'left', 5 - (m.failed + 1));
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
      locked_until = case when m.failed + 1 >= 5 then now() + public._lock_for(m.lock_level) else null end,
      lock_level = case when m.failed + 1 >= 5 then m.lock_level + 1 else m.lock_level end
      where trip_id = s.tid and traveler_id = s.me;
    return json_build_object('ok', false, 'error', 'wrong');
  end if;
  update public.members set pin_hash = extensions.crypt(p_new, extensions.gen_salt('bf', 8)), failed = 0, locked_until = null, lock_level = 0, pin_set_at = now()
    where trip_id = s.tid and traveler_id = s.me;
  update public.sessions set revoked = true where trip_id = s.tid and traveler_id = s.me and token_hash <> public._hash(p_token);
  return json_build_object('ok', true);
end $$;

-- Lecture : ni les éléments perso des autres, ni les voyageurs encore en attente.
create or replace function public.get_items(p_code text, p_token text) returns json language plpgsql security definer set search_path=public as $$
declare s record;
begin
  select * into s from public._sess(p_code, p_token);
  return coalesce((select json_agg(json_build_object('col', i.col, 'id', i.id, 'data', i.data, 'updated_at', i.updated_at))
    from public.items i where i.trip_id = s.tid and not (i.data ? '_deleted')
      and (i.data->>'owner' is null or i.data->>'owner' = s.me)
      and not (i.col = 'travelers' and public._is_pending(s.tid, i.id))), '[]'::json);
end $$;

create or replace function public.admin_pending(p_code text, p_token text) returns json language plpgsql security definer set search_path=public as $$
declare s record;
begin
  select * into s from public._sess(p_code, p_token);
  if not s.is_admin then raise exception 'interdit' using errcode = '42501'; end if;
  return coalesce((select json_agg(json_build_object('id', m.traveler_id, 'name', i.data->>'name', 'color', i.data->>'color', 'since', m.pending_since,
      'claim', (i.data->>'createdAt') is null or (i.data->>'createdAt')::timestamptz < m.pending_since - interval '1 minute') order by m.pending_since)
    from public.members m join public.items i on i.trip_id = m.trip_id and i.col = 'travelers' and i.id = m.traveler_id and not (i.data ? '_deleted')
    where m.trip_id = s.tid and not m.approved), '[]'::json);
end $$;

create or replace function public.admin_approve(p_code text, p_token text, p_traveler text) returns json language plpgsql security definer set search_path=public as $$
declare s record;
begin
  select * into s from public._sess(p_code, p_token);
  if not s.is_admin then raise exception 'interdit' using errcode = '42501'; end if;
  update public.members set approved = true, pending_since = null where trip_id = s.tid and traveler_id = p_traveler;
  return json_build_object('ok', true);
end $$;

-- Réinitialiser : le PIN est effacé, les sessions fermées ; le prochain PIN devra être validé.
create or replace function public.admin_reset_pin(p_code text, p_token text, p_traveler text) returns json language plpgsql security definer set search_path=public as $$
declare s record;
begin
  select * into s from public._sess(p_code, p_token);
  if not s.is_admin or p_traveler = s.me then raise exception 'interdit' using errcode = '42501'; end if;
  update public.members set pin_hash = null, failed = 0, locked_until = null, lock_level = 0, pin_set_at = null, approved = true, pending_since = null
    where trip_id = s.tid and traveler_id = p_traveler;
  update public.sessions set revoked = true where trip_id = s.tid and traveler_id = p_traveler;
  return json_build_object('ok', true);
end $$;

revoke all on function public._lock_for(int), public._is_pending(uuid,text) from public, anon, authenticated;
revoke all on function public.admin_pending(text,text), public.admin_approve(text,text,text) from public;
grant execute on function public.admin_pending(text,text), public.admin_approve(text,text,text) to anon, authenticated;

-- Fichiers : seulement des images dans le bucket photos.
update storage.buckets set allowed_mime_types = array['image/jpeg','image/png','image/webp','image/heic','image/heif','image/gif','image/avif'] where id = 'photos';
