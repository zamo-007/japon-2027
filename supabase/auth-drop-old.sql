-- Anciennes fonctions (sans session) : supprimées.
drop function if exists public.get_items(text);
drop function if exists public.put_item(text,text,text,jsonb);
drop function if exists public.patch_item(text,text,text,jsonb);
