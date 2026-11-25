-- Secret Santa Supabase schema. Run this entire file in Supabase SQL Editor.
create extension if not exists pgcrypto;

create table if not exists public.games (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  join_code text not null unique,
  budget text,
  organizer_id uuid not null references auth.users(id) on delete cascade,
  drawn boolean not null default false,
  created_at timestamptz not null default now()
);
create table if not exists public.participants (
  id uuid primary key default gen_random_uuid(),
  game_id uuid not null references public.games(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  display_name text not null,
  role text not null default 'participant' check(role in ('organizer','participant')),
  created_at timestamptz not null default now(),
  unique(game_id,user_id)
);
create table if not exists public.wishlists (
  participant_id uuid primary key references public.participants(id) on delete cascade,
  content text not null default '',
  updated_at timestamptz not null default now()
);
create table if not exists public.exclusions (
  game_id uuid not null references public.games(id) on delete cascade,
  giver_id uuid not null references public.participants(id) on delete cascade,
  recipient_id uuid not null references public.participants(id) on delete cascade,
  primary key(game_id,giver_id,recipient_id),
  check(giver_id <> recipient_id)
);
create table if not exists public.assignments (
  game_id uuid not null references public.games(id) on delete cascade,
  giver_id uuid not null references public.participants(id) on delete cascade,
  recipient_id uuid not null references public.participants(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key(game_id,giver_id),
  unique(game_id,recipient_id),
  check(giver_id <> recipient_id)
);

-- Security-definer helpers avoid recursive RLS checks on participants.
create or replace function public.is_game_member(p_game_id uuid)
returns boolean language sql stable security definer set search_path=public
as $$ select exists(select 1 from participants p where p.game_id=p_game_id and p.user_id=auth.uid()); $$;
create or replace function public.is_game_organizer(p_game_id uuid)
returns boolean language sql stable security definer set search_path=public
as $$ select exists(select 1 from participants p where p.game_id=p_game_id and p.user_id=auth.uid() and p.role='organizer'); $$;
create or replace function public.can_view_wishlist(p_participant_id uuid)
returns boolean language sql stable security definer set search_path=public
as $$
 select exists(select 1 from participants p where p.id=p_participant_id and p.user_id=auth.uid())
 or exists(select 1 from assignments a join participants g on g.id=a.giver_id where a.recipient_id=p_participant_id and g.user_id=auth.uid());
$$;

alter table public.games enable row level security;
alter table public.participants enable row level security;
alter table public.wishlists enable row level security;
alter table public.exclusions enable row level security;
alter table public.assignments enable row level security;

-- Members can see game metadata and the participant list, but never all wishlists/results.
drop policy if exists games_member_read on public.games;
create policy games_member_read on public.games for select to authenticated using(public.is_game_member(id));
drop policy if exists participants_member_read on public.participants;
create policy participants_member_read on public.participants for select to authenticated using(public.is_game_member(game_id));
drop policy if exists wishlists_private_read on public.wishlists;
create policy wishlists_private_read on public.wishlists for select to authenticated using(public.can_view_wishlist(participant_id));
drop policy if exists exclusions_organizer_read on public.exclusions;
create policy exclusions_organizer_read on public.exclusions for select to authenticated using(public.is_game_organizer(game_id));
drop policy if exists assignments_giver_read on public.assignments;
create policy assignments_giver_read on public.assignments for select to authenticated using(exists(select 1 from participants p where p.id=giver_id and p.user_id=auth.uid()));
-- No direct insert/update/delete policies: mutations go through validated RPC functions.

create or replace function public.create_game(p_name text,p_budget text default null)
returns jsonb language plpgsql security definer set search_path=public
as $$
declare v_game games%rowtype; v_code text;
begin
 if auth.uid() is null then raise exception 'Sign in first'; end if;
 if length(trim(coalesce(p_name,''))) < 2 then raise exception 'Game name must be at least 2 characters'; end if;
 loop
   v_code := 'SANTA-' || upper(substr(encode(gen_random_bytes(4),'hex'),1,6));
   exit when not exists(select 1 from games where join_code=v_code);
 end loop;
 insert into games(name,join_code,budget,organizer_id) values(trim(p_name),v_code,nullif(trim(p_budget),''),auth.uid()) returning * into v_game;
 insert into participants(game_id,user_id,display_name,role) values(v_game.id,auth.uid(),'Организатор','organizer');
 return jsonb_build_object('id',v_game.id,'join_code',v_game.join_code,'name',v_game.name,'budget',v_game.budget);
end; $$;

create or replace function public.join_game(p_code text,p_display_name text)
returns jsonb language plpgsql security definer set search_path=public
as $$
declare v_game games%rowtype; v_part participants%rowtype;
begin
 if auth.uid() is null then raise exception 'Sign in first'; end if;
 if length(trim(coalesce(p_display_name,''))) < 1 then raise exception 'Enter a display name'; end if;
 select * into v_game from games where join_code=upper(trim(p_code));
 if not found then raise exception 'Game code not found'; end if;
 if v_game.drawn then raise exception 'This game has already drawn'; end if;
 insert into participants(game_id,user_id,display_name,role) values(v_game.id,auth.uid(),trim(p_display_name),'participant')
 on conflict(game_id,user_id) do update set display_name=excluded.display_name returning * into v_part;
 return jsonb_build_object('game_id',v_game.id,'participant_id',v_part.id);
end; $$;

create or replace function public.save_wishlist(p_content text)
returns void language plpgsql security definer set search_path=public
as $$
declare v_pid uuid;
begin
 if auth.uid() is null then raise exception 'Sign in first'; end if;
 select id into v_pid from participants where user_id=auth.uid() order by created_at desc limit 1;
 -- The frontend calls this while viewing a game; use the participant belonging to current user and selected game from a safe explicit context below.
 if v_pid is null then raise exception 'You are not in any game'; end if;
 -- Save to most recently joined membership. (Function below is the game-specific safer variant.)
 insert into wishlists(participant_id,content,updated_at) values(v_pid,coalesce(p_content,''),now()) on conflict(participant_id) do update set content=excluded.content,updated_at=now();
end; $$;

create or replace function public.save_game_wishlist(p_game_id uuid,p_content text)
returns void language plpgsql security definer set search_path=public
as $$
declare v_pid uuid;
begin
 select id into v_pid from participants where game_id=p_game_id and user_id=auth.uid();
 if v_pid is null then raise exception 'Not a member of this game'; end if;
 insert into wishlists(participant_id,content,updated_at) values(v_pid,coalesce(p_content,''),now()) on conflict(participant_id) do update set content=excluded.content,updated_at=now();
end; $$;

create or replace function public.add_exclusion(p_game_id uuid,p_giver_id uuid,p_recipient_id uuid)
returns void language plpgsql security definer set search_path=public
as $$
begin
 if not public.is_game_organizer(p_game_id) then raise exception 'Organizer permission required'; end if;
 if exists(select 1 from games where id=p_game_id and drawn) then raise exception 'Draw already completed'; end if;
 if not exists(select 1 from participants where id=p_giver_id and game_id=p_game_id) or not exists(select 1 from participants where id=p_recipient_id and game_id=p_game_id) then raise exception 'Participants must belong to this game'; end if;
 if p_giver_id=p_recipient_id then raise exception 'A participant cannot be excluded from themselves'; end if;
 insert into exclusions(game_id,giver_id,recipient_id) values(p_game_id,p_giver_id,p_recipient_id) on conflict do nothing;
end; $$;
create or replace function public.remove_exclusion(p_game_id uuid,p_giver_id uuid,p_recipient_id uuid)
returns void language plpgsql security definer set search_path=public
as $$
begin
 if not public.is_game_organizer(p_game_id) then raise exception 'Organizer permission required'; end if;
 delete from exclusions where game_id=p_game_id and giver_id=p_giver_id and recipient_id=p_recipient_id;
end; $$;

create or replace function public.run_draw(p_game_id uuid)
returns void language plpgsql security definer set search_path=public
as $$
declare v_ids uuid[]; v_order uuid[]; v_count int; v_attempt int; v_ok boolean; v_i int; v_giver uuid; v_recipient uuid;
begin
 if not public.is_game_organizer(p_game_id) then raise exception 'Organizer permission required'; end if;
 perform 1 from games where id=p_game_id for update;
 if (select drawn from games where id=p_game_id) then raise exception 'Draw already completed'; end if;
 select array_agg(id order by random()),count(*) into v_ids,v_count from participants where game_id=p_game_id;
 if v_count<2 then raise exception 'At least 2 participants required'; end if;
 v_ok:=false;
 for v_attempt in 1..10000 loop
   select array_agg(id order by random()) into v_order from participants where game_id=p_game_id;
   v_ok:=true;
   for v_i in 1..v_count loop
     v_giver:=v_ids[v_i]; v_recipient:=v_order[v_i];
     if v_giver=v_recipient or exists(select 1 from exclusions where game_id=p_game_id and giver_id=v_giver and recipient_id=v_recipient) then v_ok:=false; exit; end if;
   end loop;
   if v_ok then exit; end if;
 end loop;
 if not v_ok then raise exception 'No valid assignment found with current restrictions. Remove some exclusions and try again.'; end if;
 for v_i in 1..v_count loop
   insert into assignments(game_id,giver_id,recipient_id) values(p_game_id,v_ids[v_i],v_order[v_i]);
 end loop;
 update games set drawn=true where id=p_game_id;
end; $$;

-- Restrict RPC execution to signed-in users.
revoke all on function public.create_game(text,text) from public;
revoke all on function public.join_game(text,text) from public;
revoke all on function public.save_wishlist(text) from public;
revoke all on function public.save_game_wishlist(uuid,text) from public;
revoke all on function public.add_exclusion(uuid,uuid,uuid) from public;
revoke all on function public.remove_exclusion(uuid,uuid,uuid) from public;
revoke all on function public.run_draw(uuid) from public;
grant execute on function public.create_game(text,text) to authenticated;
grant execute on function public.join_game(text,text) to authenticated;
grant execute on function public.save_wishlist(text) to authenticated;
grant execute on function public.save_game_wishlist(uuid,text) to authenticated;
grant execute on function public.add_exclusion(uuid,uuid,uuid) to authenticated;
grant execute on function public.remove_exclusion(uuid,uuid,uuid) to authenticated;
grant execute on function public.run_draw(uuid) to authenticated;
-- Select access is through RLS; authenticated role needs select only.
grant select on public.games,public.participants,public.wishlists,public.exclusions,public.assignments to authenticated;
