-- 小年的爱情小屋 · 留言板数据库设置
-- 用法：Supabase 项目 → SQL Editor → New query → 粘贴全部内容 → 把最后一行的密码改成你的管理员密码 → Run

create extension if not exists pgcrypto with schema extensions;

-- 留言表：任何人可读；不能直接写，只能通过下面的函数留言
create table if not exists public.guestbook (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 20),
  content text not null default '' check (char_length(content) <= 500),
  image text check (image is null or image ~ '^[0-9a-f-]{36}\.jpg$'),
  device text check (device is null or char_length(device) <= 20),
  created_at timestamptz not null default now(),
  check (char_length(content) > 0 or image is not null)
);
alter table public.guestbook enable row level security;
drop policy if exists "anyone can read messages" on public.guestbook;
create policy "anyone can read messages" on public.guestbook for select using (true);

-- 管理员密码（只存加密后的哈希，网站访客读不到这张表）
create table if not exists public.guestbook_admin (
  id int primary key default 1 check (id = 1),
  pw_hash text not null
);
alter table public.guestbook_admin enable row level security;

-- 留言：限制长度，并且全站每分钟最多 10 条，防止刷屏
create or replace function public.post_message(p_name text, p_content text, p_image text, p_device text)
returns public.guestbook
language plpgsql security definer set search_path = public
as $$
declare r public.guestbook;
begin
  if (select count(*) from public.guestbook where created_at > now() - interval '1 minute') >= 10 then
    raise exception '留言太频繁了，请稍后再试';
  end if;
  insert into public.guestbook (name, content, image, device)
  values (trim(p_name), coalesce(trim(p_content), ''), nullif(p_image, ''), left(p_device, 20))
  returning * into r;
  return r;
end $$;
revoke all on function public.post_message(text, text, text, text) from public;
grant execute on function public.post_message(text, text, text, text) to anon, authenticated;

-- 删除留言：需要管理员密码
create or replace function public.delete_message(p_id uuid, p_pw text)
returns boolean
language plpgsql security definer set search_path = public, extensions
as $$
begin
  if not exists (select 1 from public.guestbook_admin where pw_hash = crypt(p_pw, pw_hash)) then
    raise exception '管理员密码不对';
  end if;
  delete from public.guestbook where id = p_id;
  return true;
end $$;
revoke all on function public.delete_message(uuid, text) from public;
grant execute on function public.delete_message(uuid, text) to anon, authenticated;

-- 留言图片：公开可看；任何人可上传，但只能是 2 MB 以内的 jpg，文件名必须是随机 ID，且不能覆盖或删除
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('guestbook', 'guestbook', true, 2097152, array['image/jpeg'])
on conflict (id) do update set public = true, file_size_limit = 2097152, allowed_mime_types = array['image/jpeg'];
drop policy if exists "anyone can upload guestbook images" on storage.objects;
create policy "anyone can upload guestbook images" on storage.objects
  for insert to anon, authenticated
  with check (bucket_id = 'guestbook' and name ~ '^[0-9a-f-]{36}\.jpg$');

-- ↓↓↓ 把引号里的内容改成你的管理员密码（建议和网站管理员密码一样），再点 Run ↓↓↓
insert into public.guestbook_admin (id, pw_hash) values (1, extensions.crypt('在这里填你的管理员密码', extensions.gen_salt('bf')))
on conflict (id) do update set pw_hash = excluded.pw_hash;
