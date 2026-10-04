create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  role text not null default 'student' check (role in ('admin', 'student')),
  name text not null,
  email text not null unique,
  student_id text unique,
  department text not null default 'General',
  created_at timestamptz not null default now()
);

create table public.exams (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  subject text not null,
  description text not null default '',
  duration integer not null check (duration between 1 and 600),
  total_marks integer not null check (total_marks between 1 and 100000),
  pass_percent integer not null check (pass_percent between 0 and 100),
  instructions text not null default '',
  status text not null default 'draft' check (status in ('draft', 'published')),
  created_at timestamptz not null default now()
);

create table public.questions (
  id uuid primary key default gen_random_uuid(),
  exam_id uuid not null references public.exams(id) on delete cascade,
  text text not null,
  options jsonb not null check (jsonb_typeof(options) = 'array' and jsonb_array_length(options) between 2 and 8),
  position integer not null check (position >= 0),
  created_at timestamptz not null default now(),
  unique (exam_id, position)
);

create table public.answer_keys (
  question_id uuid primary key references public.questions(id) on delete cascade,
  correct_index integer not null check (correct_index >= 0)
);

create table public.attempts (
  id uuid primary key default gen_random_uuid(),
  exam_id uuid not null references public.exams(id),
  student_id uuid not null references public.profiles(id),
  started_at timestamptz not null default now(),
  submitted_at timestamptz,
  answers jsonb not null default '{}'::jsonb,
  check (jsonb_typeof(answers) = 'object')
);

create unique index attempts_one_open_per_student
  on public.attempts (exam_id, student_id) where submitted_at is null;

create table public.results (
  id uuid primary key default gen_random_uuid(),
  attempt_id uuid not null unique references public.attempts(id),
  student_id uuid not null references public.profiles(id),
  student_name text not null,
  exam_id uuid not null references public.exams(id),
  exam_name text not null,
  subject text not null,
  score integer not null,
  total_marks integer not null,
  percentage integer not null check (percentage between 0 and 100),
  passed boolean not null,
  created_at timestamptz not null default now()
);

create table public.notifications (
  id uuid primary key default gen_random_uuid(),
  type text not null,
  student_id uuid not null references public.profiles(id),
  student_name text not null,
  exam_id uuid not null references public.exams(id),
  exam_name text not null,
  reason text not null,
  message text not null,
  created_at timestamptz not null default now()
);

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public, auth
as $$
begin
  insert into public.profiles (id, name, email, student_id, department)
  values (
    new.id,
    coalesce(nullif(trim(new.raw_user_meta_data ->> 'name'), ''), split_part(new.email, '@', 1)),
    lower(new.email),
    nullif(trim(new.raw_user_meta_data ->> 'student_id'), ''),
    coalesce(nullif(trim(new.raw_user_meta_data ->> 'department'), ''), 'General')
  );
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public, auth
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'admin'
  );
$$;

alter table public.profiles enable row level security;
alter table public.exams enable row level security;
alter table public.questions enable row level security;
alter table public.answer_keys enable row level security;
alter table public.attempts enable row level security;
alter table public.results enable row level security;
alter table public.notifications enable row level security;

create policy profiles_read on public.profiles for select to authenticated
  using (id = auth.uid() or public.is_admin());
create policy profiles_update on public.profiles for update to authenticated
  using (id = auth.uid() or public.is_admin())
  with check ((id = auth.uid() and role = 'student') or public.is_admin());

create policy exams_read on public.exams for select to authenticated
  using (status = 'published' or public.is_admin());
create policy exams_admin_insert on public.exams for insert to authenticated
  with check (public.is_admin());
create policy exams_admin_update on public.exams for update to authenticated
  using (public.is_admin()) with check (public.is_admin());
create policy exams_admin_delete on public.exams for delete to authenticated
  using (public.is_admin());

create policy questions_read on public.questions for select to authenticated
  using (public.is_admin() or exists (
    select 1 from public.exams e where e.id = exam_id and e.status = 'published'
  ));
create policy questions_admin_write on public.questions for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

create policy answer_keys_admin_only on public.answer_keys for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

create policy attempts_read on public.attempts for select to authenticated
  using (student_id = auth.uid() or public.is_admin());
create policy results_read on public.results for select to authenticated
  using (student_id = auth.uid() or public.is_admin());
create policy notifications_admin_read on public.notifications for select to authenticated
  using (public.is_admin());

grant usage on schema public to authenticated;
grant select, update on public.profiles to authenticated;
grant select, insert, update, delete on public.exams, public.questions, public.answer_keys to authenticated;
grant select on public.attempts, public.results, public.notifications to authenticated;

create or replace function public.admin_add_question(
  p_exam_id uuid,
  p_text text,
  p_options jsonb,
  p_correct integer
)
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_position integer;
  v_question public.questions%rowtype;
begin
  if not public.is_admin() then raise exception 'Administrator access required.' using errcode = '42501'; end if;
  if coalesce(trim(p_text), '') = '' or length(p_text) > 2000 then raise exception 'Question text is required.'; end if;
  if coalesce(jsonb_typeof(p_options), '') <> 'array' or jsonb_array_length(p_options) < 2 or jsonb_array_length(p_options) > 8 then
    raise exception 'Provide between 2 and 8 answer options.';
  end if;
  if p_correct < 0 or p_correct >= jsonb_array_length(p_options) then raise exception 'Correct answer is out of range.'; end if;
  if exists (select 1 from public.exams where id = p_exam_id and status = 'published') then
    raise exception 'Unpublish the exam before changing its questions.';
  end if;
  select coalesce(max(position) + 1, 0) into v_position from public.questions where exam_id = p_exam_id;
  insert into public.questions (exam_id, text, options, position)
  values (p_exam_id, trim(p_text), p_options, v_position)
  returning * into v_question;
  insert into public.answer_keys (question_id, correct_index) values (v_question.id, p_correct);
  return jsonb_build_object('id', v_question.id, 'text', v_question.text, 'options', v_question.options, 'correct', p_correct, 'marks', 1);
end;
$$;

create or replace function public.start_exam(p_exam_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_exam public.exams%rowtype;
  v_attempt public.attempts%rowtype;
begin
  if auth.uid() is null or not exists (select 1 from public.profiles where id = auth.uid() and role = 'student') then
    raise exception 'Student sign-in required.' using errcode = '42501';
  end if;
  select * into v_exam from public.exams where id = p_exam_id and status = 'published';
  if not found then raise exception 'This exam is not available.'; end if;
  if not exists (select 1 from public.questions where exam_id = p_exam_id) then raise exception 'This exam has no questions.'; end if;
  select * into v_attempt from public.attempts
    where exam_id = p_exam_id and student_id = auth.uid() and submitted_at is null;
  if not found then
    begin
      insert into public.attempts (exam_id, student_id) values (p_exam_id, auth.uid()) returning * into v_attempt;
    exception when unique_violation then
      select * into v_attempt from public.attempts
        where exam_id = p_exam_id and student_id = auth.uid() and submitted_at is null;
    end;
  end if;
  return jsonb_build_object(
    'id', v_attempt.id,
    'examId', v_attempt.exam_id,
    'startedAt', floor(extract(epoch from v_attempt.started_at) * 1000)::bigint,
    'answers', v_attempt.answers
  );
end;
$$;

create or replace function public.save_exam_answer(p_attempt_id uuid, p_question_index integer, p_option_index integer)
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_attempt public.attempts%rowtype;
  v_question public.questions%rowtype;
begin
  select a.* into v_attempt from public.attempts a
  where a.id = p_attempt_id and a.student_id = auth.uid() and a.submitted_at is null
  for update;
  if not found then raise exception 'Active attempt not found.'; end if;
  if now() > v_attempt.started_at + (select duration from public.exams where id = v_attempt.exam_id) * interval '1 minute' + interval '30 seconds' then
    raise exception 'The exam time has expired.';
  end if;
  select * into v_question from public.questions
  where exam_id = v_attempt.exam_id and position = p_question_index;
  if not found then raise exception 'Question not found.'; end if;
  if p_option_index < 0 or p_option_index >= jsonb_array_length(v_question.options) then raise exception 'Answer option not found.'; end if;
  update public.attempts
  set answers = answers || jsonb_build_object(p_question_index::text, p_option_index)
  where id = p_attempt_id
  returning answers into v_attempt.answers;
  return v_attempt.answers;
end;
$$;

create or replace function public.log_exam_integrity_event(p_attempt_id uuid, p_reason text)
returns bigint
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_attempt public.attempts%rowtype;
  v_exam public.exams%rowtype;
  v_created_at timestamptz := now();
begin
  select * into v_attempt from public.attempts
  where id = p_attempt_id and student_id = auth.uid() and submitted_at is null;
  if not found then raise exception 'Active attempt not found.'; end if;
  select * into v_exam from public.exams where id = v_attempt.exam_id;
  insert into public.notifications (type, student_id, student_name, exam_id, exam_name, reason, message, created_at)
  select 'exam-integrity', p.id, p.name, v_exam.id, v_exam.name, left(trim(p_reason), 500),
    p.name || ' triggered an exam integrity alert during ' || v_exam.name || ': ' || left(trim(p_reason), 500), v_created_at
  from public.profiles p where p.id = auth.uid();
  return floor(extract(epoch from v_created_at) * 1000)::bigint;
end;
$$;

create or replace function public.submit_exam(p_attempt_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_attempt public.attempts%rowtype;
  v_exam public.exams%rowtype;
  v_result public.results%rowtype;
  v_question_count integer;
  v_score integer;
  v_percentage integer;
begin
  select * into v_attempt from public.attempts
  where id = p_attempt_id and student_id = auth.uid()
  for update;
  if not found then raise exception 'Attempt not found.'; end if;
  select * into v_result from public.results where attempt_id = p_attempt_id;
  if found then
    return jsonb_build_object('id', v_result.id, 'attemptId', v_result.attempt_id, 'studentId', v_result.student_id,
      'studentName', v_result.student_name, 'examId', v_result.exam_id, 'examName', v_result.exam_name,
      'subject', v_result.subject, 'score', v_result.score, 'totalMarks', v_result.total_marks,
      'percentage', v_result.percentage, 'passed', v_result.passed,
      'createdAt', floor(extract(epoch from v_result.created_at) * 1000)::bigint);
  end if;
  select * into v_exam from public.exams where id = v_attempt.exam_id;
  if now() > v_attempt.started_at + v_exam.duration * interval '1 minute' + interval '30 seconds' then
    raise exception 'The exam time has expired.';
  end if;
  select count(*) into v_question_count from public.questions where exam_id = v_exam.id;
  if v_question_count = 0 then raise exception 'This exam has no questions.'; end if;
  select count(*) into v_score
  from public.questions q
  join public.answer_keys k on k.question_id = q.id
  where q.exam_id = v_exam.id
    and (v_attempt.answers ->> q.position::text)::integer = k.correct_index;
  v_percentage := round(v_score::numeric * 100 / v_question_count)::integer;
  update public.attempts set submitted_at = now() where id = p_attempt_id;
  insert into public.results (attempt_id, student_id, student_name, exam_id, exam_name, subject, score, total_marks, percentage, passed)
  select p_attempt_id, p.id, p.name, v_exam.id, v_exam.name, v_exam.subject, v_score, v_exam.total_marks,
    v_percentage, v_percentage >= v_exam.pass_percent
  from public.profiles p where p.id = auth.uid()
  returning * into v_result;
  return jsonb_build_object('id', v_result.id, 'attemptId', v_result.attempt_id, 'studentId', v_result.student_id,
    'studentName', v_result.student_name, 'examId', v_result.exam_id, 'examName', v_result.exam_name,
    'subject', v_result.subject, 'score', v_result.score, 'totalMarks', v_result.total_marks,
    'percentage', v_result.percentage, 'passed', v_result.passed,
    'createdAt', floor(extract(epoch from v_result.created_at) * 1000)::bigint);
end;
$$;

grant execute on function public.is_admin() to authenticated;
grant execute on function public.admin_add_question(uuid, text, jsonb, integer) to authenticated;
grant execute on function public.start_exam(uuid) to authenticated;
grant execute on function public.save_exam_answer(uuid, integer, integer) to authenticated;
grant execute on function public.log_exam_integrity_event(uuid, text) to authenticated;
grant execute on function public.submit_exam(uuid) to authenticated;