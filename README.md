# Orbit Examination Portal

The static site uses Supabase Free for authentication and its Postgres backend. Row-level security protects user data and answer keys; SQL RPCs create attempts, save answers, log integrity events, and calculate results server-side.

## Supabase setup

The migration is in `supabase/migrations/20261004_exam_portal.sql`. It has been applied to the linked Supabase project. If setting up a different project, run that file in its SQL Editor, then set the project's Site URL to the deployed site and allow redirects for `https://kotharitirthesh30-jpg.github.io/**` and `http://localhost:3000/**`.

`app.html` contains the Supabase project URL and publishable key. Publishable keys are intended for browser use; table access is controlled by RLS. Never put a Supabase secret or service-role key in this repository.

Student registration creates a student profile. To designate the first administrator, register and confirm that account, then run this in the Supabase SQL Editor with its email:

```sql
update public.profiles
set role = 'admin'
where email = lower('your-admin-email@example.com');
```

## Local preview

Open `index.html` with a static server such as VS Code Live Server. Authentication and data use the configured Supabase project. GitHub Pages can serve this site directly; no paid Node host is required.