# SQL: 테이블에 RLS 켜고 정책 추가하기

새 마이그레이션 파일(예: `supabase/migrations/20260105000000_enable_rls.sql`)에 아래처럼 씁니다. `reports`는 예시 이름이니 본인 테이블 이름으로 바꾸세요.

```sql
-- 1. 행 단위 보안(RLS) 켜기
alter table public.reports enable row level security;

-- 2. 로그인한 사용자가 자기 행만 읽도록 허용하는 정책
create policy "reports_select_own"
  on public.reports
  for select
  to authenticated
  using ((select auth.uid()) = user_id);
```

정책이 없으면 RLS를 켠 뒤 아무도(서버의 비밀 키 제외) 데이터에 접근하지 못합니다. 읽기, 쓰기에 맞는 정책(`insert`, `update`, `delete`)도 필요한 만큼 추가하세요.

테이블을 만들 때마다 자동으로 켜고 싶다면 Supabase 문서의 이벤트 트리거 안내(`event-triggers`)를 참고하세요.
