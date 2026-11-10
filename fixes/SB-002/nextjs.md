# Next.js: 비밀 키를 서버 전용 환경 변수로 옮기기

`.env.local`에서 `NEXT_PUBLIC_`을 빼고, 비밀 키는 서버 코드에서만 읽습니다. 브라우저용 클라이언트는 공개용 키를 씁니다.

```bash
# .env.local
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=sb_publishable_xxxxxxxxxxxx   # 브라우저에 나가도 되는 키
SUPABASE_SECRET_KEY=sb_secret_xxxxxxxxxxxx                          # NEXT_PUBLIC_ 없음: 서버 전용
```

```ts
// app/api/admin/users/route.ts (서버에서만 실행됨)
import { createClient } from "@supabase/supabase-js";

export async function GET() {
  const supabase = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SECRET_KEY!,
  );
  const { data } = await supabase.from("profiles").select();
  return Response.json(data);
}
```

이미 `NEXT_PUBLIC_`을 붙여 배포했거나 저장소에 올렸다면 Supabase 대시보드에서 그 키를 새로 발급해 교체하세요.
