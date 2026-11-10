# Next.js: 비밀 키 작업을 서버로 옮기기

클라이언트 컴포넌트는 서버의 라우트 핸들러를 호출하고, 비밀 키는 그 핸들러 안에서만 읽습니다.

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

```tsx
// app/admin/page.tsx
"use client";

export default function Admin() {
  return (
    <button onClick={async () => console.log(await (await fetch("/api/admin/users")).json())}>
      불러오기
    </button>
  );
}
```

실제 서비스에서는 이 라우트 핸들러 앞에 관리자 로그인 확인을 꼭 넣으세요. 비밀 키가 이미 브라우저로 나갔다면 Supabase 대시보드에서 새로 발급해 교체하세요.
