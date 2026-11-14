import "server-only";
import { createClient } from "@supabase/supabase-js";

// 서버에서만 쓰는 관리자 클라이언트. 비밀 키는 브라우저로 나가지 않는다.
export function adminClient() {
  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
  );
}
