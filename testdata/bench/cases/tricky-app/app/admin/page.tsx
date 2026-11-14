"use client";

import { createClient } from "@supabase/supabase-js";

// 비밀 키를 다른 이름의 변수에 담아 클라이언트 컴포넌트에서 쓴다.
const url = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const adminKey = process.env.SUPABASE_SERVICE_ROLE_KEY!;

export default function Admin() {
  const supabase = createClient(url, adminKey);
  return <button onClick={() => supabase.from("orders").select()}>load</button>;
}
