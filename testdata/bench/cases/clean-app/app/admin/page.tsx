import { adminClient } from "../../lib/supabase-admin";

// 서버 컴포넌트: 관리자 클라이언트는 서버에서만 돈다.
export default async function Admin() {
  const { data } = await adminClient().from("orders").select("id,total");
  return <pre>{JSON.stringify(data)}</pre>;
}
