"use client";

import { createClient } from "@supabase/supabase-js";

export default function Admin() {
  const supabase = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
  );
  return <button onClick={() => supabase.from("users").select()}>load</button>;
}
