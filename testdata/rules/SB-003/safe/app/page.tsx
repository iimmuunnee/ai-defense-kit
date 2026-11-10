"use client";

import { createClient } from "@supabase/supabase-js";

export default function Page() {
  const supabase = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY!,
  );
  return <button onClick={() => supabase.from("posts").select()}>load</button>;
}
