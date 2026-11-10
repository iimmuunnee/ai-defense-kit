import { randomBytes } from "crypto";
import { cookies } from "next/headers";

export async function loginUrl() {
  const csrf = randomBytes(16).toString("hex");
  (await cookies()).set("oauth_state", csrf, { httpOnly: true, sameSite: "lax" });
  const clientId = process.env.NAVER_CLIENT_ID!;
  return `https://nid.naver.com/oauth2.0/authorize?response_type=code&client_id=${clientId}&state=${csrf}`;
}
