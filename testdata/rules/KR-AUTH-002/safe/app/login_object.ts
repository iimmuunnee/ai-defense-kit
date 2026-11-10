export function loginUrl(csrf: string) {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: process.env.NAVER_CLIENT_ID!,
    state: csrf,
  });
  return `https://nid.naver.com/oauth2.0/authorize?${params}`;
}
