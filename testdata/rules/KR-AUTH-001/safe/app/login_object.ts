export function loginUrl(csrf: string) {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: process.env.KAKAO_CLIENT_ID!,
    state: csrf,
  });
  return `https://kauth.kakao.com/oauth/authorize?${params}`;
}
