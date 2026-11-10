// 훈련 D7 예제: 외부 응답을 검증 없이 서명 함수에 넘긴다.
// 이 파일에서 나오는 WL-002는 코드 모양에 대한 신호일 뿐이다.
const response = await fetch(counterpartyUrl);
const signature = await signer.signTransaction((await response.json()).tx);
