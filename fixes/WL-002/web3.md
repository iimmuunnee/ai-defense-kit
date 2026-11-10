# Web3: 서명하기 전에 입력을 검사하고 한도 두기

서명 함수에는 요청이나 외부 응답을 그대로 넘기지 말고, 검사를 거친 값으로 서버가 만든 거래만 넘기세요.

```ts
import { z } from "zod";

const Transfer = z.object({
  to: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
  amount: z.coerce.bigint().positive(),
});

const input = Transfer.parse(req.body); // 형식이 맞지 않으면 여기서 멈춥니다

if (!ALLOWED_RECIPIENTS.has(input.to.toLowerCase())) throw new Error("허용되지 않은 받는 주소");
if (input.amount > MAX_AMOUNT) throw new Error("한도 초과");

// 서버가 정한 값으로 거래를 만들어 서명합니다
const sig = await wallet.signTransaction({ to: input.to, value: input.amount, chainId: CHAIN_ID });
```

- 받는 주소는 허용 목록과 비교하고, 금액에는 한 건과 하루 합계 한도를 두세요.
- 외부 서버의 응답으로 서명할 내용을 정하지 마세요. 꼭 필요하면 응답에서 필요한 필드만 꺼내 같은 검사를 거치세요.
- 서명하는 사람에게 받는 주소와 금액을 읽을 수 있는 형태로 보여 주는 단계가 필요한지 검토하세요.
- 위 예시의 `zod`와 허용 목록은 설명용입니다. 쓰는 라이브러리에 맞게 바꾸세요.
- 이미 검증한 코드라면 지문을 `.adkignore`에 적어 무시할 수 있습니다.
