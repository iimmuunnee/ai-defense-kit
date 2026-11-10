# React: HTML을 넣기 전에 정리하기

가능하면 HTML 대신 글자로 보여 주세요. React는 `{text}`로 넣은 내용을 코드로 실행하지 않습니다.

```tsx
<div>{comment.text}</div>
```

HTML을 꼭 보여 줘야 하면 믿을 수 있는 정리 라이브러리(예: DOMPurify)를 거칩니다. 라이브러리 사용법과 설정은 공식 문서로 확인하세요.

```tsx
import DOMPurify from "dompurify";

<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.html) }} />
```
