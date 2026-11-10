export function Comment({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
