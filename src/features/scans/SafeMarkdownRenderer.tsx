import { Streamdown, type StreamdownProps } from 'streamdown';
import { CopyText } from './safeMarkdown';
import { safeMarkdownUrl } from './safeMarkdownPolicy';

const components: StreamdownProps['components'] = {
  a: ({ href, children }) => {
    const safe = safeMarkdownUrl(href);
    return safe ? (
      <a href={safe} target="_blank" rel="noopener noreferrer nofollow">
        {children}
      </a>
    ) : (
      <span>{children}</span>
    );
  },
  img: ({ alt }) => <span>{alt ?? 'Изображение отключено'}</span>,
  code: ({ children }) => <code>{children}</code>,
  pre: ({ children, node }) => {
    const code =
      node?.children
        .flatMap((child) =>
          child.type === 'element'
            ? child.children.flatMap((part) => (part.type === 'text' ? part.value : ''))
            : [],
        )
        .join('') ?? '';
    return (
      <div>
        <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{children}</pre>
        <CopyText text={code} label="Скопировать код" />
      </div>
    );
  },
};
const noPlugins: NonNullable<StreamdownProps['rehypePlugins']> = [];
export default function SafeMarkdownRenderer({ text }: { text: string }) {
  return (
    <Streamdown
      mode="static"
      parseIncompleteMarkdown={false}
      controls={false}
      components={components}
      rehypePlugins={noPlugins}
      remarkPlugins={noPlugins}
      remarkRehypeOptions={{ allowDangerousHtml: false }}
    >
      {text}
    </Streamdown>
  );
}
