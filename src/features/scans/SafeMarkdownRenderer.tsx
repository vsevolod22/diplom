import { Streamdown, type StreamdownProps } from 'streamdown';
import remarkGfm from 'remark-gfm';
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
  table: ({ children }) => (
    <div className="scan-markdown__table" role="region" aria-label="Таблица" tabIndex={0}>
      <table>{children}</table>
    </div>
  ),
};
const codeBlock: NonNullable<StreamdownProps['components']>['pre'] = ({ children, node }) => {
  const code =
    node?.children
      .flatMap((child) =>
        child.type === 'element'
          ? child.children.flatMap((part) => (part.type === 'text' ? part.value : ''))
          : [],
      )
      .join('') ?? '';
  return (
    <div className="scan-markdown__code-block">
      <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{children}</pre>
      <CopyText text={code} label="Скопировать код" />
    </div>
  );
};
const copyComponents: StreamdownProps['components'] = { ...components, pre: codeBlock };
const previewComponents: StreamdownProps['components'] = {
  ...components,
  pre: ({ children }) => <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{children}</pre>,
};
const noPlugins: NonNullable<StreamdownProps['rehypePlugins']> = [];
const remarkPlugins: NonNullable<StreamdownProps['remarkPlugins']> = [remarkGfm];
export default function SafeMarkdownRenderer({
  text,
  showCopy = true,
}: {
  text: string;
  showCopy?: boolean;
}) {
  return (
    <Streamdown
      className="scan-markdown"
      mode="static"
      parseIncompleteMarkdown={false}
      controls={false}
      components={showCopy ? copyComponents : previewComponents}
      rehypePlugins={noPlugins}
      remarkPlugins={remarkPlugins}
      remarkRehypeOptions={{ allowDangerousHtml: false }}
    >
      {text}
    </Streamdown>
  );
}
