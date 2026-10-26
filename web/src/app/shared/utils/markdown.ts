import { Marked } from 'marked';

const HTML_ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

/**
 * Markdown renderer of the previews. Raw HTML written in the text is shown as text, not
 * interpreted; the result is still bound with [innerHTML], which Angular sanitizes.
 */
const renderer = new Marked({
  gfm: true,
  async: false,
  renderer: {
    html: ({ text }) => text.replace(/[&<>"']/g, (char) => HTML_ESCAPES[char]),
  },
});

/** HTML of a Markdown text, and where each of its top level blocks starts in the text. */
export interface RenderedMarkdown {
  /** One <div> per top level block (heading, paragraph, list, code, table...). */
  html: string;
  /** Character offset in the text of the block rendered by each <div>, in order. */
  offsets: number[];
}

/**
 * Render Markdown text as HTML for a preview. Each top level block gets its own <div>, so that
 * a side by side editor can match the blocks of the text with those of the preview.
 */
export function renderMarkdown(text: string): RenderedMarkdown {
  const tokens = renderer.lexer(text);
  const parts: string[] = [];
  const offsets: number[] = [];
  let offset = 0;
  for (const token of tokens) {
    // Reference links are defined anywhere in the text: each block keeps the whole list.
    const html =
      token.type === 'space'
        ? ''
        : renderer.parser(Object.assign([token], { links: tokens.links }));
    if (html.trim()) {
      parts.push(`<div>${html}</div>`);
      offsets.push(offset);
    }
    offset += token.raw.length;
  }
  return { html: parts.join(''), offsets };
}
