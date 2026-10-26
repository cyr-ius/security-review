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

/** Render Markdown text as HTML for a preview. */
export function renderMarkdown(text: string): string {
  return renderer.parse(text, { async: false });
}
