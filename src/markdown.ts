import { marked } from 'marked';

/**
 * Render Markdown body text to an HTML fragment suitable for an email HTML part.
 * GFM on (tables, lists, autolinks); `breaks: true` so single newlines become <br>,
 * matching how a model writes an email body. Raw HTML in the source passes through.
 *
 * No wrapper <html>/<body> and no inline styling: Gmail accepts a fragment and
 * renders it with its own defaults.
 */
export function markdownToHtml(markdown: string): string {
 if (!markdown || markdown.trim() === '') return '';
 return marked.parse(markdown, { async: false, gfm: true, breaks: true });
}
