/** Styles that change where the text of a text area wraps, copied to its mirror. */
const MIRRORED_STYLES = [
  'font-family',
  'font-size',
  'font-weight',
  'font-style',
  'line-height',
  'letter-spacing',
  'word-spacing',
  'tab-size',
  'text-indent',
  'text-transform',
  'padding-top',
  'padding-right',
  'padding-bottom',
  'padding-left',
];

/**
 * Vertical position of each character offset of a text area's value, in its scrolled content.
 * The text is laid out again, wrapped the same way, in a hidden copy of the text area.
 */
export function textOffsetTops(
  textarea: HTMLTextAreaElement,
  offsets: readonly number[],
): number[] {
  const style = getComputedStyle(textarea);
  const mirror = document.createElement('div');
  for (const name of MIRRORED_STYLES) {
    mirror.style.setProperty(name, style.getPropertyValue(name));
  }
  const padding = parseFloat(style.paddingLeft) + parseFloat(style.paddingRight);
  Object.assign(mirror.style, {
    position: 'absolute',
    top: '0',
    left: '-10000px',
    visibility: 'hidden',
    boxSizing: 'content-box',
    border: '0',
    inlineSize: `${textarea.clientWidth - padding}px`,
    whiteSpace: 'pre-wrap',
    overflowWrap: 'break-word',
  });
  const value = textarea.value;
  const markers: HTMLElement[] = [];
  let start = 0;
  for (const offset of offsets) {
    mirror.append(value.slice(start, offset));
    const marker = document.createElement('span');
    mirror.append(marker);
    markers.push(marker);
    start = offset;
  }
  mirror.append(value.slice(start));
  document.body.append(mirror);
  const tops = markers.map((marker) => marker.offsetTop);
  mirror.remove();
  return tops;
}

/**
 * Scroll position of a pane that matches `top` in another pane. `from` and `to` are the
 * positions of the same anchors (the blocks of a Markdown text) in each pane, in order:
 * between two anchors, the position is interpolated.
 */
export function mapScroll(
  top: number,
  from: readonly number[],
  to: readonly number[],
  fromPane: HTMLElement,
  toPane: HTMLElement,
): number {
  const fromMax = fromPane.scrollHeight - fromPane.clientHeight;
  const toMax = toPane.scrollHeight - toPane.clientHeight;
  if (top >= fromMax - 1) {
    return toMax;
  }
  const source = [0, ...from, fromPane.scrollHeight];
  const target = [0, ...to, toPane.scrollHeight];
  let index = 0;
  while (index < source.length - 2 && source[index + 1] <= top) {
    index++;
  }
  const span = source[index + 1] - source[index];
  const ratio = span > 0 ? (top - source[index]) / span : 0;
  const mapped = target[index] + ratio * (target[index + 1] - target[index]);
  return Math.min(Math.max(mapped, 0), toMax);
}
