// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
import { HostListener } from '@angular/core';

declare function handle(data: unknown): void;
declare const worker: Worker;
const ALLOWED = ['https://trusted.example'];

window.addEventListener('message', (event) => {
  // ruleid: secreview.js.message-origin-unchecked
  handle(event.data);
});

window.addEventListener('message', (event) => {
  // ok: secreview.js.message-origin-unchecked
  if (event.origin === 'https://trusted.example') handle(event.data);
});

window.addEventListener('message', (e) => {
  if (!ALLOWED.includes(e.origin)) return;
  // ok: secreview.js.message-origin-unchecked
  handle(e.data);
});

worker.onmessage = (event) => {
  // ruleid: secreview.js.message-origin-unchecked
  handle(event.data);
};

export class MessageListener {
  @HostListener('window:message', ['$event'])
  onMessage(event: MessageEvent): void {
    // ruleid: secreview.js.message-origin-unchecked
    handle(event.data);
  }

  @HostListener('window:message', ['$event'])
  onCheckedMessage(event: MessageEvent): void {
    if (event.origin !== ALLOWED[0]) {
      return;
    }
    // ok: secreview.js.message-origin-unchecked
    handle(event.data);
  }
}
