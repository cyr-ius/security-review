// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
import { Component, ElementRef, inject } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import { ActivatedRoute } from '@angular/router';
import DOMPurify from 'dompurify';

@Component({ selector: 'app-preview', template: '<div [innerHTML]="html"></div>' })
export class PreviewComponent {
  private readonly sanitizer = inject(DomSanitizer);
  private readonly route = inject(ActivatedRoute);
  private readonly element = inject(ElementRef);
  html: SafeHtml = '';

  show(content: string): void {
    // ruleid: secreview.angular.bypass-security-trust-dynamic
    this.html = this.sanitizer.bypassSecurityTrustHtml(content);
    // ok: secreview.angular.bypass-security-trust-dynamic
    this.html = this.sanitizer.bypassSecurityTrustHtml('<b>static</b>');
    // ok: secreview.angular.bypass-security-trust-dynamic
    this.html = this.sanitizer.bypassSecurityTrustHtml(DOMPurify.sanitize(content));
  }

  fromLink(): void {
    const message = new URLSearchParams(location.search).get('message');
    // ruleid: secreview.js.taint-dom-xss
    this.element.nativeElement.innerHTML = '<p>' + message + '</p>';
    // ok: secreview.js.taint-dom-xss
    this.element.nativeElement.textContent = message;
    // ok: secreview.js.taint-dom-xss
    this.element.nativeElement.innerHTML = DOMPurify.sanitize(message);
  }

  fromRoute(): void {
    const title = this.route.snapshot.queryParamMap.get('title');
    // ruleid: secreview.js.taint-dom-xss
    document.write(`<h1>${title}</h1>`);
  }
}
