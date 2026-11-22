import { Signal, TemplateRef } from '@angular/core';

/**
 * A tab of a page with tabs (Rules...) whose buttons belong on the line of the page title, as on
 * the pages without tabs: the page shows the template of the open tab there, still bound to it.
 */
export interface TabWithHeaderActions {
  readonly headerActions: Signal<TemplateRef<unknown> | undefined>;
}

export function hasHeaderActions(component: object): component is TabWithHeaderActions {
  return 'headerActions' in component;
}
