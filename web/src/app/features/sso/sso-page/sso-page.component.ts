import { Component } from '@angular/core';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { HelpLinkComponent } from '../../../shared/components/help-link/help-link.component';
import { OidcMappingsComponent } from '../oidc-mappings/oidc-mappings.component';
import { SsoSettingsComponent } from '../sso-settings/sso-settings.component';

/**
 * Administrator page for single sign-on: its settings, which override the SECREVIEW_OIDC_*
 * variables, and the OIDC mappings: what an OIDC user may do comes from the mappings of the
 * values of its roles claim, with the roles given to it on the Users page.
 */
@Component({
  selector: 'app-sso-page',
  imports: [HelpLinkComponent, OidcMappingsComponent, SsoSettingsComponent, TranslatePipe],
  templateUrl: './sso-page.component.html',
})
export class SsoPageComponent {}
