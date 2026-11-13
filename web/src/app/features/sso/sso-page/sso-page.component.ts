import { Component } from '@angular/core';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { OidcMappingsComponent } from '../oidc-mappings/oidc-mappings.component';
import { SsoSettingsComponent } from '../sso-settings/sso-settings.component';

/**
 * OIDC sign-in tab of the Users page: its settings, which override the SECREVIEW_OIDC_*
 * variables, and the OIDC mappings: what an OIDC user may do comes from the mappings of the
 * values of its roles claim, with the roles given to it on the Accounts tab.
 */
@Component({
  selector: 'app-sso-page',
  imports: [OidcMappingsComponent, SsoSettingsComponent, TranslatePipe],
  templateUrl: './sso-page.component.html',
})
export class SsoPageComponent {}
