import { defineMessages } from '../catalog';

/** My account page. */
export const account = defineMessages({
  en: {
    'account.mustChange':
      'Your password was set by an administrator: choose your own before using the interface.',
    'account.sso': 'OIDC account',
    'account.local': 'Local account',
    'account.permissionsTitle': 'My permissions',
    'account.passwordTitle': 'Change password',
    'account.current': 'Current password',
    'account.new': 'New password',
    'account.confirmation': 'Confirmation',
    'account.mismatch': 'The two passwords differ.',
    'account.submit': 'Change the password',
    'account.ssoInfo': 'OIDC account: the password is managed by your identity provider, not here.',
    'account.changed': 'Password changed. Your other sessions were closed.',
    'account.wrongCurrent': 'The current password is wrong.',
    'account.mustDiffer': 'The new password must differ from the current one.',
    'account.refusedDetail': 'Password refused: {detail}',
    'account.refused': 'Password refused.',
    'account.failed': 'The password change failed.',
    'apiTokens.title': 'API tokens',
    'apiTokens.help':
      'A personal API token calls the REST API (Swagger “Authorize” button, scripts) with your current rights, which come from your groups. It stops working when your account is deleted or loses its rights. Like every token, it never accepts a risk nor marks a false positive.',
    'apiTokens.create': 'Create a token',
    'apiTokens.empty': 'No API tokens.',
  },
  fr: {
    'account.mustChange':
      'Votre mot de passe a été défini par un administrateur : choisissez le vôtre avant d’utiliser l’interface.',
    'account.sso': 'Compte OIDC',
    'account.local': 'Compte local',
    'account.permissionsTitle': 'Mes permissions',
    'account.passwordTitle': 'Changer de mot de passe',
    'account.current': 'Mot de passe actuel',
    'account.new': 'Nouveau mot de passe',
    'account.confirmation': 'Confirmation',
    'account.mismatch': 'Les deux mots de passe diffèrent.',
    'account.submit': 'Changer le mot de passe',
    'account.ssoInfo':
      "Compte OIDC : le mot de passe est géré par votre fournisseur d'identité, pas ici.",
    'account.changed': 'Mot de passe modifié. Vos autres sessions ont été fermées.',
    'account.wrongCurrent': 'Le mot de passe actuel est incorrect.',
    'account.mustDiffer': "Le nouveau mot de passe doit être différent de l'actuel.",
    'account.refusedDetail': 'Mot de passe refusé : {detail}',
    'account.refused': 'Mot de passe refusé.',
    'account.failed': 'Le changement de mot de passe a échoué.',
    'apiTokens.title': 'Jetons API',
    'apiTokens.help':
      "Un jeton API personnel appelle l'API REST (bouton « Authorize » du Swagger, scripts) avec vos droits actuels, qui viennent de vos groupes. Il cesse de fonctionner quand votre compte est supprimé ou perd ses droits. Comme tout jeton, il n'accepte jamais un risque et ne marque jamais un faux positif.",
    'apiTokens.create': 'Créer un jeton',
    'apiTokens.empty': 'Aucun jeton API.',
  },
  es: {
    'account.mustChange':
      'Un administrador definió su contraseña: elija la suya antes de usar la interfaz.',
    'account.sso': 'Cuenta OIDC',
    'account.local': 'Cuenta local',
    'account.permissionsTitle': 'Mis permisos',
    'account.passwordTitle': 'Cambiar la contraseña',
    'account.current': 'Contraseña actual',
    'account.new': 'Nueva contraseña',
    'account.confirmation': 'Confirmación',
    'account.mismatch': 'Las dos contraseñas no coinciden.',
    'account.submit': 'Cambiar la contraseña',
    'account.ssoInfo':
      'Cuenta OIDC: la contraseña la gestiona su proveedor de identidad, no esta interfaz.',
    'account.changed': 'Contraseña cambiada. Se han cerrado sus otras sesiones.',
    'account.wrongCurrent': 'La contraseña actual es incorrecta.',
    'account.mustDiffer': 'La nueva contraseña debe ser distinta de la actual.',
    'account.refusedDetail': 'Contraseña rechazada: {detail}',
    'account.refused': 'Contraseña rechazada.',
    'account.failed': 'El cambio de contraseña ha fallado.',
    'apiTokens.title': 'Tokens API',
    'apiTokens.help':
      'Un token API personal llama a la API REST (botón «Authorize» de Swagger, scripts) con sus permisos actuales, que provienen de sus grupos. Deja de funcionar cuando su cuenta se elimina o pierde sus permisos. Como todo token, nunca acepta un riesgo ni marca un falso positivo.',
    'apiTokens.create': 'Crear un token',
    'apiTokens.empty': 'No hay tokens API.',
  },
});
