import { defineMessages } from '../catalog';

/** OAuth login of the MCP clients: consent screen and approved clients of My account. */
export const oauth = defineMessages({
  en: {
    'oauth.title': 'Connect an MCP client',
    'oauth.lead':
      '{client} asks to use the Security Review MCP server on your behalf: it will reach the projects you may read, review them and save reports, without changing any finding status.',
    'oauth.unnamed': 'An MCP client',
    'oauth.signedInAs': 'Signed in as {user}',
    'oauth.redirect': 'After your answer, the browser goes back to {host}.',
    'oauth.warning':
      'Only approve a client you started yourself just now (Claude Code, VS Code...). The name is chosen by the client.',
    'oauth.approve': 'Approve',
    'oauth.deny': 'Deny',
    'oauth.loading': 'Loading the request...',
    'oauth.expired':
      'This request is unknown or has expired: start the connection again from the MCP client.',
    'oauth.forbidden':
      'You may not connect an MCP client: ask an administrator for the MCP token permission.',
    'oauth.failed': 'The decision could not be saved. Try again.',
    'oauth.redirecting': 'Back to the MCP client...',
    'oauth.grantsTitle': 'Connected MCP clients',
    'oauth.grantsHelp':
      'MCP clients you approved with the OAuth login. They reach the projects you may read; revoke one to cut its access at once.',
    'oauth.client': 'Client',
    'oauth.lastUsed': 'Last used',
    'oauth.neverUsed': 'Never',
    'oauth.confirmRevoke': 'Revoke the access of {client}?',
    'oauth.revoke': 'Revoke',
    'oauth.revokeClient': 'Revoke {client}',
    'oauth.revoked': 'Access of {client} revoked.',
    'oauth.revokeFailed': 'The access could not be revoked.',
    'oauth.loadError': 'Could not load the connected MCP clients.',
  },
  fr: {
    'oauth.title': 'Connecter un client MCP',
    'oauth.lead':
      '{client} demande à utiliser le serveur MCP Security Review en votre nom : il accédera aux projets que vous pouvez lire, pourra les relire et enregistrer des rapports, sans changer le statut d’aucun finding.',
    'oauth.unnamed': 'Un client MCP',
    'oauth.signedInAs': 'Connecté en tant que {user}',
    'oauth.redirect': 'Après votre réponse, le navigateur revient vers {host}.',
    'oauth.warning':
      'N’autorisez qu’un client que vous venez de lancer vous-même (Claude Code, VS Code...). Le nom est choisi par le client.',
    'oauth.approve': 'Autoriser',
    'oauth.deny': 'Refuser',
    'oauth.loading': 'Chargement de la demande...',
    'oauth.expired':
      'Cette demande est inconnue ou a expiré : relancez la connexion depuis le client MCP.',
    'oauth.forbidden':
      'Vous ne pouvez pas connecter de client MCP : demandez la permission des jetons MCP à un administrateur.',
    'oauth.failed': 'La décision n’a pas pu être enregistrée. Réessayez.',
    'oauth.redirecting': 'Retour vers le client MCP...',
    'oauth.grantsTitle': 'Clients MCP connectés',
    'oauth.grantsHelp':
      'Les clients MCP que vous avez autorisés par la connexion OAuth. Ils accèdent aux projets que vous pouvez lire ; révoquez-en un pour couper son accès immédiatement.',
    'oauth.client': 'Client',
    'oauth.lastUsed': 'Dernière utilisation',
    'oauth.neverUsed': 'Jamais',
    'oauth.confirmRevoke': 'Révoquer l’accès de {client} ?',
    'oauth.revoke': 'Révoquer',
    'oauth.revokeClient': 'Révoquer {client}',
    'oauth.revoked': 'Accès de {client} révoqué.',
    'oauth.revokeFailed': 'L’accès n’a pas pu être révoqué.',
    'oauth.loadError': 'Impossible de charger les clients MCP connectés.',
  },
  es: {
    'oauth.title': 'Conectar un cliente MCP',
    'oauth.lead':
      '{client} solicita usar el servidor MCP Security Review en su nombre: accederá a los proyectos que usted puede leer, podrá revisarlos y guardar informes, sin cambiar el estado de ningún hallazgo.',
    'oauth.unnamed': 'Un cliente MCP',
    'oauth.signedInAs': 'Conectado como {user}',
    'oauth.redirect': 'Tras su respuesta, el navegador vuelve a {host}.',
    'oauth.warning':
      'Autorice solo un cliente que usted mismo acaba de iniciar (Claude Code, VS Code...). El nombre lo elige el cliente.',
    'oauth.approve': 'Autorizar',
    'oauth.deny': 'Rechazar',
    'oauth.loading': 'Cargando la solicitud...',
    'oauth.expired':
      'Esta solicitud es desconocida o ha caducado: vuelva a iniciar la conexión desde el cliente MCP.',
    'oauth.forbidden':
      'No puede conectar un cliente MCP: pida a un administrador el permiso de los tokens MCP.',
    'oauth.failed': 'No se pudo guardar la decisión. Inténtelo de nuevo.',
    'oauth.redirecting': 'Volviendo al cliente MCP...',
    'oauth.grantsTitle': 'Clientes MCP conectados',
    'oauth.grantsHelp':
      'Los clientes MCP que autorizó con el inicio de sesión OAuth. Acceden a los proyectos que usted puede leer; revoque uno para cortar su acceso de inmediato.',
    'oauth.client': 'Cliente',
    'oauth.lastUsed': 'Último uso',
    'oauth.neverUsed': 'Nunca',
    'oauth.confirmRevoke': '¿Revocar el acceso de {client}?',
    'oauth.revoke': 'Revocar',
    'oauth.revokeClient': 'Revocar {client}',
    'oauth.revoked': 'Acceso de {client} revocado.',
    'oauth.revokeFailed': 'No se pudo revocar el acceso.',
    'oauth.loadError': 'No se pudieron cargar los clientes MCP conectados.',
  },
});
