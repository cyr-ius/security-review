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
      'Connecting an MCP client is disabled on this server: ask an administrator for an MCP token.',
    'oauth.failed': 'The decision could not be saved. Try again.',
    'oauth.redirecting': 'Back to the MCP client...',
    'oauth.grantsTitle': 'Connected MCP clients',
    'oauth.grantsHelp':
      'MCP clients you approved with the OAuth login. They reach the projects you may read; revoke one to cut its access at once.',
    'oauth.client': 'Client',
    'oauth.lastUsed': 'Last used',
    'oauth.neverUsed': 'Never',
    'oauth.noGrantsMine':
      'No client approved yet. Configure your MCP client without a token: it opens the browser so that you approve it here.',
    'oauth.confirmRevoke': 'Revoke the access of {client}?',
    'oauth.revoke': 'Revoke',
    'oauth.revokeClient': 'Revoke {client}',
    'oauth.revoked': 'Access of {client} revoked.',
    'oauth.revokeFailed': 'The access could not be revoked.',
    'oauth.loadError': 'Could not load the connected MCP clients.',
    'oauth.adminTitle': 'MCP clients (OAuth login)',
    'oauth.adminHelp':
      'Clients that log in through the browser instead of a personal token. Revoke a grant to cut one user; delete a client to cut all its users (it must register again). The other settings are variables of the Controller server.',
    'oauth.mcpUrl': 'MCP endpoint',
    'oauth.enabled': 'Enable OAuth login',
    'oauth.mcpUrlHelp':
      'Enter the public address of your MCP server (e.g. https://mcp.example.com/mcp).',
    'oauth.off':
      'The OAuth login is off: the MCP clients without a token are sent to the enrollment server.',
    'oauth.confirmOff':
      'Turn the OAuth login off? The approved clients are suspended at once and work again when it is turned back on. To cut them for good, use Revoke all.',
    'oauth.turnedOn': 'OAuth login enabled.',
    'oauth.turnedOff': 'OAuth login disabled: the approved clients are suspended.',
    'oauth.suspended':
      'Suspended: these clients are refused while the OAuth login is off, and work again when it is turned back on.',
    'oauth.revokeAll': 'Revoke all',
    'oauth.confirmRevokeAll':
      'Revoke the access of every approved client? Each one will have to be approved again.',
    'oauth.allRevoked': '{count} access(es) revoked.',
    'oauth.urlSaved': 'MCP endpoint saved.',
    'oauth.urlMissing': 'Enter the address of the MCP endpoint (http or https).',
    'oauth.redirects': 'Accepted redirects',
    'oauth.loopback': 'loopback interface',
    'oauth.lifetimes': 'Token lifetimes',
    'oauth.lifetimesValue': 'access {minutes} min · refresh {days} days',
    'oauth.clientsCount': 'Registered clients',
    'oauth.grantsAdminTitle': 'Approved clients',
    'oauth.user': 'User',
    'oauth.noGrants': 'No client approved yet.',
    'oauth.clientsTitle': 'Registered clients',
    'oauth.redirectUris': 'Redirect URIs',
    'oauth.approvals': 'Approvals',
    'oauth.unapproved': 'Not approved',
    'oauth.noClients': 'No registered client.',
    'oauth.deleteClientLabel': 'Delete {client}',
    'oauth.confirmRevokeGrant': 'Revoke the access of {client} for {user}?',
    'oauth.confirmDeleteClient': 'Delete {client} and revoke all its accesses?',
    'oauth.clientDeleted': '{client} deleted.',
    'oauth.adminLoadError': 'Could not load the MCP clients of the OAuth login.',
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
      'La connexion d’un client MCP est désactivée sur ce serveur : demandez un jeton MCP à un administrateur.',
    'oauth.failed': 'La décision n’a pas pu être enregistrée. Réessayez.',
    'oauth.redirecting': 'Retour vers le client MCP...',
    'oauth.grantsTitle': 'Clients MCP connectés',
    'oauth.grantsHelp':
      'Les clients MCP que vous avez autorisés par la connexion OAuth. Ils accèdent aux projets que vous pouvez lire ; révoquez-en un pour couper son accès immédiatement.',
    'oauth.client': 'Client',
    'oauth.lastUsed': 'Dernière utilisation',
    'oauth.neverUsed': 'Jamais',
    'oauth.noGrantsMine':
      'Aucun client autorisé pour l’instant. Configurez votre client MCP sans jeton : il ouvre le navigateur pour que vous l’autorisiez ici.',
    'oauth.confirmRevoke': 'Révoquer l’accès de {client} ?',
    'oauth.revoke': 'Révoquer',
    'oauth.revokeClient': 'Révoquer {client}',
    'oauth.revoked': 'Accès de {client} révoqué.',
    'oauth.revokeFailed': 'L’accès n’a pas pu être révoqué.',
    'oauth.loadError': 'Impossible de charger les clients MCP connectés.',
    'oauth.adminTitle': 'Clients MCP (connexion OAuth)',
    'oauth.adminHelp':
      'Les clients qui se connectent par le navigateur au lieu d’un jeton personnel. Révoquez un accès pour couper un utilisateur ; supprimez un client pour couper tous ses utilisateurs (il devra se réenregistrer). Les autres réglages sont des variables du serveur Controller.',
    'oauth.mcpUrl': 'Point d’accès MCP',
    'oauth.enabled': 'Connexion OAuth',
    'oauth.mcpUrlHelp':
      'Saisissez l’adresse publique de votre serveur MCP (ex. https://mcp.example.com/mcp).',
    'oauth.off':
      'La connexion OAuth est désactivée : les clients MCP sans jeton sont orientés vers le serveur d’enrôlement.',
    'oauth.confirmOff':
      'Désactiver la connexion OAuth ? Les clients autorisés sont suspendus immédiatement et fonctionnent de nouveau à sa réactivation. Pour les couper définitivement, utilisez Tout révoquer.',
    'oauth.turnedOn': 'Connexion OAuth activée.',
    'oauth.turnedOff': 'Connexion OAuth désactivée : les clients autorisés sont suspendus.',
    'oauth.suspended':
      'Suspendus : ces clients sont refusés tant que la connexion OAuth est désactivée, et fonctionnent de nouveau à sa réactivation.',
    'oauth.revokeAll': 'Tout révoquer',
    'oauth.confirmRevokeAll':
      'Révoquer l’accès de tous les clients autorisés ? Chacun devra être autorisé de nouveau.',
    'oauth.allRevoked': '{count} accès révoqué(s).',
    'oauth.urlSaved': 'Point d’accès MCP enregistré.',
    'oauth.urlMissing': 'Saisissez l’adresse du point d’accès MCP (http ou https).',
    'oauth.redirects': 'Redirections acceptées',
    'oauth.loopback': 'interface loopback',
    'oauth.lifetimes': 'Durée des jetons',
    'oauth.lifetimesValue': 'accès {minutes} min · rafraîchissement {days} jours',
    'oauth.clientsCount': 'Clients enregistrés',
    'oauth.grantsAdminTitle': 'Clients autorisés',
    'oauth.user': 'Utilisateur',
    'oauth.noGrants': 'Aucun client autorisé pour l’instant.',
    'oauth.clientsTitle': 'Clients enregistrés',
    'oauth.redirectUris': 'URI de redirection',
    'oauth.approvals': 'Autorisations',
    'oauth.unapproved': 'Non autorisé',
    'oauth.noClients': 'Aucun client enregistré.',
    'oauth.deleteClientLabel': 'Supprimer {client}',
    'oauth.confirmRevokeGrant': 'Révoquer l’accès de {client} pour {user} ?',
    'oauth.confirmDeleteClient': 'Supprimer {client} et révoquer tous ses accès ?',
    'oauth.clientDeleted': '{client} supprimé.',
    'oauth.adminLoadError': 'Impossible de charger les clients MCP de la connexion OAuth.',
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
      'La conexión de un cliente MCP está desactivada en este servidor: pida un token MCP a un administrador.',
    'oauth.failed': 'No se pudo guardar la decisión. Inténtelo de nuevo.',
    'oauth.redirecting': 'Volviendo al cliente MCP...',
    'oauth.grantsTitle': 'Clientes MCP conectados',
    'oauth.grantsHelp':
      'Los clientes MCP que autorizó con el inicio de sesión OAuth. Acceden a los proyectos que usted puede leer; revoque uno para cortar su acceso de inmediato.',
    'oauth.client': 'Cliente',
    'oauth.lastUsed': 'Último uso',
    'oauth.neverUsed': 'Nunca',
    'oauth.noGrantsMine':
      'Ningún cliente autorizado todavía. Configure su cliente MCP sin token: abre el navegador para que lo autorice aquí.',
    'oauth.confirmRevoke': '¿Revocar el acceso de {client}?',
    'oauth.revoke': 'Revocar',
    'oauth.revokeClient': 'Revocar {client}',
    'oauth.revoked': 'Acceso de {client} revocado.',
    'oauth.revokeFailed': 'No se pudo revocar el acceso.',
    'oauth.loadError': 'No se pudieron cargar los clientes MCP conectados.',
    'oauth.adminTitle': 'Clientes MCP (inicio de sesión OAuth)',
    'oauth.adminHelp':
      'Los clientes que inician sesión con el navegador en lugar de un token personal. Revoque un acceso para cortar a un usuario; elimine un cliente para cortar a todos sus usuarios (deberá registrarse de nuevo). Los demás ajustes son variables del servidor Controller.',
    'oauth.mcpUrl': 'Punto de acceso MCP',
    'oauth.enabled': 'Activar el inicio de sesión OAuth',
    'oauth.mcpUrlHelp':
      'Introduzca la dirección pública de su servidor MCP (p. ej. https://mcp.example.com/mcp).',
    'oauth.off':
      'El inicio de sesión OAuth está desactivado: los clientes MCP sin token se envían al servidor de inscripción.',
    'oauth.confirmOff':
      '¿Desactivar el inicio de sesión OAuth? Los clientes autorizados quedan suspendidos de inmediato y vuelven a funcionar al reactivarlo. Para cortarlos definitivamente, use Revocar todo.',
    'oauth.turnedOn': 'Inicio de sesión OAuth activado.',
    'oauth.turnedOff':
      'Inicio de sesión OAuth desactivado: los clientes autorizados quedan suspendidos.',
    'oauth.suspended':
      'Suspendidos: estos clientes se rechazan mientras el inicio de sesión OAuth está desactivado, y vuelven a funcionar al reactivarlo.',
    'oauth.revokeAll': 'Revocar todo',
    'oauth.confirmRevokeAll':
      '¿Revocar el acceso de todos los clientes autorizados? Cada uno deberá autorizarse de nuevo.',
    'oauth.allRevoked': '{count} acceso(s) revocado(s).',
    'oauth.urlSaved': 'Punto de acceso MCP guardado.',
    'oauth.urlMissing': 'Introduzca la dirección del punto de acceso MCP (http o https).',
    'oauth.redirects': 'Redirecciones aceptadas',
    'oauth.loopback': 'interfaz loopback',
    'oauth.lifetimes': 'Duración de los tokens',
    'oauth.lifetimesValue': 'acceso {minutes} min · actualización {days} días',
    'oauth.clientsCount': 'Clientes registrados',
    'oauth.grantsAdminTitle': 'Clientes autorizados',
    'oauth.user': 'Usuario',
    'oauth.noGrants': 'Ningún cliente autorizado por ahora.',
    'oauth.clientsTitle': 'Clientes registrados',
    'oauth.redirectUris': 'URI de redirección',
    'oauth.approvals': 'Autorizaciones',
    'oauth.unapproved': 'No autorizado',
    'oauth.noClients': 'Ningún cliente registrado.',
    'oauth.deleteClientLabel': 'Eliminar {client}',
    'oauth.confirmRevokeGrant': '¿Revocar el acceso de {client} para {user}?',
    'oauth.confirmDeleteClient': '¿Eliminar {client} y revocar todos sus accesos?',
    'oauth.clientDeleted': '{client} eliminado.',
    'oauth.adminLoadError': 'No se pudieron cargar los clientes MCP del inicio de sesión OAuth.',
  },
});
