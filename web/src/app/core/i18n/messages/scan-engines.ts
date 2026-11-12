import { defineMessages } from '../catalog';

/** Scan engines page: the engines enrolled with the Controller server. */
export const scanEngines = defineMessages({
  en: {
    'scanEngines.title': 'Scan engines',
    'scanEngines.subtitle':
      'Engines that run the rules and OpenGrep of the code scans in place of the Controller server.',
    'scanEngines.help':
      'Each engine enrolls at its start with the shared secret SECREVIEW_SCAN_ENGINE_TOKEN, then reads the rules through the REST API with its own OAuth access token, which it renews before it expires. It reads no database. A revoked engine is refused at once and enrolls again only when it restarts; to shut every engine out, change the shared secret.',
    'scanEngines.enabled':
      'The code scans go to the active engines, the one with the most free slots first.',
    'scanEngines.disabled':
      'Scan engines are off: the Controller server scans itself. Set SECREVIEW_SCAN_ENGINE_TOKEN on the Controller server and on the engines to turn them on.',
    'scanEngines.networks': 'Addresses accepted from the engines: {networks}',
    'scanEngines.url': 'URL',
    'scanEngines.status': 'Status',
    'scanEngines.active': 'Active',
    'scanEngines.inactive': 'No heartbeat',
    'scanEngines.freeSlots': 'Free slots',
    'scanEngines.freeSlotsValue': '{codebase} scans · {fragments} fragments',
    'scanEngines.lifetimes':
      'Access tokens valid {minutes} min; an engine not seen for {days} days is deleted.',
    'scanEngines.name': 'Engine',
    'scanEngines.version': 'Version',
    'scanEngines.enrolledAt': 'Enrolled on',
    'scanEngines.lastSeen': 'Last seen',
    'scanEngines.revoke': 'Revoke',
    'scanEngines.revokeLabel': 'Revoke the scan engine {name}',
    'scanEngines.confirmRevoke':
      'Revoke the scan engine {name}? Its scans fail at once, until it restarts and enrolls again.',
    'scanEngines.revoked': 'Scan engine {name} revoked.',
    'scanEngines.none': 'No scan engine is enrolled.',
    'scanEngines.loadError': 'The scan engines could not be loaded.',
  },
  fr: {
    'scanEngines.title': 'Moteurs de scan',
    'scanEngines.subtitle':
      'Moteurs qui exécutent les règles et OpenGrep des scans de code à la place du serveur Controller.',
    'scanEngines.help':
      'Chaque moteur s’enrôle à son démarrage avec le secret partagé SECREVIEW_SCAN_ENGINE_TOKEN, puis lit les règles par l’API REST avec son propre jeton d’accès OAuth, qu’il renouvelle avant son expiration. Il ne lit aucune base de données. Un moteur révoqué est refusé aussitôt et ne s’enrôle de nouveau qu’à son redémarrage ; pour écarter tous les moteurs, changez le secret partagé.',
    'scanEngines.enabled':
      'Les scans de code partent vers les moteurs actifs, celui qui a le plus de créneaux libres d’abord.',
    'scanEngines.disabled':
      'Les moteurs de scan sont désactivés : le serveur Controller scanne lui-même. Définissez SECREVIEW_SCAN_ENGINE_TOKEN sur le serveur Controller et sur les moteurs pour les activer.',
    'scanEngines.networks': 'Adresses acceptées des moteurs : {networks}',
    'scanEngines.url': 'URL',
    'scanEngines.status': 'État',
    'scanEngines.active': 'Actif',
    'scanEngines.inactive': 'Sans battement de cœur',
    'scanEngines.freeSlots': 'Créneaux libres',
    'scanEngines.freeSlotsValue': '{codebase} scans · {fragments} fragments',
    'scanEngines.lifetimes':
      'Jetons d’accès valables {minutes} min ; un moteur absent depuis {days} jours est supprimé.',
    'scanEngines.name': 'Moteur',
    'scanEngines.version': 'Version',
    'scanEngines.enrolledAt': 'Enrôlé le',
    'scanEngines.lastSeen': 'Vu pour la dernière fois',
    'scanEngines.revoke': 'Révoquer',
    'scanEngines.revokeLabel': 'Révoquer le moteur de scan {name}',
    'scanEngines.confirmRevoke':
      'Révoquer le moteur de scan {name} ? Ses scans échouent aussitôt, jusqu’à ce qu’il redémarre et s’enrôle de nouveau.',
    'scanEngines.revoked': 'Moteur de scan {name} révoqué.',
    'scanEngines.none': 'Aucun moteur de scan n’est enrôlé.',
    'scanEngines.loadError': 'Impossible de charger les moteurs de scan.',
  },
  es: {
    'scanEngines.title': 'Motores de escaneo',
    'scanEngines.subtitle':
      'Motores que ejecutan las reglas y OpenGrep de los escaneos de código en lugar del servidor Controller.',
    'scanEngines.help':
      'Cada motor se inscribe al arrancar con el secreto compartido SECREVIEW_SCAN_ENGINE_TOKEN y luego lee las reglas por la API REST con su propio token de acceso OAuth, que renueva antes de que caduque. No lee ninguna base de datos. Un motor revocado se rechaza de inmediato y solo se inscribe de nuevo al reiniciarse; para excluir a todos los motores, cambie el secreto compartido.',
    'scanEngines.enabled':
      'Los escaneos de código van a los motores activos, primero el que tiene más huecos libres.',
    'scanEngines.disabled':
      'Los motores de escaneo están desactivados: el servidor Controller escanea él mismo. Defina SECREVIEW_SCAN_ENGINE_TOKEN en el servidor Controller y en los motores para activarlos.',
    'scanEngines.networks': 'Direcciones aceptadas de los motores: {networks}',
    'scanEngines.url': 'URL',
    'scanEngines.status': 'Estado',
    'scanEngines.active': 'Activo',
    'scanEngines.inactive': 'Sin latido',
    'scanEngines.freeSlots': 'Huecos libres',
    'scanEngines.freeSlotsValue': '{codebase} escaneos · {fragments} fragmentos',
    'scanEngines.lifetimes':
      'Tokens de acceso válidos {minutes} min; un motor sin actividad durante {days} días se elimina.',
    'scanEngines.name': 'Motor',
    'scanEngines.version': 'Versión',
    'scanEngines.enrolledAt': 'Inscrito el',
    'scanEngines.lastSeen': 'Última actividad',
    'scanEngines.revoke': 'Revocar',
    'scanEngines.revokeLabel': 'Revocar el motor de escaneo {name}',
    'scanEngines.confirmRevoke':
      '¿Revocar el motor de escaneo {name}? Sus escaneos fallan de inmediato, hasta que se reinicie y se inscriba de nuevo.',
    'scanEngines.revoked': 'Motor de escaneo {name} revocado.',
    'scanEngines.none': 'No hay ningún motor de escaneo inscrito.',
    'scanEngines.loadError': 'No se pudieron cargar los motores de escaneo.',
  },
});
