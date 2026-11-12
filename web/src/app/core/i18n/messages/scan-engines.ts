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
    'scanEngines.flowTitle': 'Activity',
    'scanEngines.flowLabel':
      'Flow of the code scans: {codebase} scans from the pipelines and {fragments} fragments from the agents, through the Controller server, to {active} active engines out of {total}.',
    'scanEngines.flowPipelines': 'Pipelines',
    'scanEngines.flowAgents': 'Agents',
    'scanEngines.flowPipelinesTitle': '{count} code scans (security-review-ci, codebase reviews)',
    'scanEngines.flowAgentsTitle': '{count} fragments (scan_code of the agents)',
    'scanEngines.flowController': 'Controller server',
    'scanEngines.flowControllerTitle':
      '{active} active engines out of {total}, {used} of {capacity} slots in use, {files} files scanned',
    'scanEngines.flowActive': 'active',
    'scanEngines.flowFiles': '{count} files',
    'scanEngines.flowSlots': '{used}/{total} slots',
    'scanEngines.flowFallbackLocal': 'Fallback: local scan',
    'scanEngines.flowFallbackRefuse': 'No fallback (503)',
    'scanEngines.flowEngineTitle':
      '{name} {version}: {codebase} code scans, {fragments} fragments, {files} files, {failed} failed, {busy} refused when busy; {used} of {capacity} slots in use',
    'scanEngines.flowLegendCodebase': 'Code scans (pipelines)',
    'scanEngines.flowLegendFragment': 'Fragments (scan_code)',
    'scanEngines.flowLegendLive':
      'Moving dots: scans running now. Counters since each engine started.',
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
    'scanEngines.flowTitle': 'Activité',
    'scanEngines.flowLabel':
      'Flux des scans de code : {codebase} scans des pipelines et {fragments} fragments des agents, par le serveur Controller, vers {active} moteurs actifs sur {total}.',
    'scanEngines.flowPipelines': 'Pipelines',
    'scanEngines.flowAgents': 'Agents',
    'scanEngines.flowPipelinesTitle': '{count} scans de code (security-review-ci, revues du dépôt)',
    'scanEngines.flowAgentsTitle': '{count} fragments (scan_code des agents)',
    'scanEngines.flowController': 'Serveur Controller',
    'scanEngines.flowControllerTitle':
      '{active} moteurs actifs sur {total}, {used} créneaux occupés sur {capacity}, {files} fichiers scannés',
    'scanEngines.flowActive': 'actifs',
    'scanEngines.flowFiles': '{count} fichiers',
    'scanEngines.flowSlots': '{used}/{total} créneaux',
    'scanEngines.flowFallbackLocal': 'Repli : scan local',
    'scanEngines.flowFallbackRefuse': 'Sans repli (503)',
    'scanEngines.flowEngineTitle':
      '{name} {version} : {codebase} scans de code, {fragments} fragments, {files} fichiers, {failed} en échec, {busy} refusés car occupé ; {used} créneaux occupés sur {capacity}',
    'scanEngines.flowLegendCodebase': 'Scans de code (pipelines)',
    'scanEngines.flowLegendFragment': 'Fragments (scan_code)',
    'scanEngines.flowLegendLive':
      'Points en mouvement : scans en cours. Compteurs depuis le démarrage de chaque moteur.',
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
    'scanEngines.flowTitle': 'Actividad',
    'scanEngines.flowLabel':
      'Flujo de los escaneos de código: {codebase} escaneos de los pipelines y {fragments} fragmentos de los agentes, por el servidor Controller, hacia {active} motores activos de {total}.',
    'scanEngines.flowPipelines': 'Pipelines',
    'scanEngines.flowAgents': 'Agentes',
    'scanEngines.flowPipelinesTitle':
      '{count} escaneos de código (security-review-ci, revisiones del repositorio)',
    'scanEngines.flowAgentsTitle': '{count} fragmentos (scan_code de los agentes)',
    'scanEngines.flowController': 'Servidor Controller',
    'scanEngines.flowControllerTitle':
      '{active} motores activos de {total}, {used} de {capacity} huecos ocupados, {files} archivos escaneados',
    'scanEngines.flowActive': 'activos',
    'scanEngines.flowFiles': '{count} archivos',
    'scanEngines.flowSlots': '{used}/{total} huecos',
    'scanEngines.flowFallbackLocal': 'Respaldo: escaneo local',
    'scanEngines.flowFallbackRefuse': 'Sin respaldo (503)',
    'scanEngines.flowEngineTitle':
      '{name} {version}: {codebase} escaneos de código, {fragments} fragmentos, {files} archivos, {failed} fallidos, {busy} rechazados por estar ocupado; {used} de {capacity} huecos ocupados',
    'scanEngines.flowLegendCodebase': 'Escaneos de código (pipelines)',
    'scanEngines.flowLegendFragment': 'Fragmentos (scan_code)',
    'scanEngines.flowLegendLive':
      'Puntos en movimiento: escaneos en curso. Contadores desde el arranque de cada motor.',
  },
});
