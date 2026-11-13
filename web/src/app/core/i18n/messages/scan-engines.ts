import { defineMessages } from '../catalog';

/** Activity page: the activity diagram, then the engines enrolled with the Controller server. */
export const scanEngines = defineMessages({
  en: {
    'scanEngines.pageSubtitle':
      'The agents, pipelines, MCP servers, Controller servers and scan engines at work.',
    'scanEngines.title': 'Scan engines',
    'scanEngines.subtitle':
      'Engines that run the rules and OpenGrep of the code scans in place of the Controller server.',
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
    'scanEngines.flowTitle': 'Activity diagram',
    'scanEngines.flowLabel':
      'Current activity: {codebase} pipeline scans and {fragments} agent fragments in progress, through {mcp} active MCP servers and {controllers} active Controller server processes, to {active} active engines out of {total}.',
    'scanEngines.flowPipelines': 'Pipelines',
    'scanEngines.flowAgents': 'Agents',
    'scanEngines.flowPipelinesTitle':
      '{count}/{total} codebase scan slots occupied (security-review-ci, codebase reviews)',
    'scanEngines.flowAgentsTitle': '{count}/{total} fragment slots occupied (scan_code requests)',
    'scanEngines.flowController': 'Controller server',
    'scanEngines.flowControllerInstance': 'Controller server {number}',
    'scanEngines.flowControllerTitle':
      '{active} active engines out of {total}, {pipelines} pipeline scans and {fragments} fragments in progress, {files} files in progress',
    'scanEngines.flowActive': 'active',
    'scanEngines.flowFiles': '{count} files in progress',
    'scanEngines.flowSlotsShort': 'slots',
    'scanEngines.flowSentOne': '1 upload',
    'scanEngines.flowSent': '{count} uploads',
    'scanEngines.flowSentShort': 'uploads',
    'scanEngines.flowEngineFilesOne': '1 file',
    'scanEngines.flowEngineFiles': '{count} files',
    'scanEngines.flowEngineNow': 'In progress: {codebase} codebase scans, {fragments} fragments',
    'scanEngines.flowRequestsShort': 'requests',
    'scanEngines.flowAgentCountOne': '1 agent',
    'scanEngines.flowAgentCount': '{count} agents',
    'scanEngines.flowSlots': '{used}/{total} slots',
    'scanEngines.flowFallbackLocal': 'Fallback: local scan',
    'scanEngines.flowControllerScans': 'Scans itself (engines off)',
    'scanEngines.flowFallbackRefuse': 'No fallback (503)',
    'scanEngines.flowEngineTitle':
      '{name} {version}: {codebase} code scans, {fragments} fragments, {files} files, {failed} failed, {busy} refused when busy; {used} of {capacity} slots in use',
    'scanEngines.flowMcpInstance': 'MCP server {number}',
    'scanEngines.flowAgentTitle':
      '{client} {version}, through MCP server {number}, last request at {time}\nSince the last heartbeat: {requests}',
    'scanEngines.flowMoreAgents': 'Other agents',
    'scanEngines.flowMoreAgentsTitle': '{count} other agents seen lately',
    'scanEngines.flowMcpDelegated': 'scan_code delegated',
    'scanEngines.flowMcpLocal': 'Local scan',
    'scanEngines.flowMcpTitleDelegated':
      '{name} {version}, code scans sent to the Controller server\nSince the last heartbeat: {requests}',
    'scanEngines.flowMcpTitleLocal':
      '{name} {version}, code scans run by the MCP server itself (delegation off)\nSince the last heartbeat: {requests}',
    'scanEngines.flowRequests':
      '{code} code scans, {deps} dependency scans, {reports} reports and triage, {reads} reads',
    'scanEngines.flowControllerRequests':
      'Received since the last heartbeat: {pipeline} pipeline scans (security-review-ci), {code} code scans and {deps} dependency scans of the agents',
  },
  fr: {
    'scanEngines.pageSubtitle':
      'Les agents, pipelines, serveurs MCP, serveurs Controller et moteurs de scan à l’œuvre.',
    'scanEngines.title': 'Moteurs de scan',
    'scanEngines.subtitle':
      'Moteurs qui exécutent les règles et OpenGrep des scans de code à la place du serveur Controller.',
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
    'scanEngines.flowTitle': 'Diagramme d’activité',
    'scanEngines.flowLabel':
      'Activité en cours : {codebase} scans de pipeline et {fragments} fragments d’agents, par {mcp} serveurs MCP actifs et {controllers} instances actives du serveur Controller, vers {active} moteurs actifs sur {total}.',
    'scanEngines.flowPipelines': 'Pipelines',
    'scanEngines.flowAgents': 'Agents',
    'scanEngines.flowPipelinesTitle':
      '{count}/{total} créneaux de scan de code occupés (security-review-ci, revues du dépôt)',
    'scanEngines.flowAgentsTitle':
      '{count}/{total} créneaux de fragment occupés (requêtes scan_code)',
    'scanEngines.flowController': 'Serveur Controller',
    'scanEngines.flowControllerInstance': 'Serveur Controller {number}',
    'scanEngines.flowControllerTitle':
      '{active} moteurs actifs sur {total}, {pipelines} scans de pipeline et {fragments} fragments en cours, {files} fichiers en cours',
    'scanEngines.flowActive': 'actifs',
    'scanEngines.flowFiles': '{count} fichiers en cours',
    'scanEngines.flowSlotsShort': 'créneaux',
    'scanEngines.flowSentOne': '1 envoi',
    'scanEngines.flowSent': '{count} envois',
    'scanEngines.flowSentShort': 'envois',
    'scanEngines.flowEngineFilesOne': '1 fichier',
    'scanEngines.flowEngineFiles': '{count} fichiers',
    'scanEngines.flowEngineNow': 'En cours : {codebase} scans de dépôt, {fragments} fragments',
    'scanEngines.flowRequestsShort': 'requêtes',
    'scanEngines.flowAgentCountOne': '1 agent',
    'scanEngines.flowAgentCount': '{count} agents',
    'scanEngines.flowSlots': '{used}/{total} créneaux',
    'scanEngines.flowFallbackLocal': 'Repli : scan local',
    'scanEngines.flowControllerScans': 'Scanne lui-même (moteurs désactivés)',
    'scanEngines.flowFallbackRefuse': 'Sans repli (503)',
    'scanEngines.flowEngineTitle':
      '{name} {version} : {codebase} scans de code, {fragments} fragments, {files} fichiers, {failed} en échec, {busy} refusés car occupé ; {used} créneaux occupés sur {capacity}',
    'scanEngines.flowMcpInstance': 'Serveur MCP {number}',
    'scanEngines.flowAgentTitle':
      '{client} {version}, par le serveur MCP {number}, dernière requête à {time}\nDepuis le dernier battement de cœur : {requests}',
    'scanEngines.flowMoreAgents': 'Autres agents',
    'scanEngines.flowMoreAgentsTitle': '{count} autres agents vus récemment',
    'scanEngines.flowMcpDelegated': 'scan_code délégué',
    'scanEngines.flowMcpLocal': 'Scan local',
    'scanEngines.flowMcpTitleDelegated':
      '{name} {version}, scans de code envoyés au serveur Controller\nDepuis le dernier battement de cœur : {requests}',
    'scanEngines.flowMcpTitleLocal':
      '{name} {version}, scans de code faits par le serveur MCP lui-même (délégation désactivée)\nDepuis le dernier battement de cœur : {requests}',
    'scanEngines.flowRequests':
      '{code} scans de code, {deps} scans de dépendances, {reports} rapports et triage, {reads} lectures',
    'scanEngines.flowControllerRequests':
      'Reçus depuis le dernier battement de cœur : {pipeline} scans de pipeline (security-review-ci), {code} scans de code et {deps} scans de dépendances des agents',
  },
  es: {
    'scanEngines.pageSubtitle':
      'Los agentes, pipelines, servidores MCP, servidores Controller y motores de escaneo en funcionamiento.',
    'scanEngines.title': 'Motores de escaneo',
    'scanEngines.subtitle':
      'Motores que ejecutan las reglas y OpenGrep de los escaneos de código en lugar del servidor Controller.',
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
    'scanEngines.flowTitle': 'Diagrama de actividad',
    'scanEngines.flowLabel':
      'Actividad actual: {codebase} escaneos de pipelines y {fragments} fragmentos de agentes en curso, por {mcp} servidores MCP activos y {controllers} instancias activas del servidor Controller, hacia {active} motores activos de {total}.',
    'scanEngines.flowPipelines': 'Pipelines',
    'scanEngines.flowAgents': 'Agentes',
    'scanEngines.flowPipelinesTitle':
      '{count}/{total} huecos de escaneo de código ocupados (security-review-ci, revisiones del repositorio)',
    'scanEngines.flowAgentsTitle':
      '{count}/{total} huecos de fragmentos ocupados (solicitudes scan_code)',
    'scanEngines.flowController': 'Servidor Controller',
    'scanEngines.flowControllerInstance': 'Servidor Controller {number}',
    'scanEngines.flowControllerTitle':
      '{active} motores activos de {total}, {pipelines} escaneos de pipelines y {fragments} fragmentos en curso, {files} archivos en curso',
    'scanEngines.flowActive': 'activos',
    'scanEngines.flowFiles': '{count} archivos en curso',
    'scanEngines.flowSlotsShort': 'huecos',
    'scanEngines.flowSentOne': '1 envío',
    'scanEngines.flowSent': '{count} envíos',
    'scanEngines.flowSentShort': 'envíos',
    'scanEngines.flowEngineFilesOne': '1 archivo',
    'scanEngines.flowEngineFiles': '{count} archivos',
    'scanEngines.flowEngineNow':
      'En curso: {codebase} escaneos de repositorio, {fragments} fragmentos',
    'scanEngines.flowRequestsShort': 'solicitudes',
    'scanEngines.flowAgentCountOne': '1 agente',
    'scanEngines.flowAgentCount': '{count} agentes',
    'scanEngines.flowSlots': '{used}/{total} huecos',
    'scanEngines.flowFallbackLocal': 'Respaldo: escaneo local',
    'scanEngines.flowControllerScans': 'Escanea él mismo (motores desactivados)',
    'scanEngines.flowFallbackRefuse': 'Sin respaldo (503)',
    'scanEngines.flowEngineTitle':
      '{name} {version}: {codebase} escaneos de código, {fragments} fragmentos, {files} archivos, {failed} fallidos, {busy} rechazados por estar ocupado; {used} de {capacity} huecos ocupados',
    'scanEngines.flowMcpInstance': 'Servidor MCP {number}',
    'scanEngines.flowAgentTitle':
      '{client} {version}, a través del servidor MCP {number}, última petición a las {time}\nDesde el último latido: {requests}',
    'scanEngines.flowMoreAgents': 'Otros agentes',
    'scanEngines.flowMoreAgentsTitle': '{count} otros agentes vistos recientemente',
    'scanEngines.flowMcpDelegated': 'scan_code delegado',
    'scanEngines.flowMcpLocal': 'Escaneo local',
    'scanEngines.flowMcpTitleDelegated':
      '{name} {version}, escaneos de código enviados al servidor Controller\nDesde el último latido: {requests}',
    'scanEngines.flowMcpTitleLocal':
      '{name} {version}, escaneos de código hechos por el propio servidor MCP (delegación desactivada)\nDesde el último latido: {requests}',
    'scanEngines.flowRequests':
      '{code} escaneos de código, {deps} escaneos de dependencias, {reports} informes y triaje, {reads} lecturas',
    'scanEngines.flowControllerRequests':
      'Recibidos desde el último latido: {pipeline} escaneos de pipelines (security-review-ci), {code} escaneos de código y {deps} escaneos de dependencias de los agentes',
  },
});
