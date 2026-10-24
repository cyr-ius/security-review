import { defineMessages } from '../catalog';

/** Exports of the findings: sending through a connector from a finding card (settings: see connectors). */
export const exports = defineMessages({
  en: {
    'exports.send': 'Send to {system}',
    'exports.record': '{system} {key}',
    'exports.failed': 'Sending to {system} failed: {error}',
    'exports.sending': 'Sending to {system}…',
    'exports.forbidden': 'You may not send the findings of this project.',
    'exports.notReady': 'Sending refused: {detail}',
    'exports.refused': 'The external system refused the finding: {detail}',
  },
  fr: {
    'exports.send': 'Envoyer vers {system}',
    'exports.record': '{system} {key}',
    'exports.failed': "Échec de l'envoi vers {system} : {error}",
    'exports.sending': 'Envoi vers {system}…',
    'exports.forbidden': 'Vous ne pouvez pas envoyer les findings de ce projet.',
    'exports.notReady': 'Envoi refusé : {detail}',
    'exports.refused': 'Le système externe a refusé le finding : {detail}',
  },
  es: {
    'exports.send': 'Enviar a {system}',
    'exports.record': '{system} {key}',
    'exports.failed': 'Fallo del envío a {system}: {error}',
    'exports.sending': 'Enviando a {system}…',
    'exports.forbidden': 'No puede enviar los hallazgos de este proyecto.',
    'exports.notReady': 'Envío rechazado: {detail}',
    'exports.refused': 'El sistema externo rechazó el hallazgo: {detail}',
  },
});
