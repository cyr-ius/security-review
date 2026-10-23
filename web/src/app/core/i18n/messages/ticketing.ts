import { defineMessages } from '../catalog';

/** Tickets of the findings: sending from a finding card (settings: see connectors). */
export const ticketing = defineMessages({
  en: {
    'ticketing.send': 'Send to {system}',
    'ticketing.ticket': '{system} ticket {key}',
    'ticketing.ticketFailed': 'Sending to {system} failed: {error}',
    'ticketing.ticketSending': 'Sending to {system}…',
    'ticketing.forbidden': 'You may not send the findings of this project.',
    'ticketing.notReady': 'Sending refused: {detail}',
    'ticketing.refused': 'The ticketing system refused the ticket: {detail}',
  },
  fr: {
    'ticketing.send': 'Envoyer vers {system}',
    'ticketing.ticket': 'Ticket {system} {key}',
    'ticketing.ticketFailed': "Échec de l'envoi vers {system} : {error}",
    'ticketing.ticketSending': 'Envoi vers {system}…',
    'ticketing.forbidden': 'Vous ne pouvez pas envoyer les findings de ce projet.',
    'ticketing.notReady': 'Envoi refusé : {detail}',
    'ticketing.refused': 'Le système de ticketing a refusé le ticket : {detail}',
  },
  es: {
    'ticketing.send': 'Enviar a {system}',
    'ticketing.ticket': 'Ticket {system} {key}',
    'ticketing.ticketFailed': 'Fallo del envío a {system}: {error}',
    'ticketing.ticketSending': 'Enviando a {system}…',
    'ticketing.forbidden': 'No puede enviar los hallazgos de este proyecto.',
    'ticketing.notReady': 'Envío rechazado: {detail}',
    'ticketing.refused': 'El sistema de ticketing rechazó el ticket: {detail}',
  },
});
