## REST API

### `/api/sites`

A `POST` to `/api/sites` can be used to add a new site associated with a key.

A `GET` to `/api/sites` can be used to get a list of all the sites belonging to a key.

### `/api/config`

A `GET` to `/api/config` will return the list of available themes and the currently selected theme.

A `PUT` to `/api/config` can be used to change the site's theme.

NB: All requests require a [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md) authorization header to be present!

## Blossom API

Servus implements the [Blossom API](https://github.com/hzrd149/blossom) and therefore acts as your personal Blossom server.

* PUT `/upload`
* GET `/list/<pubkey>`
* DELETE `/<sha256>`

## NIP-96 API

Servus implements [NIP-96](https://github.com/nostr-protocol/nips/blob/master/96.md) file storage.

* POST `/api/files`
* DELETE `/api/files/<sha256>`