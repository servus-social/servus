## REST API

### `/api/sites`

A `POST` to `/api/sites` can be used to add a new site associated with a key.

A `GET` to `/api/sites` can be used to get a list of all the sites belonging to a key.

### `/api/config`

A `GET` to `/api/config` will return the currently selected theme.

A `PUT` to `/api/config` can be used to change the site's theme.

NB: All requests require a [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md) authorization header to be present!

### Testing on localhost

The `X-Target-Host` request header can be passed to specify which site's API is to invoked when hitting the API via `localhost` or `127.0.0.1`. This is not a problem in production environments, when the site can be determined from the actual host used to access the API.

## Blossom API

Servus implements the [Blossom API](https://github.com/hzrd149/blossom) and therefore acts as your personal Blossom server.

* PUT `/upload`
* GET `/list/<pubkey>`
* DELETE `/<sha256>`

## NIP-05 API

* GET `/.well-known/nostr.json` will return a JSON that contains the site's Nostr pubkey
