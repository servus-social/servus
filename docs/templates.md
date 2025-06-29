## Themes

**Servus** uses Zola themes. First time you run **Servus** it will ask you whether you want to download the themes, but you can also install/create your own themes!

## Supported template functions

### `get_url`
### `load_data`

Note: The `load_data` implementation differs from [Zola's](https://www.getzola.org/documentation/templates/overview/#load-data). Instead of the `path` and `url` parameters it requires a `d` parameter that is used to query the Nostr events of kind [`30078`](https://github.com/nostr-protocol/nips/blob/master/78.md) and return the event's content.