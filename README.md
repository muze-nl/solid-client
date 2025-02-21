# @muze-nl/solid-client

```javascript
import solid from '@muze-nl/solid-client'
import {_, from,first} from '@muze-nl/jaqt'

const c = solid.client(options)
const session = c.login(webid)
let username
if (session.isAuthenticated()) {
	username = from(session.profile)
		.select(first(_.foaf$name,_.vcard$fn, 'John Doe'))
}
let movies = await session.pod().cd('/movies/').list()
let foo = session.get(fooUrl).data
session.logout() // -> oidc rp logout
```

## cookbook

### list of pods from users profile
```javascript
	const pods = session.profile.pim$storage
```
