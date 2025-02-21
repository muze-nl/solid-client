import * as metro from '@muze-nl/metro/src/metro.mjs'
import {isAuthorized} from '@muze-nl/metro-oauth2/src/oauth2.mjs'
import oidcmw from '@muze-nl/metro-oidc/src/oidcmw.mjs'
import {oldm} from '@muze-nl/oldm'
import {_, from,one} from '@muze-nl/jaqt'
import jsfs from '@muze-nl/jsfs/src/browser.js'

class solidClient {
	#client;
	options;

	constructor(options) {
		let defaultOptions = {
			//.. add default settings for metro client for solid use
			oidc: {
				client_info: {
					client_id: metro.url(window.location).authority
				}
			},
			prefixes: {
				// pim, foaf, etc.
			}
		}
		this.options = Object.assign({}, defaultOptions, options)
		this.#client = metro.client(options)
			.with(oidcmw(options.oidc))
	}

	login(webId, force=false) {
		const session = new solidSession(this.#client, webId, this.options)
		session.login(force)
		return session
	}
}

export default solidClient

function oldmmw(prefixes, context) {
    return async (req, next) => {
        // if req.data => check content-type, convert to that (body = oldm.write(req.data))
        if (req.data && req.data.write) {
            req = req.with({
                headers: {
                    'Content-Type': req.data.type
                },
                body: await req.data.write()
            })
        }
        let res = await next(req)
        if (res.ok) {
            // if res.content-type matches supported type, parse body, and set that (body = oldm.parse(await req.text()))
            if (!res.data) {
                const body = await context.parse(await res.text(), res.url)
                res = res.with({body})
            }
        }
        return res
    }
}

class solidSession {
	
	#client;
	#options;
	context;
	profile;

	constructor(client, webId, options) {
		this.#options = options
		this.context = oldm.context({
			prefixes: options.prefixes,
			parser: oldm.n3Parser,
			writer: oldm.n3Writer
		})
		this.#client = client.with(oldmmw(options.prefixes, this.context))
	}

	async login(forceLoginPrompt=false) {
		// first get the oidcIssuer
		if (!this.profile || !this.oidcIssuer) {
			this.profile = await client.get(webId)?.data
			this.oidcIssuer = this.profile.primary.solid$oidcIssuer
			options.openid_configuration.issuer = oidcIssuer
		}

		if (!forceLoginPrompt && this.isAuthorized()) {
			return
		}

		// temporary enable force_authorization so next request
		// will access authorize endpoint
		let force_authorization = options.force_authorization
		options.oauth2_configuration.force_authorization = true

		// if forceLoginPrompt, this forces the IdP to re-authenticate the user
		let keep = {}
		if (forceLoginPrompt) {
			for (let prop of ['max_age','prompt']) {
				keep[prop] = options.oauth2_configuration[prop]
			}
			options.oauth2_configuration.max_age = 0
			options.oauth2_configuration.prompt  = 'login'
		}

		// this call is only there to trigger the authorize endpoint
		await client.get(webId)

		// reset options back to what they were
		options.force_authorization = force_authorization
		for (let prop in keep) {
			options.oauth2_configuration[prop]  = keep[prop]
		}
	}

	async logout() {
		if (options.openid_configuration.end_session_endpoint) {
			let response = await this.#client.get(options.openid_configuration.end_session_endpoint, {
				id_token_hint: options.tokens.get('id_token'),
				client_id: options.client_info.client_id,
				post_logout_redirect_url: options.client_info.post_logout_redirect_urls[0]
			})
		}
		options.oauth2_configuration.tokens.clear()
		options.openid_configuration.store.clear()
	}

	isAuthorized() {
		return isAuthorized(this.#options.oauth2_configuration.tokens)
	}

	isAuthenticated() {
		return this.#options.openid_configuration.store.get('id_token')
	}

	pod(podURI=null,context) {
		if (!podURI) {
			podURI = from(this.profile).select(one(_.pim$storage, 'first'))
		}
		if (!podURI) {
			throw new Error('No pim:storage found in users profile')
		}
		return jsfs.fs(new Pod(this.#client, context, podURI))
	}

	get() {
		return this.#client.get.apply(this.#client, arguments)
	}

	post() {
		return this.#client.post.apply(this.#client, arguments)
	}

	put() {
		return this.#client.put.apply(this.#client, arguments)
	}

	patch() {
		return this.#client.patch.apply(this.#client, arguments)
	}

	delete() {
		return this.#client.delete.apply(this.#client, arguments)
	}
}

class Pod {
	#client;
	#baseUrl;
	#path;
	#context;

	constructor(client, context, URI, path='/') {
		this.#client = client
		this.#baseUrl = URI
		this.#path = path
		this.#context = context
	}

	get name() {
		return 'Solid Pod'
	}

	get path() {
		return this.#path
	}

	supportsWrite() {
		return true // check for write access somehow?
	}

	supportsStreamingWrite() {
		return false // for now
	}

	supportsStreadmingRead() {
		return false // for now
	}

	cd(path) {
		path = this.#getPath(path)
		if (path == this.#path) {
			return this
		}
		return new Pod(this.#client, this.#baseUrl, path)
	}

	async write(path, contents, metadata=null) {
		//TODO: implement
	}

	writeStream(path, writer, metadata=null) {
		throw new Error('Not implemented')
	}

	async read(path) {
		path = this.#getPath(path)
		let response = await this.#client.get(metro.url(this.#baseUrl, path))
		return {
			type: response.headers.get('Content-Type'),
			name: jsfs.Path.filename(path),
			http: {
				headers: response.headers,
				status: response.status,
				url: response.url
			},
			body: response.body,
			contents: response.data //parsed by oldmmw
		}
	}

	readStream(path, reader) {
		throw new Error('Not implemented')
	}

	async exists(path) {
		path = this.#getPath(path)
		this.#client.head(metro.url(this.#baseUrl, path))
	}

	async delete(path) {
		path = this.#getPath(path)
		this.#client.delete(metro.url(this.#baseUrl, path))		
	}

	async list(path=null) {
		path = this.#getPath(path)
		const result = await this.read(path)
		// list resource/containers in result.contents
		return from(result.contents)
			.where({
				a: _.ldp$Resource
			})
			.select({
				filename: o => jsfs.Path.filename(metro.url(o.id)),
				path: o => metro.url(o.id).pathname,
				name: o => jsfs.Path.filename(metro.url(o.id)),
				// FIXME: implement type as well (folder/file/mimetype?)
			})
	}

	#getPath(path){
		if (!path) {
			path = this.#path
		}
		if (!jsfs.Path.isPath(path)) {
			throw new TypeError(path+' is not a valid path')			
		}
		return path
	}
}

