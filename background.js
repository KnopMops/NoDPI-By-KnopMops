let proxyEnabled = false

checkProxyStatus()

chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
	if (request.action === 'enableProxy') {
		enableProxy()
			.then(() => {
				proxyEnabled = true
				sendResponse({ success: true })
			})
			.catch(error => {
				sendResponse({ success: false, message: error.message })
			})
		return true
	}

	if (request.action === 'disableProxy') {
		disableProxy()
			.then(() => {
				proxyEnabled = false
				sendResponse({ success: true })
			})
			.catch(error => {
				sendResponse({ success: false, message: error.message })
			})
		return true
	}

	if (request.action === 'getStatus') {
		checkProxyStatus().then(status => {
			sendResponse({ enabled: status })
		})
		return true
	}
})

async function checkProxyStatus() {
	return new Promise(resolve => {
		chrome.proxy.settings.get({}, function (config) {
			if (
				config.value &&
				config.value.mode === 'fixed_servers' &&
				config.value.rules &&
				config.value.rules.singleProxy &&
				config.value.rules.singleProxy.host === '127.0.0.1' &&
				config.value.rules.singleProxy.port === 8881
			) {
				proxyEnabled = true
				resolve(true)
			} else {
				proxyEnabled = false
				resolve(false)
			}
		})
	})
}

async function enableProxy() {
	try {
		const config = {
			mode: 'fixed_servers',
			rules: {
				singleProxy: {
					scheme: 'http',
					host: '127.0.0.1',
					port: 8881,
				},
				bypassList: ['localhost', '127.0.0.1'],
			},
		}

		await chrome.proxy.settings.set({ value: config, scope: 'regular' })
		proxyEnabled = true
		console.log('Прокси активирован: 127.0.0.1:8881')
	} catch (error) {
		console.error('Ошибка при включении прокси:', error)
		throw error
	}
}

async function disableProxy() {
	try {
		await chrome.proxy.settings.set({
			value: { mode: 'direct' },
			scope: 'regular',
		})
		proxyEnabled = false
		console.log('Прокси деактивирован')
	} catch (error) {
		console.error('Ошибка при выключении прокси:', error)
		throw error
	}
}

chrome.proxy.onProxyError.addListener(function (error) {
	console.error('Ошибка прокси:', error)
})
