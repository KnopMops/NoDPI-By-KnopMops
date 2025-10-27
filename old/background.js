chrome.runtime.onInstalled.addListener(() => {
	chrome.storage.local.set({ enabled: false })
})

// Функция переключения прокси
function setProxy(enabled) {
	if (enabled) {
		chrome.proxy.settings.set(
			{
				value: {
					mode: 'fixed_servers',
					rules: {
						singleProxy: { scheme: 'http', host: '127.0.0.1', port: 8881 },
					},
				},
				scope: 'regular',
			},
			() => console.log('Proxy enabled')
		)
	} else {
		chrome.proxy.settings.clear({ scope: 'regular' }, () =>
			console.log('Proxy disabled')
		)
	}
}

// Слушаем сообщения от popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
	if (request.action === 'toggleProxy') {
		chrome.storage.local.get('enabled', data => {
			const newState = !data.enabled
			setProxy(newState)
			chrome.storage.local.set({ enabled: newState })
			sendResponse({ enabled: newState })
		})
		return true // async response
	}
})
