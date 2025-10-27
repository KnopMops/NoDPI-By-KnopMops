document.getElementById('toggleBtn').addEventListener('click', () => {
	chrome.runtime.sendMessage({ action: 'toggleProxy' }, response => {
		updateUI(response.enabled)
	})
})

function updateUI(enabled) {
	const status = document.getElementById('status')
	const btn = document.getElementById('toggleBtn')

	if (enabled) {
		status.textContent = 'Proxy ON'
		status.style.color = '#4caf50'
		btn.textContent = 'Выключить'
	} else {
		status.textContent = 'Proxy OFF'
		status.style.color = '#f44336'
		btn.textContent = 'Включить'
	}
}

// при загрузке обновляем UI
chrome.storage.local.get('enabled', data => {
	updateUI(data.enabled)
})
