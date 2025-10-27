document.addEventListener('DOMContentLoaded', function () {
	const enableBtn = document.getElementById('enableBtn')
	const disableBtn = document.getElementById('disableBtn')
	const statusDiv = document.getElementById('status')

	// Проверка статуса прокси при загрузке
	updateStatus()

	// Обновление статуса каждые 2 секунды
	setInterval(updateStatus, 2000)

	enableBtn.addEventListener('click', function () {
		enableBtn.disabled = true
		disableBtn.disabled = true

		chrome.runtime.sendMessage({ action: 'enableProxy' }, function (response) {
			enableBtn.disabled = false
			disableBtn.disabled = false

			if (response.success) {
				updateStatus()
			} else {
				statusDiv.textContent = 'Ошибка: ' + response.message
				statusDiv.className = 'status-disabled'
			}
		})
	})

	disableBtn.addEventListener('click', function () {
		enableBtn.disabled = true
		disableBtn.disabled = true

		chrome.runtime.sendMessage({ action: 'disableProxy' }, function (response) {
			enableBtn.disabled = false
			disableBtn.disabled = false

			if (response.success) {
				updateStatus()
			} else {
				statusDiv.textContent = 'Ошибка: ' + response.message
				statusDiv.className = 'status-disabled'
			}
		})
	})

	function updateStatus() {
		chrome.runtime.sendMessage({ action: 'getStatus' }, function (response) {
			if (response.enabled) {
				statusDiv.textContent = 'Прокси включен (127.0.0.1:8881)'
				statusDiv.className = 'status-enabled'
				enableBtn.disabled = true
				disableBtn.disabled = false
			} else {
				statusDiv.textContent = 'Прокси выключен'
				statusDiv.className = 'status-disabled'
				enableBtn.disabled = false
				disableBtn.disabled = true
			}
		})
	}
})
