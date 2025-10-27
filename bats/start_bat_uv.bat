@echo off
echo Start bat...
echo.
E:
cd Projects\nodpi_browser\proxy\nodpi\src
uv run nd.py
echo.
echo Прокси-сервер был остановлен.
echo Нажмите любую клавишу для закрытия окна...
pause > nul