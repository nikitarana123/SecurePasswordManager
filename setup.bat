@echo off

echo ==========================================
echo Secure Password Manager - Setup
echo ==========================================

echo.
echo Creating virtual environment...

python -m venv venv

if errorlevel 1 (
    echo Failed to create virtual environment.
    pause
    exit /b 1
)

echo.
echo Activating virtual environment...

call venv\Scripts\activate

echo.
echo Installing required packages...

python -m pip install --upgrade pip
pip install -r requirements.txt

if errorlevel 1 (
    echo Failed to install required packages.
    pause
    exit /b 1
)

echo.
echo ==========================================
echo Setup completed successfully.
echo ==========================================

echo.
echo Before running the application, configure:
echo PASSWORD_MANAGER_KEY
echo PASSWORD_MANAGER_SECRET_KEY

echo.
echo Then run:
echo python app.py

echo.
pause