@echo off
setlocal

pushd "%~dp0"

openfiles > nul
if errorlevel 1 echo �Ǘ��҂Ƃ��Ď��s���Ă��������I & pause & exit 1

rem �t�@�C���̑��݊m�F
if not exist .\Setup-WinRMConfiguration.ps1 (
    echo �uSetup-WinRMConfiguration.ps1�v������܂���B
    echo �usetup.bat�v���uSetup-WinRMConfiguration.ps1�v�Ɠ����t�H���_�ɔz�u���Ă��������B
    pause
    exit 1
)

SET /P ANSWER="WinRM�ڑ��̂��߂̐ݒ���J�n���܂��B��낵���ł��� (y/n)�H"
if /i {%ANSWER%}=={y} (goto :yes)
if /i {%ANSWER%}=={Y} (goto :yes)
if /i {%ANSWER%}=={yes} (goto :yes)
echo �un�v���I�����ꂽ�̂ŃZ�b�g�A�b�v���I�����܂��B
pause
exit 0

:yes

echo �A�J�E���g������͂��Ă��������B
echo �A�J�E���g���́u�R���s���[�^��\�A�J�E���g���v�܂��́u�h���C����\�A�J�E���g���v�Ŏw��ł��܂��B
set /p account=">"
echo. > .\Setup-WinRMConfiguration.ps1:Zone.Identifier
powershell -ExecutionPolicy RemoteSigned -File .\Setup-WinRMConfiguration.ps1 %account%

if not %errorlevel% equ 0 (
    echo WinRM�ڑ��̐ݒ�Ɏ��s���܂����B�Z�b�g�A�b�v���I�����܂��B
    pause
    exit 1
)

echo WinRM�ڑ��̐ݒ肪�������܂����B�Z�b�g�A�b�v���I�����܂��B
popd

pause

exit 0