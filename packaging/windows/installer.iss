; Inno Setup script for Pluto Advance 0.5
;
; Build (on Windows, after PyInstaller has run):
;     iscc packaging\windows\installer.iss
;
; Produces packaging\windows\Output\Pluto-Advance-0.5-Setup.exe

#define AppName "Pluto Advance"
#define AppVersion "0.5.0"
#define AppPublisher "Pluto Advance Project"
#define AppExeName "PlutoAdvance.exe"
#define AppId "{{B4E7A2C1-9F3D-4A8E-B5C6-1D2E3F4A5B6C}"

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
VersionInfoVersion={#AppVersion}

; Per-user install by default: no administrator rights needed, which keeps the
; agent out of Program Files and away from privileges it does not need.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}

; Mutable data lives in %LOCALAPPDATA%, never in the install directory, so an
; installed copy never needs write access to itself.
UsePreviousAppDir=yes
DisableProgramGroupPage=yes
LicenseFile=..\..\LICENSE
InfoBeforeFile=before-install.txt
OutputDir=Output
OutputBaseFilename=Pluto-Advance-0.5-Setup
SetupIconFile=..\..\assets\pluto.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
UninstallDisplayIcon={app}\{#AppExeName}
UninstallDisplayName={#AppName} {#AppVersion}
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; \
    GroupDescription: "Shortcuts:"
Name: "startmenuicon"; Description: "Create a &Start menu entry"; \
    GroupDescription: "Shortcuts:"; Flags: checkedonce

[Files]
; The whole PyInstaller one-folder build.
Source: "dist\PlutoAdvance\*"; DestDir: "{app}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs

; Documentation the user may want after install.
Source: "..\..\README.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\..\SECURITY.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\..\docs\STATUS.md"; DestDir: "{app}\docs"; Flags: ignoreversion skipifsourcedoesntexist

; NOTE: no API key, .env file or credential is ever bundled.

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"; \
    Comment: "Your Intelligent Digital Operator"; Tasks: startmenuicon
Name: "{group}\{#AppName} documentation"; Filename: "{app}\docs\README.md"; \
    Tasks: startmenuicon
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"; \
    Tasks: startmenuicon
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; \
    Comment: "Your Intelligent Digital Operator"; Tasks: desktopicon

[Dirs]
; User data directory, created at install so first run never has to.
Name: "{localappdata}\PlutoAdvance"; Flags: uninsneveruninstall
Name: "{localappdata}\PlutoAdvance\logs"; Flags: uninsneveruninstall

[Run]
Filename: "{app}\{#AppExeName}"; \
    Description: "Start {#AppName} now"; \
    Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Remove only what the installer created. User data in %LOCALAPPDATA% is left
; alone and the uninstaller offers to remove it explicitly instead.
Type: filesandordirs; Name: "{app}\_internal"
Type: filesandordirs; Name: "{app}\docs"

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
  Answer: Integer;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{localappdata}\PlutoAdvance');
    if DirExists(DataDir) then
    begin
      Answer := MsgBox(
        'Remove Pluto''s data as well?' + #13#10#13#10 +
        'This deletes your task history, audit log, memory and settings from:' +
        #13#10 + DataDir + #13#10#13#10 +
        'Your Claude API key is stored in the Windows Credential Manager and ' +
        'is removed separately — see the documentation.' + #13#10#13#10 +
        'Choose No to keep your data for a future reinstall.',
        mbConfirmation, MB_YESNO);
      if Answer = IDYES then
        DelTree(DataDir, True, True, True);
    end;
  end;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
end;
