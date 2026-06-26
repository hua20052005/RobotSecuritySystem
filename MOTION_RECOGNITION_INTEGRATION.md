# Motion Recognition Integration

This integration keeps the legacy motion module unchanged and adds a separate
recognition-first pipeline.

## What Was Added

- `backend/motion_recognition_api.py`
  - New FastAPI router mounted at `/api/motion-recognition`.
  - Loads the copied action recognizer model.
  - Runs either single-action recognition or sequence recognition.
  - Sends recognized action labels to PAPB for action-flow validation.
  - Saves each run into the existing task history database.

- `backend/motion_recognition/robot_traffic_action/`
  - A self-contained copy of the current action-recognition code from
    `C:\Users\Mojo0108\Documents\New project\src\robot_traffic_action`.

- `models/motion_recognition/motion_model.pkl`
  - The current trained recognizer model copied from
    `outputs_motion_new_actions_traffic\motion_model.pkl`.

- `backend/payload_api/main.py`
  - Includes the new router while preserving the old `/api/motion/analyze`.

## API

Health check:

```powershell
curl http://127.0.0.1:8010/api/motion-recognition/health
```

Recognize a sequence and validate its action flow:

```powershell
curl -X POST http://127.0.0.1:8010/api/motion-recognition/recognize `
  -F "file=@seq08_basic_showcase.pcap" `
  -F "mode=sequence" `
  -F "method=dp" `
  -F "validate_flow=true"
```

Recognize a single action:

```powershell
curl -X POST http://127.0.0.1:8010/api/motion-recognition/recognize `
  -F "file=@test_data/hello/hello6.pcap" `
  -F "mode=single"
```

Use scripted sequence recognition when the expected action order is known:

```powershell
curl -X POST http://127.0.0.1:8010/api/motion-recognition/recognize `
  -F "file=@seq08_basic_showcase.pcap" `
  -F "mode=sequence" `
  -F "method=scripted" `
  -F "transcript=stand,hello,stand,backflip" `
  -F "validate_flow=true"
```

## Fallback Design

The old module remains available:

- Legacy motion modeling: `/api/motion/analyze`
- New recognition + PAPB validation: `/api/motion-recognition/recognize`
- Direct PAPB validation: `/api/papb/detect`

This means the system can fall back to the original temporal modeling module if
the new recognizer model or copied package needs adjustment.

## Runtime Note

The local `.venv` in this directory currently points to an old Python path. If
backend startup fails with `Unable to create process`, recreate the virtual
environment:

```powershell
cd C:\Users\Mojo0108\Desktop\system\RobotSecuritySystem
Remove-Item -Recurse -Force .venv
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -r requirements.txt
pip install -r .\payload-detection\requirements.txt
```
