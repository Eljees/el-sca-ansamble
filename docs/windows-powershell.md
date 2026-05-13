# Windows PowerShell

```powershell
docker compose config
docker compose build
docker compose --profile update up
docker compose --profile scan up
docker compose --profile test-failover up
pytest
.\scripts\windows\pack-artifacts.ps1
```

Example local mount pattern:

```powershell
docker compose run --rm -v ${PWD}:/workspace grype-updater update grype
```
