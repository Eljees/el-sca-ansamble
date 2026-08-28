# v5 watcher: wait for cvebt_build (per-source builder) -> ship /out tgz to node -> import.
$log = 'D:\dev\el-sca-ansamble\artifacts\sneakernet.log'
function L([string]$m) { (Get-Date -Format 'HH:mm:ss') + '  ' + $m | Out-File $log -Append -Encoding utf8 }
Set-Content $log '=== sneakernet v5 start ===' -Encoding utf8

L 'waiting for cvebt_build...'
$rc = docker wait cvebt_build 2>&1
L ('build exit code: ' + $rc)
docker logs cvebt_build 2>&1 | Select-String -Pattern 'STEP|rc=|PACKED|audit' | Select-Object -Last 15 | Out-File $log -Append -Encoding utf8

if (-not (Test-Path D:\tmp\cvebt_pack\cvebt_db.tgz)) { L 'FATAL: no cvebt_db.tgz in /out'; exit 2 }
$sz = [math]::Round((Get-Item D:\tmp\cvebt_pack\cvebt_db.tgz).Length / 1MB, 1)
L ('tgz size MB: ' + $sz)

L 'scp tgz to node...'
cmd /c "scp -o MACs=hmac-sha2-256 -i C:\Users\314he\.ssh\elaria_rostel D:\tmp\cvebt_pack\cvebt_db.tgz yuriy.tumanov@10.2.108.47:/tmp/cvebt_db.tgz"
L ('scp tgz rc: ' + $LASTEXITCODE)
if ($LASTEXITCODE -ne 0) { L 'FATAL: scp failed'; exit 3 }
cmd /c "scp -o MACs=hmac-sha2-256 -i C:\Users\314he\.ssh\elaria_rostel D:\dev\el-sca-ansamble\artifacts\node_import.sh yuriy.tumanov@10.2.108.47:/tmp/node_import.sh"
L ('scp import.sh rc: ' + $LASTEXITCODE)
L 'running import on node...'
cmd /c "ssh -o ConnectTimeout=20 -m hmac-sha2-256 -i C:\Users\314he\.ssh\elaria_rostel yuriy.tumanov@10.2.108.47 bash /tmp/node_import.sh"
L ('node import rc: ' + $LASTEXITCODE)
L '=== pipeline done ==='
