# Local operations and recovery

ScopeLens supports one Docker Compose deployment for local authorized work. The
operational stack and the public demo are separate. The operational stack can run
bounded checks against server-owned scope. The public demo contains recorded,
sanitized data and no operational API.

## Start the local stack

Run the following commands from the repository root in PowerShell or a WSL shell.
Docker Desktop must be using Linux containers.

```powershell
Copy-Item .env.example .env
```

Set these values in `.env` before starting:

- `SCOPELENS_POSTGRES_PASSWORD`: a new local password using URL-safe characters
- `SCOPELENS_API_TOKEN`: 32 to 512 visible ASCII characters

The file is ignored by Git. Do not put either value in the frontend configuration.
The dashboard asks for the API token and keeps it in memory for the current tab.

```powershell
docker compose config --quiet
docker compose build
docker compose up -d --wait
docker compose ps
```

The API is available at `http://127.0.0.1:8000` and the dashboard at
`http://127.0.0.1:8080`. PostgreSQL and the lab target have no host-published
ports. The API listens on all interfaces inside its container so Docker can publish
it, while Compose restricts the host publication to loopback.

The API startup command validates `deploy/scope.lab.toml`, waits for PostgreSQL,
and applies the Alembic migration chain. It never resets or downgrades the database.
A migration error stops the API and remains visible in `docker compose logs api`.

## Run the controlled workflow

The bundled configuration authorizes one lab address and two distinct
`example.invalid` origins on that address. Web authorization and network
authorization remain separate entries.

1. Open the dashboard and enter the API token.
2. Create an assessment for `controlled-lab` with the `web_recheck` stage.
3. Execute that pending assessment explicitly. The vulnerable fixture exposes a
   directory listing.
4. Replace the lab target with the fixed fixture:

   ```powershell
   docker compose -f compose.yaml -f deploy/compose.fixed.yaml up -d --build --force-recreate lab-target
   ```

5. Create a focused retest for the same approved origin and address, then execute
   it. An explicit comparison between the two persisted rechecks can report the
   directory-listing condition as resolved within that route and backend context.

This resolution does not claim that application code was fixed or that another
route or backend is safe. To exercise uncertainty, stop the lab target before a
new focused retest. The failed acquisition remains inconclusive and cannot resolve
the previous condition.

```powershell
docker compose stop lab-target
# Create and execute the focused retest in the dashboard.
docker compose up -d lab-target
```

Restore the vulnerable fixture with:

```powershell
docker compose up -d --build --force-recreate lab-target
```

## Shutdown and interruption recovery

`docker compose stop` preserves the PostgreSQL and artifact volumes. A later
`docker compose up -d --wait` restores the same data. Startup does not execute a
pending assessment or replay interrupted work.

If the API process stops while a stage is running, restart the stack and inspect
the assessment. Reconcile stale work explicitly:

```powershell
docker compose exec api scopelens assessment-reconcile --artifacts /var/lib/scopelens
```

Reconciliation marks abandoned running work as interrupted. Start a new assessment
if the operation should be repeated.

## Back up PostgreSQL and artifacts together

PostgreSQL stores manifests, history, evidence metadata, and digests. The private
artifact volume stores the captured bytes. A database backup alone cannot restore
verifiable evidence.

Stop operational writes before copying either side:

```powershell
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-CheckedNative {
    param([scriptblock]$Command, [string]$FailureMessage)
    & $Command
    $ExitCode = $LASTEXITCODE
    if ($ExitCode -ne 0) {
        throw "$FailureMessage (exit code $ExitCode)."
    }
}

$BackupRoot = Join-Path (Resolve-Path .) "backups"
New-Item -ItemType Directory -Path $BackupRoot -Force -ErrorAction Stop | Out-Null
if (-not (Test-Path -LiteralPath $BackupRoot -PathType Container)) {
    throw "Backup root is not a directory: $BackupRoot"
}
$BackupDir = Join-Path $BackupRoot ("scopelens-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
if (Test-Path -LiteralPath $BackupDir) {
    throw "Backup destination already exists: $BackupDir"
}
New-Item -ItemType Directory -Path $BackupDir -ErrorAction Stop | Out-Null
$ArtifactsBackup = Join-Path $BackupDir "artifacts"
New-Item -ItemType Directory -Path $ArtifactsBackup -ErrorAction Stop | Out-Null
$DumpBackup = Join-Path $BackupDir "scopelens.dump"
$CompleteMarker = Join-Path $BackupDir "BACKUP_COMPLETE"

try {
    Invoke-CheckedNative { docker compose stop api dashboard } "Could not quiesce ScopeLens"
    Invoke-CheckedNative { docker compose exec -T postgres pg_dump -U scopelens -d scopelens -Fc -f /tmp/scopelens.dump } "PostgreSQL backup failed"
    Invoke-CheckedNative { docker compose cp postgres:/tmp/scopelens.dump $DumpBackup } "Could not copy the PostgreSQL backup"
    Invoke-CheckedNative { docker compose cp api:/var/lib/scopelens/. $ArtifactsBackup } "Could not copy the artifact backup"
    Invoke-CheckedNative { docker compose exec -T postgres rm /tmp/scopelens.dump } "Could not remove the temporary database dump"

    if (-not (Test-Path -LiteralPath $DumpBackup -PathType Leaf) -or (Get-Item -LiteralPath $DumpBackup).Length -eq 0) {
        throw "The PostgreSQL backup is missing or empty."
    }
    if (-not (Test-Path -LiteralPath $ArtifactsBackup -PathType Container)) {
        throw "The artifact backup is missing."
    }

    $MarkerTemp = Join-Path $BackupDir ".BACKUP_COMPLETE.tmp"
    [IO.File]::WriteAllText($MarkerTemp, "scopelens-paired-backup-v1")
    Move-Item -LiteralPath $MarkerTemp -Destination $CompleteMarker -ErrorAction Stop
} catch {
    Write-Warning "Backup incomplete. Do not restore from $BackupDir because BACKUP_COMPLETE was not created."
    throw
}
```

The destination must be new and empty so files from older snapshots cannot be
mixed into the backup. Keep the database dump and artifact directory as one set.
Only a set with the exact `BACKUP_COMPLETE` marker is restorable. A failed attempt
is left unmarked for diagnosis or deliberate removal. Record when the stack was
stopped so the two copies are not mistaken for independent snapshots.

Restore into a new, empty Compose project or after deliberately removing the old
volumes. Start PostgreSQL first, restore the database dump, create the API container,
then copy the matching artifacts into its volume. The copied artifact tree must be
owned by UID/GID `10001:10001`; directories require mode `0700` and files require
mode `0600`. Start the API only after both sides are in place.

For a new empty Compose project, first stop the source stack with `docker compose
down` without `--volumes`. This preserves its data while removing the fixed lab
network, which cannot coexist with a second copy. Use a distinct project name for
every restore command. `pg_restore --clean` replaces data in the selected database,
so do not run it against a database you intend to keep.

```powershell
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-CheckedNative {
    param([scriptblock]$Command, [string]$FailureMessage)
    & $Command
    $ExitCode = $LASTEXITCODE
    if ($ExitCode -ne 0) {
        throw "$FailureMessage (exit code $ExitCode)."
    }
}

$BackupDir = (Resolve-Path -LiteralPath "backups/scopelens-YYYYMMDD-HHMMSS" -ErrorAction Stop).Path
$DumpBackup = Join-Path $BackupDir "scopelens.dump"
$ArtifactsBackup = Join-Path $BackupDir "artifacts"
$CompleteMarker = Join-Path $BackupDir "BACKUP_COMPLETE"
if (-not (Test-Path -LiteralPath $DumpBackup -PathType Leaf) -or (Get-Item -LiteralPath $DumpBackup).Length -eq 0) {
    throw "The PostgreSQL backup is missing or empty."
}
if (-not (Test-Path -LiteralPath $ArtifactsBackup -PathType Container)) {
    throw "The artifact backup is missing."
}
if (-not (Test-Path -LiteralPath $CompleteMarker -PathType Leaf) -or (Get-Content -LiteralPath $CompleteMarker -Raw -ErrorAction Stop) -ne "scopelens-paired-backup-v1") {
    throw "The paired backup is incomplete or has an invalid completion marker."
}

$RestoreProject = "scopelens-restore"
$SourceConfigJson = Invoke-CheckedNative { docker compose config --format json } "Could not inspect the source Compose project"
$SourceProject = ($SourceConfigJson | ConvertFrom-Json -ErrorAction Stop).name
if ($RestoreProject -eq $SourceProject) {
    throw "Use a restore project that is distinct from the source project."
}
$ExistingContainers = @(Invoke-CheckedNative { docker ps --all --quiet --filter "label=com.docker.compose.project=$RestoreProject" } "Could not inspect restore containers")
$ExistingVolumes = @(Invoke-CheckedNative { docker volume ls --quiet --filter "label=com.docker.compose.project=$RestoreProject" } "Could not inspect restore volumes")
if ($ExistingContainers.Count -ne 0 -or $ExistingVolumes.Count -ne 0) {
    throw "Restore project $RestoreProject already has containers or volumes. Use a new empty project."
}

try {
    Invoke-CheckedNative { docker compose down } "Could not stop the source stack"
    Invoke-CheckedNative { docker compose -p $RestoreProject build api dashboard lab-target } "Could not build the restore services"
    Invoke-CheckedNative { docker compose -p $RestoreProject up -d --wait postgres } "Restore PostgreSQL did not become ready"
    Invoke-CheckedNative { docker compose -p $RestoreProject cp $DumpBackup postgres:/tmp/scopelens.dump } "Could not copy the database backup into PostgreSQL"
    Invoke-CheckedNative { docker compose -p $RestoreProject exec -T postgres pg_restore --exit-on-error --clean --if-exists -U scopelens -d scopelens /tmp/scopelens.dump } "PostgreSQL restore failed"
    Invoke-CheckedNative { docker compose -p $RestoreProject create api } "Could not create the stopped API container"
    Invoke-CheckedNative { docker compose -p $RestoreProject cp "$ArtifactsBackup/." api:/var/lib/scopelens/ } "Could not copy the artifact backup"
    Invoke-CheckedNative { docker compose -p $RestoreProject run --rm --no-deps --user 0 --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --entrypoint sh api -c 'chown -R 10001:10001 /var/lib/scopelens && find /var/lib/scopelens -type d -exec chmod 700 {} \; && find /var/lib/scopelens -type f -exec chmod 600 {} \;' } "Could not repair artifact ownership and permissions"
    Invoke-CheckedNative { docker compose -p $RestoreProject up -d --wait } "The restored stack did not become ready"
    Invoke-CheckedNative { docker compose -p $RestoreProject exec -T api scopelens history-reconcile --artifacts /var/lib/scopelens } "History reconciliation failed"
    Invoke-CheckedNative { docker compose -p $RestoreProject exec -T api scopelens assessment-reconcile --artifacts /var/lib/scopelens } "Assessment reconciliation failed"
} catch {
    Write-Warning "Restore failed. Do not treat $RestoreProject as restored or start its API manually."
    throw
}
```

If restore fails after PostgreSQL starts, leave the disposable restore project for
diagnosis or stop and remove that project's resources explicitly. Do not start its
API manually and do not reuse its partial volumes for another restore attempt.

History reconciliation reports missing, corrupt, and unreferenced files. It does
not delete artifacts or rewrite completed evidence as valid. A database reference
without its artifact remains an evidence-health problem. An artifact without a
database reference remains unreferenced. Digest mismatch remains corrupt evidence.

## Public demo

The public demo is built from the M14 allowlisted snapshot pipeline:

```powershell
uv run --locked python deploy/generate_demo_snapshot.py demo-snapshot.json
cd frontend
npm ci
npm run build:demo
npm run verify:demo
```

The generator refuses to overwrite an existing file. The committed fixture at
`frontend/demo-data/public-snapshot.json` is checked against the same deterministic
projection in tests.

Preview the static demo without starting PostgreSQL or the operational API:

```powershell
docker compose -f deploy/compose.demo.yaml up -d --build --wait
```

Open `http://127.0.0.1:8081/demo.html`. This image contains only static files. It
has no token, scanners, worker action, private volume, or connection to the
operational Compose networks. The resulting `frontend/dist-demo/` directory can be
served by a static host; no external deployment is performed by this repository.
