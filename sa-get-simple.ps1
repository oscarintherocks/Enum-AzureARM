# Fixed Azure Storage Blob Download Script
# Addresses the issues with Get-AzStorageBlobVersion and directory creation
# Requires Az.Storage module

param(
    [Parameter(Mandatory=$false)]
    [string]$StorageAccountName = "examplestorageaccount",
    
    [Parameter(Mandatory=$false)]
    [string]$StorageAccountKey = "EXAMPLE_KEY_REPLACE_WITH_REAL_KEY=="
)

Write-Host "Starting Azure Storage Blob Download..."

# Check and import required module
if (-not (Get-Module -Name Az.Storage -ListAvailable)) {
    Write-Error "Az.Storage module is not installed. Please install it using: Install-Module -Name Az.Storage -Force"
    exit 1
}

if (-not (Get-Module -Name Az.Storage)) {
    Write-Host "Importing Az.Storage module..."
    try {
        Import-Module Az.Storage -Force
        Write-Host "Az.Storage module imported successfully"
    } catch {
        Write-Error "Failed to import Az.Storage module: $($_.Exception.Message)"
        exit 1
    }
}

# Create storage context
try {
    $ctx = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey
    Write-Host "Storage context created successfully"
} catch {
    Write-Error "Failed to create storage context: $($_.Exception.Message)"
    exit 1
}

# Create base download directory
$baseDir = ".\StorageDownloads"
if (-not (Test-Path $baseDir)) {
    New-Item -ItemType Directory -Path $baseDir -Force | Out-Null
    Write-Host "Created base directory: $baseDir"
}

# Get all containers
try {
    $containers = Get-AzStorageContainer -Context $ctx
    Write-Host "Found $($containers.Count) containers"
} catch {
    Write-Error "Failed to retrieve containers: $($_.Exception.Message)"
    exit 1
}

$totalFiles = 0

foreach ($container in $containers) {
    $containerName = $container.Name
    Write-Host "`nProcessing container: $containerName"
    
    # Create container directory
    $containerDir = Join-Path $baseDir $containerName
    if (-not (Test-Path $containerDir)) {
        New-Item -ItemType Directory -Path $containerDir -Force | Out-Null
        Write-Host "  Created container directory: $containerDir"
    }

    # Get all blobs in the container
    try {
        $blobs = Get-AzStorageBlob -Container $containerName -Context $ctx
        Write-Host "  Found $($blobs.Count) blobs in '$containerName'"

        foreach ($blob in $blobs) {
            try {
                # Handle blob path (create subdirectories if needed)
                $blobPath = $blob.Name
                $blobDir = Split-Path $blobPath -Parent
                $blobFileName = Split-Path $blobPath -Leaf
                
                # Create subdirectories if blob has path separators
                if ($blobDir) {
                    $fullBlobDir = Join-Path $containerDir $blobDir
                    if (-not (Test-Path $fullBlobDir)) {
                        New-Item -ItemType Directory -Path $fullBlobDir -Force | Out-Null
                        Write-Host "    Created subdirectory: $fullBlobDir"
                    }
                    $destinationPath = Join-Path $fullBlobDir $blobFileName
                } else {
                    $destinationPath = Join-Path $containerDir $blobFileName
                }
                
                Write-Host "    Downloading: $blobFileName"

                # Download the blob
                Get-AzStorageBlobContent -Container $containerName -Blob $blob.Name -Destination $destinationPath -Context $ctx -Force
                $totalFiles++
                
            } catch {
                Write-Warning "    Failed to download '$($blob.Name)': $($_.Exception.Message)"
            }
        }
        
        Write-Host "  Container '$containerName' processing completed"
        
    } catch {
        Write-Warning "  Failed to process container '$containerName': $($_.Exception.Message)"
    }
}

Write-Host "`nDownload completed!"
Write-Host "Files saved to: $baseDir"
Write-Host "Total files downloaded: $totalFiles"

# Show summary
Write-Host "`nSummary:"
try {
    $downloadedFiles = Get-ChildItem -Path $baseDir -Recurse -File
    $totalSize = ($downloadedFiles | Measure-Object -Property Length -Sum).Sum
    
    Write-Host "Files downloaded: $($downloadedFiles.Count)"
    Write-Host "Total size: $([math]::Round($totalSize / 1MB, 2)) MB"
    
    # Show container breakdown
    $containerDirs = Get-ChildItem -Path $baseDir -Directory
    foreach ($containerDir in $containerDirs) {
        $containerFiles = Get-ChildItem -Path $containerDir.FullName -Recurse -File
        Write-Host "  $($containerDir.Name): $($containerFiles.Count) files"
    }
} catch {
    Write-Warning "Could not generate summary: $($_.Exception.Message)"
}

Write-Host "`nScript completed successfully!"