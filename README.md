# sales_with_cicd_on_fabric

Fabric CI/CD automation workflows for the Sales project.

## Repository Structure

```
.github/workflows/                      # GitHub Actions workflow definitions
  update-variable-libraries.yml         #   → Update Fabric Variable Libraries
  create-adls-connection.yml            #   → Create ADLS Gen2 Connection

workflows/                              # Scripts & config per workflow
  update-variable-libraries/            # ── Update Variable Libraries ──
    update_variable_library.py          #   Python script
    variable_updates.yml                #   Configuration (which variables to update)
    requirements.txt                    #   Python dependencies

  create-adls-connection/               # ── Create ADLS Gen2 Connection ──
    create_adls_connection.py           #   Python script
    create_adls_connection.ps1          #   PowerShell alternative
```

## Workflows

### Update Variable Libraries

Modifies variable values in Fabric Variable Libraries via REST API.
Triggered manually (`workflow_dispatch`) with optional dry-run mode.

### Create ADLS Gen2 Connection

Creates a shareable cloud connection to Azure Data Lake Storage Gen2 in Fabric.
Triggered manually (`workflow_dispatch`).
