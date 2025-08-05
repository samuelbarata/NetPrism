# NetPrism


## Running with Docker

For convenience, this repository includes a helper script, `netprism.sh`, designed to simplify running the tool as a Docker container.

The script is a self-contained configuration file that you `source` in your terminal. When sourced, it sets up your shell session with `netprism` and `np` commands that are pre-configured to mount the correct local configuration files into the container.

This allows you to manage multiple network environments (e.g., a lab, production) by simply maintaining a separate copy of the `netprism.sh` script for each one.

### Prerequisites

* **Docker** must be installed and running on your system.

### Setup Instructions

1. **Download [`netprism.sh`](neprism.sh) from this repo** 

2.  **Create an Environment File**: Make a copy of the `netprism.sh` script for the environment you want to manage.
    ```bash
    cp netprism.sh my_lab_env.sh
    ```

3.  **Edit the Configuration**: Open your new script (e.g., `my_lab_env.sh`) in a text editor and modify the variables in the `--- USER CONFIGURATION ---` section to match your setup.

### Configuration Variables

The following variables need to be set in your environment script:

| Variable        | Required | Description                                                                                                                                                             |
| --------------- | :------: | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DOCKER_IMAGE`  |    No    | The name of the Docker image to use. Defaults to `samuelbarata/netprism`.                                                                                                |
| `TAG`           |    No    | The tag of the Docker image. Defaults to `latest`.                                                                                                                      |
| `CERT_FILE`     |    No    | The **full path** to your CA certificate file if you are using one.                                                                                           |
| `CLAB_TOPO`     |   Yes* | The **full path** to your Containerlab topology file (e.g., `netprism.clab.yaml`).                                                                                      |
| `NORNIR_DIR`    |   Yes* | The **full path** to the **directory** containing your Nornir files (`nornir_config.yaml`, `hosts.yaml`, etc.). **Note:** Paths inside your `nornir_config.yaml` must be relative. |
| `NORNIR_CONFIG` |    No    | The name of the Nornir configuration file within `NORNIR_DIR`. Defaults to `nornir_config.yaml`.                                                                         |

**\*Note:** `CLAB_TOPO` and `NORNIR_DIR` are **mutually exclusive**. You must set one and leave the other empty (`""`).

### Usage Example

Once your environment script is configured, you can activate it and run commands.

1.  **Source the Script**: In your terminal, `source` the script for the environment you want to work with. This command only needs to be run once per terminal session.

    ```bash
    source ./my_lab_env.sh
    ```
    You should see the confirmation message:
    `✅ Netprism environment configured. You can now use the 'netprism' and 'np' commands.`

2.  **Execute Commands**: You can now run `netprism` commands as if it were a native application. The script handles the Docker commands in the background.

    To get system information from your nodes:
    ```bash
    netprism sys-info
    ```
    Or using the short alias:
    ```bash
    np sys-info
    ```

---

## Running Locally

If you prefer to run the application directly on your machine without Docker, you can do so using Poetry for dependency management.

### Prerequisites

* **Python** 3.12+
* **Poetry** 2.1+

### Setup Instructions

1.  **Clone the Repository**

2.  **Install Poetry**: If you don't have Poetry installed, follow the official instructions:
    [https://python-poetry.org/docs/#installation](https://python-poetry.org/docs/#installation)

3.  **Install Dependencies**: Use Poetry to install the project's dependencies into a virtual environment.
    ```bash
    poetry install
    ```

### Usage Example

When running locally, you do not use the `netprism.sh` sourcing script. Instead, you run the application using `poetry run` and pass configuration files directly as command-line flags.

To get system information from your nodes using a Nornir configuration:
```bash
poetry run netprism --cfg /path/to/your/nornir/nornir_config.yaml sys-info
```
Or using a Containerlab deployment:
```bash
poetry run netprism --topo-file /path/to/your/containerlab/topology.yaml --cert-file /path/to/your/containerlab/clab-deployment-folder/.tls/ca/ca.pem sys-info
``` 
