#!/bin/bash
#
# #############################################################################
# Netprism Environment Configuration
# #############################################################################
#
# This script is meant to be SOURCED, not executed. It prepares your current
# shell session with the 'netprism' and 'np' commands tailored to a specific
# environment.
#
# ## How It Works:
#
# When you source this file, it immediately processes your configuration and
# builds the necessary Docker arguments. It then defines a 'netprism'
# function that uses these pre-built arguments.
#
# ## Usage:
#
# 1.  Copy this file for each network environment you manage (e.g.,
#     'lab_env.sh', 'prod_env.sh').
# 2.  Edit the "USER CONFIGURATION" section in each file.
# 3.  In your terminal, source the script for the environment you want to use:
#
#     source ./lab_env.sh
#
# 4.  You can now use the netprism commands directly:
#
#     netprism sys-info
#     np arp -i site=lab
#
# 5.  To switch environments, simply source a different configuration file.
#
# #############################################################################


# =============================================================================
# --- USER CONFIGURATION ---
#
# Edit the variables below to match your environment's file paths.
# Leave a variable empty ("") if it's not used.
# =============================================================================

# --- Image Settings ---
DOCKER_IMAGE="samuelbarata/netprism"
TAG="latest"

# --- File Paths ---
CERT_FILE="/home/samuelbarata/labs/dci-netprism-lab/clab-netprism-demo/.tls/ca/ca.pem"

# Option 1: Containerlab (mutually exclusive with Nornir)
CLAB_TOPO="/home/samuelbarata/labs/dci-netprism-lab/netprism.clab.yaml"

# Option 2: Nornir (mutually exclusive with Containerlab)
# IMPORTANT: This should be the path to the DIRECTORY containing your nornir
#            files (nornir_config.yaml, hosts.yaml, etc).
#            Paths inside nornir_config.yaml MUST be relative (e.g., "hosts.yaml").
NORNIR_DIR="" #"/home/samuelbarata/labs/dci-netprism-lab/nornir"
# (Optional) Specify a non-default config file name. Defaults to nornir_config.yaml
NORNIR_CONFIG="nornir_config.yaml"


# =============================================================================
# --- SCRIPT LOGIC (Runs when sourced) ---
# =============================================================================

# This check prevents the script from running if it's executed directly.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "❌ Error: This script is meant to be sourced, not executed." >&2
    echo "   Usage: source ${BASH_SOURCE[0]}" >&2
    exit 1
fi

# --- Validate Mutual Exclusion ---
if [[ -n "$CLAB_TOPO" && -n "$NORNIR_DIR" ]]; then
    echo "❌ Error: CLAB_TOPO and NORNIR_DIR are mutually exclusive." >&2
    echo "   Please fix the configuration in this script." >&2
    return 1
fi

# --- Prepare Docker Arguments ---
# These arrays are created in your shell environment when you source the file.
# We pre-populate it with the mandatory /etc/hosts mount using the robust --mount syntax.
DOCKER_ARGS=("--mount=type=bind,source=/etc/hosts,target=/etc/hosts,readonly")
NETPRISM_ARGS=()

# Helper function to mount single files
_add_file_arg() {
    local host_path="$1"
    local container_arg="$2"
    if [[ -f "$host_path" ]]; then
        local filename
        filename=$(basename "$host_path")
        local container_path="/data/$filename"
        # Using the more robust --mount syntax to avoid shell word-splitting issues.
        # This creates a single, unambiguous argument for the mount.
        DOCKER_ARGS+=("--mount=type=bind,source=$host_path,target=$container_path,readonly")
        NETPRISM_ARGS+=("$container_arg" "$container_path")
    else
        echo "⚠️ Warning: Config file not found, skipping mount: $host_path" >&2
    fi
}

if [[ -n "$CLAB_TOPO" ]]; then _add_file_arg "$CLAB_TOPO" "--topo-file"; fi
if [[ -n "$CERT_FILE" ]]; then _add_file_arg "$CERT_FILE" "--cert-file"; fi

# Handle Nornir directory mount
if [[ -n "$NORNIR_DIR" ]]; then
    # Expand tilde (~) in path
    eval expanded_nornir_dir="$NORNIR_DIR"
    if [[ -d "$expanded_nornir_dir" ]]; then
        # Use the --mount syntax for the directory as well.
        DOCKER_ARGS+=("--mount=type=bind,source=$expanded_nornir_dir,target=/nornir,readonly")
        NETPRISM_ARGS+=(--cfg "/nornir/${NORNIR_CONFIG:-nornir_config.yaml}")
    else
        echo "⚠️ Warning: Nornir directory not found, skipping mount: $expanded_nornir_dir" >&2
    fi
fi

# Unset the helper function so it doesn't linger in the shell
unset -f _add_file_arg

# =============================================================================
# --- COMMAND DEFINITION ---
# =============================================================================

# Define the main 'netprism' function. This is more robust than an alias and
# uses the argument arrays that were just created above.
netprism() {
    docker run -it --rm \
        --network host \
        "${DOCKER_ARGS[@]}" \
        "$DOCKER_IMAGE:$TAG" \
        "${NETPRISM_ARGS[@]}" \
        "$@"
}

# Define the short alias to call our new function
alias np='netprism'

echo "✅ Netprism environment configured. You can now use the 'netprism' and 'np' commands."
