#!/bin/bash

# Get the absolute path of the current directory
current_directory=$(pwd)

# Print the result
echo "The absolute path of the current directory is: $current_directory"

# Build Deployment and create global_secrets.h
echo "Building Deployment to generate global_secrets.h...."
poetry run ectf_build_depl -d "$current_directory" || { echo "ERROR: Failed to build deployment."; exit 1; }

# Build Application processor
echo "Building Application Processor...."
poetry run ectf_build_ap -d "$current_directory" -on ap --p 123456 -c 2 -ids "0x11111124, 0x11111125" -b "Test boot message" -t 0123456789abcdef -od build || { echo "ERROR: Failed to build Application processor."; exit 1; }

# Build Component A
echo "Building Component A...."
poetry run ectf_build_comp -d "$current_directory" -on comp -od build -id 0x11111124 -b "Component boot" -al "McLean" -ad "08/08/08" -ac "Fritz" || { echo "ERROR: Failed to build Component A."; exit 1; }

# Build Component B
echo "Building Component B...."
poetry run ectf_build_comp -d "$current_directory" -on comp -od build -id 0x11111125 -b "Component boot" -al "Doe" -ad "03/04/05" -ac "John" || { echo "ERROR: Failed to build Component B."; exit 1; }

echo "SUCCESS: Script executed successfully."
