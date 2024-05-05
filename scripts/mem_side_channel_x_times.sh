#!/bin/bash

if [ $# -ne 2 ]; then
    echo "Usage: $0 <num_iterations> <options>"
    exit 1
fi

command="printf \"1234\n\" | ./cc20 -E debian.iso -j"
options=$2
num_iterations=$1

for ((i=1; i<=num_iterations; i++)); do
    eval "$command $i $options"
    echo "Iteration $i completed."
done