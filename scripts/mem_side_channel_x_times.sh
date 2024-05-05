#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 <num_iterations>"
    exit 1
fi

command="printf \"1234\n\" | ./cc20 -E debian.iso -H -j "
num_iterations=$2

for ((i=1; i<=$num_iterations; i++)); do
    $command $i
    echo "Iteration $i completed."
done
