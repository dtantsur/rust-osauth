#!/bin/bash

set -eux

LOG_DIR=${LOG_DIR:-/tmp/devstack-logs}
mkdir -p "$LOG_DIR/examples"

EXAMPLES="compute-versions list-servers list-servers-paginated object-store"

OS_CLOUD=devstack-admin openstack flavor create test-flavor \
    --ram 512 --disk 5 --vcpu 1 --public

export OS_CLOUD=devstack
export RUST_BACKTRACE=1
export RUST_LOG=osauth,osproto,reqwest,hyper

FAILED=
set +ex
echo "******************************"

for example in $EXAMPLES; do
    echo "Running example $example..."
    cargo run --example $example 2>&1 | tee "$LOG_DIR/examples/$example.log"
    if [[ $? != 0 ]]; then
        FAILED+="$example "
    fi
    echo "******************************"
done

if [[ "$FAILED" != "" ]]; then
    echo "ERROR: the following examples have failed: $FAILED"
    exit 1
fi
