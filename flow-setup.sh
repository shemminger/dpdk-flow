#! /bin/bash
# Run with 16 MAC addresses

if [ -z "$1" ]
then
    echo "Usage: $0 Nvnic"
    exit 1
fi
NVNIC=$1

declare -A MACS
for (( i=0 ; i<$NVNIC ; i++))
do
    h=`printf '%02x' $((i+1))`
    MACS[${i}]=1a:00:00:a5:5a:${h}
done

./build/flow-demo -n 2 -l 1-4 ${EAL_ARGS} -- -v ${MACS[*]}
