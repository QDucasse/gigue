#!/usr/bin/env bash

set -Eeuo pipefail
trap cleanup SIGINT SIGTERM ERR EXIT

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd -P)

cleanup() {
  trap - SIGINT SIGTERM ERR EXIT
}

setup_colors() {
  if [[ -t 2 ]] && [[ -z "${NO_COLOR-}" ]] && [[ "${TERM-}" != "dumb" ]]; then
    NOFORMAT='\033[0m' RED='\033[0;31m' GREEN='\033[0;32m' ORANGE='\033[0;33m' BLUE='\033[0;34m' PURPLE='\033[0;35m' CYAN='\033[0;36m' YELLOW='\033[1;33m'
  else
    NOFORMAT='' RED='' GREEN='' ORANGE='' BLUE='' PURPLE='' CYAN='' YELLOW=''
  fi
}

die() {
  local msg=$1
  local code=${2-1} # default exit status 1
  msg "$msg"
  exit "$code"
}

msg() {
  echo >&2 -e "${1-}"
}

setup_colors

values="low medium high"


CORE=${1:-"cva6"}
RUN=${2:-10}
ISOLATION=${3:-"none"}
CONFIG="toccata/config/manuscript_config_reduced.json"
BASE_DIR="toccata/results/manuscript-no-isolation"

msg "Starting benchmarks!" 
for meth_val in $values; do
    for call_val in $values; do
        msg "${GREEN}$meth_val methods${NOFORMAT} / ${ORANGE} $call_val call occupation${NOFORMAT}" 
        DATA_FILE=$(find toccata/results/manuscript-no-isolation -type f -wholename "*_${meth_val}_nbmethods_${call_val}_calloccup/data.json")
        SEEDS=$(python scripts/get_seeds.py ${DATA_FILE})
        python -m toccata -f ${CONFIG} -i ${ISOLATION} -n $meth_val -c $call_val -r ${RUN} -e ${CORE} -s ${SEEDS}
    done
done

for meth_val in $values; do
    for mem_val in $values; do
        msg "${GREEN}$meth_val methods${NOFORMAT} / ${ORANGE} $mem_val memory access${NOFORMAT}" 
        DATA_FILE=$(find ${BASE_DIR} -type f -wholename "*_${meth_val}_nbmethods_${mem_val}_memaccess/data.json")
        SEEDS=$(python scripts/get_seeds.py ${DATA_FILE})
        python -m toccata -f ${CONFIG} -i ${ISOLATION} -n $meth_val -m $mem_val -r ${RUN} -e ${CORE} -s ${SEEDS}
    done
done
