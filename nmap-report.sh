#!/bin/bash

# Tools array for external functionalities
tools=(dirb nikto whatweb sslscan ike yawast)

# Usage function for script instructions
usage() {
    echo -e "[*] Usage:"
    echo -e "[*] $0 [-r] [-n|-e] [-d] <NMAP-FILE>"
    echo -e "\t-r: Build a reusable version of the report"
    echo -e "\t-n: Build target files for ${tools[@]}"
    echo -e "\t-e: Executes ${tools[@]} [implies -n]"
    echo -e "\t-d: Show debug messages"
    echo -e "\t-p <state>: List ports by state (open|filtered|closed|all)"
    exit 1
}

# Function to list ports by state
list_ports_by_state() {
    local file=$1
    local state=$2
    if [[ "$state" == "all" ]]; then
        cat "$file" | grep -P "^\d{1,5}" | grep -P "open|closed" | awk -F "/" '{print $1}' | sort -u | sed "s/$/,/g" | tr -d "\n" | sed "s/,$//g"
    else
        cat "$file" | grep -P "^\d{1,5}" | grep -P "$state" | awk -F "/" '{print $1}' | sort -u | sed "s/$/,/g" | tr -d "\n" | sed "s/,$//g"
    fi
}

# Function to execute external tools
execute() {
    for tool in ${tools[@]}; do
        if [[ "$(which $tool)" != "" ]]; then
            mkdir -p $tool
            case "$tool" in
                dirb) echo "dirb-exec";;
                nikto) echo "nikto-exec";;
                sslscan) echo "sslscan-exec";;
                ike) echo "iker-exec";;
                *) echo "$tool: Tool execution not implemented";;
            esac
        fi
    done
}

# Main script logic
PARAMS=""
FILE=""
exe=0
report=0
gen=0
debug=0
port_state=""

if [ $# -lt 1 ]; then
    usage
fi

while (( "$#" )); do
    case "$1" in
        -h|--help) usage;;
        -r|--report) report=1; shift 1;;
        -g|--generate) gen=1; shift 1;;
        -e|--execute) exe=1; shift 1;;
        -d|--debug) debug=1; shift 1;;
        -p|--ports) port_state=$2; shift 2;;
        --) shift; break;;
        -*|--*=) echo "Error: Unsupported flag $1" >&2; exit 1;;
        *) FILE="$1"; shift;;
    esac
done

if [ ! -f "$FILE" ]; then
    echo "[!] Not a valid nmap file"
    usage
fi

if [[ -n "$port_state" ]]; then
    list_ports_by_state "$FILE" "$port_state"
    exit 0
fi

cat "$FILE" | grep -v "scan initiated" | grep -P "report|open" > "./_tmp"

ip=""
nothing_found=1
printf "%.15s\t%.5s\t%.15s\t%.40s\n" "IP             " "PORT" "PROTOCOL" "SERVICE"

while read line; do
    if [[ "$(echo $line | grep report)" == "" ]]; then
        port="$(echo $line | grep -o -P '^\d{2,5}')"
        proto="$(echo $line | awk '{print $3}')"
        t=$((9 - $(echo $proto | wc -c)))

        if [ $gen -gt 0 ]; then
            scheme=""
            case "$proto" in
                *https*) scheme="https";;
                *http*) scheme="http";;
                *ssl*) scheme="ssl";;
                *ike*) scheme="ike";;
            esac
            if [[ -n "$scheme" ]]; then
                case "$scheme" in
                    "ssl") echo "$ip:$port" >> "./ssl-targets.txt";;
                    "ike") echo "$ip" >> "./ike-targets.txt";;
                    *) echo "$scheme://$ip:$port" >> "./$scheme-targets.txt";;
                esac
            fi
        fi

        if [ $t -gt 0 ]; then
            printf -v pad "%.${t}s" "        "
            proto="$proto$pad"
        fi

        reason="$(echo $line | awk '{print $4}')"
        skip=0
        s="$(echo $line | awk '{print $5}')"

        if [[ "$s" == "ttl" ]]; then
            if [[ -z "$(echo $line | awk '{print $7}')" ]]; then
                skip=1
            fi
            sn=7
        else
            sn=5
        fi

        if [ $skip -eq 0 ]; then
            service="$(echo $line | awk -v start=$sn '{for (i=start;i<NF;i++) printf "%s%s",$i,(i+4>NF?" ":FS);print $NF}')"
        else
            service="Unknown Service"
        fi

        nothing_found=0
        printf "%.15s\t%.5s\t%.15s\t%.40s\n" "$ip" "$port" "$proto" "$service"
    else
        if [[ $nothing_found -eq 1 && -n $ip ]]; then
            printf "%.15s\t%.5s\t%.15s\t%.40s\n" "$ip" "N/A" "Open Ports" "Services"
        fi
        printf "%.s-" {1..73}
        printf "\n"
        ip="$(echo $line | grep -o -P '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')"
        nothing_found=1
    fi
done < "./_tmp"

rm -f "./_tmp"

if [ $exe -gt 0 ]; then
    execute
fi
