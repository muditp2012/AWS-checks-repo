#!/usr/bin/env bash
# =============================================================================
# AWS EC2 Security & Best-Practice Audit Script
# Based on: Trend Micro TrendAI Vision One™ Cloud Risk Management – EC2 Checks
# https://www.trendmicro.com/trendaivisiononecloudriskmanagement/knowledge-base/aws/EC2/
#
# Usage:
#   chmod +x aws_ec2_audit.sh
#   ./aws_ec2_audit.sh                              # all regions (auto-discovered)
#   ./aws_ec2_audit.sh --regions us-east-1,eu-west-1
#   ./aws_ec2_audit.sh --profile my-profile --regions us-east-1
#   ./aws_ec2_audit.sh --output-file report.txt
#
# Prerequisites:
#   • AWS CLI v2 installed and configured (aws configure / IAM role / env vars)
#   • jq >= 1.5
#   • Relevant read-only IAM permissions (ec2:Describe*, autoscaling:Describe*,
#     cloudwatch:Describe*, ce:GetReservationCoverage, etc.)
# =============================================================================

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

PASS_LABEL="${GREEN}[PASS]${RESET}"
FAIL_LABEL="${RED}[FAIL]${RESET}"
WARN_LABEL="${YELLOW}[WARN]${RESET}"
INFO_LABEL="${CYAN}[INFO]${RESET}"

# ── Counters ──────────────────────────────────────────────────────────────────
TOTAL=0; PASSED=0; FAILED=0; WARNINGS=0

pass()    { echo -e "${PASS_LABEL} $*"; PASSED=$((PASSED+1));   TOTAL=$((TOTAL+1)); }
fail()    { echo -e "${FAIL_LABEL} $*"; FAILED=$((FAILED+1));   TOTAL=$((TOTAL+1)); }
warn()    { echo -e "${WARN_LABEL} $*"; WARNINGS=$((WARNINGS+1)); TOTAL=$((TOTAL+1)); }
info()    { echo -e "${INFO_LABEL} $*"; }
header()  { echo -e "\n${BOLD}${CYAN}════════════════════════════════════════════════════${RESET}";
            echo -e "${BOLD}${CYAN}  $*${RESET}";
            echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════${RESET}"; }
section() { echo -e "\n${BOLD}── $* ──${RESET}"; }

# ── Argument parsing ──────────────────────────────────────────────────────────
AWS_PROFILE=""
REGIONS_ARG=""
OUTPUT_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)      AWS_PROFILE="$2"; shift 2 ;;
    --regions)      REGIONS_ARG="$2"; shift 2 ;;
    --output-file)  OUTPUT_FILE="$2"; shift 2 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

AWS_OPTS=()
[[ -n "$AWS_PROFILE" ]] && AWS_OPTS+=(--profile "$AWS_PROFILE")

aws_cmd() { aws "${AWS_OPTS[@]}" "$@"; }

# ── Redirect output to file if requested ─────────────────────────────────────
if [[ -n "$OUTPUT_FILE" ]]; then
  exec > >(tee "$OUTPUT_FILE") 2>&1
fi

# ── Dependency check ──────────────────────────────────────────────────────────
for dep in aws jq; do
  command -v "$dep" &>/dev/null || { echo "ERROR: '$dep' not found in PATH"; exit 1; }
done

# ── Discover regions ──────────────────────────────────────────────────────────
if [[ -n "$REGIONS_ARG" ]]; then
  IFS=',' read -ra REGIONS <<< "$REGIONS_ARG"
else
  info "Discovering enabled AWS regions …"
  mapfile -t REGIONS < <(aws_cmd ec2 describe-regions \
    --query 'Regions[*].RegionName' --output text | tr '\t' '\n' | sort)
fi

ACCOUNT_ID=$(aws_cmd sts get-caller-identity --query Account --output text)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

header "AWS EC2 Audit – Account: ${ACCOUNT_ID}  |  ${TIMESTAMP}"
info "Regions scanned: ${REGIONS[*]}"

# =============================================================================
#  GLOBAL / ACCOUNT-WIDE CHECKS
# =============================================================================
header "GLOBAL CHECKS (account-wide)"

# ── EC2-LIMIT | Service Limit Check ──────────────────────────────────────────
section "EC2-LIMIT | Running On-Demand Instance Quota"
LIMIT_INFO=$(aws_cmd service-quotas list-service-quotas \
  --service-code ec2 \
  --query "Quotas[?QuotaName=='Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances']|[0]" \
  --output json 2>/dev/null || echo "null")
if [[ "$LIMIT_INFO" != "null" && -n "$LIMIT_INFO" ]]; then
  LIMIT_VAL=$(echo "$LIMIT_INFO" | jq -r '.Value // "unknown"')
  info "EC2-LIMIT: On-Demand Standard instances quota: ${LIMIT_VAL} vCPUs. Review and request increase if needed."
  warn "EC2-LIMIT: Verify your account has not reached EC2 instance limits for production workloads."
else
  warn "EC2-LIMIT: Could not retrieve quota info. Check service-quotas permissions."
fi

# ── EC2-RI-FAILED | Failed Reserved Instance Purchases ───────────────────────
section "EC2-RI-FAILED | Failed Reserved Instance Purchases (all regions)"
RI_FAILED_FOUND=false
for REGION in "${REGIONS[@]}"; do
  FAILED_RIS=$(aws_cmd ec2 describe-reserved-instances \
    --region "$REGION" \
    --filters "Name=state,Values=payment-failed" \
    --query 'ReservedInstances[*].ReservedInstancesId' \
    --output text 2>/dev/null | tr '\t' '\n' || true)
  if [[ -n "$FAILED_RIS" ]]; then
    fail "EC2-RI-FAILED [${REGION}]: Failed RI purchases found → $(echo "$FAILED_RIS" | tr '\n' ' ')"
    RI_FAILED_FOUND=true
  fi
done
$RI_FAILED_FOUND || pass "EC2-RI-FAILED: No failed Reserved Instance purchases found."

# =============================================================================
#  PER-REGION CHECKS
# =============================================================================
for REGION in "${REGIONS[@]}"; do

  header "REGION: ${REGION}"

  # ── Pre-fetch all instance data once per region ───────────────────────────
  info "Fetching EC2 instances …"
  INSTANCES=$(aws_cmd ec2 describe-instances \
    --region "$REGION" \
    --query 'Reservations[*].Instances[*]' \
    --output json 2>/dev/null | jq -c '[.[][]]')
  INSTANCE_COUNT=$(echo "$INSTANCES" | jq 'length')
  info "Instances found: ${INSTANCE_COUNT}"

  # ── Pre-fetch ASG instance IDs ────────────────────────────────────────────
  ASG_INSTANCE_IDS=$(aws_cmd autoscaling describe-auto-scaling-instances \
    --region "$REGION" \
    --query 'AutoScalingInstances[*].InstanceId' \
    --output text 2>/dev/null | tr '\t' '\n' || true)

  # ── Pre-fetch Security Groups ─────────────────────────────────────────────
  info "Fetching security groups …"
  SGS_JSON=$(aws_cmd ec2 describe-security-groups \
    --region "$REGION" \
    --output json 2>/dev/null || echo '{"SecurityGroups":[]}')
  SG_COUNT=$(echo "$SGS_JSON" | jq '.SecurityGroups | length')
  info "Security groups found: ${SG_COUNT}"

  # =========================================================================
  # 1. EC2 INSTANCE CHECKS
  # =========================================================================
  section "1 | EC2 INSTANCE CHECKS"

  if [[ "$INSTANCE_COUNT" -eq 0 ]]; then
    info "No EC2 instances in ${REGION} – skipping instance checks."
  else

    # ── EC2-023 | Instances In VPC ──────────────────────────────────────────
    section "EC2-023 | EC2 Instances In VPC (not EC2-Classic)"
    CLASSIC_INSTANCES=$(echo "$INSTANCES" | \
      jq -r '[.[] | select(.VpcId == null or .VpcId == "") | .InstanceId] | join(", ")')
    if [[ -z "$CLASSIC_INSTANCES" || "$CLASSIC_INSTANCES" == "null" ]]; then
      pass "EC2-023 [${REGION}]: All instances are running inside a VPC."
    else
      fail "EC2-023 [${REGION}]: Instances NOT in a VPC (EC2-Classic): ${CLASSIC_INSTANCES}"
    fi

    # ── EC2-030 | Termination Protection ───────────────────────────────────
    section "EC2-030 | EC2 Instance Termination Protection"
    while IFS=$'\t' read -r INSTANCE_ID STATE; do
      [[ -z "$INSTANCE_ID" ]] && continue
      [[ "$STATE" != "running" && "$STATE" != "stopped" ]] && continue
      if echo "$ASG_INSTANCE_IDS" | grep -qw "$INSTANCE_ID"; then
        info "EC2-030 [${REGION}]: ${INSTANCE_ID} is in an ASG – termination protection managed by ASG."
        continue
      fi
      TERM_PROTECTED=$(aws_cmd ec2 describe-instance-attribute \
        --region "$REGION" \
        --instance-id "$INSTANCE_ID" \
        --attribute disableApiTermination \
        --query 'DisableApiTermination.Value' \
        --output text 2>/dev/null || echo "false")
      if [[ "$TERM_PROTECTED" == "True" || "$TERM_PROTECTED" == "true" ]]; then
        pass "EC2-030 [${REGION}]: ${INSTANCE_ID} – Termination Protection ENABLED."
      else
        fail "EC2-030 [${REGION}]: ${INSTANCE_ID} – Termination Protection DISABLED. Remediate: aws ec2 modify-instance-attribute --region ${REGION} --instance-id ${INSTANCE_ID} --disable-api-termination"
      fi
    done < <(echo "$INSTANCES" | jq -r '.[] | [.InstanceId, .State.Name] | @tsv')

    # ── EC2-035 | Naming Conventions (Name tag) ─────────────────────────────
    section "EC2-035 | EC2 Instance Naming Conventions (Name tag)"
    while IFS=$'\t' read -r INSTANCE_ID NAME_TAG; do
      [[ -z "$INSTANCE_ID" ]] && continue
      if [[ -z "$NAME_TAG" || "$NAME_TAG" == "null" ]]; then
        fail "EC2-035 [${REGION}]: ${INSTANCE_ID} – Missing 'Name' tag."
      else
        pass "EC2-035 [${REGION}]: ${INSTANCE_ID} – Name='${NAME_TAG}'."
      fi
    done < <(echo "$INSTANCES" | jq -r \
      '.[] | [.InstanceId, (.Tags // [] | map(select(.Key=="Name")) | .[0].Value // "")] | @tsv')

    # ── EC2-058 | Detailed Monitoring ──────────────────────────────────────
    section "EC2-058 | EC2 Instance Detailed Monitoring"
    while IFS=$'\t' read -r INSTANCE_ID MON_STATE; do
      [[ -z "$INSTANCE_ID" ]] && continue
      if [[ "$MON_STATE" == "enabled" ]]; then
        pass "EC2-058 [${REGION}]: ${INSTANCE_ID} – Detailed monitoring ENABLED."
      else
        warn "EC2-058 [${REGION}]: ${INSTANCE_ID} – Detailed monitoring DISABLED (basic, 5-min intervals). Remediate: aws ec2 monitor-instances --region ${REGION} --instance-ids ${INSTANCE_ID}"
      fi
    done < <(echo "$INSTANCES" | jq -r '.[] | [.InstanceId, .Monitoring.State] | @tsv')

    # ── EC2-ORPHAN | Instances Not In an Auto Scaling Group ────────────────
    section "EC2-ORPHAN | EC2 Instances Not In Auto Scaling Group"
    while IFS= read -r INSTANCE_ID; do
      [[ -z "$INSTANCE_ID" ]] && continue
      if echo "$ASG_INSTANCE_IDS" | grep -qw "$INSTANCE_ID"; then
        pass "EC2-ORPHAN [${REGION}]: ${INSTANCE_ID} – Member of an ASG."
      else
        warn "EC2-ORPHAN [${REGION}]: ${INSTANCE_ID} – NOT in any Auto Scaling Group (orphaned)."
      fi
    done < <(echo "$INSTANCES" | jq -r '.[] | select(.State.Name == "running") | .InstanceId')

    # ── EC2-PUBLIC-IP | Instances With Public IP ───────────────────────────
    section "EC2-PUBLIC-IP | EC2 Instances With Public IP Addresses"
    while IFS=$'\t' read -r INSTANCE_ID PUBLIC_IP; do
      [[ -z "$INSTANCE_ID" ]] && continue
      if [[ -n "$PUBLIC_IP" && "$PUBLIC_IP" != "null" && "$PUBLIC_IP" != "" ]]; then
        fail "EC2-PUBLIC-IP [${REGION}]: ${INSTANCE_ID} – Public IP: ${PUBLIC_IP}. Ensure only web-tier instances are internet-facing."
      else
        pass "EC2-PUBLIC-IP [${REGION}]: ${INSTANCE_ID} – No public IP address."
      fi
    done < <(echo "$INSTANCES" | jq -r \
      '.[] | select(.State.Name == "running") | [.InstanceId, (.PublicIpAddress // "")] | @tsv')

    # ── EC2-IAM-ROLE | IAM Role Attached ──────────────────────────────────
    section "EC2-IAM-ROLE | EC2 Instances With IAM Role (Instance Profile)"
    while IFS=$'\t' read -r INSTANCE_ID IAM_ARN; do
      [[ -z "$INSTANCE_ID" ]] && continue
      if [[ -n "$IAM_ARN" && "$IAM_ARN" != "null" && "$IAM_ARN" != "" ]]; then
        pass "EC2-IAM-ROLE [${REGION}]: ${INSTANCE_ID} – IAM role: ${IAM_ARN}."
      else
        fail "EC2-IAM-ROLE [${REGION}]: ${INSTANCE_ID} – NO IAM instance profile attached. Attach a role to avoid using long-lived access keys."
      fi
    done < <(echo "$INSTANCES" | jq -r \
      '.[] | select(.State.Name == "running") | [.InstanceId, (.IamInstanceProfile.Arn // "")] | @tsv')

    # ── EC2-MULTI-ENI | Instances With Multiple ENIs ───────────────────────
    section "EC2-MULTI-ENI | EC2 Instances With Multiple Network Interfaces"
    while IFS=$'\t' read -r INSTANCE_ID ENI_COUNT; do
      [[ -z "$INSTANCE_ID" ]] && continue
      if [[ "$ENI_COUNT" -gt 1 ]]; then
        warn "EC2-MULTI-ENI [${REGION}]: ${INSTANCE_ID} – Has ${ENI_COUNT} ENIs. Review if multiple interfaces are intentional."
      else
        pass "EC2-MULTI-ENI [${REGION}]: ${INSTANCE_ID} – Single ENI."
      fi
    done < <(echo "$INSTANCES" | jq -r \
      '.[] | select(.State.Name == "running") | [.InstanceId, (.NetworkInterfaces | length | tostring)] | @tsv')

    # ── EC2-TENANCY | Dedicated Tenancy Review ─────────────────────────────
    section "EC2-TENANCY | Dedicated Instance Tenancy"
    while IFS=$'\t' read -r INSTANCE_ID TENANCY; do
      [[ -z "$INSTANCE_ID" ]] && continue
      if [[ "$TENANCY" == "dedicated" || "$TENANCY" == "host" ]]; then
        warn "EC2-TENANCY [${REGION}]: ${INSTANCE_ID} – Dedicated tenancy '${TENANCY}'. Confirm this is required for compliance (expensive)."
      else
        pass "EC2-TENANCY [${REGION}]: ${INSTANCE_ID} – Tenancy: '${TENANCY}'."
      fi
    done < <(echo "$INSTANCES" | jq -r '.[] | [.InstanceId, .Placement.Tenancy] | @tsv')

    # ── EC2-EVENTS | Scheduled Maintenance Events ──────────────────────────
    section "EC2-EVENTS | EC2 Instances With Scheduled Events"
    EVENTS_JSON=$(aws_cmd ec2 describe-instance-status \
      --region "$REGION" \
      --query 'InstanceStatuses[?Events != null && Events != `[]`]' \
      --output json 2>/dev/null || echo "[]")
    EVENT_COUNT=$(echo "$EVENTS_JSON" | jq 'length')
    if [[ "$EVENT_COUNT" -gt 0 ]]; then
      fail "EC2-EVENTS [${REGION}]: ${EVENT_COUNT} instance(s) have scheduled maintenance events pending:"
      echo "$EVENTS_JSON" | jq -r '.[] | "  → InstanceId: " + .InstanceId + " Event: " + (.Events[0].Code // "unknown")'
    else
      pass "EC2-EVENTS [${REGION}]: No instances have pending scheduled events."
    fi

    # ── EC2-GENERATION | Latest-Generation Instance Types ─────────────────
    section "EC2-GENERATION | Previous-Generation Instance Types"
    PREV_GEN_RE='^(t1|m1|m2|m3|c1|c3|r3|i2|hs1|cr1|cc2|g2)\.'
    while IFS=$'\t' read -r INSTANCE_ID INSTANCE_TYPE; do
      [[ -z "$INSTANCE_ID" ]] && continue
      if echo "$INSTANCE_TYPE" | grep -qE "$PREV_GEN_RE"; then
        fail "EC2-GENERATION [${REGION}]: ${INSTANCE_ID} – Previous-gen type '${INSTANCE_TYPE}'. Upgrade to current generation."
      else
        pass "EC2-GENERATION [${REGION}]: ${INSTANCE_ID} – Current-gen type '${INSTANCE_TYPE}'."
      fi
    done < <(echo "$INSTANCES" | jq -r '.[] | select(.State.Name == "running") | [.InstanceId, .InstanceType] | @tsv')

    # ── EC2-AZ-DIST | AZ Distribution ─────────────────────────────────────
    section "EC2-AZ-DIST | EC2 Instance Distribution Across Availability Zones"
    AZ_COUNT=$(echo "$INSTANCES" | \
      jq -r '[.[] | select(.State.Name == "running") | .Placement.AvailabilityZone] | unique | length')
    if [[ "$AZ_COUNT" -ge 2 ]]; then
      pass "EC2-AZ-DIST [${REGION}]: Running instances span ${AZ_COUNT} Availability Zones."
      echo "$INSTANCES" | jq -r \
        '[.[] | select(.State.Name == "running") | .Placement.AvailabilityZone] |
         group_by(.) | .[] | "  → " + .[0] + ": " + (length | tostring) + " instance(s)"'
    elif [[ "$INSTANCE_COUNT" -gt 1 ]]; then
      fail "EC2-AZ-DIST [${REGION}]: All running instances are confined to ${AZ_COUNT} AZ. Distribute across multiple AZs for HA."
    else
      info "EC2-AZ-DIST [${REGION}]: Single or no running instances – AZ distribution not applicable."
    fi

    # ── EC2-IMDSv2 | Instance Metadata Service v2 ─────────────────────────
    section "EC2-IMDSv2 | IMDSv2 Enforced (HttpTokens=required)"
    while IFS=$'\t' read -r INSTANCE_ID HTTP_TOKENS HTTP_HOP; do
      [[ -z "$INSTANCE_ID" ]] && continue
      if [[ "$HTTP_TOKENS" == "required" ]]; then
        pass "EC2-IMDSv2 [${REGION}]: ${INSTANCE_ID} – IMDSv2 enforced."
      else
        fail "EC2-IMDSv2 [${REGION}]: ${INSTANCE_ID} – IMDSv2 NOT enforced (HttpTokens=${HTTP_TOKENS}). Remediate: aws ec2 modify-instance-metadata-options --region ${REGION} --instance-id ${INSTANCE_ID} --http-tokens required"
      fi
      if [[ "$HTTP_HOP" =~ ^[0-9]+$ && "$HTTP_HOP" -gt 1 ]]; then
        warn "EC2-IMDSv2 [${REGION}]: ${INSTANCE_ID} – Metadata hop limit=${HTTP_HOP} (>1). Consider reducing to 1."
      fi
    done < <(echo "$INSTANCES" | jq -r \
      '.[] | select(.State.Name == "running") |
       [.InstanceId,
        (.MetadataOptions.HttpTokens // "optional"),
        (.MetadataOptions.HttpPutResponseHopLimit // 1 | tostring)] | @tsv')

  fi  # end INSTANCE_COUNT > 0

  # =========================================================================
  # 2. AMI CHECKS
  # =========================================================================
  section "2 | AMI CHECKS"

  # ── EC2-AMI-PUBLIC | Publicly Shared AMIs ────────────────────────────────
  section "EC2-AMI-PUBLIC | Publicly Shared AMIs Owned by This Account"
  PUBLIC_AMIS=$(aws_cmd ec2 describe-images \
    --region "$REGION" \
    --owners self \
    --filters "Name=is-public,Values=true" \
    --query 'Images[*].ImageId' \
    --output text 2>/dev/null | tr '\t' '\n' | grep -v '^$' || true)
  if [[ -n "$PUBLIC_AMIS" ]]; then
    while IFS= read -r AMI_ID; do
      fail "EC2-AMI-PUBLIC [${REGION}]: AMI ${AMI_ID} is PUBLICLY shared. Make private: aws ec2 modify-image-attribute --region ${REGION} --image-id ${AMI_ID} --launch-permission '{\"Remove\":[{\"Group\":\"all\"}]}'"
    done <<< "$PUBLIC_AMIS"
  else
    pass "EC2-AMI-PUBLIC [${REGION}]: No publicly shared AMIs owned by this account."
  fi

  # ── EC2-ALLOWED-AMIS | Allowed AMIs Feature ──────────────────────────────
  section "EC2-ALLOWED-AMIS | Allowed AMIs Feature Enabled"
  ALLOWED_AMIS_STATUS=$(aws_cmd ec2 get-allowed-images-settings \
    --region "$REGION" \
    --query 'State' \
    --output text 2>/dev/null || echo "unsupported")
  case "$ALLOWED_AMIS_STATUS" in
    enabled)     pass "EC2-ALLOWED-AMIS [${REGION}]: Allowed AMIs feature is ENABLED." ;;
    disabled)    warn "EC2-ALLOWED-AMIS [${REGION}]: Allowed AMIs feature is DISABLED. Enable to restrict instance launches to approved AMIs." ;;
    unsupported) info "EC2-ALLOWED-AMIS [${REGION}]: get-allowed-images-settings not available in this region/CLI version." ;;
    *)           warn "EC2-ALLOWED-AMIS [${REGION}]: Allowed AMIs feature state: '${ALLOWED_AMIS_STATUS}'." ;;
  esac

  # =========================================================================
  # 3. SECURITY GROUP CHECKS
  # =========================================================================
  section "3 | SECURITY GROUP CHECKS"

  if [[ "$SG_COUNT" -eq 0 ]]; then
    info "No security groups found in ${REGION}."
  else

    # ── EC2-DEFAULT-SG | Default SG Must Have No Rules ─────────────────────
    section "EC2-DEFAULT-SG | Default Security Groups Have No Rules"
    while IFS=$'\t' read -r SG_ID VPC_ID INBOUND OUTBOUND; do
      [[ -z "$SG_ID" ]] && continue
      if [[ "$INBOUND" -eq 0 && "$OUTBOUND" -eq 0 ]]; then
        pass "EC2-DEFAULT-SG [${REGION}]: Default SG ${SG_ID} (VPC: ${VPC_ID}) – No rules (compliant)."
      else
        fail "EC2-DEFAULT-SG [${REGION}]: Default SG ${SG_ID} (VPC: ${VPC_ID}) – Has ${INBOUND} inbound + ${OUTBOUND} outbound rules. Remove all rules from default SGs."
      fi
    done < <(echo "$SGS_JSON" | jq -r \
      '.SecurityGroups[] | select(.GroupName == "default") |
       [.GroupId, (.VpcId // "no-vpc"),
        (.IpPermissions | length | tostring),
        (.IpPermissionsEgress | length | tostring)] | @tsv')

    # ── EC2-DEFAULT-SG-IN-USE | Default SG Not Used by Instances ───────────
    section "EC2-DEFAULT-SG-IN-USE | Default Security Groups Not Assigned to Instances"
    while IFS= read -r DEFAULT_SG; do
      [[ -z "$DEFAULT_SG" ]] && continue
      ATTACHED=$(echo "$INSTANCES" | jq -r \
        --arg SG "$DEFAULT_SG" \
        '[.[] | select(.SecurityGroups[].GroupId == $SG) | .InstanceId] | join(", ")')
      if [[ -n "$ATTACHED" && "$ATTACHED" != "null" ]]; then
        fail "EC2-DEFAULT-SG-IN-USE [${REGION}]: Default SG ${DEFAULT_SG} is in use by: ${ATTACHED}. Use custom security groups instead."
      else
        pass "EC2-DEFAULT-SG-IN-USE [${REGION}]: Default SG ${DEFAULT_SG} not attached to any instance."
      fi
    done < <(echo "$SGS_JSON" | jq -r '.SecurityGroups[] | select(.GroupName == "default") | .GroupId')

    # ── EC2-SG-DESC | Rule Descriptions ────────────────────────────────────
    section "EC2-SG-DESC | Security Group Rules Have Descriptions"
    while IFS=$'\t' read -r SG_ID SG_NAME; do
      [[ -z "$SG_ID" ]] && continue
      # Count rules missing description in IpRanges or Ipv6Ranges
      MISSING=$(echo "$SGS_JSON" | jq -r \
        --arg ID "$SG_ID" '
        .SecurityGroups[] | select(.GroupId == $ID) |
        [(.IpPermissions[], .IpPermissionsEgress[]) |
          (.IpRanges[] | select((.Description == null) or (.Description == ""))) ,
          (.Ipv6Ranges[] | select((.Description == null) or (.Description == "")))
        ] | length' 2>/dev/null || echo "0")
      if [[ "$MISSING" -gt 0 ]]; then
        warn "EC2-SG-DESC [${REGION}]: SG ${SG_ID} (${SG_NAME}) – ${MISSING} rule(s) missing descriptions."
      else
        pass "EC2-SG-DESC [${REGION}]: SG ${SG_ID} (${SG_NAME}) – All rules have descriptions."
      fi
    done < <(echo "$SGS_JSON" | jq -r '.SecurityGroups[] | [.GroupId, .GroupName] | @tsv')

    # ── EC2-SG-RULE-COUNT | Too Many Rules ─────────────────────────────────
    section "EC2-SG-RULE-COUNT | Security Group Rule Count (max recommended: 50)"
    MAX_RULES=50
    while IFS=$'\t' read -r SG_ID SG_NAME INBOUND OUTBOUND; do
      [[ -z "$SG_ID" ]] && continue
      TOTAL_RULES=$(( INBOUND + OUTBOUND ))
      if [[ "$TOTAL_RULES" -gt "$MAX_RULES" ]]; then
        warn "EC2-SG-RULE-COUNT [${REGION}]: SG ${SG_ID} (${SG_NAME}) – ${TOTAL_RULES} rules (>${MAX_RULES}). Consolidate to improve performance."
      else
        pass "EC2-SG-RULE-COUNT [${REGION}]: SG ${SG_ID} (${SG_NAME}) – ${TOTAL_RULES} rules."
      fi
    done < <(echo "$SGS_JSON" | jq -r \
      '.SecurityGroups[] |
       [.GroupId, .GroupName,
        (.IpPermissions | length | tostring),
        (.IpPermissionsEgress | length | tostring)] | @tsv')

    # ── EC2-SG-OPEN-PORTS | Unrestricted Inbound on Sensitive Ports ─────────
    section "EC2-SG-OPEN-PORTS | Unrestricted Inbound on Sensitive Ports (0.0.0.0/0 or ::/0)"
    declare -A SENSITIVE_PORTS=(
      [22]="SSH"   [3389]="RDP"    [23]="Telnet"  [21]="FTP"
      [25]="SMTP"  [3306]="MySQL"  [5432]="PostgreSQL" [6379]="Redis"
      [27017]="MongoDB" [9200]="Elasticsearch" [5601]="Kibana"
      [2375]="Docker-unencrypted" [2376]="Docker-TLS"
      [8080]="HTTP-alt" [8443]="HTTPS-alt"
    )
    OPEN_PORT_FOUND=false
    while IFS=$'\t' read -r SG_ID SG_NAME; do
      [[ -z "$SG_ID" ]] && continue
      SG_DATA=$(echo "$SGS_JSON" | jq -c --arg ID "$SG_ID" '.SecurityGroups[] | select(.GroupId == $ID)')

      # Check all-traffic rule first
      ALL_OPEN=$(echo "$SG_DATA" | jq -r '
        .IpPermissions[] | select(.IpProtocol == "-1") |
        ((.IpRanges[] | select(.CidrIp == "0.0.0.0/0")) // empty),
        ((.Ipv6Ranges[] | select(.CidrIpv6 == "::/0")) // empty)
        ' 2>/dev/null | head -1 || true)
      if [[ -n "$ALL_OPEN" ]]; then
        fail "EC2-SG-OPEN-PORTS [${REGION}]: SG ${SG_ID} (${SG_NAME}) – Allows ALL inbound traffic from 0.0.0.0/0 or ::/0."
        OPEN_PORT_FOUND=true
        continue
      fi

      for PORT in "${!SENSITIVE_PORTS[@]}"; do
        SERVICE="${SENSITIVE_PORTS[$PORT]}"
        OPEN=$(echo "$SG_DATA" | jq -r --argjson P "$PORT" '
          .IpPermissions[] |
          select(
            (.IpProtocol == "tcp" or .IpProtocol == "-1") and
            ((.FromPort // 0) <= $P) and ((.ToPort // 65535) >= $P)
          ) |
          ((.IpRanges[] | select(.CidrIp == "0.0.0.0/0")) // empty),
          ((.Ipv6Ranges[] | select(.CidrIpv6 == "::/0")) // empty)
          ' 2>/dev/null | head -1 || true)
        if [[ -n "$OPEN" ]]; then
          fail "EC2-SG-OPEN-PORTS [${REGION}]: SG ${SG_ID} (${SG_NAME}) – Port ${PORT} (${SERVICE}) open to 0.0.0.0/0 or ::/0."
          OPEN_PORT_FOUND=true
        fi
      done
    done < <(echo "$SGS_JSON" | jq -r '.SecurityGroups[] | [.GroupId, .GroupName] | @tsv')
    $OPEN_PORT_FOUND || pass "EC2-SG-OPEN-PORTS [${REGION}]: No unrestricted inbound rules found on sensitive ports."
    unset SENSITIVE_PORTS

    # ── EC2-SG-PORT-RANGE | Wide Port Ranges ───────────────────────────────
    section "EC2-SG-PORT-RANGE | Security Groups With Wide Port Ranges (>1024 ports)"
    WIDE_FOUND=false
    while IFS=$'\t' read -r SG_ID SG_NAME FROM_PORT TO_PORT; do
      [[ -z "$SG_ID" ]] && continue
      if [[ "$FROM_PORT" =~ ^[0-9]+$ && "$TO_PORT" =~ ^[0-9]+$ ]]; then
        RANGE=$(( TO_PORT - FROM_PORT ))
        if [[ "$RANGE" -gt 1024 ]]; then
          warn "EC2-SG-PORT-RANGE [${REGION}]: SG ${SG_ID} (${SG_NAME}) – Inbound range ${FROM_PORT}-${TO_PORT} (${RANGE} ports). Restrict to only required ports."
          WIDE_FOUND=true
        fi
      fi
    done < <(echo "$SGS_JSON" | jq -r '
      .SecurityGroups[] | . as $sg |
      .IpPermissions[] |
      select(.FromPort != null and .ToPort != null) |
      [$sg.GroupId, $sg.GroupName, (.FromPort | tostring), (.ToPort | tostring)] | @tsv')
    $WIDE_FOUND || pass "EC2-SG-PORT-RANGE [${REGION}]: No unusually wide port ranges found in security groups."

  fi  # end SG checks

  # =========================================================================
  # 4. EBS / VOLUME CHECKS
  # =========================================================================
  section "4 | EBS VOLUME CHECKS"

  # ── EC2-EBS-DEFAULT-ENC | Default EBS Encryption ─────────────────────────
  section "EC2-EBS-DEFAULT-ENC | Account-Level Default EBS Encryption"
  EBS_DEFAULT_ENC=$(aws_cmd ec2 get-ebs-encryption-by-default \
    --region "$REGION" \
    --query 'EbsEncryptionByDefault' \
    --output text 2>/dev/null || echo "false")
  if [[ "$EBS_DEFAULT_ENC" == "True" || "$EBS_DEFAULT_ENC" == "true" ]]; then
    pass "EC2-EBS-DEFAULT-ENC [${REGION}]: Default EBS encryption is ENABLED."
  else
    fail "EC2-EBS-DEFAULT-ENC [${REGION}]: Default EBS encryption is DISABLED. Remediate: aws ec2 enable-ebs-encryption-by-default --region ${REGION}"
  fi

  # ── EC2-EBS-ENC | Unencrypted EBS Volumes ────────────────────────────────
  section "EC2-EBS-ENC | Unencrypted EBS Volumes"
  UNENCRYPTED_VOLS=$(aws_cmd ec2 describe-volumes \
    --region "$REGION" \
    --filters "Name=encrypted,Values=false" \
    --query 'Volumes[*].[VolumeId,Size,State,Attachments[0].InstanceId]' \
    --output text 2>/dev/null || true)
  if [[ -n "$UNENCRYPTED_VOLS" ]]; then
    while IFS=$'\t' read -r VOL_ID SIZE STATE INST_ID; do
      fail "EC2-EBS-ENC [${REGION}]: Volume ${VOL_ID} (${SIZE}GB, ${STATE}, instance: ${INST_ID:-unattached}) is NOT encrypted."
    done <<< "$UNENCRYPTED_VOLS"
  else
    pass "EC2-EBS-ENC [${REGION}]: All EBS volumes are encrypted."
  fi

  # ── EC2-EBS-UNATTACHED | Unattached EBS Volumes ───────────────────────────
  section "EC2-EBS-UNATTACHED | Unattached (Available) EBS Volumes"
  UNATTACHED_VOLS=$(aws_cmd ec2 describe-volumes \
    --region "$REGION" \
    --filters "Name=status,Values=available" \
    --query 'Volumes[*].[VolumeId,Size]' \
    --output text 2>/dev/null || true)
  if [[ -n "$UNATTACHED_VOLS" ]]; then
    while IFS=$'\t' read -r VOL_ID SIZE; do
      warn "EC2-EBS-UNATTACHED [${REGION}]: Volume ${VOL_ID} (${SIZE}GB) is unattached. Delete if not needed."
    done <<< "$UNATTACHED_VOLS"
  else
    pass "EC2-EBS-UNATTACHED [${REGION}]: No unattached EBS volumes."
  fi

  # ── EC2-EBS-SNAP-PUBLIC | Public EBS Snapshots ───────────────────────────
  section "EC2-EBS-SNAP-PUBLIC | Publicly Accessible EBS Snapshots"
  SNAP_IDS=$(aws_cmd ec2 describe-snapshots \
    --region "$REGION" \
    --owner-ids self \
    --filters "Name=status,Values=completed" \
    --query 'Snapshots[*].SnapshotId' \
    --output text 2>/dev/null | tr '\t' '\n' || true)

  PUBLIC_SNAP_FOUND=false
  for SNAP_ID in $SNAP_IDS; do
    [[ -z "$SNAP_ID" ]] && continue
    PUBLIC_PERM=$(aws_cmd ec2 describe-snapshot-attribute \
      --region "$REGION" \
      --snapshot-id "$SNAP_ID" \
      --attribute createVolumePermission \
      --query 'CreateVolumePermissions[?Group==`all`].Group' \
      --output text 2>/dev/null || true)
    if [[ -n "$PUBLIC_PERM" ]]; then
      fail "EC2-EBS-SNAP-PUBLIC [${REGION}]: Snapshot ${SNAP_ID} is PUBLICLY accessible. Remediate: aws ec2 modify-snapshot-attribute --region ${REGION} --snapshot-id ${SNAP_ID} --attribute createVolumePermission --operation-type remove --group-names all"
      PUBLIC_SNAP_FOUND=true
    fi
  done
  $PUBLIC_SNAP_FOUND || pass "EC2-EBS-SNAP-PUBLIC [${REGION}]: No public EBS snapshots found."

  # =========================================================================
  # 5. ELASTIC IP CHECKS
  # =========================================================================
  section "5 | ELASTIC IP CHECKS"

  # ── EC2-EIP-UNATTACHED | Unattached Elastic IPs ───────────────────────────
  section "EC2-EIP | Unattached Elastic IP Addresses (cost waste)"
  UNATTACHED_EIPS=$(aws_cmd ec2 describe-addresses \
    --region "$REGION" \
    --query 'Addresses[?AssociationId==null].PublicIp' \
    --output text 2>/dev/null | tr '\t' '\n' | grep -v '^$' || true)
  if [[ -n "$UNATTACHED_EIPS" ]]; then
    while IFS= read -r EIP; do
      warn "EC2-EIP [${REGION}]: Unattached Elastic IP ${EIP} is incurring charges. Release if unused."
    done <<< "$UNATTACHED_EIPS"
  else
    pass "EC2-EIP [${REGION}]: No unattached Elastic IP addresses."
  fi

  # =========================================================================
  # 6. VPC / NETWORK CHECKS
  # =========================================================================
  section "6 | VPC / NETWORK CHECKS"

  VPCS=$(aws_cmd ec2 describe-vpcs \
    --region "$REGION" \
    --query 'Vpcs[*]' \
    --output json 2>/dev/null || echo "[]")

  # ── EC2-VPC-FLOW-LOGS | Flow Logs Enabled ────────────────────────────────
  section "EC2-VPC-FLOW-LOGS | VPC Flow Logs Enabled"
  while IFS= read -r VPC_ID; do
    [[ -z "$VPC_ID" ]] && continue
    ACTIVE_LOGS=$(aws_cmd ec2 describe-flow-logs \
      --region "$REGION" \
      --filter "Name=resource-id,Values=${VPC_ID}" \
      --query 'FlowLogs[?FlowLogStatus==`ACTIVE`].FlowLogId' \
      --output text 2>/dev/null || true)
    if [[ -n "$ACTIVE_LOGS" ]]; then
      pass "EC2-VPC-FLOW-LOGS [${REGION}]: VPC ${VPC_ID} – Flow logs active."
    else
      fail "EC2-VPC-FLOW-LOGS [${REGION}]: VPC ${VPC_ID} – NO active VPC flow logs. Enable for traffic auditing and forensics."
    fi
  done < <(echo "$VPCS" | jq -r '.[].VpcId')

  # ── EC2-VPC-DEFAULT-IN-USE | Default VPC Used ────────────────────────────
  section "EC2-VPC-DEFAULT | Default VPC Not Used for Production Workloads"
  DEFAULT_VPC_IDS=$(echo "$VPCS" | jq -r '.[] | select(.IsDefault == true) | .VpcId')
  for DVPC in $DEFAULT_VPC_IDS; do
    [[ -z "$DVPC" ]] && continue
    DEFAULT_VPC_INSTANCES=$(echo "$INSTANCES" | jq -r \
      --arg VPC "$DVPC" \
      '[.[] | select(.VpcId == $VPC and .State.Name == "running") | .InstanceId] | join(", ")')
    if [[ -n "$DEFAULT_VPC_INSTANCES" && "$DEFAULT_VPC_INSTANCES" != "null" ]]; then
      warn "EC2-VPC-DEFAULT [${REGION}]: Default VPC ${DVPC} has running instances: ${DEFAULT_VPC_INSTANCES}. Use dedicated custom VPCs for workloads."
    else
      pass "EC2-VPC-DEFAULT [${REGION}]: Default VPC ${DVPC} has no running instances."
    fi
  done

  # =========================================================================
  # 7. KEY PAIR CHECKS
  # =========================================================================
  section "7 | KEY PAIR CHECKS"

  section "EC2-KEY-PAIRS | Unused EC2 Key Pairs"
  ALL_KPS=$(aws_cmd ec2 describe-key-pairs \
    --region "$REGION" \
    --query 'KeyPairs[*].KeyName' \
    --output text 2>/dev/null | tr '\t' '\n' | grep -v '^$' || true)
  USED_KPS=$(echo "$INSTANCES" | jq -r '[.[] | select(.State.Name == "running") | .KeyName // empty] | unique[]')
  for KP in $ALL_KPS; do
    [[ -z "$KP" ]] && continue
    if echo "$USED_KPS" | grep -qxF "$KP"; then
      pass "EC2-KEY-PAIRS [${REGION}]: Key pair '${KP}' is in use."
    else
      warn "EC2-KEY-PAIRS [${REGION}]: Key pair '${KP}' not used by any running instance. Delete if not needed."
    fi
  done
  [[ -z "$ALL_KPS" ]] && info "EC2-KEY-PAIRS [${REGION}]: No key pairs in this region."

  # =========================================================================
  # 8. CLOUDWATCH ALARM CHECKS
  # =========================================================================
  section "8 | CLOUDWATCH ALARM CHECKS"

  section "EC2-CW-ALARMS | CloudWatch Alarms Exist for Running EC2 Instances"
  if [[ "$INSTANCE_COUNT" -gt 0 ]]; then
    CW_INSTANCE_IDS=$(aws_cmd cloudwatch describe-alarms \
      --region "$REGION" \
      --alarm-types MetricAlarm \
      --query "MetricAlarms[?Namespace=='AWS/EC2'].Dimensions[?Name=='InstanceId'].Value" \
      --output text 2>/dev/null | tr '\t' '\n' | sort -u || true)

    while IFS= read -r INSTANCE_ID; do
      [[ -z "$INSTANCE_ID" ]] && continue
      if echo "$CW_INSTANCE_IDS" | grep -qxF "$INSTANCE_ID"; then
        pass "EC2-CW-ALARMS [${REGION}]: ${INSTANCE_ID} – CloudWatch alarms configured."
      else
        warn "EC2-CW-ALARMS [${REGION}]: ${INSTANCE_ID} – NO CloudWatch alarms found. Configure alarms for CPU, status checks, and network."
      fi
    done < <(echo "$INSTANCES" | jq -r '.[] | select(.State.Name == "running") | .InstanceId')
  else
    info "EC2-CW-ALARMS [${REGION}]: No running instances – skipping alarm check."
  fi

  # =========================================================================
  # 9. RESERVED INSTANCE CHECKS
  # =========================================================================
  section "9 | RESERVED INSTANCE CHECKS"

  section "EC2-RI-COVERAGE | Reserved Instance Coverage"
  END_DATE=$(date -u +"%Y-%m-%d")
  START_DATE=$(date -u -d "30 days ago" +"%Y-%m-%d" 2>/dev/null || \
               date -u -v-30d +"%Y-%m-%d" 2>/dev/null || echo "")

  if [[ -n "$START_DATE" ]]; then
    RI_COVERAGE=$(aws_cmd ce get-reservation-coverage \
      --time-period "Start=${START_DATE},End=${END_DATE}" \
      --granularity MONTHLY \
      --filter '{"Dimensions":{"Key":"SERVICE","Values":["Amazon Elastic Compute Cloud - Compute"]}}' \
      --query 'Total.CoverageHours.CoverageHoursPercentage' \
      --output text 2>/dev/null || echo "N/A")
    if [[ "$RI_COVERAGE" == "N/A" ]]; then
      info "EC2-RI-COVERAGE [${REGION}]: Could not retrieve RI coverage (Cost Explorer access may be required)."
    else
      RI_PCT=$(printf "%.0f" "$RI_COVERAGE" 2>/dev/null || echo "0")
      if [[ "$RI_PCT" -lt 50 ]]; then
        warn "EC2-RI-COVERAGE: RI coverage over last 30 days: ${RI_PCT}%. Consider purchasing Reserved Instances to reduce costs."
      else
        pass "EC2-RI-COVERAGE: RI coverage over last 30 days: ${RI_PCT}%."
      fi
    fi
  else
    info "EC2-RI-COVERAGE: Could not calculate date range for RI coverage check."
  fi

done  # end per-region loop

# =============================================================================
#  FINAL SUMMARY
# =============================================================================
header "AUDIT COMPLETE – SUMMARY"
echo -e "  ${BOLD}Account ID :${RESET} ${ACCOUNT_ID}"
echo -e "  ${BOLD}Timestamp  :${RESET} ${TIMESTAMP}"
echo -e "  ${BOLD}Regions    :${RESET} ${REGIONS[*]}"
echo ""
echo -e "  ${BOLD}Total Checks :${RESET} ${TOTAL}"
echo -e "  ${GREEN}${BOLD}  PASSED   :${RESET} ${PASSED}"
echo -e "  ${RED}${BOLD}  FAILED   :${RESET} ${FAILED}"
echo -e "  ${YELLOW}${BOLD}  WARNINGS :${RESET} ${WARNINGS}"
echo ""

if [[ "$FAILED" -eq 0 && "$WARNINGS" -eq 0 ]]; then
  echo -e "${GREEN}${BOLD}✔  Excellent! No critical findings or warnings.${RESET}"
elif [[ "$FAILED" -eq 0 ]]; then
  echo -e "${YELLOW}${BOLD}⚠  No critical failures, but ${WARNINGS} warning(s) should be reviewed.${RESET}"
else
  echo -e "${RED}${BOLD}✘  ${FAILED} critical finding(s) require immediate attention.${RESET}"
fi
echo ""
