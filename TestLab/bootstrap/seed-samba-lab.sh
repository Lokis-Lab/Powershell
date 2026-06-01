#!/usr/bin/env bash
# Seed users and OUs in the Samba AD DC container (docker compose exec dc1 /bootstrap/seed-samba-lab.sh)
set -euo pipefail

DOMAIN="${DOMAIN:-SCRIPTTEST}"
ADMIN_PASS="${ADMIN_PASS:-${LAB_ADMIN_PASSWORD:-P@ssw0rd!Lab2026}}"
USER_PASS="${USER_PASS:-P@ssw0rd!Lab2026}"

echo "==> Creating OUs"
for ou in Workstations Servers "Users/IT" "Users/Sales" "Users/Finance" "Users/Legacy"; do
  parent="DC=lab,DC=scripttest,DC=local"
  IFS='/' read -ra parts <<< "$ou"
  dn=""
  for part in "${parts[@]}"; do
    if [[ -z "$dn" ]]; then
      dn="OU=${part},${parent}"
    else
      dn="OU=${part},${dn}"
    fi
  done
  samba-tool ou create "$dn" 2>/dev/null || echo "OU exists or skipped: $dn"
done

create_user() {
  local user="$1"
  local ou_dn="$2"
  local never_expire="${3:-0}"
  if samba-tool user show "$user" &>/dev/null; then
    echo "User exists: $user"
    return
  fi
  samba-tool user create "$user" "$USER_PASS" --userou="$ou_dn"
  if [[ "$never_expire" == "1" ]]; then
  samba-tool user setexpiry "$user" --noexpiry
  fi
  echo "Created user: $user"
}

BASE="DC=lab,DC=scripttest,DC=local"
create_user "alice.it" "OU=IT,OU=Users,${BASE}" 0
create_user "bob.sales" "OU=Sales,OU=Users,${BASE}" 0
create_user "carol.finance" "OU=Finance,OU=Users,${BASE}" 0
create_user "svc_backup" "OU=Legacy,OU=Users,${BASE}" 1
create_user "jim.legacy" "OU=Legacy,OU=Users,${BASE}" 1
create_user "admin_legacy" "OU=Legacy,OU=Users,${BASE}" 1

echo "==> Samba GPO list (create Windows GPOs with Initialize-TestLabDomain.ps1 for full RSAT testing)"
samba-tool gpo listall || true

echo "==> Done. Domain: lab.scripttest.local  NetBIOS: ${DOMAIN}"
echo "    Run Initialize-TestLabDomain.ps1 from a Windows RSAT host joined to this domain for full GPO coverage."
