# Owner-local settings for the lab shell scripts (sourced, POSIX sh). The Python twin is
# tools/guardian_local.py: environment first, then ~/.config/m5-guardian/local.conf (or the file
# named by GUARDIAN_LOCAL_CONF) as KEY=VALUE lines; every key is listed in lab/local.conf.example.
#
#   guardian_conf KEY [ALIAS...]   print the first non-empty value; status 1 when none is set
#   guardian_store_path            print the configured artifact store (GUARDIAN_STORE), unchecked
#   guardian_store                 print the artifact store after the fail-closed check; status 2 and a
#                                  named message otherwise

guardian_conf_file() { printf '%s\n' "${GUARDIAN_LOCAL_CONF:-$HOME/.config/m5-guardian/local.conf}"; }

guardian_conf() {
  for _gk in "$@"; do
    eval "_gv=\${$_gk:-}"
    [ -n "$_gv" ] && { printf '%s\n' "$_gv"; return 0; }
  done
  _gf=$(guardian_conf_file)
  [ -f "$_gf" ] || return 1
  for _gk in "$@"; do
    _gv=$(sed -n "s/^[[:space:]]*$_gk[[:space:]]*=[[:space:]]*//p" "$_gf" | tail -n 1 | sed 's/[[:space:]]*$//')
    case "$_gv" in
      \"*\") _gv=${_gv#\"}; _gv=${_gv%\"} ;;
      \'*\') _gv=${_gv#\'}; _gv=${_gv%\'} ;;
    esac
    [ -n "$_gv" ] && { printf '%s\n' "$_gv"; return 0; }
  done
  return 1
}

guardian_store_path() { guardian_conf GUARDIAN_STORE GUARDIAN_BROW_ROOT; }

guardian_store() {
  _gs=$(guardian_store_path) || {
    echo "GUARDIAN_STORE (the artifact store) is not set: export GUARDIAN_STORE=... or add it to $(guardian_conf_file) (every key is listed in lab/local.conf.example)" >&2
    return 2
  }
  _gm=$(guardian_conf GUARDIAN_STORE_MOUNT) || _gm=
  if [ -n "$_gm" ] && ! mount | grep -q " on $_gm (smbfs"; then
    echo "$_gm (GUARDIAN_STORE_MOUNT) is not mounted as smbfs; nothing is read or written" >&2
    return 2
  fi
  [ -f "$_gs/.guardian-store-root" ] || {
    echo "$_gs has no .guardian-store-root sentinel; refusing to use it as the artifact store" >&2
    return 2
  }
  printf '%s\n' "$_gs"
}
