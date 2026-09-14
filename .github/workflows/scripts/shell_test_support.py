"""Compatibility for Linux deployment commands executed in local shell tests."""

import sys


def linux_shell_prelude():
    if sys.platform != "darwin":
        return ""
    # Use the native tools explicitly so a contributor's GNU-tool PATH does
    # not change which argument conventions these adapters must supply.
    return '''
sed() {
    if [ "$1" = -i ]; then
        shift
        /usr/bin/sed -i '' "$@"
    else
        /usr/bin/sed "$@"
    fi
}
install() {
    if [ "$1" = -D ]; then
        shift
        for destination do :; done
        mkdir -p "$(dirname "$destination")" || return
    fi
    /usr/bin/install "$@"
}
'''
