#!/bin/bash -x

set -e

if [ $# -ne 1 ]; then
  echo "Usage: $0 <release name>"
  exit 1
fi

# Strip the v off v0 in case I forget
RELEASE_NAME="$(echo "$1" | sed "s/^v//")"
BASE_COMMIT=$(git rev-parse HEAD)
# Thanks, xonsh
PREVIOUS_BRANCH=$(git symbolic-ref --short HEAD)

# Thanks, xonsh
if [ "X$(git status --porcelain --untracked-files=no --ignore-submodules=untracked)" != "X" ]; then
  echo "Dirty working tree-- commit first and try again"
  exit 1
fi

# Switch to release branch and update it to our base commit
git switch -qC release $BASE_COMMIT

# De-submodule all the submodules
SUBMODULES=$(git ls-tree -r HEAD "--format=%(path) %(objecttype)" | grep commit | cut -f1 "-d ")

recover() {
  # Put the .git file back so git knows where they go
  while IFS= read -r SUBMODULE || [[ -n "$SUBMODULE" ]]; do
    # todo: recurse submodules?
    # Gross https://stackoverflow.com/a/7305217
    REL_PATH=$(python3 -c "import os.path; print(os.path.relpath('.git/modules/$SUBMODULE', '$SUBMODULE'))")
    echo "gitdir: ${REL_PATH}" > "${SUBMODULE}/.git"
  done < <(printf '%s' "$SUBMODULES")

  # And now we can switch branches apparently totally fine
  git switch "$PREVIOUS_BRANCH"

  # And update them just in case
  while IFS= read -r SUBMODULE || [[ -n "$SUBMODULE" ]]; do
    # todo: recurse submodules?
    git submodule update --init --recursive -- "$SUBMODULE"
  done < <(printf '%s' "$SUBMODULES")
}

# Iterate the list https://superuser.com/a/284226
while IFS= read -r SUBMODULE || [[ -n "$SUBMODULE" ]]; do
  # todo: recurse submodules?
  git rm --cached "$SUBMODULE"
  rm "$SUBMODULE/.git"
  git add "$SUBMODULE"
done < <(printf '%s' "$SUBMODULES")

git commit -m "Flattened submodules for release v${RELEASE_NAME}" || (recover && exit 1)
git tag "$RELEASE_NAME" -s || (recover && exit 1)
git push -f origin release || (recover && exit 1)
git push origin "refs/tags/${RELEASE_NAME}" || (recover && exit 1)
# todo: make github release?

recover