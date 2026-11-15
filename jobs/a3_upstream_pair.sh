#!/bin/bash
# PUBLIC UPSTREAM build only. No guest triggers or original OEM inputs.
set -euo pipefail
OLD=e44cee1bf51e606f3e70a213eb5a1abb3fa56a81
FIX=f6c93e8ecaaf12959b7ef6eb611351001db2ff5d
OLD_BLOB=6ff6367793b9e2a5508a278c91e1fdd765fbd024
FIX_BLOB=7391ec00a1cc1b0a4b63fe3f84ad30528b623f6d
SRC="$RUNNER_TEMP/a3-upstream-linux"
OBJ="$RUNNER_TEMP/a3-build"
OUT="$RUNNER_TEMP/a3-output"
mkdir -p "$SRC" "$OBJ" "$OUT"
git -C "$SRC" init -q
git -C "$SRC" remote add origin https://github.com/gregkh/linux.git
git -C "$SRC" -c protocol.version=2 fetch --no-tags --depth=1 --filter=blob:none origin "$OLD"
git -C "$SRC" checkout -q --detach FETCH_HEAD
test "$(git -C "$SRC" rev-parse HEAD)" = "$OLD"
test "$(git -C "$SRC" rev-parse HEAD:fs/exec.c)" = "$OLD_BLOB"
echo "A3_UPSTREAM_OLD_COMMIT=$OLD"
curl -fsSL --retry 4 --max-time 80 \
  "https://raw.githubusercontent.com/gregkh/linux/$FIX/fs/exec.c" -o "$RUNNER_TEMP/fixed-exec.c"
python3 - "$RUNNER_TEMP/fixed-exec.c" "$FIX_BLOB" <<'PY'
import hashlib,sys
data=open(sys.argv[1],"rb").read()
sha=hashlib.sha1(f"blob {len(data)}\0".encode()+data).hexdigest()
assert sha==sys.argv[2],(sha,sys.argv[2])
print("A3_FIXED_SOURCE_PIN=PASS")
PY
make -s -C "$SRC" O="$OBJ" x86_64_defconfig
"$SRC/scripts/config" --file "$OBJ/.config" \
  -e MODULES -d DEBUG_INFO -d DEBUG_INFO_BTF -d KASAN -d KCOV \
  -e BLK_DEV_INITRD -e RD_GZIP -e DEVTMPFS -e DEVTMPFS_MOUNT \
  -e BINFMT_ELF -e PROC_FS -e SYSFS -e TMPFS -e POSIX_TIMERS \
  -e SERIAL_8250 -e SERIAL_8250_CONSOLE -e KALLSYMS -e KALLSYMS_ALL \
  -e FTRACE -e KPROBES -e KPROBE_EVENTS -e FRAME_POINTER \
  -d SLAB_MERGE_DEFAULT
make -s -C "$SRC" O="$OBJ" olddefconfig
for config in CONFIG_POSIX_TIMERS CONFIG_BLK_DEV_INITRD CONFIG_SERIAL_8250_CONSOLE CONFIG_MODULES CONFIG_KPROBES CONFIG_KPROBE_EVENTS; do
 grep -qx "$config=y" "$OBJ/.config" || { echo "A3_CONFIG_BLOCKER=$config"; exit 11; }
done
echo "A3_KERNEL_CONFIG_PASS"
make -s -C "$SRC" O="$OBJ" -j4 bzImage
cp "$OBJ/arch/x86/boot/bzImage" "$OUT/old.bzImage"
cp "$OBJ/System.map" "$OUT/old.System.map"
cp "$OBJ/.config" "$OUT/old.config"
cp "$RUNNER_TEMP/fixed-exec.c" "$SRC/fs/exec.c"
test "$(git -C "$SRC" hash-object --no-filters fs/exec.c)" = "$FIX_BLOB"
test "$(git -C "$SRC" diff --name-only)" = fs/exec.c
make -s -C "$SRC" O="$OBJ" -j4 bzImage
cp "$OBJ/arch/x86/boot/bzImage" "$OUT/fixed.bzImage"
cp "$OBJ/System.map" "$OUT/fixed.System.map"
cp "$OBJ/.config" "$OUT/fixed.config"
printf 'PUBLIC_UPSTREAM_ONLY=1\nOLD_COMMIT=%s\nFIXED_FILE_COMMIT=%s\nOLD_BLOB=%s\nFIXED_BLOB=%s\nWORKFLOW_SHA=%s\n' \
  "$OLD" "$FIX" "$OLD_BLOB" "$FIX_BLOB" "$GITHUB_SHA" > "$OUT/provenance.txt"
(cd "$OUT"; sha256sum *.bzImage *.config *.map provenance.txt > SHA256SUMS)
echo "A3_PUBLIC_PAIR_BUILT=PASS"
