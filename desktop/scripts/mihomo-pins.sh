# WhiteVPN Android 1.8.0-beta.2 core inputs. Source this from setup and build.
FLCLASH_REPO="https://github.com/WhiteDNS/FlClash.git"
FLCLASH_COMMIT="6631f476312c6b5da0418178f3d4c3f47ba2d52b"
MIHOMO_REPO="https://github.com/WhiteDNS/mihomo.git"
MIHOMO_COMMIT="deef0cffd2fdc136c30e5ed887b4f77fae6fa6c9"
MIHOMO_TAG="v1.19.34"
export GOTOOLCHAIN=go1.26.8
MIHOMO_BUILD_ID="${FLCLASH_COMMIT}-${MIHOMO_COMMIT}-${GOTOOLCHAIN}"
