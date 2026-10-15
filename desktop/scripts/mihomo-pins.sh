# WhiteVPN Android 1.7.1 core inputs. Source this from setup and build.
FLCLASH_REPO="https://github.com/WhiteDNS/FlClash.git"
FLCLASH_COMMIT="8f08f6e2d732c58bcbb9d13771af4456c039fe46"
MIHOMO_REPO="https://github.com/WhiteDNS/mihomo.git"
MIHOMO_COMMIT="05fb40f89637aa27d81b638bff765a6d57797cdb"
MIHOMO_TAG="v1.19.30"
export GOTOOLCHAIN=go1.26.8
MIHOMO_BUILD_ID="${FLCLASH_COMMIT}-${MIHOMO_COMMIT}-${GOTOOLCHAIN}"
