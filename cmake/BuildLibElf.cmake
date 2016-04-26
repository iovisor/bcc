include(ExternalProject)

ExternalProject_Add(libelf
  PREFIX "vendor/elfutils"
  URL http://archive.ubuntu.com/ubuntu/pool/main/e/elfutils/elfutils_0.163.orig.tar.bz2
  URL_HASH SHA1=7931b4961364a8a17c708138c70c552ae2881227
  BUILD_IN_SOURCE 1
  CONFIGURE_COMMAND "<SOURCE_DIR>/configure"
  BUILD_COMMAND make -C "<SOURCE_DIR>/libelf" libelf_pic.a
  INSTALL_COMMAND ""
)

ExternalProject_Get_Property(libelf SOURCE_DIR)
set(LIBELF_INCLUDE_DIRS ${SOURCE_DIR}/libelf)
set(LIBELF_LIBRARIES ${SOURCE_DIR}/libelf/libelf_pic.a)
