package=native_libmultiprocess
$(package)_version=6929c40913ce2bbee58754f2984ddd7ec97b44ea
$(package)_download_path=https://github.com/chaincodelabs/libmultiprocess/archive
$(package)_file_name=$($(package)_version).tar.gz
$(package)_sha256_hash=e0aab3166ca902e7b255b4e1766c71c5e99170534ae412136e4133d4f85745d7
$(package)_dependencies=native_capnp

define $(package)_config_cmds
  $($(package)_cmake) .
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install-bin
endef
