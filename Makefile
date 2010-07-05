KERNEL_DIR = /lib/modules/$(shell uname -r)/build
VERSION = 0.3

EXTRA_CFLAGS += -I$(SUBDIRS)/libtommath

TOM_OBJECTS = libtommath/bncore.o libtommath/bn_mp_init.o libtommath/bn_mp_clear.o libtommath/bn_mp_exch.o libtommath/bn_mp_grow.o libtommath/bn_mp_shrink.o \
	libtommath/bn_mp_clamp.o libtommath/bn_mp_zero.o  libtommath/bn_mp_set.o libtommath/bn_mp_set_int.o libtommath/bn_mp_init_size.o libtommath/bn_mp_copy.o \
	libtommath/bn_mp_init_copy.o libtommath/bn_mp_abs.o libtommath/bn_mp_neg.o libtommath/bn_mp_cmp_mag.o libtommath/bn_mp_cmp.o libtommath/bn_mp_cmp_d.o \
	libtommath/bn_mp_rshd.o libtommath/bn_mp_lshd.o libtommath/bn_mp_mod_2d.o libtommath/bn_mp_div_2d.o libtommath/bn_mp_mul_2d.o libtommath/bn_mp_div_2.o \
	libtommath/bn_mp_mul_2.o libtommath/bn_s_mp_add.o libtommath/bn_s_mp_sub.o libtommath/bn_fast_s_mp_mul_digs.o libtommath/bn_s_mp_mul_digs.o \
	libtommath/bn_fast_s_mp_mul_high_digs.o libtommath/bn_s_mp_mul_high_digs.o libtommath/bn_fast_s_mp_sqr.o libtommath/bn_s_mp_sqr.o \
	libtommath/bn_mp_add.o libtommath/bn_mp_sub.o libtommath/bn_mp_karatsuba_mul.o libtommath/bn_mp_mul.o libtommath/bn_mp_karatsuba_sqr.o \
	libtommath/bn_mp_sqr.o libtommath/bn_mp_div.o libtommath/bn_mp_mod.o libtommath/bn_mp_add_d.o libtommath/bn_mp_sub_d.o libtommath/bn_mp_mul_d.o \
	libtommath/bn_mp_div_d.o libtommath/bn_mp_mod_d.o libtommath/bn_mp_expt_d.o libtommath/bn_mp_addmod.o libtommath/bn_mp_submod.o \
	libtommath/bn_mp_mulmod.o libtommath/bn_mp_sqrmod.o libtommath/bn_mp_gcd.o libtommath/bn_mp_lcm.o libtommath/bn_fast_mp_invmod.o libtommath/bn_mp_invmod.o \
	libtommath/bn_mp_reduce.o libtommath/bn_mp_montgomery_setup.o libtommath/bn_fast_mp_montgomery_reduce.o libtommath/bn_mp_montgomery_reduce.o \
	libtommath/bn_mp_exptmod_fast.o libtommath/bn_mp_exptmod.o libtommath/bn_mp_2expt.o libtommath/bn_mp_n_root.o libtommath/bn_mp_jacobi.o libtommath/bn_reverse.o \
	libtommath/bn_mp_count_bits.o libtommath/bn_mp_read_unsigned_bin.o libtommath/bn_mp_read_signed_bin.o libtommath/bn_mp_to_unsigned_bin.o \
	libtommath/bn_mp_to_signed_bin.o libtommath/bn_mp_unsigned_bin_size.o libtommath/bn_mp_signed_bin_size.o  \
	libtommath/bn_mp_xor.o libtommath/bn_mp_and.o libtommath/bn_mp_or.o libtommath/bn_mp_rand.o libtommath/bn_mp_montgomery_calc_normalization.o \
	libtommath/bn_mp_prime_is_divisible.o libtommath/bn_prime_tab.o libtommath/bn_mp_prime_fermat.o libtommath/bn_mp_prime_miller_rabin.o \
	libtommath/bn_mp_prime_is_prime.o libtommath/bn_mp_prime_next_prime.o libtommath/bn_mp_dr_reduce.o \
	libtommath/bn_mp_dr_is_modulus.o libtommath/bn_mp_dr_setup.o libtommath/bn_mp_reduce_setup.o \
	libtommath/bn_mp_toom_mul.o libtommath/bn_mp_toom_sqr.o libtommath/bn_mp_div_3.o libtommath/bn_s_mp_exptmod.o \
	libtommath/bn_mp_reduce_2k.o libtommath/bn_mp_reduce_is_2k.o libtommath/bn_mp_reduce_2k_setup.o \
	libtommath/bn_mp_reduce_2k_l.o libtommath/bn_mp_reduce_is_2k_l.o libtommath/bn_mp_reduce_2k_setup_l.o \
	libtommath/bn_mp_radix_smap.o libtommath/bn_mp_read_radix.o libtommath/bn_mp_toradix.o libtommath/bn_mp_radix_size.o \
	libtommath/bn_mp_cnt_lsb.o libtommath/bn_error.o \
	libtommath/bn_mp_init_multi.o libtommath/bn_mp_clear_multi.o libtommath/bn_mp_exteuclid.o libtommath/bn_mp_toradix_n.o \
	libtommath/bn_mp_prime_random_ex.o libtommath/bn_mp_get_int.o libtommath/bn_mp_sqrt.o libtommath/bn_mp_is_square.o libtommath/bn_mp_init_set.o \
	libtommath/bn_mp_init_set_int.o libtommath/bn_mp_invmod_slow.o libtommath/bn_mp_prime_rabin_miller_trials.o \
	libtommath/bn_mp_to_signed_bin_n.o libtommath/bn_mp_to_unsigned_bin_n.o

cryptodev-objs = cryptodev_main.o cryptodev_cipher.o ncr.o \
	ncr-data.o ncr-key.o ncr-limits.o ncr-sessions.o \
	ncr-key-wrap.o ncr-key-storage.o $(TOM_OBJECTS)


obj-m += cryptodev.o

build:
	@echo "#define VERSION \"$(VERSION)\"" > version.h
	make -C $(KERNEL_DIR) SUBDIRS=`pwd` modules

install:
	make -C $(KERNEL_DIR) SUBDIRS=`pwd` modules_install
	@echo "Installing cryptodev.h in /usr/include/crypto ..."
	@install -D cryptodev.h /usr/include/crypto/cryptodev.h
	@install -D ncr.h /usr/include/crypto/ncr.h

clean:
	make -C $(KERNEL_DIR) SUBDIRS=`pwd` clean
	rm -f $(hostprogs)
	KERNEL_DIR=$(KERNEL_DIR) make -C examples clean

check:
	KERNEL_DIR=$(KERNEL_DIR) make -C examples check

FILEBASE = cryptodev-linux-$(VERSION)
TMPDIR ?= /tmp
OUTPUT = $(FILEBASE).tar.gz

dist: clean
	@echo Packing
	@rm -f *.tar.gz
	@mkdir $(TMPDIR)/$(FILEBASE)
	@cp -ar . $(TMPDIR)/$(FILEBASE)
	@rm -rf $(TMPDIR)/$(FILEBASE)/.git* $(TMPDIR)/$(FILEBASE)/releases $(TMPDIR)/$(FILEBASE)/scripts
	@tar -C /tmp -czf ./$(OUTPUT) $(FILEBASE)
	@rm -rf $(TMPDIR)/$(FILEBASE)
	@echo Signing $(OUTPUT)
	@gpg --output $(OUTPUT).sig -sb $(OUTPUT)
	@gpg --verify $(OUTPUT).sig $(OUTPUT)
	@mv $(OUTPUT) $(OUTPUT).sig releases/
