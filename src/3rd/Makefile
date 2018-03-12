
CURRENT_DIR = $(shell pwd)

SNARK = snark/libsnark.a
SNARK_PATH = snark

SODIUM = libsodium-1.0.12/build/lib/libsodium.a
SODIUM_PATH = libsodium-1.0.12

LIBSNARK_CXXFLAGS = -fPIC -DBINARY_OUTPUT -DNO_PT_COMPRESSION=1 -fstack-protector-all -I$(CURRENT_DIR)/$(SODIUM_PATH)/build/include
LIBSNARK_CONFIG_FLAGS = CURVE=ALT_BN128 NO_PROCPS=1 NO_DOCS=1 STATIC=1 NO_SUPERCOP=1 FEATUREFLAGS=-DMONTGOMERY_OUTPUT NO_COPY_DEPINST=1 NO_COMPILE_LIBGTEST=1

GMP = gmp-6.1.2/build/lib/libgmp.a 
GMP_PATH = gmp-6.1.2

all: $(GMP)\
	 $(SODIUM)\
	 $(SNARK)

$(GMP): $(wildcard gmp-6.1.2/*)
		@echo "**************building libgmp and libgmpxx now**********" && cd $(GMP_PATH) && ./configure --prefix=$(CURRENT_DIR)/$(GMP_PATH)/build --enable-cxx --disable-shared && $(MAKE) && $(MAKE) install

$(SODIUM): $(wildcard libsodium-1.0.12/src/*)
		@echo "**************building libsodium now************" && cd $(SODIUM_PATH) && ./configure --prefix=$(CURRENT_DIR)/$(SODIUM_PATH)/build && $(MAKE) install

$(SNARK): $(wildcard snark/src/*)
		@echo "**************building snark now****************" && $(AM_V_at) CXXFLAGS="$(LIBSNARK_CXXFLAGS)" $(MAKE) $(AM_MAKEFLAGS) -C $(SNARK_PATH)/ install PREFIX=build $(LIBSNARK_CONFIG_FLAGS) OPTFLAGS="-O2 -march=x86-64" 


clean:\
	SNARK_clean \
	SODIUM_clean \

SNARK_clean:
		@echo "********************Cleaning snark now***************" && cd $(SNARK_PATH) && make clean

SODIUM_clean:
		@echo "********************Cleaning sodium now**************" && cd $(SODIUM_PATH) && make clean