SGX_SDK ?= /opt/intel/sgxsdk
SGXSSL ?= /opt/intel/sgxssl

SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1
QUIET ?= 1

CXX ?= g++
CC ?= gcc

# Crypto library used by both host and enclave (headers + sources).
PBC_PROJECT_DIR ?= ../CH_PBC_example-main
BUILD_DIR := build

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_FLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_FLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts
	UaeService_Library_Name := sgx_uae_service
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
else
	Urts_Library_Name := sgx_urts_sim
	UaeService_Library_Name := sgx_uae_service_sim
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
endif

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_FLAGS += -O0 -g
else
	SGX_COMMON_FLAGS += -O2
endif

# Optional extra flags for non-standard dependency locations (host-side).
# Example:
#   make HOST_EXTRA_CFLAGS="-I/opt/pbc/include" HOST_EXTRA_LDFLAGS="-L/opt/pbc/lib"
HOST_EXTRA_CFLAGS ?=
HOST_EXTRA_LDFLAGS ?=

# Enclave-side dependencies (pbc/gmp headers + static libs built for SGX).
# Put them under ../sgx_deps/{include,lib} or override SGX_DEPS_DIR.
SGX_DEPS_DIR ?= ../sgx_deps
SGX_DEPS_INCLUDE := $(SGX_DEPS_DIR)/include
SGX_DEPS_LIB := $(SGX_DEPS_DIR)/lib
ENCLAVE_EXTRA_CFLAGS ?=
ENCLAVE_EXTRA_LDFLAGS ?=

APP_INCLUDE := -IApp -I$(PBC_PROJECT_DIR)/include -I$(SGX_SDK)/include
APP_DEFINES :=
ifeq ($(QUIET), 1)
	APP_DEFINES += -DCH_PBC_QUIET
endif
APP_CFLAGS := $(SGX_COMMON_FLAGS) -fPIC -Wno-attributes $(APP_INCLUDE) $(APP_DEFINES) -std=c++17 -pthread $(HOST_EXTRA_CFLAGS)

ifeq ($(SGX_MODE), HW)
	APP_SGX_LDFLAGS := -lsgx_urts
else
	APP_SGX_LDFLAGS := -L$(SGX_LIBRARY_PATH) -Wl,-rpath,$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -l$(UaeService_Library_Name)
endif

APP_LDFLAGS := $(SGX_COMMON_FLAGS) $(APP_SGX_LDFLAGS) -lpthread -lgmp -lpbc -lssl -lcrypto $(HOST_EXTRA_LDFLAGS)

ENCLAVE_INCLUDE := -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx -I$(SGX_SDK)/include/tlibcxx \
	-I$(SGXSSL)/include $(if $(wildcard $(SGX_DEPS_INCLUDE)),-I$(SGX_DEPS_INCLUDE),) -I/usr/include/x86_64-linux-gnu
ENCLAVE_CFLAGS := $(SGX_COMMON_FLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector -fno-builtin-printf $(ENCLAVE_INCLUDE) $(ENCLAVE_EXTRA_CFLAGS)
ENCLAVE_CXXFLAGS := $(ENCLAVE_CFLAGS) -nostdinc++ -std=c++17

ENCLAVE_SECURITY_LDFLAGS := -Wl,-z,relro,-z,now,-z,noexecstack
ENCLAVE_VERSION_SCRIPT := Enclave/Enclave_debug.lds
ifeq ($(SGX_DEBUG), 0)
	ENCLAVE_VERSION_SCRIPT := Enclave/Enclave.lds
endif

ENCLAVE_LINK_FLAGS := $(ENCLAVE_SECURITY_LDFLAGS) \
	-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,-Bstatic \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-L$(SGXSSL)/lib64 -Wl,--whole-archive -lsgx_tsgxssl -Wl,--no-whole-archive -lsgx_tsgxssl_crypto \
	$(if $(wildcard $(SGX_DEPS_LIB)),-L$(SGX_DEPS_LIB),) -L/usr/lib/x86_64-linux-gnu \
	-Wl,--start-group -lsgx_tstdc -lsgx_pthread -lsgx_tcxx -lsgx_tcrypto -l$(Service_Library_Name) -lpbc -lgmp -Wl,--end-group \
	-Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=$(ENCLAVE_VERSION_SCRIPT) \
	$(ENCLAVE_EXTRA_LDFLAGS)

PROJECT_CPP_SRCS := \
	$(PBC_PROJECT_DIR)/src/curve/params.cpp \
	$(PBC_PROJECT_DIR)/src/utils/func.cpp \
	$(PBC_PROJECT_DIR)/src/RSA/RSA.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/CP_ABE.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/FAME-OD.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/data_structure/access_structure.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/data_structure/binary_tree.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/data_structure/element_t_matrix.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/data_structure/element_t_vector.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/data_structure/multiway_tree.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/data_structure/num_vector.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/policy/policy_generation.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/policy/policy_resolution.cpp \
	$(PBC_PROJECT_DIR)/src/SE/AES.cpp

APP_CPP_SRCS := App/App.cpp
APP_C_SRCS := App/Enclave_u.c

APP_OBJS := \
	$(APP_CPP_SRCS:%.cpp=$(BUILD_DIR)/%.o) \
	$(APP_C_SRCS:%.c=$(BUILD_DIR)/%.o) \
	$(PROJECT_CPP_SRCS:$(PBC_PROJECT_DIR)/%.cpp=$(BUILD_DIR)/project/%.o)

ENCLAVE_CPP_SRCS := Enclave/Enclave.cpp
ENCLAVE_C_SRCS := Enclave/Enclave_t.c Enclave/sgx_glibc_compat.c
ENCLAVE_OBJS := \
	$(ENCLAVE_CPP_SRCS:%.cpp=$(BUILD_DIR)/%.o) \
	$(ENCLAVE_C_SRCS:%.c=$(BUILD_DIR)/%.o)

APP_NAME := app
ENCLAVE_NAME := enclave.so
SIGNED_ENCLAVE_NAME := enclave.signed.so
ENCLAVE_CONFIG := Enclave/Enclave.config.xml
ENCLAVE_KEY := Enclave/Enclave_private_test.pem

.PHONY: all clean run

all: $(APP_NAME) $(SIGNED_ENCLAVE_NAME)

run: all
	./$(APP_NAME) --curve a --out artifacts/results.json

clean:
	rm -rf $(BUILD_DIR) $(APP_NAME) $(ENCLAVE_NAME) $(SIGNED_ENCLAVE_NAME) .config_* App/Enclave_u.* Enclave/Enclave_t.* $(ENCLAVE_KEY) artifacts

$(ENCLAVE_KEY):
	@mkdir -p Enclave
	/usr/bin/openssl genrsa -3 -out $(ENCLAVE_KEY) 3072

App/Enclave_u.c App/Enclave_u.h: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include

Enclave/Enclave_t.c Enclave/Enclave_t.h: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include

$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) -c $(APP_CFLAGS) $< -o $@

# App.cpp includes the edger8r-generated header; ensure it exists before compiling.
$(BUILD_DIR)/App/App.o: App/Enclave_u.h

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) -c $(SGX_COMMON_FLAGS) -fPIC -Wno-attributes -IApp -I$(SGX_SDK)/include $< -o $@

$(BUILD_DIR)/project/%.o: $(PBC_PROJECT_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) -c $(APP_CFLAGS) $< -o $@

$(BUILD_DIR)/Enclave/Enclave.o: Enclave/Enclave.cpp Enclave/Enclave_t.h
	@mkdir -p $(dir $@)
	$(CXX) -c $(ENCLAVE_CXXFLAGS) $< -o $@

# Compile enclave C sources (edger8r output + any enclave-local C helpers).
$(BUILD_DIR)/Enclave/%.o: Enclave/%.c
	@mkdir -p $(dir $@)
	$(CC) -c $(ENCLAVE_CFLAGS) $< -o $@

$(APP_NAME): App/Enclave_u.c App/Enclave_u.h $(APP_OBJS)
	$(CXX) $(APP_OBJS) -o $@ $(APP_LDFLAGS)

$(ENCLAVE_NAME): Enclave/Enclave_t.c Enclave/Enclave_t.h $(ENCLAVE_OBJS)
	$(CXX) $(ENCLAVE_OBJS) -o $@ $(ENCLAVE_LINK_FLAGS)

$(SIGNED_ENCLAVE_NAME): $(ENCLAVE_NAME) $(ENCLAVE_KEY)
	$(SGX_ENCLAVE_SIGNER) sign -key $(ENCLAVE_KEY) -enclave $(ENCLAVE_NAME) -out $@ -config $(ENCLAVE_CONFIG)
