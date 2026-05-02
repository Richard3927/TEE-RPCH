PBC_PROJECT_DIR ?= $(abspath ../CH_PBC_example-main)
BUILD_DIR := build

CXX ?= g++

DEBUG ?= 0

ifeq ($(DEBUG), 1)
	CXXFLAGS_OPT := -O0 -g
else
	CXXFLAGS_OPT := -O2
endif

# CH_PBC_QUIET disables verbose debug prints inside the crypto library (important for timing).
CXXFLAGS := $(CXXFLAGS_OPT) -std=c++17 -pthread -DCH_PBC_QUIET \
	-I. -I$(PBC_PROJECT_DIR)/include -I/usr/local/include -I/home/lsy/include

LDFLAGS := -lgmp -lpbc \
	-L/home/lsy/HR-PCH/libs -Wl,-rpath,/home/lsy/HR-PCH/libs \
	-L/usr/local/lib -Wl,-rpath,/usr/local/lib \
	-lssl -lcrypto

DEP_SRCS := \
	$(PBC_PROJECT_DIR)/src/scheme/PCH_DSS_2019.cpp \
	$(PBC_PROJECT_DIR)/src/scheme/EHR_RPCH.cpp \
	$(PBC_PROJECT_DIR)/src/scheme/RPCH_XNM_2021.cpp \
	$(PBC_PROJECT_DIR)/src/scheme/TAR_PCH.cpp \
	$(PBC_PROJECT_DIR)/src/scheme/RPCH_TMM_2022.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/RABEDI.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/TAR_ABE.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/CP_ABE.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/RABE.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/RABE_TMM.cpp \
	$(PBC_PROJECT_DIR)/src/SE/AES.cpp \
	$(PBC_PROJECT_DIR)/src/RSA/RSA.cpp \
	$(PBC_PROJECT_DIR)/src/curve/params.cpp \
	$(PBC_PROJECT_DIR)/src/utils/func.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/data_structure/access_structure.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/data_structure/binary_tree.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/data_structure/binary_tree_RABE.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/data_structure/element_t_matrix.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/data_structure/element_t_vector.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/data_structure/multiway_tree.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/data_structure/num_vector.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/policy/policy_generation.cpp \
	$(PBC_PROJECT_DIR)/src/ABE/policy/policy_resolution.cpp

DEP_OBJS := $(patsubst $(PBC_PROJECT_DIR)/src/%.cpp,$(BUILD_DIR)/dep/%.o,$(DEP_SRCS))

MAIN_OBJS := $(BUILD_DIR)/main.o $(BUILD_DIR)/jmc_kh_lattice.o

.PHONY: all clean

all: rpch_bench

clean:
	rm -rf $(BUILD_DIR) rpch_bench artifacts

$(BUILD_DIR)/main.o: main.cpp
	@mkdir -p $(dir $@)
	$(CXX) -c $(CXXFLAGS) $< -o $@

$(BUILD_DIR)/jmc_kh_lattice.o: jmc_kh_lattice.cpp jmc_kh_lattice.h
	@mkdir -p $(dir $@)
	$(CXX) -c $(CXXFLAGS) $< -o $@

# Build dependency objects under build/dep/ with a normalized path (no ../../.. in target names).
$(BUILD_DIR)/dep/%.o: $(PBC_PROJECT_DIR)/src/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) -c $(CXXFLAGS) $< -o $@

rpch_bench: $(MAIN_OBJS) $(DEP_OBJS)
	$(CXX) $(MAIN_OBJS) $(DEP_OBJS) -o $@ $(LDFLAGS)
