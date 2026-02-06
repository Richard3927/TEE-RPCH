cmake_minimum_required(VERSION 3.0)
project(DCH)

set(CMAKE_CXX_STANDARD 17)
SET(CMAKE_BUILD_TYPE "Debug")
# SET(CMAKE_BUILD_TYPE "Release")

find_package(OpenSSL REQUIRED)
include_directories(include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -pthread -mavx2 -O0")
add_compile_options(-Wunknown-pragmas)

FIND_PACKAGE(OpenMP REQUIRED)
if (OPENMP_FOUND)
    message("OPENMP FOUND")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
endif ()

if (ENABLE_OMP)
    message("OpenMP enabled")
    add_definitions("-DParallel")
endif (ENABLE_OMP)

if (LOCAL_DEBUG)
    message("LOCAL_DEBUG enabled")
    add_definitions("-DDEBUG")
endif (LOCAL_DEBUG)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS}")

link_libraries(gmp pbc OpenSSL::SSL)

add_executable(CH_FS_ECC_CCTY_2024_test
        src/scheme/CH_FS_ECC_CCTY_2024.cpp
        src/utils/func.cpp
        src/curve/params.cpp
        unit_test/CH_FS_ECC_CCTY_2024_test.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/num_vector.cpp
)

add_executable(RABE_test  
        src/ABE/RABE.cpp
        src/curve/params.cpp
        src/utils/func.cpp
        unit_test/ABE_test/RABE_test.cpp
        src/ABE/data_structure/access_structure.cpp
        src/ABE/data_structure/binary_tree.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/multiway_tree.cpp
        src/ABE/data_structure/num_vector.cpp
        src/ABE/policy/policy_generation.cpp
        src/ABE/policy/policy_resolution.cpp
        src/ABE/data_structure/binary_tree_RABE.cpp
)

add_executable(RABE_TMM_test  
        src/ABE/RABE_TMM.cpp
        src/curve/params.cpp
        src/utils/func.cpp
        unit_test/ABE_test/RABE_TMM_test.cpp
        src/ABE/data_structure/access_structure.cpp
        src/ABE/data_structure/binary_tree.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/multiway_tree.cpp
        src/ABE/data_structure/num_vector.cpp
        src/ABE/policy/policy_generation.cpp
        src/ABE/policy/policy_resolution.cpp
        src/ABE/data_structure/binary_tree_RABE.cpp
)

add_executable(RPCH_XNM_2021_test
    src/scheme/RPCH_XNM_2021.cpp
    src/SE/AES.cpp
    src/curve/params.cpp
    src/utils/func.cpp
    src/RSA/RSA.cpp
    unit_test/RPCH_XNM_2021_test.cpp
    src/ABE/RABE.cpp
    src/ABE/data_structure/access_structure.cpp
    src/ABE/data_structure/binary_tree.cpp
    src/ABE/data_structure/element_t_matrix.cpp
    src/ABE/data_structure/element_t_vector.cpp
    src/ABE/data_structure/multiway_tree.cpp
    src/ABE/data_structure/num_vector.cpp
    src/ABE/policy/policy_generation.cpp
    src/ABE/policy/policy_resolution.cpp
    src/ABE/data_structure/binary_tree_RABE.cpp
)

add_executable(RPCH_TMM_2022_test
    src/scheme/RPCH_TMM_2022.cpp
    src/curve/params.cpp
    src/utils/func.cpp
    unit_test/RPCH_TMM_2022_test.cpp
    src/ABE/RABE_TMM.cpp
    src/ABE/data_structure/access_structure.cpp
    src/ABE/data_structure/binary_tree.cpp
    src/ABE/data_structure/element_t_matrix.cpp
    src/ABE/data_structure/element_t_vector.cpp
    src/ABE/data_structure/multiway_tree.cpp
    src/ABE/data_structure/num_vector.cpp
    src/ABE/policy/policy_generation.cpp
    src/ABE/policy/policy_resolution.cpp
    src/ABE/data_structure/binary_tree_RABE.cpp
)

add_executable(BLS_test
        src/signature/BLS.cpp
        src/utils/func.cpp
        unit_test/signature_test/BLS_test.cpp
        src/curve/params.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/num_vector.cpp
)

add_executable(AES_test
        src/SE/AES.cpp
        src/utils/func.cpp
        unit_test/SE_test/AES_test.cpp
        src/curve/params.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/num_vector.cpp
)

add_executable(PCH_DSS_2019_test
    src/scheme/PCH_DSS_2019.cpp
    src/SE/AES.cpp
    src/curve/params.cpp
    src/utils/func.cpp
    src/RSA/RSA.cpp
    unit_test/PCH_DSS_2019_test.cpp
    src/ABE/CP_ABE.cpp
    src/ABE/data_structure/access_structure.cpp
    src/ABE/data_structure/binary_tree.cpp
    src/ABE/data_structure/element_t_matrix.cpp
    src/ABE/data_structure/element_t_vector.cpp
    src/ABE/data_structure/multiway_tree.cpp
    src/ABE/data_structure/num_vector.cpp
    src/ABE/policy/policy_generation.cpp
    src/ABE/policy/policy_resolution.cpp
)

add_executable(DPCH_MXN_2022_test
    src/scheme/DPCH_MXN_2022.cpp
    src/scheme/CH_ET_BC_CDK_2017.cpp
    src/SE/AES.cpp
    src/curve/params.cpp
    src/utils/func.cpp
    src/RSA/RSA.cpp
    unit_test/DPCH_MXN_2022_test.cpp
    src/ABE/MA_ABE.cpp
    src/signature/BLS.cpp
    src/ABE/data_structure/access_structure.cpp
    src/ABE/data_structure/binary_tree.cpp
    src/ABE/data_structure/element_t_matrix.cpp
    src/ABE/data_structure/element_t_vector.cpp
    src/ABE/data_structure/multiway_tree.cpp
    src/ABE/data_structure/num_vector.cpp
    src/ABE/policy/policy_generation.cpp
    src/ABE/policy/policy_resolution.cpp
)

add_executable(MAPCH_ZLW_2021_test
    src/scheme/MAPCH_ZLW_2021.cpp
    src/scheme/CH_ET_BC_CDK_2017.cpp
    src/curve/params.cpp
    src/utils/func.cpp
    src/RSA/RSA.cpp
    unit_test/MAPCH_ZLW_2021_test.cpp
    src/ABE/MA_ABE.cpp
    src/ABE/data_structure/access_structure.cpp
    src/ABE/data_structure/binary_tree.cpp
    src/ABE/data_structure/element_t_matrix.cpp
    src/ABE/data_structure/element_t_vector.cpp
    src/ABE/data_structure/multiway_tree.cpp
    src/ABE/data_structure/num_vector.cpp
    src/ABE/policy/policy_generation.cpp
    src/ABE/policy/policy_resolution.cpp
)

add_executable(RSA_test
    src/RSA/RSA.cpp
    src/utils/func.cpp
    unit_test/RSA_test/RSA_test.cpp    
    src/ABE/data_structure/access_structure.cpp
    src/ABE/data_structure/binary_tree.cpp
    src/ABE/data_structure/element_t_matrix.cpp
    src/ABE/data_structure/element_t_vector.cpp
    src/ABE/data_structure/multiway_tree.cpp
    src/ABE/data_structure/num_vector.cpp
    src/ABE/policy/policy_generation.cpp
    src/ABE/policy/policy_resolution.cpp
)

add_executable(ABET_test  
        src/ABE/ABET.cpp
        src/curve/params.cpp
        src/utils/func.cpp
        unit_test/ABE_test/ABET_test.cpp
        src/ABE/data_structure/access_structure.cpp
        src/ABE/data_structure/binary_tree.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/multiway_tree.cpp
        src/ABE/data_structure/num_vector.cpp
        src/ABE/policy/policy_generation.cpp
        src/ABE/policy/policy_resolution.cpp
)

add_executable(PCHBA_TLL_2020_test
        src/scheme/PCHBA_TLL_2020.cpp
        src/curve/params.cpp
        src/utils/func.cpp
        unit_test/PCHBA_TLL_2020_test.cpp
        src/ABE/ABET.cpp
        src/ABE/data_structure/access_structure.cpp
        src/ABE/data_structure/binary_tree.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/multiway_tree.cpp
        src/ABE/data_structure/num_vector.cpp
        src/ABE/policy/policy_generation.cpp
        src/ABE/policy/policy_resolution.cpp
)

add_executable(CP_ABE_test  
        src/ABE/CP_ABE.cpp
        src/curve/params.cpp
        src/utils/func.cpp
        unit_test/ABE_test/CP_ABE_test.cpp
        src/ABE/data_structure/access_structure.cpp
        src/ABE/data_structure/binary_tree.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/multiway_tree.cpp
        src/ABE/data_structure/num_vector.cpp
        src/ABE/policy/policy_generation.cpp
        src/ABE/policy/policy_resolution.cpp
)

add_executable(MA_ABE_test  
        src/ABE/MA_ABE.cpp
        src/curve/params.cpp
        src/utils/func.cpp
        unit_test/ABE_test/MA_ABE_test.cpp
        src/ABE/data_structure/access_structure.cpp
        src/ABE/data_structure/binary_tree.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/multiway_tree.cpp
        src/ABE/data_structure/num_vector.cpp
        src/ABE/policy/policy_generation.cpp
        src/ABE/policy/policy_resolution.cpp
)

add_executable(CH_KEF_F_CTZ_2010_test
        src/scheme/CH_KEF_F_CTZ_2010.cpp
        src/utils/func.cpp
        unit_test/CH_KEF_F_CTZ_2010_test.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/num_vector.cpp
)

add_executable(CH_KEF_NoMH_AM_2004_test
        src/scheme/CH_KEF_NoMH_AM_2004.cpp
        src/utils/func.cpp
        src/curve/params.cpp
        unit_test/CH_KEF_NoMH_AM_2004_test.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/num_vector.cpp
)

add_executable(CH_CDK_2017_test 
        src/scheme/CH_CDK_2017.cpp
        src/utils/func.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/num_vector.cpp
        src/RSA/RSA.cpp
        unit_test/CH_CDK_2017_test.cpp)

add_executable(CH_ET_BC_CDK_2017_test 
        src/scheme/CH_ET_BC_CDK_2017.cpp
        src/utils/func.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/num_vector.cpp
        src/RSA/RSA.cpp
        unit_test/CH_ET_BC_CDK_2017_test.cpp)

add_executable(CH_KEF_MH_RSA_F_AM_2004_test 
        src/scheme/CH_KEF_MH_RSA_F_AM_2004.cpp
        src/utils/func.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/num_vector.cpp
        src/RSA/RSA.cpp
        unit_test/CH_KEF_MH_RSA_F_AM_2004_test.cpp)

add_executable(MCH_CDK_2017_test 
        src/scheme/MCH_CDK_2017.cpp
        src/utils/func.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/num_vector.cpp
        src/RSA/RSA.cpp
        unit_test/MCH_CDK_2017_test.cpp)

add_executable(CHET_RSA_CDK_2017_test 
        src/scheme/CHET_RSA_CDK_2017.cpp
        src/utils/func.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/num_vector.cpp
        src/RSA/RSA.cpp
        unit_test/CHET_RSA_CDK_2017_test.cpp)

add_executable(IB_CH_KEF_CZS_2014_test src/scheme/IB_CH_KEF_CZS_2014.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/num_vector.cpp
        unit_test/IB_CH_KEF_CZS_2014_test.cpp)

add_executable(CH_KEF_DLP_LLA_2012_test src/scheme/CH_KEF_DLP_LLA_2012.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/num_vector.cpp
        unit_test/CH_KEF_DLP_LLA_2012_test.cpp)

add_executable(CR_CH_DSS_2020_test src/scheme/CR_CH_DSS_2020.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/num_vector.cpp
        unit_test/CR_CH_DSS_2020_test.cpp)

add_executable(FCR_CH_PreQA_DKS_2020_test src/scheme/FCR_CH_PreQA_DKS_2020.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/num_vector.cpp
        unit_test/FCR_CH_PreQA_DKS_2020_test.cpp)

add_executable(CH_KEF_MH_SDH_DL_AM_2004_test src/scheme/CH_KEF_MH_SDH_DL_AM_2004.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/num_vector.cpp
        unit_test/CH_KEF_MH_SDH_DL_AM_2004_test.cpp)

add_executable(ID_B_CollRes_XSL_2021_test src/scheme/ID_B_CollRes_XSL_2021.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/num_vector.cpp
        unit_test/ID_B_CollRes_XSL_2021_test.cpp)

add_executable(CH_KEF_CZK_2004_test src/scheme/CH_KEF_CZK_2004.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/num_vector.cpp
        unit_test/CH_KEF_CZK_2004_test.cpp)

add_executable(CH_ET_test src/scheme/CH_ET.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/num_vector.cpp
        unit_test/CH_ET_test.cpp)

add_executable(IB_CH_MD_LSX_2022_test 
        src/scheme/IB_CH_MD_LSX_2022.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/num_vector.cpp
        unit_test/IB_CH_MD_LSX_2022_test.cpp)

add_executable(CH_KEF_DL_CZT_2011_test src/scheme/CH_KEF_DL_CZT_2011.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/num_vector.cpp
        unit_test/CH_KEF_DL_CZT_2011_test.cpp)

add_executable(IB_CH_ZSS_2003_test 
        src/scheme/IB_CH_ZSS_2003.cpp
        src/curve/params.cpp
        src/utils/func.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/num_vector.cpp
        unit_test/IB_CH_ZSS_2003_test.cpp)
        
add_executable(FAME-2OD_test  
        src/ABE/FAME-2OD.cpp
        src/curve/params.cpp
        src/utils/func.cpp
        unit_test/ABE_test/FAME-2OD_test.cpp
        src/ABE/data_structure/access_structure.cpp
        src/ABE/data_structure/binary_tree.cpp
        src/ABE/data_structure/element_t_matrix.cpp
        src/ABE/data_structure/element_t_vector.cpp
        src/ABE/data_structure/multiway_tree.cpp
        src/ABE/data_structure/num_vector.cpp
        src/ABE/policy/policy_generation.cpp
        src/ABE/policy/policy_resolution.cpp
)

add_executable(RPCH_2OD_test
    src/scheme/RPCH_2OD.cpp
    src/SE/AES.cpp
    src/curve/params.cpp
    src/utils/func.cpp
    src/RSA/RSA.cpp
    unit_test/RPCH_2OD_test.cpp
    src/ABE/FAME-2OD.cpp
    src/ABE/data_structure/access_structure.cpp
    src/ABE/data_structure/binary_tree.cpp
    src/ABE/data_structure/element_t_matrix.cpp
    src/ABE/data_structure/element_t_vector.cpp
    src/ABE/data_structure/multiway_tree.cpp
    src/ABE/data_structure/num_vector.cpp
    src/ABE/policy/policy_generation.cpp
    src/ABE/policy/policy_resolution.cpp
)

# google test
enable_testing() 
add_executable(TestAll unit_test/TestAll.cpp)
target_link_libraries(TestAll PRIVATE gtest pthread)
add_test(TestAll ${CMAKE_BINARY_DIR}/TestAll)
