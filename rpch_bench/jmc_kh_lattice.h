#pragma once

#include <cstddef>
#include <map>
#include <string>
#include <vector>

struct SchemeResult {
    std::map<std::string, double> times_ms;
    std::map<std::string, std::size_t> sizes_bytes;
};

SchemeResult bench_jmc_kh(
    int users,
    const std::vector<std::string>& attrs,
    int policy_attrs,
    const std::string& curve,
    bool run_ops);
